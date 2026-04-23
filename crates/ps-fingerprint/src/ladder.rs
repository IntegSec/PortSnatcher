//! `ProbeLadder`: walks probes on fresh connections, one per attempt,
//! short-circuiting on a strong match (confidence >= 0.9).
//!
//! Each ladder invocation emits a stream of `ProbeAttempted` events,
//! then a terminal `FingerprintCaptured` and `CatchComplete`. Artifacts
//! live under `<artifacts_root>/<catch_id>/`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::net::TcpStream;

use ps_bus::broadcast::BusSender;
use ps_core::engagement::Engagement;
use ps_core::event::payload::{
    CatchComplete, EventBody, FingerprintCaptured, ProbeAttempted, TlsInfo,
};
use ps_core::event::Event;
use ps_core::id::CatchId;
use ps_core::target::Target;
use ps_core::technique::TechniqueTag;

use crate::cache::FingerprintCache;
use crate::probes::{Fingerprinter, ProbeContext, ProbeOutcome, Protocol};
use crate::report::FingerprintReport;

/// Default per-probe timeout budget.
const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_millis(500);
/// Excerpt truncation length for the `banner_excerpt` field.
const EXCERPT_LIMIT: usize = 200;

/// Walks probes on fresh connections in registration order.
///
/// The ladder is constructed once per engagement and is cheap to clone
/// — the probes themselves live behind an `Arc`. The `cache` is shared
/// across catches within an engagement.
pub struct ProbeLadder {
    /// Probes in ladder order. First probe gets the catch stream; each
    /// subsequent probe gets a freshly-connected `TcpStream`.
    pub probes: Vec<Arc<dyn Fingerprinter>>,
    /// Engagement artifact root. The ladder writes under
    /// `<artifacts_root>/catches/<catch_id>/`.
    pub artifacts_root: PathBuf,
    /// Per-engagement fingerprint cache.
    pub cache: FingerprintCache,
}

impl ProbeLadder {
    /// Build a ladder with the supplied probes, artifact root, and cache.
    pub fn new(
        probes: Vec<Arc<dyn Fingerprinter>>,
        artifacts_root: PathBuf,
        cache: FingerprintCache,
    ) -> Self {
        Self {
            probes,
            artifacts_root,
            cache,
        }
    }

    /// Run the ladder against a catch.
    ///
    /// `initial_stream` is the stream the engine handed us on catch.
    /// It's consumed by the first probe that is authorised; subsequent
    /// probes each get a fresh `TcpStream::connect` to preserve the
    /// "fresh connection per probe" discipline.
    pub async fn run(
        &self,
        engagement: &Engagement,
        catch_id: CatchId,
        target: Target,
        initial_stream: TcpStream,
        bus: &BusSender,
    ) {
        let catch_dir = self
            .artifacts_root
            .join("catches")
            .join(catch_id.to_string());
        let _ = tokio::fs::create_dir_all(&catch_dir).await;
        let started = Instant::now();

        // Cache short-circuit: if we've already fingerprinted this
        // (ip,port), skip the ladder and emit a CatchComplete reusing
        // the cached protocol.
        if let Some(cached) = self.cache.get(&target).await {
            emit_catch_complete(
                bus,
                engagement,
                catch_id,
                started,
                0,
                cached.protocol_guess,
                &cached.artifacts_path,
            );
            return;
        }

        let mut current_stream: Option<TcpStream> = Some(initial_stream);
        let mut best: Option<(Protocol, f32, Bytes)> = None;
        // Event-payload TlsInfo (populated by TlsHello probe in Phase 3 polish).
        let event_tls_info: Option<TlsInfo> = None;
        // Report-level TlsInfo persisted on the cache (same story).
        let report_tls_info: Option<crate::report::TlsInfo> = None;
        let mut probes_run = 0u32;

        for probe in self.probes.iter() {
            // Ladder-level scope gating happens before we consume the stream.
            if !probe_authorised(engagement, probe.as_ref()) {
                emit_probe_attempted(
                    bus,
                    engagement,
                    catch_id,
                    probe.name(),
                    "skipped_by_scope",
                    0,
                );
                continue;
            }
            if probe.is_destructive()
                && engagement
                    .scope_file
                    .excluded_techniques
                    .iter()
                    .any(|t| matches!(t, TechniqueTag::Destructive))
            {
                emit_probe_attempted(
                    bus,
                    engagement,
                    catch_id,
                    probe.name(),
                    "skipped_destructive_excluded",
                    0,
                );
                continue;
            }

            // Fresh-connection discipline: first probe consumes the
            // initial stream; every subsequent probe gets a new one.
            let stream = match current_stream.take() {
                Some(s) => s,
                None => match TcpStream::connect((target.ip, target.port)).await {
                    Ok(s) => s,
                    Err(_) => {
                        // Port closed between attempts — stop the ladder.
                        break;
                    }
                },
            };

            let ctx = ProbeContext {
                engagement_id: engagement.id,
                catch_id,
                target: target.clone(),
                artifacts_dir: catch_dir.clone(),
                timeout: DEFAULT_PROBE_TIMEOUT,
                stream: Some(stream),
            };
            let outcome = probe.probe(ctx).await;
            probes_run += 1;
            match outcome {
                ProbeOutcome::Match {
                    protocol,
                    confidence,
                    bytes,
                } => {
                    emit_probe_attempted(
                        bus,
                        engagement,
                        catch_id,
                        probe.name(),
                        "match",
                        bytes.len(),
                    );
                    let better = best.as_ref().map(|b| confidence > b.1).unwrap_or(true);
                    if better {
                        best = Some((protocol, confidence, bytes));
                    }
                    if confidence >= 0.9 {
                        break;
                    }
                }
                ProbeOutcome::NoMatch => {
                    emit_probe_attempted(bus, engagement, catch_id, probe.name(), "nomatch", 0);
                }
                ProbeOutcome::Error(e) => {
                    tracing::debug!("probe {} error: {e:#}", probe.name());
                    emit_probe_attempted(bus, engagement, catch_id, probe.name(), "error", 0);
                }
                ProbeOutcome::Skipped { reason } => {
                    tracing::debug!("probe {} skipped: {reason}", probe.name());
                    emit_probe_attempted(bus, engagement, catch_id, probe.name(), "skipped", 0);
                }
            }
        }

        let banner_excerpt = best
            .as_ref()
            .map(|b| truncate_excerpt(&b.2))
            .unwrap_or_default();
        let protocol_guess = best.as_ref().map(|b| b.0);
        let confidence = best.as_ref().map(|b| b.1).unwrap_or(0.0);
        let path_string = catch_dir.to_string_lossy().into_owned();

        let captured = Event::new(
            engagement.id,
            Some(catch_id),
            EventBody::FingerprintCaptured(FingerprintCaptured {
                protocol_guess: protocol_guess.map(protocol_wire_name),
                confidence,
                banner_excerpt,
                tls_info: event_tls_info.clone(),
                artifacts_path: path_string.clone(),
            }),
        );
        bus.send(captured);

        emit_catch_complete(
            bus,
            engagement,
            catch_id,
            started,
            probes_run,
            protocol_guess,
            &catch_dir,
        );

        if let Some((protocol, conf, bytes)) = best {
            let report = FingerprintReport {
                catch_id,
                protocol_guess: Some(protocol),
                confidence: conf,
                banner_excerpt: bytes,
                tls_info: report_tls_info,
                probes_run: vec![],
                artifacts_path: catch_dir.clone(),
            };
            self.cache.insert(target, report).await;
            let _ = self.cache.flush().await;
        }
    }
}

fn probe_authorised(engagement: &Engagement, probe: &dyn Fingerprinter) -> bool {
    let authorised = &engagement.scope_file.authorized_techniques;
    if authorised.is_empty() {
        return true;
    }
    probe.techniques().iter().any(|t| authorised.contains(t))
}

fn truncate_excerpt(bytes: &[u8]) -> String {
    let lossy = String::from_utf8_lossy(bytes);
    if lossy.chars().count() <= EXCERPT_LIMIT {
        return lossy.into_owned();
    }
    lossy.chars().take(EXCERPT_LIMIT).collect()
}

fn protocol_wire_name(p: Protocol) -> String {
    match p {
        Protocol::Http11 => "http11".into(),
        Protocol::Http2 => "http2".into(),
        Protocol::Https => "https".into(),
        Protocol::Tls => "tls".into(),
        Protocol::Ssh => "ssh".into(),
        Protocol::Redis => "redis".into(),
        Protocol::Mongo => "mongo".into(),
        Protocol::Postgres => "postgres".into(),
        Protocol::Smb => "smb".into(),
        Protocol::Unknown => "unknown".into(),
    }
}

fn emit_probe_attempted(
    bus: &BusSender,
    engagement: &Engagement,
    catch_id: CatchId,
    probe: &'static str,
    outcome: &'static str,
    bytes_captured: usize,
) {
    let event = Event::new(
        engagement.id,
        Some(catch_id),
        EventBody::ProbeAttempted(ProbeAttempted {
            probe: probe.to_owned(),
            outcome: outcome.to_owned(),
            bytes_captured,
        }),
    );
    bus.send(event);
}

fn emit_catch_complete(
    bus: &BusSender,
    engagement: &Engagement,
    catch_id: CatchId,
    started: Instant,
    probes_run: u32,
    protocol: Option<Protocol>,
    catch_dir: &std::path::Path,
) {
    let event = Event::new(
        engagement.id,
        Some(catch_id),
        EventBody::CatchComplete(CatchComplete {
            total_duration_ms: started.elapsed().as_millis() as u64,
            probes_run,
            final_protocol: protocol.map(protocol_wire_name),
            artifacts_path: catch_dir.to_string_lossy().into_owned(),
        }),
    );
    bus.send(event);
}
