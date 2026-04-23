//! Probe registry, core trait, and shared context/outcome types.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;

use ps_core::id::{CatchId, EngagementId};
use ps_core::target::Target;
use ps_core::technique::TechniqueTag;

pub mod http;
pub mod mongo;
pub mod passive_banner;
pub mod postgres;
pub mod redis;
pub mod smb;
pub mod ssh;
pub mod tls_hello;

/// Protocol guesses emitted by probes and surfaced on `FingerprintReport`.
///
/// The enum serializes as lowercase strings so the cache and event
/// payloads use stable wire names (e.g. `"http11"`, `"tls"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// HTTP/1.1 plaintext.
    Http11,
    /// HTTP/2 cleartext (h2c) or negotiated via ALPN.
    Http2,
    /// HTTPS (HTTP over TLS) when we know the inner layer.
    Https,
    /// TLS negotiated successfully; inner protocol unknown.
    Tls,
    /// SSH (any version).
    Ssh,
    /// Redis (resp protocol).
    Redis,
    /// MongoDB wire protocol.
    Mongo,
    /// PostgreSQL wire protocol v3.
    Postgres,
    /// SMB / CIFS.
    Smb,
    /// Recognised-as-something but nothing specific matched.
    Unknown,
}

/// Inputs handed to each probe invocation.
///
/// The probe takes ownership of `stream` via `ctx.stream.take()`; the
/// ladder guarantees a fresh `TcpStream` is supplied on every attempt
/// (either the initial catch stream for the first probe, or a fresh
/// `TcpStream::connect` for subsequent probes).
pub struct ProbeContext {
    /// Engagement in whose scope this probe runs.
    pub engagement_id: EngagementId,
    /// Catch this probe attempt belongs to.
    pub catch_id: CatchId,
    /// Target being probed.
    pub target: Target,
    /// Per-catch artifact directory (already created by the ladder).
    pub artifacts_dir: PathBuf,
    /// Overall timeout budget for this probe.
    pub timeout: Duration,
    /// Stream the probe will consume. Always `Some` when invoked by the
    /// ladder; an `Option` so probes can `take()` ownership.
    pub stream: Option<TcpStream>,
}

/// Result of one probe attempt.
#[derive(Debug)]
pub enum ProbeOutcome {
    /// Probe recognised the protocol. `confidence >= 0.9` is treated as
    /// a strong signal and will short-circuit the ladder.
    Match {
        /// Best guess for what the target is running.
        protocol: Protocol,
        /// Confidence in `[0.0, 1.0]`.
        confidence: f32,
        /// Raw bytes the probe captured.
        bytes: Bytes,
    },
    /// Probe ran but no signature matched.
    NoMatch,
    /// Probe failed (timeout, IO error, parse error, ...).
    Error(anyhow::Error),
    /// Probe declined to run for a probe-internal reason (distinct from
    /// ladder-level scope skips).
    Skipped {
        /// Short human-readable reason.
        reason: &'static str,
    },
}

/// One probe in the ladder. Implementors must be stateless (the ladder
/// holds them behind an `Arc<dyn Fingerprinter>`), `Send + Sync`, and
/// cheap to clone via `Arc`.
#[async_trait]
pub trait Fingerprinter: Send + Sync {
    /// Stable wire name (used in `ProbeAttempted.probe`).
    fn name(&self) -> &'static str;
    /// Technique tags this probe embodies. Used for scope gating.
    fn techniques(&self) -> &'static [TechniqueTag];
    /// Whether this probe is "destructive" (writes, auth attempts, etc.).
    /// Defaults to `false` — most probes are read-mostly.
    fn is_destructive(&self) -> bool {
        false
    }
    /// Run the probe, consuming the supplied `ctx.stream`.
    async fn probe(&self, ctx: ProbeContext) -> ProbeOutcome;
}
