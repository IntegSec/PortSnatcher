//! Orchestrator: owns the event bus, spawns sinks, runs the engagement,
//! shuts down cleanly on Ctrl-C or when the engagement window expires.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use ps_bus::auth::AuthToken;
use ps_bus::broadcast::BusSender;
use ps_bus::server::ServerState;
use ps_core::config::Config;
use ps_core::engagement::Engagement;
use ps_core::event::payload::{EngagementFinished, EngagementStarted, EventBody};
use ps_core::event::Event;
use ps_core::id::EngagementId;
use ps_core::port::PortSpec;
use ps_core::profile::Profile;
use ps_core::scope::file::ScopeFile;
use ps_core::scope::guard::ScopeGuard;
use ps_core::target::{CidrBlock, Target};
use ps_core::technique::TechniqueTag;
use ps_engine::engine::{EngineContext, ProbeEngine};
use ps_engine::{ConnectEngine, RateLimiter};
use ps_fingerprint::cache::FingerprintCache;
use ps_fingerprint::ladder::ProbeLadder;
use ps_fingerprint::probes::{
    http::{HttpGetRoot, HttpHead},
    mongo::MongoIsMaster,
    passive_banner::PassiveBanner,
    postgres::PostgresStartup,
    redis::RedisPing,
    smb::SmbNegotiate,
    ssh::SshBanner,
    tls_hello::TlsHello,
    Fingerprinter,
};
use ps_notify::sink::EventSink;
use ps_notify::{JsonlSink, TerminalSink};
use ps_proxy::dumb_tunnel::DumbTunnel;
use ps_proxy::hold_open::{HoldOpen, HoldOpenManager};
use ps_proxy::Ca;
use std::collections::HashSet;
use tokio::net::TcpStream as AsyncTcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

use crate::cli::{Cli, ProfileArg};
use crate::cmd::dry_run::{simulate, SimulationConfig};

pub struct Orchestrator {
    pub cli: Cli,
    pub bus: BusSender,
    pub sinks: Arc<Vec<Arc<dyn EventSink>>>,
    pub shutdown: CancellationToken,
}

impl Orchestrator {
    pub async fn from_cli(cli: Cli) -> anyhow::Result<Self> {
        let (bus, _initial_rx) = BusSender::new(1024);

        let mut sinks: Vec<Arc<dyn EventSink>> = vec![Arc::new(TerminalSink)];
        let jsonl_path = cli.artifacts_dir.join("events.jsonl");
        let jsonl = JsonlSink::open(jsonl_path.clone())
            .await
            .with_context(|| format!("open jsonl at {}", jsonl_path.display()))?;
        sinks.push(Arc::new(jsonl));

        Ok(Self {
            cli,
            bus,
            sinks: Arc::new(sinks),
            shutdown: CancellationToken::new(),
        })
    }

    /// Spawn a background task that forwards every bus event to every
    /// sink. Each sink runs independently; a slow sink never blocks the
    /// bus or any other sink.
    pub fn spawn_sink_dispatcher(&self) {
        let sinks = self.sinks.clone();
        let mut rx = self.bus.subscribe();
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    res = rx.recv() => {
                        match res {
                            Ok(ev) => {
                                for sink in sinks.iter() {
                                    let sink = Arc::clone(sink);
                                    let ev = ev.clone();
                                    tokio::spawn(async move {
                                        sink.emit(&ev).await;
                                    });
                                }
                            }
                            Err(ps_bus::broadcast::BusError::Closed) => break,
                            Err(ps_bus::broadcast::BusError::Lagged(n)) => {
                                tracing::warn!("sink dispatcher lagged {n} events");
                            }
                        }
                    }
                }
            }
        });
    }

    /// Start the bus HTTP server, write bus.json, and spawn the sink
    /// dispatcher. Returns the bound SocketAddr.
    async fn bring_up_bus(&self) -> anyhow::Result<(SocketAddr, AuthToken)> {
        let token = AuthToken::generate();
        let bind: SocketAddr = self
            .cli
            .bus_listen
            .parse()
            .with_context(|| format!("parse --bus-listen {}", self.cli.bus_listen))?;
        let actual = ps_bus::server::run(
            bind,
            ServerState {
                bus: self.bus.clone(),
                token: token.clone(),
            },
            self.shutdown.clone(),
        )
        .await
        .context("bus server bind")?;
        write_bus_info(&self.cli.artifacts_dir, &actual, &token)
            .await
            .ok();
        self.spawn_sink_dispatcher();
        Ok((actual, token))
    }

    pub async fn run_dry(&self) -> anyhow::Result<()> {
        self.bring_up_bus().await?;

        let sim = SimulationConfig {
            profile: format!("{:?}", self.cli.profile).to_lowercase(),
            engine: self.cli.engine.as_wire().to_owned(),
            targets: vec![self
                .cli
                .target
                .clone()
                .unwrap_or_else(|| "127.0.0.1".into())],
            ports: self
                .cli
                .ports
                .clone()
                .unwrap_or_else(|| "ephemeral-iana".into()),
            artifacts_root: self.cli.artifacts_dir.to_string_lossy().into_owned(),
            ..Default::default()
        };
        simulate(&self.bus, sim).await;

        // Give sinks a beat to flush.
        tokio::time::sleep(Duration::from_millis(200)).await;
        self.shutdown.cancel();
        Ok(())
    }

    /// Live engagement: ConnectEngine catches ports, ProbeLadder
    /// fingerprints each. Runs until the port plan has been exercised
    /// for `duration_ms` (default 10s when unspecified) or a shutdown
    /// is requested.
    pub async fn run_live(&self, duration_ms: u64) -> anyhow::Result<()> {
        self.bring_up_bus().await?;

        let prepared = build_engagement(&self.cli).await?;
        let engagement = prepared.engagement;
        let engagement_id = engagement.id;
        let port_plan = build_port_plan(&self.cli, &prepared.scope_ips)?;
        tracing::info!(
            "built port plan: {} (ip, port) tuples across {} target(s)",
            port_plan.len(),
            port_plan
                .iter()
                .map(|(ip, _)| *ip)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        );

        let profile_defaults = engagement.profile.defaults();
        let rate = Arc::new(RateLimiter::new(
            profile_defaults.global_pps,
            profile_defaults.per_target_pps,
        ));

        // Emit EngagementStarted.
        self.bus.send(Event::new(
            engagement_id,
            None,
            EventBody::EngagementStarted(EngagementStarted {
                profile: format!("{:?}", engagement.profile).to_lowercase(),
                engine: self.cli.engine.as_wire().to_owned(),
                targets: port_plan
                    .iter()
                    .map(|(ip, _)| ip.to_string())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                ports: self
                    .cli
                    .ports
                    .clone()
                    .unwrap_or_else(|| "ephemeral-iana".into()),
                rate_cap_pps: profile_defaults.global_pps,
                dry_run: false,
            }),
        ));

        // mpsc channel the engine pushes ConnectionCaught onto; ladder
        // worker pool drains it.
        let (catch_tx, mut catch_rx) = mpsc::channel(64);

        let ctx = EngineContext {
            engagement: engagement.clone(),
            rate_limiter: rate,
            catch_tx,
            bus: self.bus.clone(),
            plan: port_plan,
        };

        // Spawn hold-open manager BEFORE the engine starts. It
        // subscribes to PortOpenDetected events on the bus, and for
        // each new (ip, port) opens a fresh upstream TcpStream and
        // hands it to DumbTunnel::establish. One tunnel per (ip, port);
        // re-catches are no-ops. Subscribing before the engine emits
        // ensures no early catch is lost to the broadcast.
        spawn_hold_open_manager(self.bus.clone(), self.shutdown.clone(), engagement_id);

        let engine = Box::new(ConnectEngine::new());
        let engine_handle = engine.start(ctx).await?;

        // Spawn the ladder worker pool.
        let ladder = Arc::new(build_ladder(&self.cli.artifacts_dir).await?);
        let ladder_shutdown = self.shutdown.clone();
        let ladder_engagement = engagement.clone();
        let ladder_bus = self.bus.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = ladder_shutdown.cancelled() => break,
                    got = catch_rx.recv() => {
                        let Some(caught) = got else { break };
                        let ladder = Arc::clone(&ladder);
                        let engagement = ladder_engagement.clone();
                        let bus = ladder_bus.clone();
                        tokio::spawn(async move {
                            ladder
                                .run(
                                    &engagement,
                                    caught.catch_id,
                                    caught.target,
                                    caught.stream,
                                    &bus,
                                )
                                .await;
                        });
                    }
                }
            }
        });

        // Periodic progress heartbeat. Long scans against filtered
        // hosts can otherwise look dead — no events fire until a port
        // opens. A tracing::info! every 15 seconds gives the operator a
        // pulse.
        let hb_shutdown = self.shutdown.clone();
        let hb_total_ms = duration_ms;
        let hb_started = Instant::now();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await; // consume the immediate first tick
            loop {
                tokio::select! {
                    _ = hb_shutdown.cancelled() => break,
                    _ = interval.tick() => {
                        let elapsed = hb_started.elapsed().as_secs();
                        let total = hb_total_ms / 1000;
                        let remaining = total.saturating_sub(elapsed);
                        tracing::info!("scan heartbeat  elapsed={}s remaining={}s", elapsed, remaining);
                    }
                }
            }
        });

        // Run until duration or shutdown.
        let timer = tokio::time::sleep(Duration::from_millis(duration_ms));
        tokio::pin!(timer);
        let mut ctrl_c = Box::pin(tokio::signal::ctrl_c());
        let reason = tokio::select! {
            _ = self.shutdown.cancelled() => "shutdown",
            _ = &mut timer => "window_expired",
            _ = &mut ctrl_c => "interrupted",
        };

        engine_handle.stop();

        // Let in-flight catches/probes drain before the terminal event.
        tokio::time::sleep(Duration::from_millis(300)).await;

        self.bus.send(Event::new(
            engagement_id,
            None,
            EventBody::EngagementFinished(EngagementFinished {
                catches_total: 0, // best-effort; full accounting is a polish item
                artifacts_root: self.cli.artifacts_dir.to_string_lossy().into_owned(),
                reason: reason.to_owned(),
            }),
        ));

        // Final flush window: let the sink dispatcher pick up the
        // EngagementFinished event before we tear it down.
        tokio::time::sleep(Duration::from_millis(400)).await;
        self.shutdown.cancel();
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(())
    }
}

/// Output of [`build_engagement`] — the runtime Engagement plus the
/// scope-derived list of IPs we'd naturally target if `--target` is
/// omitted. `scope_ips` is the union of every `/32`/`/128` in
/// `authorized_targets.ip_ranges` plus every IPv4 we resolved from
/// `authorized_targets.domains`.
pub struct PreparedScope {
    pub engagement: Engagement,
    pub scope_ips: Vec<IpAddr>,
}

/// Build an `Engagement` from the CLI. If `--scope-file` is supplied,
/// load it AND resolve every non-wildcard domain into its current IPv4
/// addresses via `tokio::net::lookup_host`; each resolved IPv4 is
/// added to the `ScopeGuard`'s allowlist as a `/32`. This matches the
/// spec's monotonic-scope-growth policy for the single-startup case.
///
/// When no scope file is provided, construct a minimal synthetic one —
/// permissive against the CLI `--target` (or loopback) with an open
/// time window — so quick CLI-only runs still work.
async fn build_engagement(cli: &Cli) -> anyhow::Result<PreparedScope> {
    let config = if let Some(path) = cli.config.as_ref() {
        Config::load(path).with_context(|| format!("load config {}", path.display()))?
    } else {
        Config::from_toml_str(r#"scope_file = "unused""#).expect("minimal inline config parses")
    };

    let profile: Profile = match cli.profile {
        ProfileArg::Internal => Profile::Internal,
        ProfileArg::External => Profile::External,
        ProfileArg::Ctf => Profile::Ctf,
    };

    let (scope_file, guard_cidr) = if let Some(path) = cli.scope_file.as_ref() {
        let sf =
            ScopeFile::load(path).with_context(|| format!("load scope file {}", path.display()))?;
        (sf, None)
    } else {
        // Fall back to a CLI-only target. If --target is set and parses
        // as a CIDR, use it; otherwise limit to loopback.
        let cidr = cli
            .target
            .as_deref()
            .and_then(|t| t.parse::<CidrBlock>().ok())
            .or_else(|| "127.0.0.0/8".parse().ok());
        // Synthesize a minimal valid ScopeFile so Engagement has one.
        let raw = r#"{
            "engagement_id": "ENG-CLI",
            "client": "local",
            "operator": "operator",
            "authorized_targets": { "ip_ranges": [], "domains": [], "urls": [], "cloud_accounts": [] },
            "excluded_targets": [],
            "authorized_techniques": ["recon", "web_app", "api_testing", "ssl_tls"],
            "excluded_techniques": ["destructive", "dos", "social_engineering"],
            "engagement_window": { "start": "2000-01-01T00:00:00Z", "end": "2099-12-31T23:59:59Z" }
        }"#;
        let sf: ScopeFile = serde_json::from_str(raw).expect("synthetic scope parses");
        (sf, cidr)
    };

    let mut builder = ScopeGuard::builder();
    let mut scope_ips: Vec<IpAddr> = Vec::new();

    // Authorized CIDRs go straight into the guard. For /32 entries we
    // also surface them as candidate targets.
    for cidr_str in &scope_file.authorized_targets.ip_ranges {
        match cidr_str.parse::<ipnet::IpNet>() {
            Ok(net) => {
                builder = builder.allow_cidr(net);
                // For /32 (or /128) ranges record the exact host as a
                // candidate target. For broader CIDRs we skip iteration
                // here (could be millions of addresses); the operator
                // should pass --target explicitly in that case.
                let is_host = matches!(net, ipnet::IpNet::V4(n) if n.prefix_len() == 32)
                    || matches!(net, ipnet::IpNet::V6(n) if n.prefix_len() == 128);
                if is_host {
                    scope_ips.push(net.network());
                }
            }
            Err(e) => {
                tracing::warn!("ignoring bad CIDR in scope file: {cidr_str} ({e})");
            }
        }
    }

    // Authorized domains: resolve now, add each resolved IPv4 as /32.
    // Wildcards (`*.example.com`) can't be resolved; we log and skip.
    for domain in &scope_file.authorized_targets.domains {
        if domain.starts_with('*') {
            tracing::info!(
                "scope domain {domain} is a wildcard — cannot resolve; matching hosts must be \
                 added as explicit entries or via --target"
            );
            continue;
        }
        match tokio::net::lookup_host(format!("{domain}:0")).await {
            Ok(addrs) => {
                let mut found = 0usize;
                for addr in addrs {
                    if let IpAddr::V4(v4) = addr.ip() {
                        let net: ipnet::IpNet = format!("{v4}/32").parse().expect("/32 parses");
                        builder = builder.allow_cidr(net);
                        scope_ips.push(IpAddr::V4(v4));
                        found += 1;
                        tracing::info!("scope domain {domain} resolved to {v4} (added as /32)");
                    }
                }
                if found == 0 {
                    tracing::warn!(
                        "scope domain {domain} resolved to zero IPv4 addresses — skipping"
                    );
                }
            }
            Err(e) => {
                tracing::warn!("scope domain {domain} failed to resolve: {e} — skipping");
            }
        }
    }

    if let Some(cidr) = guard_cidr {
        builder = builder.allow_cidr(cidr.0);
    }
    builder = builder
        .allow_techniques(scope_file.authorized_techniques.clone())
        .deny_techniques(scope_file.excluded_techniques.clone())
        .window(
            scope_file.engagement_window.start,
            scope_file.engagement_window.end,
        );
    for host in &scope_file.excluded_targets {
        if let Ok(ip) = host.parse::<IpAddr>() {
            builder = builder.deny_host(ip);
        }
    }

    // De-duplicate scope_ips so a domain that resolves to the same IP as
    // an explicit /32 entry doesn't appear twice.
    scope_ips.sort();
    scope_ips.dedup();

    let guard = builder.build();
    Ok(PreparedScope {
        engagement: Engagement::new(EngagementId::new(), profile, scope_file, config, guard),
        scope_ips,
    })
}

/// Expand `--target` + `--ports` into an explicit `(ip, port)` plan.
///
/// Precedence:
/// 1. If `--target` is set, parse it as a single IP and use only that.
/// 2. Otherwise, iterate every IP in `scope_ips` (from the scope file's
///    `/32`s and resolved domains).
/// 3. If both are empty, error out — defaulting silently to loopback
///    lies to the operator and leads to a flood of `ScopeViolationBlocked`
///    events.
fn build_port_plan(cli: &Cli, scope_ips: &[IpAddr]) -> anyhow::Result<Vec<(IpAddr, u16)>> {
    let ports_str = cli.ports.as_deref().unwrap_or("top-1000");
    let ports =
        PortSpec::from_spec_str(ports_str).with_context(|| format!("parse --ports {ports_str}"))?;

    let ips: Vec<IpAddr> = if let Some(target_str) = cli.target.as_deref() {
        let ip: IpAddr = target_str
            .parse()
            .with_context(|| format!("parse --target as IP {target_str}"))?;
        vec![ip]
    } else if !scope_ips.is_empty() {
        tracing::info!(
            "no --target supplied; using {} scope-derived target(s): {:?}",
            scope_ips.len(),
            scope_ips
        );
        scope_ips.to_vec()
    } else {
        anyhow::bail!(
            "no --target supplied and the scope file has no resolvable targets (no /32 ip_ranges \
             and no resolvable domains). Add a target explicitly or populate the scope file."
        );
    };

    let mut plan = Vec::with_capacity(ips.len() * ports.len());
    for ip in &ips {
        for port in ports.iter() {
            plan.push((*ip, port));
        }
    }
    Ok(plan)
}

/// Subscribe to `PortOpenDetected` on the bus and stand up a DumbTunnel
/// per first-seen `(ip, port)`. The tunnel's own `HoldOpenClosed`
/// event removes the entry from the active set so a later re-open can
/// spawn a fresh tunnel.
///
/// CA bootstrap is best-effort: if `Ca::new_or_load` fails (e.g. the
/// config dir is not writable), we log a warning and skip hold-open.
/// ConnectEngine + fingerprinter remain unaffected.
fn spawn_hold_open_manager(
    bus: BusSender,
    shutdown: CancellationToken,
    engagement_id: EngagementId,
) {
    // Subscribe BEFORE any async work. tokio::broadcast doesn't buffer
    // events for a late subscriber, so if we subscribe inside the
    // spawned task — after CA file I/O / keygen completes — any
    // PortOpenDetected events the engine fires in the meantime are
    // lost and hold-open never starts for them. This was the root
    // cause of "TUI Tunnel column stays blank" in v1.2.2.
    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        // Prepare HoldOpenManager once. CA storage lives under the
        // XDG-aware config dir (macOS/Linux/Windows all picked via
        // `directories`). Hold-open is best-effort: if CA setup
        // fails (locked-down filesystem, etc.), we log and skip.
        let ca_dir = match ps_proxy::ca::storage::default_dir() {
            Some(d) => d,
            None => {
                tracing::warn!(
                    "hold-open manager disabled — no config dir available for CA storage"
                );
                return;
            }
        };
        let ca = match Ca::new_or_load(&ca_dir) {
            Ok(ca) => Arc::new(ca),
            Err(e) => {
                tracing::warn!(
                    "hold-open manager disabled — could not load/generate MITM CA at {}: {e:#}. \
                     ConnectEngine + fingerprint will still run.",
                    ca_dir.display()
                );
                return;
            }
        };
        let manager = Arc::new(HoldOpenManager::new(
            ps_proxy::hold_open::DEFAULT_PORT_RANGE,
            ca,
        ));
        let active: Arc<Mutex<HashSet<(IpAddr, u16)>>> = Arc::new(Mutex::new(HashSet::new()));

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                recv = rx.recv() => {
                    let ev = match recv {
                        Ok(ev) => ev,
                        Err(ps_bus::broadcast::BusError::Closed) => break,
                        Err(_) => continue,
                    };
                    match &ev.body {
                        EventBody::PortOpenDetected(p) => {
                            let Ok(ip) = p.target.parse::<IpAddr>() else { continue };
                            let port = p.port;
                            // De-dup: one tunnel per (ip, port).
                            {
                                let mut set = active.lock().await;
                                if !set.insert((ip, port)) {
                                    continue;
                                }
                            }
                            let catch_id = ev.catch_id.unwrap_or_default();
                            let bus = bus.clone();
                            let manager = Arc::clone(&manager);
                            let active = Arc::clone(&active);
                            tokio::spawn(async move {
                                if let Err(e) =
                                    run_one_hold_open(manager, bus, engagement_id, catch_id, ip, port).await
                                {
                                    tracing::warn!("hold-open {ip}:{port} failed: {e:#}");
                                }
                                let mut set = active.lock().await;
                                set.remove(&(ip, port));
                            });
                        }
                        EventBody::PortClosedDetected(p) => {
                            // If the port closed before or during hold-open,
                            // let the tunnel's own lifecycle handle cleanup.
                            // The active-set entry is removed by the
                            // spawned task above on Drop. We just log.
                            tracing::debug!(
                                "port closed {}:{} (hold-open will exit via upstream_closed)",
                                p.target,
                                p.port
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
    });
}

/// Open a fresh upstream `TcpStream` to `(ip, port)` and run one
/// DumbTunnel session. Returns when the tunnel closes.
async fn run_one_hold_open(
    manager: Arc<HoldOpenManager>,
    bus: BusSender,
    engagement_id: EngagementId,
    catch_id: ps_core::id::CatchId,
    ip: IpAddr,
    port: u16,
) -> anyhow::Result<()> {
    let addr = SocketAddr::new(ip, port);
    let upstream = tokio::time::timeout(Duration::from_millis(1500), AsyncTcpStream::connect(addr))
        .await
        .context("upstream connect timed out for hold-open")?
        .context("upstream connect failed for hold-open")?;

    let tunnel = DumbTunnel::new(manager);
    Box::new(tunnel)
        .establish(catch_id, upstream, addr, None, bus, engagement_id)
        .await?;
    Ok(())
}

/// Build a full-registry ProbeLadder rooted at the artifacts dir.
async fn build_ladder(artifacts_dir: &Path) -> anyhow::Result<ProbeLadder> {
    let cache_path = artifacts_dir.join("fingerprint-cache.json");
    let cache = FingerprintCache::load(cache_path)
        .await
        .unwrap_or_else(|_| FingerprintCache::new(artifacts_dir.join("fingerprint-cache.json")));

    let probes: Vec<Arc<dyn Fingerprinter>> = vec![
        Arc::new(PassiveBanner),
        Arc::new(TlsHello),
        Arc::new(HttpHead),
        Arc::new(HttpGetRoot),
        Arc::new(SshBanner),
        Arc::new(RedisPing),
        Arc::new(MongoIsMaster),
        Arc::new(PostgresStartup),
        Arc::new(SmbNegotiate),
    ];

    Ok(ProbeLadder {
        probes,
        artifacts_root: artifacts_dir.to_path_buf(),
        cache,
    })
}

async fn write_bus_info(
    artifacts_dir: &PathBuf,
    addr: &SocketAddr,
    token: &AuthToken,
) -> anyhow::Result<()> {
    tokio::fs::create_dir_all(artifacts_dir).await.ok();
    let info = serde_json::json!({
        "bus_addr": addr.to_string(),
        "bearer_token": token.0,
    });
    let path = artifacts_dir.join("bus.json");
    tokio::fs::write(path, serde_json::to_vec_pretty(&info)?).await?;
    Ok(())
}

// Silence dead-code warnings while only a subset of imports are used
// by the in-scope code path.
#[allow(dead_code)]
fn _touch(_: TechniqueTag, _: Target) {}
