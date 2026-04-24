//! Orchestrator: owns the event bus, spawns sinks, runs the engagement,
//! shuts down cleanly on Ctrl-C or when the engagement window expires.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

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
use tokio::sync::mpsc;
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

        let engagement = build_engagement(&self.cli).await?;
        let engagement_id = engagement.id;
        let port_plan = build_port_plan(&self.cli)?;

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
        self.shutdown.cancel();

        // Give in-flight work a moment to finish cleanly.
        tokio::time::sleep(Duration::from_millis(300)).await;

        self.bus.send(Event::new(
            engagement_id,
            None,
            EventBody::EngagementFinished(EngagementFinished {
                catches_total: 0, // best-effort; full accounting is Phase 2+ polish
                artifacts_root: self.cli.artifacts_dir.to_string_lossy().into_owned(),
                reason: reason.to_owned(),
            }),
        ));

        // Final flush window.
        tokio::time::sleep(Duration::from_millis(200)).await;
        Ok(())
    }
}

/// Build an `Engagement` from the CLI. If `--scope-file` is supplied,
/// load it; otherwise construct a minimal permissive scope for quick
/// CLI-only runs (127.0.0.0/8 with an open time window — matching the
/// safety posture of allowing only loopback by default when no scope
/// file is present).
async fn build_engagement(cli: &Cli) -> anyhow::Result<Engagement> {
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
    for cidr_str in &scope_file.authorized_targets.ip_ranges {
        if let Ok(net) = cidr_str.parse() {
            builder = builder.allow_cidr(net);
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
    let guard = builder.build();
    Ok(Engagement::new(
        EngagementId::new(),
        profile,
        scope_file,
        config,
        guard,
    ))
}

/// Expand the CLI `--target` and `--ports` into an explicit (ip, port) plan.
fn build_port_plan(cli: &Cli) -> anyhow::Result<Vec<(IpAddr, u16)>> {
    let target_str = cli.target.as_deref().unwrap_or("127.0.0.1");
    let ip: IpAddr = target_str
        .parse::<IpAddr>()
        .with_context(|| format!("parse --target as IP {target_str}"))?;

    let ports_str = cli.ports.as_deref().unwrap_or("top-1000");
    let ports =
        PortSpec::from_spec_str(ports_str).with_context(|| format!("parse --ports {ports_str}"))?;

    Ok(ports.iter().map(|p| (ip, p)).collect())
}

/// Build a full-registry ProbeLadder rooted at the artifacts dir.
async fn build_ladder(artifacts_dir: &Path) -> anyhow::Result<ProbeLadder> {
    let cache_path = artifacts_dir.join("fingerprint-cache.json");
    let cache = FingerprintCache::load(cache_path)
        .await
        .unwrap_or_else(|_| FingerprintCache::new(artifacts_dir.join("fingerprint-cache.json")));

    let probes: Vec<Arc<dyn Fingerprinter>> = vec![
        Arc::new(PassiveBanner::default()),
        Arc::new(TlsHello::default()),
        Arc::new(HttpHead::default()),
        Arc::new(HttpGetRoot::default()),
        Arc::new(SshBanner::default()),
        Arc::new(RedisPing::default()),
        Arc::new(MongoIsMaster::default()),
        Arc::new(PostgresStartup::default()),
        Arc::new(SmbNegotiate::default()),
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
