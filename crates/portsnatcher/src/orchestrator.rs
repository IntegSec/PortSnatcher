//! Orchestrator: owns the event bus, spawns sinks, runs the engagement,
//! shuts down cleanly on Ctrl-C or when the engagement window expires.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use ps_bus::auth::AuthToken;
use ps_bus::broadcast::BusSender;
use ps_bus::server::ServerState;
use ps_notify::sink::EventSink;
use ps_notify::{JsonlSink, TerminalSink};
use tokio_util::sync::CancellationToken;

use crate::cli::Cli;
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

    pub async fn run_dry(&self) -> anyhow::Result<()> {
        // Start the bus HTTP server.
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

        // Kick off synthetic events.
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
