#![allow(dead_code)]

//! PortSnatcher binary entry point.

use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

mod cli;
mod cmd;
mod orchestrator;
mod tui;

use crate::cli::{Cli, Command};
use crate::orchestrator::Orchestrator;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing();

    if let Some(Command::Version) = cli.cmd {
        println!("portsnatcher {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let tui_requested = cli.tui;
    let dry_run = cli.dry_run;
    let orch = Orchestrator::from_cli(cli).await?;

    // Spawn TUI alongside the engagement when --tui is set. The TUI
    // and the engagement share the same bus/shutdown — either can
    // trigger cleanup.
    let tui_handle = if tui_requested {
        let bus = orch.bus.clone();
        let shutdown = orch.shutdown.clone();
        Some(tokio::spawn(async move {
            if let Err(e) = tui::runtime::run(bus, shutdown.clone()).await {
                tracing::warn!("tui exited with error: {e:#}");
            }
            // User quit the TUI → trigger shutdown so the engagement
            // winds down.
            shutdown.cancel();
        }))
    } else {
        None
    };

    let result = if dry_run {
        orch.run_dry().await
    } else {
        let duration_ms = orch.cli.duration_ms;
        orch.run_live(duration_ms).await
    };

    if let Some(h) = tui_handle {
        // Ensure the TUI cleanup runs (raw-mode restore etc.) before
        // main exits.
        let _ = h.await;
    }

    // Silence the unused-import lint on CancellationToken when the TUI
    // branch compiles out on a downstream consumer.
    let _unused_ct: Option<CancellationToken> = None;

    result
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,hyper=warn,h2=warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}
