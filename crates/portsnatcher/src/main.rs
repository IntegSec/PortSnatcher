#![allow(dead_code)]

//! PortSnatcher binary entry point.

use std::path::Path;

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
    init_tracing(cli.tui, &cli.artifacts_dir);

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

fn init_tracing(tui_mode: bool, artifacts_dir: &Path) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,hyper=warn,h2=warn"));

    // In TUI mode the alternate screen owns stdout and crossterm owns
    // raw mode. Letting tracing write to either stdout *or* stderr
    // smashes the rendered frames with log lines. Sink to a file
    // instead so the screen stays clean and the operational log is
    // still recoverable post-engagement.
    if tui_mode {
        let _ = std::fs::create_dir_all(artifacts_dir);
        let log_path = artifacts_dir.join("portsnatcher-tui.log");
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            Ok(file) => {
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_target(false)
                    .with_ansi(false)
                    .with_writer(std::sync::Mutex::new(file))
                    .init();
                return;
            }
            Err(e) => {
                // No file? Last-resort: install a do-nothing subscriber
                // so library calls to tracing::* don't end up on stdout
                // and corrupt the TUI. Surface the failure once on
                // stderr before crossterm grabs the screen.
                eprintln!("tui log file {log_path:?} unavailable: {e}; tracing disabled");
                tracing_subscriber::fmt()
                    .with_env_filter(EnvFilter::new("off"))
                    .with_writer(std::io::sink)
                    .init();
                return;
            }
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}
