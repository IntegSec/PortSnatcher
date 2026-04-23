#![allow(dead_code)]

//! PortSnatcher binary entry point.

use clap::Parser;
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

    if cli.dry_run {
        let orch = Orchestrator::from_cli(cli).await?;
        orch.run_dry().await?;
        return Ok(());
    }

    anyhow::bail!("non-dry-run execution lands in a follow-up; use --dry-run to validate wiring");
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,hyper=warn,h2=warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}
