//! Command-line interface.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "portsnatcher",
    version,
    about = "Catch ephemeral ports the moment they open"
)]
pub struct Cli {
    /// Target IP or CIDR. Overrides scope file.
    #[arg(value_name = "TARGET")]
    pub target: Option<String>,

    /// Port specification (e.g. "ephemeral-iana", "1024-65535", "22,80,443").
    #[arg(long)]
    pub ports: Option<String>,

    /// Pentest profile.
    #[arg(long, value_enum, default_value_t = ProfileArg::Internal)]
    pub profile: ProfileArg,

    /// TOML config file.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Scope file (JSON — agentic-pentest-proxy format).
    #[arg(long = "scope-file")]
    pub scope_file: Option<PathBuf>,

    /// Probe engine selection.
    #[arg(long, value_enum, default_value_t = EngineArg::Auto)]
    pub engine: EngineArg,

    /// Bind address for the event bus HTTP server.
    #[arg(long = "bus-listen", default_value = "127.0.0.1:7177")]
    pub bus_listen: String,

    /// Artifact output directory.
    #[arg(long = "artifacts-dir", default_value = "./artifacts")]
    pub artifacts_dir: PathBuf,

    /// Simulate a full engagement without sending packets. Emits a
    /// synthetic event stream for wiring / config validation.
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// Render the live ratatui TUI. Defaults off; explicit opt-in.
    #[arg(long)]
    pub tui: bool,

    /// Maximum live-engagement duration in milliseconds. Default 10s.
    /// Shorter values are handy for automated smoke tests and quick probes.
    #[arg(long = "duration-ms", default_value_t = 10_000)]
    pub duration_ms: u64,

    /// Override hard safety caps. Required for some operations; its
    /// presence shows up in audit logs and pentest reports.
    #[arg(long = "i-know-what-im-doing")]
    pub i_know_what_im_doing: bool,

    #[command(subcommand)]
    pub cmd: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print the build version and exit.
    Version,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileArg {
    Internal,
    External,
    Ctf,
}

impl From<ProfileArg> for ps_core::Profile {
    fn from(p: ProfileArg) -> Self {
        match p {
            ProfileArg::Internal => ps_core::Profile::Internal,
            ProfileArg::External => ps_core::Profile::External,
            ProfileArg::Ctf => ps_core::Profile::Ctf,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineArg {
    Auto,
    Raw,
    Connect,
}

impl EngineArg {
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Raw => "raw",
            Self::Connect => "connect",
        }
    }
}
