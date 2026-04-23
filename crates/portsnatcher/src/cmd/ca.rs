//! `portsnatcher ca` subcommand — manage the MITM certificate authority.
//!
//! The main binary and `cli` module expose a `CaSubcommand` enum and
//! dispatch to [`run`]. Each variant is a thin wrapper around
//! [`ps_proxy::Ca`] and [`ps_proxy::ca::trust`] so the CLI layer stays
//! declarative.

use std::path::PathBuf;

use clap::Subcommand;
use ps_proxy::ca::{storage, trust};
use ps_proxy::{Ca, CaFingerprint};

/// `portsnatcher ca <sub>` operations.
#[derive(Debug, Clone, Subcommand)]
pub enum CaSubcommand {
    /// Generate the CA on disk if it doesn't exist; print its path
    /// and fingerprint.
    Init {
        /// Override the default CA directory.
        #[arg(long = "dir")]
        dir: Option<PathBuf>,
    },
    /// Install the CA into the platform trust store. Requires elevation.
    Install {
        /// Override the default CA directory.
        #[arg(long = "dir")]
        dir: Option<PathBuf>,
    },
    /// Remove the CA from the platform trust store.
    Uninstall,
    /// Print the CA fingerprint in colon-separated hex.
    Fingerprint {
        /// Override the default CA directory.
        #[arg(long = "dir")]
        dir: Option<PathBuf>,
    },
    /// Print the CA status: path, fingerprint, and whether it's
    /// currently installed into the system trust store.
    Show {
        /// Override the default CA directory.
        #[arg(long = "dir")]
        dir: Option<PathBuf>,
    },
}

/// Dispatch a `portsnatcher ca <sub>` invocation.
pub async fn run(sub: CaSubcommand) -> anyhow::Result<()> {
    match sub {
        CaSubcommand::Init { dir } => init(dir),
        CaSubcommand::Install { dir } => install(dir),
        CaSubcommand::Uninstall => uninstall(),
        CaSubcommand::Fingerprint { dir } => fingerprint(dir),
        CaSubcommand::Show { dir } => show(dir),
    }
}

fn resolve_dir(dir: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(d) = dir {
        return Ok(d);
    }
    storage::default_dir()
        .ok_or_else(|| anyhow::anyhow!("no home directory resolved; pass --dir explicitly"))
}

fn init(dir: Option<PathBuf>) -> anyhow::Result<()> {
    let dir = resolve_dir(dir)?;
    let ca = Ca::new_or_load(&dir)?;
    println!("PortSnatcher CA initialised");
    println!("  directory:   {}", dir.display());
    println!("  certificate: {}", storage::cert_path(&dir).display());
    println!("  key:         {}", storage::key_path(&dir).display());
    println!("  fingerprint: {}", CaFingerprint(ca.fingerprint_sha256));
    Ok(())
}

fn install(dir: Option<PathBuf>) -> anyhow::Result<()> {
    let dir = resolve_dir(dir)?;
    // Ensure the CA exists before attempting to install it.
    let ca = Ca::new_or_load(&dir)?;
    let cert_path = storage::cert_path(&dir);
    println!(
        "Installing PortSnatcher CA (fingerprint {}) into the system trust store...",
        CaFingerprint(ca.fingerprint_sha256)
    );
    trust::install(&cert_path)?;
    println!("Done. The CA is now trusted by applications that use the OS trust store.");
    Ok(())
}

fn uninstall() -> anyhow::Result<()> {
    println!("Removing PortSnatcher CA from the system trust store...");
    trust::uninstall()?;
    println!("Done.");
    Ok(())
}

fn fingerprint(dir: Option<PathBuf>) -> anyhow::Result<()> {
    let dir = resolve_dir(dir)?;
    let ca = Ca::new_or_load(&dir)?;
    println!("{}", CaFingerprint(ca.fingerprint_sha256));
    Ok(())
}

fn show(dir: Option<PathBuf>) -> anyhow::Result<()> {
    let dir = resolve_dir(dir)?;
    let ca = Ca::new_or_load(&dir)?;
    let installed = match trust::is_installed() {
        Ok(true) => "yes",
        Ok(false) => "no",
        Err(_) => "unknown",
    };
    println!("PortSnatcher CA");
    println!("  directory:        {}", dir.display());
    println!("  certificate:      {}", storage::cert_path(&dir).display());
    println!("  key:              {}", storage::key_path(&dir).display());
    println!(
        "  fingerprint:      {}",
        CaFingerprint(ca.fingerprint_sha256)
    );
    println!("  trusted by OS:    {installed}");
    Ok(())
}
