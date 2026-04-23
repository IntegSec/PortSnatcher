//! `portsnatcher cleanup`: removes orphaned kernel-assist state left
//! behind by crashed / SIGKILLed engagements.
//!
//! Each raw-engine kassist writes a small state file (`nft-<id>.state`,
//! `pf-<id>.state`, `windivert-<id>.state`) under a well-known temp
//! directory when installed. Normal teardown removes both the kernel
//! rule and the state file. After a crash, the rule survives but the
//! process is gone — this command scans for the state files and
//! reverses the install.
//!
//! `--dry-run` prints what would be removed without executing anything.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Run cleanup. If `dry_run` is true, print actions but do not execute.
pub async fn run(dry_run: bool) -> anyhow::Result<()> {
    let state_dir = state_dir();
    if !state_dir.exists() {
        println!(
            "cleanup: no state directory at {}, nothing to do",
            state_dir.display()
        );
        return Ok(());
    }

    let mut removed = 0usize;
    let mut skipped = 0usize;

    let entries = match std::fs::read_dir(&state_dir) {
        Ok(e) => e,
        Err(e) => {
            anyhow::bail!("cleanup: cannot read {}: {e}", state_dir.display());
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        if name.starts_with("nft-") && name.ends_with(".state") {
            if handle_nft(&path, dry_run)? {
                removed += 1;
            } else {
                skipped += 1;
            }
        } else if name.starts_with("pf-") && name.ends_with(".state") {
            if handle_pf(&path, dry_run)? {
                removed += 1;
            } else {
                skipped += 1;
            }
        } else if name.starts_with("windivert-") && name.ends_with(".state") {
            if handle_windivert(&path, dry_run)? {
                removed += 1;
            } else {
                skipped += 1;
            }
        } else {
            // Unknown files in the state dir — ignore.
            continue;
        }
    }

    if dry_run {
        println!(
            "cleanup (dry-run): would remove {removed} orphan(s); {skipped} could not be handled"
        );
    } else {
        println!("cleanup: removed {removed} orphan(s); {skipped} could not be handled");
    }
    Ok(())
}

fn state_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var("TEMP")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows\Temp"));
        base.join("portsnatcher")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/tmp/portsnatcher")
    }
}

/// Handle an `nft-<id>.state` file. Shells out to `nft delete table inet <name>`.
/// Returns `true` if the orphan was (or would be) removed.
fn handle_nft(path: &Path, dry_run: bool) -> anyhow::Result<bool> {
    let table = match std::fs::read_to_string(path) {
        Ok(s) => s.trim().to_string(),
        Err(e) => {
            eprintln!("cleanup: cannot read {}: {e}", path.display());
            return Ok(false);
        }
    };
    if table.is_empty() {
        eprintln!("cleanup: empty nft state file {}", path.display());
        return Ok(false);
    }

    if dry_run {
        println!(
            "cleanup (dry-run): would run `nft delete table inet {table}` and remove {}",
            path.display()
        );
        return Ok(true);
    }

    match Command::new("nft")
        .args(["delete", "table", "inet", &table])
        .output()
    {
        Ok(out) if out.status.success() => {
            println!("cleanup: deleted nft table `{table}`");
        }
        Ok(out) => {
            eprintln!(
                "cleanup: nft delete `{table}` failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Err(e) => {
            eprintln!("cleanup: nft invocation failed: {e}");
        }
    }

    let _ = std::fs::remove_file(path);
    Ok(true)
}

/// Handle a `pf-<id>.state` file. Shells out to `pfctl -a portsnatcher -F all`.
fn handle_pf(path: &Path, dry_run: bool) -> anyhow::Result<bool> {
    let anchor = match std::fs::read_to_string(path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => "portsnatcher".to_string(),
    };
    let anchor = if anchor.is_empty() {
        "portsnatcher".to_string()
    } else {
        anchor
    };

    if dry_run {
        println!(
            "cleanup (dry-run): would run `pfctl -a {anchor} -F all` and remove {}",
            path.display()
        );
        return Ok(true);
    }

    match Command::new("pfctl")
        .args(["-a", &anchor, "-F", "all"])
        .output()
    {
        Ok(out) if out.status.success() => {
            println!("cleanup: flushed pf anchor `{anchor}`");
        }
        Ok(out) => {
            eprintln!(
                "cleanup: pfctl flush failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Err(e) => {
            eprintln!("cleanup: pfctl invocation failed: {e}");
        }
    }

    let _ = std::fs::remove_file(path);
    Ok(true)
}

/// Handle a `windivert-<id>.state` file. WinDivert handles are
/// process-scoped (a dead process releases them), so we just remove the
/// stale file.
fn handle_windivert(path: &Path, dry_run: bool) -> anyhow::Result<bool> {
    if dry_run {
        println!(
            "cleanup (dry-run): would remove WinDivert state file {}",
            path.display()
        );
        return Ok(true);
    }
    match std::fs::remove_file(path) {
        Ok(_) => println!("cleanup: removed WinDivert state file {}", path.display()),
        Err(e) => eprintln!("cleanup: failed to remove {}: {e}", path.display()),
    }
    Ok(true)
}
