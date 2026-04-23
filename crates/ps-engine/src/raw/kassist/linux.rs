//! Linux kernel-assist using `nftables`.
//!
//! Installs a tiny anonymous table whose sole purpose is to DROP outbound
//! TCP RST packets from our local userspace stack so the kernel doesn't
//! race us and close the ephemeral port out from under smoltcp.
//!
//! Requires the `nft` binary on PATH and `CAP_NET_ADMIN`. If either is
//! missing this backend silently returns `Ok(None)` and the `RawEngine`
//! falls back to the userspace smoltcp implementation.

use std::path::{Path, PathBuf};
use std::process::Command;

use ps_core::engagement::Engagement;

use super::{Handle, KernelAssist};

const STATE_DIR: &str = "/tmp/portsnatcher";

/// Cheap capability probe — used by `RawEngine::probe_capability_report`.
/// Returns `true` if `nft` is on PATH. We intentionally do *not* run a
/// privileged command here (that's deferred to `try_install` where we
/// can accept the latency).
pub fn probe() -> bool {
    which::which("nft").is_ok()
}

/// Attempt to install the nftables kernel-assist. Returns `Ok(None)`
/// when the backend isn't usable on this host — callers treat that as
/// "fall back to userspace."
pub fn try_install(engagement: &Engagement) -> anyhow::Result<Option<Handle>> {
    if !probe() {
        tracing::debug!("nft not on PATH — skipping Linux kassist");
        return Ok(None);
    }

    // Best-effort CAP_NET_ADMIN probe: listing rules requires it and is
    // non-mutating. If this fails we silently back out.
    let listing = Command::new("nft").args(["list", "ruleset"]).output();
    match listing {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            tracing::debug!(
                stderr = %String::from_utf8_lossy(&out.stderr),
                "nft list ruleset failed — assuming no CAP_NET_ADMIN, skipping kassist"
            );
            return Ok(None);
        }
        Err(e) => {
            tracing::debug!(error = %e, "nft invocation failed — skipping kassist");
            return Ok(None);
        }
    }

    let table_name = format!("portsnatcher_{}", engagement.id);
    let state_path = state_file_path_for(&engagement.id.to_string());

    let mut assist = NftAssist {
        table_name,
        state_path,
        installed: false,
    };
    assist.install()?;

    Ok(Some(Handle(Box::new(assist))))
}

fn state_file_path_for(engagement_id: &str) -> PathBuf {
    PathBuf::from(STATE_DIR).join(format!("nft-{engagement_id}.state"))
}

/// nftables-backed `KernelAssist` implementation.
pub struct NftAssist {
    table_name: String,
    state_path: PathBuf,
    installed: bool,
}

impl KernelAssist for NftAssist {
    fn install(&mut self) -> anyhow::Result<()> {
        if self.installed {
            return Ok(());
        }

        // Create state dir. Best-effort — cleanup can still find the
        // table via `nft list tables` even without state file.
        if let Some(parent) = self.state_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let steps: [&[&str]; 3] = [
            &["add", "table", "inet", &self.table_name],
            &[
                "add",
                "chain",
                "inet",
                &self.table_name,
                "out",
                "{ type filter hook output priority 0; }",
            ],
            &[
                "add",
                "rule",
                "inet",
                &self.table_name,
                "out",
                "tcp",
                "flags",
                "rst",
                "drop",
                "comment",
                "\"portsnatcher rst-drop\"",
            ],
        ];

        for args in steps {
            match Command::new("nft").args(args).output() {
                Ok(out) if out.status.success() => {}
                Ok(out) => {
                    tracing::warn!(
                        args = ?args,
                        stderr = %String::from_utf8_lossy(&out.stderr),
                        "nft step failed — kassist is best-effort, continuing"
                    );
                }
                Err(e) => {
                    tracing::warn!(error = %e, args = ?args, "nft shell-out failed");
                }
            }
        }

        // Write the state file (contents = table name so cleanup can
        // reconstruct the delete command).
        let _ = std::fs::write(&self.state_path, &self.table_name);
        self.installed = true;
        Ok(())
    }

    fn uninstall(&mut self) -> anyhow::Result<()> {
        if !self.installed {
            return Ok(());
        }
        match Command::new("nft")
            .args(["delete", "table", "inet", &self.table_name])
            .output()
        {
            Ok(out) if out.status.success() => {}
            Ok(out) => tracing::warn!(
                stderr = %String::from_utf8_lossy(&out.stderr),
                "nft delete table failed"
            ),
            Err(e) => tracing::warn!(error = %e, "nft delete shell-out failed"),
        }
        let _ = std::fs::remove_file(&self.state_path);
        self.installed = false;
        Ok(())
    }

    fn state_file_path(&self) -> &Path {
        &self.state_path
    }
}

impl Drop for NftAssist {
    fn drop(&mut self) {
        let _ = self.uninstall();
    }
}
