//! macOS kernel-assist using `pfctl` anchors.
//!
//! Installs a `portsnatcher` anchor that blocks outbound TCP RST packets
//! via `block return-rst out proto tcp from any to any flags R/R`. This
//! prevents the kernel from racing us with a RST when smoltcp has already
//! sniffed the SYN/ACK on the wire.
//!
//! On Apple Silicon / SIP, `pfctl` behaves as normal for admin users; we
//! probe at install time and fall back to userspace silently if the
//! command returns non-zero (see plan §17 macOS SIP decision).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ps_core::engagement::Engagement;

use super::{Handle, KernelAssist};

const STATE_DIR: &str = "/tmp/portsnatcher";
const ANCHOR_NAME: &str = "portsnatcher";
const ANCHOR_RULE: &str = "block return-rst out proto tcp from any to any flags R/R\n";

/// Cheap capability probe — used by `RawEngine::probe_capability_report`.
/// Runs `pfctl -s info`, which requires admin on macOS but is read-only
/// and won't change system state.
pub fn probe() -> bool {
    match Command::new("pfctl").args(["-s", "info"]).output() {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

/// Attempt to install the pf anchor. `Ok(None)` on any capability issue;
/// callers fall back to userspace.
pub fn try_install(engagement: &Engagement) -> anyhow::Result<Option<Handle>> {
    if !probe() {
        tracing::debug!("pfctl unavailable — skipping macOS kassist");
        return Ok(None);
    }

    let state_path = state_file_path_for(&engagement.id.to_string());

    let mut assist = PfAssist {
        anchor: ANCHOR_NAME.to_string(),
        state_path,
        installed: false,
    };
    assist.install()?;
    Ok(Some(Handle(Box::new(assist))))
}

fn state_file_path_for(engagement_id: &str) -> PathBuf {
    PathBuf::from(STATE_DIR).join(format!("pf-{engagement_id}.state"))
}

/// pf-backed `KernelAssist` implementation.
pub struct PfAssist {
    anchor: String,
    state_path: PathBuf,
    installed: bool,
}

impl KernelAssist for PfAssist {
    fn install(&mut self) -> anyhow::Result<()> {
        if self.installed {
            return Ok(());
        }
        if let Some(parent) = self.state_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // `pfctl -a <anchor> -f -` reads rules from stdin.
        let mut child = match Command::new("pfctl")
            .args(["-a", &self.anchor, "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "pfctl spawn failed — kassist best-effort");
                return Ok(());
            }
        };

        if let Some(mut stdin) = child.stdin.take() {
            if let Err(e) = stdin.write_all(ANCHOR_RULE.as_bytes()) {
                tracing::warn!(error = %e, "writing to pfctl stdin failed");
            }
        }

        match child.wait_with_output() {
            Ok(out) if out.status.success() => {}
            Ok(out) => tracing::warn!(
                stderr = %String::from_utf8_lossy(&out.stderr),
                "pfctl load failed — continuing with userspace fallback"
            ),
            Err(e) => tracing::warn!(error = %e, "pfctl wait failed"),
        }

        let _ = std::fs::write(&self.state_path, &self.anchor);
        self.installed = true;
        Ok(())
    }

    fn uninstall(&mut self) -> anyhow::Result<()> {
        if !self.installed {
            return Ok(());
        }
        match Command::new("pfctl")
            .args(["-a", &self.anchor, "-F", "all"])
            .output()
        {
            Ok(out) if out.status.success() => {}
            Ok(out) => tracing::warn!(
                stderr = %String::from_utf8_lossy(&out.stderr),
                "pfctl flush failed"
            ),
            Err(e) => tracing::warn!(error = %e, "pfctl flush shell-out failed"),
        }
        let _ = std::fs::remove_file(&self.state_path);
        self.installed = false;
        Ok(())
    }

    fn state_file_path(&self) -> &Path {
        &self.state_path
    }
}

impl Drop for PfAssist {
    fn drop(&mut self) {
        let _ = self.uninstall();
    }
}
