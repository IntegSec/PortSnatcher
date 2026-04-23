//! Windows kernel-assist using WinDivert (runtime-loaded).
//!
//! WinDivert's driver is GPLv2/LGPLv3; PortSnatcher is Apache-2.0. To keep
//! our binary Apache-pure we **do not link** or bundle WinDivert — the
//! operator installs it themselves. At runtime we try to load
//! `WinDivert.dll` via `libloading`; if absent, we log a one-shot hint
//! pointing at the install URL and return `Ok(None)` so the raw engine
//! falls back to the userspace smoltcp path.
//!
//! # v0.3.0-alpha status
//!
//! The actual WinDivert filter/handle integration (opening the driver,
//! installing the `"outbound and tcp.Rst"` filter, dropping matches) is
//! a Phase-5 follow-up. For now this module:
//!
//! 1. Probes for the DLL.
//! 2. Logs what it *would* do in a real integration.
//! 3. Returns `Ok(None)` so the engine uses userspace smoltcp.
//!
//! This preserves the "kassist is a pure optimization" invariant while
//! leaving the skeleton in place for the real binding.

use std::path::{Path, PathBuf};

use ps_core::engagement::Engagement;

use super::{Handle, KernelAssist};

const DLL_CANDIDATES: &[&str] = &[
    r"C:\Windows\System32\WinDivert.dll",
    r"C:\Windows\System32\WinDivert64.dll",
    "WinDivert.dll",
];

/// Cheap capability probe — returns `true` if `libloading` can find a
/// WinDivert DLL on this host. We immediately drop the library handle.
pub fn probe() -> bool {
    for candidate in DLL_CANDIDATES {
        // SAFETY: loading a DLL is inherently unsafe because running code
        // in the library's `DllMain` can do anything. We accept this as a
        // minimal capability probe; the library is dropped immediately.
        let loaded = unsafe { libloading::Library::new(candidate) };
        if loaded.is_ok() {
            return true;
        }
    }
    false
}

/// Attempt to install the WinDivert kassist. In v0.3.0-alpha this always
/// returns `Ok(None)` — the real integration is a Phase-5 follow-up.
/// When the DLL is missing we log a hint pointing at the install URL.
pub fn try_install(engagement: &Engagement) -> anyhow::Result<Option<Handle>> {
    if !probe() {
        tracing::info!(
            "WinDivert not installed — raw-engine falling back to userspace. See https://reqrypt.org/windivert.html"
        );
        return Ok(None);
    }

    tracing::info!(
        engagement_id = %engagement.id,
        "WinDivert DLL detected. v0.3.0-alpha logs intent only; full integration lands in Phase 5."
    );
    tracing::info!(
        "WinDivert kassist would open handle with filter \"outbound and tcp.Rst\" and action DROP"
    );

    // We have to fall back to userspace until the real binding lands.
    // Keeping a state file path around though — `portsnatcher cleanup`
    // can scan for stale files even though there's no persistent state.
    let _ = state_file_path_for(&engagement.id.to_string());

    Ok(None)
}

fn state_file_path_for(engagement_id: &str) -> PathBuf {
    let base = std::env::var("TEMP")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows\Temp"));
    base.join("portsnatcher")
        .join(format!("windivert-{engagement_id}.state"))
}

/// Skeleton `KernelAssist` impl for future WinDivert integration. Kept
/// around so the shape is clear for the Phase-5 follow-up; not currently
/// constructed.
#[allow(dead_code)]
pub struct WinDivertAssist {
    state_path: PathBuf,
    installed: bool,
}

#[allow(dead_code)]
impl WinDivertAssist {
    pub fn new(engagement_id: &str) -> Self {
        Self {
            state_path: state_file_path_for(engagement_id),
            installed: false,
        }
    }
}

impl KernelAssist for WinDivertAssist {
    fn install(&mut self) -> anyhow::Result<()> {
        tracing::warn!(
            "WinDivertAssist::install is a phase-5 placeholder — not actually installing"
        );
        self.installed = true;
        Ok(())
    }

    fn uninstall(&mut self) -> anyhow::Result<()> {
        self.installed = false;
        Ok(())
    }

    fn state_file_path(&self) -> &Path {
        &self.state_path
    }
}
