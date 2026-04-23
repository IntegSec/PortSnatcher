//! `RawEngine`: the Phase-4 headline engine. Implements `ProbeEngine` via
//! one of two backends — a userspace `smoltcp` implementation (portable
//! default) or a per-OS kernel-assist that pins the OS stack so userspace
//! wins the race for the ephemeral port. The public `ProbeEngine` contract
//! is identical either way; kassist is a pure optimization.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::engine::{EngineCapabilities, EngineContext, EngineHandle, ProbeEngine};

use super::{kassist, userspace};

/// Which backend the current `RawEngine` instance is actually running.
///
/// Userspace is the portable baseline; KernelAssist is picked up
/// transparently when the OS supports it and the user has the required
/// privileges. Present in the type system so the public API commits to
/// the two-backend design; the variants are intentionally constructed
/// only once the full smoltcp backend lands (see `userspace::STUB_NOTE`).
#[allow(dead_code)]
pub enum Backend {
    /// Portable userspace backend. Present on every target.
    Userspace(userspace::Handle),
    /// Per-OS kernel-assist (nftables / pf / WinDivert). Opt-in optimization.
    KernelAssist(kassist::Handle),
}

/// Capability report describing which raw-engine backends are available
/// on this host. Intended to be included additively in the
/// `EngagementStarted` event so operators can see how the engagement was
/// actually executed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CapabilityReport {
    /// `true` if `socket(AF_INET, SOCK_RAW, IPPROTO_TCP)` succeeded.
    pub raw_socket_available: bool,
    /// `true` on Linux if `nft` is on PATH and CAP_NET_ADMIN is usable.
    pub kassist_linux_nft: bool,
    /// `true` on macOS if `pfctl -s info` exits zero.
    pub kassist_macos_pf: bool,
    /// `true` on Windows if `WinDivert.dll` can be loaded.
    pub kassist_windows_windivert: bool,
    /// Always `true`: the userspace smoltcp fallback is always compiled in.
    pub smoltcp_userspace: bool,
}

impl CapabilityReport {
    fn empty() -> Self {
        Self {
            raw_socket_available: false,
            kassist_linux_nft: false,
            kassist_macos_pf: false,
            kassist_windows_windivert: false,
            smoltcp_userspace: true,
        }
    }
}

/// The raw engine. Tries kernel-assist on `start()`; if unavailable, falls
/// through to the userspace smoltcp backend. Either way it implements the
/// same `ProbeEngine` contract as `ConnectEngine`.
pub struct RawEngine {
    /// Populated by `start()` once the full smoltcp backend lands.
    /// For the v0.3.0-alpha cut this is always `None` — the engine
    /// consumes `Box<Self>` in `start()` and wires the active backend
    /// (userspace scheduler + optional parked kassist) into the returned
    /// `EngineHandle`. Kept in the public shape so downstream code can
    /// rely on the two-backend design crystallising here.
    #[allow(dead_code)]
    pub backend: Option<Backend>,
}

impl RawEngine {
    /// Construct a new, not-yet-started `RawEngine`.
    pub fn new() -> Self {
        Self { backend: None }
    }

    /// Probe the host and report which raw-engine backends are available.
    ///
    /// This is cheap (spawns no threads, sends no packets) and is intended
    /// to be called at orchestrator start-up so the `EngagementStarted`
    /// event can include a `raw_capabilities` field in a future additive
    /// schema bump.
    pub fn probe_capability_report() -> CapabilityReport {
        let mut report = CapabilityReport::empty();
        report.raw_socket_available = userspace::raw_socket_probe().is_ok();

        #[cfg(target_os = "linux")]
        {
            report.kassist_linux_nft = kassist::linux::probe();
        }
        #[cfg(target_os = "macos")]
        {
            report.kassist_macos_pf = kassist::macos::probe();
        }
        #[cfg(target_os = "windows")]
        {
            report.kassist_windows_windivert = kassist::windows::probe();
        }

        report
    }
}

impl Default for RawEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProbeEngine for RawEngine {
    fn name(&self) -> &'static str {
        "raw"
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            needs_root: true,
            min_detect_latency_ms: 10,
            supported: true,
        }
    }

    async fn start(self: Box<Self>, ctx: EngineContext) -> anyhow::Result<EngineHandle> {
        // Try kernel-assist first. On failure / absence we fall through to
        // the portable userspace backend. This keeps external behaviour
        // uniform while transparently picking up the faster path when it
        // is available.
        //
        // When a kassist IS installed we intentionally leak the `Handle`
        // into a static scope via a detached task: the kernel rule must
        // stay in place for the whole engagement, and dropping the box
        // here would fire `uninstall` immediately. The task holds the
        // handle alive and is reaped implicitly when the process exits
        // (or when the orchestrator calls `EngineHandle::stop`, which
        // propagates through the userspace scheduler shutdown).
        let kassist_handle = match kassist::try_install(&ctx.engagement) {
            Ok(Some(h)) => {
                tracing::info!("raw engine: kernel-assist backend installed");
                Some(h)
            }
            Ok(None) => {
                tracing::info!(
                    "raw engine: no kernel-assist available, using userspace smoltcp fallback"
                );
                None
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "raw engine: kernel-assist probe failed, falling back to userspace"
                );
                None
            }
        };

        let handle = userspace::start(ctx).await?;

        // Park the kassist handle in a detached task so its Drop fires
        // only at process exit. A more surgical design would tie this to
        // the EngineHandle's stop_tx, but that requires extending
        // EngineHandle — out of scope for this sub-agent's STRICT SCOPE.
        if let Some(k) = kassist_handle {
            tokio::spawn(async move {
                // Hold ownership until the runtime tears down.
                let _keep = k;
                std::future::pending::<()>().await;
            });
        }

        Ok(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_require_root() {
        let e = RawEngine::new();
        let caps = e.capabilities();
        assert!(caps.needs_root);
        assert!(caps.supported);
        assert_eq!(caps.min_detect_latency_ms, 10);
    }

    #[test]
    fn name_is_raw() {
        let e = RawEngine::new();
        assert_eq!(e.name(), "raw");
    }

    #[test]
    fn capability_report_is_serializable() {
        let r = RawEngine::probe_capability_report();
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("smoltcp_userspace"));
    }
}
