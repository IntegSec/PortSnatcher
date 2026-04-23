//! Per-OS kernel-assist backends.
//!
//! Each OS-specific module exposes a `try_install()` that returns:
//!
//! - `Ok(Some(Handle))` if the kernel-assist rule was installed successfully,
//! - `Ok(None)` if the OS doesn't support it or the tooling isn't present,
//! - `Err(_)` only for genuine errors the caller should surface.
//!
//! Per plan §17 the kassist backends are a **pure optimization**: the
//! `RawEngine`'s externally visible behaviour is identical whether or
//! not a kassist is available. When missing, the userspace smoltcp
//! fallback handles the engagement.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

use ps_core::engagement::Engagement;

/// Common kernel-assist contract. Each per-OS impl installs its flavour
/// of "drop the kernel's RST for this flow so userspace wins the race,"
/// writes a state file so crash recovery can find it, and uninstalls
/// when the engagement ends.
pub trait KernelAssist: Send + Sync {
    /// Install the kernel-level rule. Must be idempotent on retries.
    fn install(&mut self) -> anyhow::Result<()>;

    /// Remove the kernel-level rule. Best-effort; logs on failure.
    fn uninstall(&mut self) -> anyhow::Result<()>;

    /// Path to the on-disk state file so `portsnatcher cleanup` can
    /// find orphaned rules after a crash / SIGKILL.
    fn state_file_path(&self) -> &std::path::Path;
}

/// Opaque handle wrapping a boxed `KernelAssist` impl. Consumed by the
/// `RawEngine` and dropped at engagement teardown, which triggers
/// `uninstall` in the `Drop` impl of the inner type.
pub struct Handle(pub Box<dyn KernelAssist>);

/// Try to install a kernel-assist for this engagement. Dispatches to
/// the per-OS module at compile time.
pub fn try_install(engagement: &Engagement) -> anyhow::Result<Option<Handle>> {
    #[cfg(target_os = "linux")]
    {
        return linux::try_install(engagement);
    }
    #[cfg(target_os = "macos")]
    {
        return macos::try_install(engagement);
    }
    #[cfg(target_os = "windows")]
    {
        return windows::try_install(engagement);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = engagement;
        Ok(None)
    }
}
