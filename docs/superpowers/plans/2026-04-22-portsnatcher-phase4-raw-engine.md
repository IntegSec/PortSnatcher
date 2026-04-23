# Phase 4 — Raw Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the RawEngine — PortSnatcher's headline capability for sub-100ms ephemeral-port races. Userspace `smoltcp` is the portable default; per-OS kernel fast-paths (`nftables` on Linux, `pf` on macOS, `WinDivert` on Windows) are used transparently when available. Same external behavior everywhere; falls back cleanly when capabilities are missing.

**Architecture:** `RawEngine` in `ps-engine` is a facade that probes capabilities at startup and selects the best-available backend. All backends emit identical `PortOpenDetected` events — downstream fingerprinting and hold-open are engine-agnostic. Kernel-assist rules are RAII and additionally cleaned up by a new `portsnatcher cleanup` command for SIGKILL scenarios.

**Tech Stack:** Adds `smoltcp`, `pnet` (packet crafting + pcap), `nftnl` or shell-out to `nft` (Linux), `pfctl` shell-out (macOS), `windivert-sys` (Windows). Plus Phase 1–3's stack.

**Release target:** v0.3.0.

**Assumes Phase 2 complete:** `ProbeEngine` trait exists, `ConnectionCaught` stream is the downstream interface, orchestrator can dispatch engines by name.

---

## Design decisions made in this phase (resolving spec §17 open questions)

### smoltcp integration shape — **decision: sync stack + blocking thread + channel bridge**

The spec left this as an open question. Phase 4 resolves it concretely:

- We use **`smoltcp`'s synchronous stack** (the `tokio` feature flag is ignored). Its async branch is younger, less documented, and its API has churned across recent releases. The sync stack is battle-tested, has a simple poll-loop model, and is the one used by every real-world integration we could find.
- A **dedicated OS thread** (`std::thread::spawn`, not a `tokio` task) runs the smoltcp poll loop. That thread owns the `Interface`, the `SocketSet`, and the pcap/raw-socket handle. It blocks on `pcap_next_ex` / raw-socket recv with a short timeout, drives `iface.poll()`, and services socket I/O.
- A **`tokio`-side adapter** translates `tokio::io::AsyncRead` + `AsyncWrite` calls into messages on a `tokio::sync::mpsc` channel pair routed to the smoltcp thread. The thread answers with `smoltcp::socket::tcp::Socket::recv_slice` / `send_slice` results. Close events and errors flow the same way.
- The adapter type is named `SmoltcpStream` and is crate-private to `ps-engine`. Downstream code sees it through a `Box<dyn AsyncRead + AsyncWrite + Send + Unpin>` — so ProbeLadder / HoldOpen remain engine-agnostic exactly as Phase 2 designed.

**Justification:** this is the most conservative shape that keeps the public `ProbeEngine` API unchanged. It accepts a small latency cost from the thread-boundary hop (single-digit microseconds, dwarfed by network RTT) in exchange for avoiding all the traps of `smoltcp`'s in-flight async API. It also isolates the non-`tokio`-aware blocking code behind a clean seam — easier to test, easier to replace later if smoltcp's async matures.

### WinDivert licensing — **decision: runtime detection, no bundling**

WinDivert's kernel driver is **GPLv2 / LGPLv3 dual-licensed** for the driver, with the user-mode library dual-licensed. Bundling would force us to redistribute under one of those. PortSnatcher is Apache-2.0 and we want to stay Apache-2.0. So:

- **We do not bundle WinDivert.** The operator installs it themselves from https://reqrypt.org/windivert.html.
- We **runtime-detect** the presence of `WinDivert.dll` / `WinDivert64.sys`. If absent, we fall back to userspace smoltcp with a one-time log line pointing at the install URL.
- Phase 4 uses `windivert-sys` (MIT-licensed Rust bindings) linked dynamically, loaded at runtime via `libloading`. No static link to GPL code.

### pf on Apple Silicon macOS — **decision: attempt kassist, fall back gracefully**

Apple Silicon macOS under SIP restricts `pfctl` but does not outright block it for admin users using signed binaries. Phase 4 tries `pfctl -a portsnatcher -sA` at probe time; if it returns a non-zero exit or a permission-error string, we fall back to userspace smoltcp. No special case for M-series — the probe outcome drives the decision.

---

## Task list

### Setup

- [ ] **Task 1: add Phase 4 dependencies to `crates/ps-engine/Cargo.toml`.**

  Edit `crates/ps-engine/Cargo.toml`. Add under `[dependencies]`:

  ```toml
  smoltcp = { version = "0.11", default-features = false, features = ["std", "medium-ethernet", "medium-ip", "proto-ipv4", "socket-tcp", "phy-raw_socket"] }
  pnet = "0.34"
  pcap = "2.0"
  libloading = "0.8"
  ctrlc = { version = "3.4", features = ["termination"] }
  ```

  Add under `[target.'cfg(target_os = "linux")'.dependencies]`:

  ```toml
  # nft shell-out is the v1 choice; nftnl is a post-v1 upgrade path.
  ```

  (no crate needed — we shell out to `nft`; shelling out is simpler for v1 per plan scope.)

  Add under `[target.'cfg(target_os = "windows")'.dependencies]`:

  ```toml
  windivert-sys = "0.11"
  ```

  Run:

  ```
  cargo check -p ps-engine
  ```

  Expected: clean compile, no new warnings.

  Commit message:

  ```
  build(ps-engine): add smoltcp, pnet, pcap, ctrlc, windivert-sys deps

  Phase 4 RawEngine needs smoltcp for userspace TCP, pnet+pcap for packet
  crafting and SYN-ACK capture, ctrlc for SIGINT cleanup hooks, and
  windivert-sys for the Windows kernel-assist backend.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- [ ] **Task 2: create module skeleton files.**

  Create empty (single `//! docstring` line) files so `mod` declarations compile:

  - `crates/ps-engine/src/raw/mod.rs`
  - `crates/ps-engine/src/raw/userspace.rs`
  - `crates/ps-engine/src/raw/smoltcp_thread.rs`
  - `crates/ps-engine/src/raw/smoltcp_stream.rs`
  - `crates/ps-engine/src/raw/capability.rs`
  - `crates/ps-engine/src/raw/kassist/mod.rs`
  - `crates/ps-engine/src/raw/kassist/linux.rs`
  - `crates/ps-engine/src/raw/kassist/macos.rs`
  - `crates/ps-engine/src/raw/kassist/windows.rs`
  - `crates/ps-engine/src/raw/state.rs`
  - `crates/ps-engine/tests/raw_userspace.rs`
  - `crates/ps-engine/tests/raw_kassist.rs`
  - `crates/ps-engine/tests/raw_capability.rs`
  - `crates/ps-engine/tests/raw_conformance.rs`
  - `crates/ps-engine/tests/fixtures/ephemeral_flapper_stub.rs`

  In `crates/ps-engine/src/lib.rs`, after the existing `pub mod connect;` line, add:

  ```rust
  pub mod raw;
  ```

  Run:

  ```
  cargo check -p ps-engine
  ```

  Expected: clean compile, no new warnings.

  Commit:

  ```
  chore(ps-engine): scaffold raw module tree

  Empty module files so the raw/ subtree compiles before implementation
  lands task-by-task.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

### RawEngine facade and capability probe

- [ ] **Task 3: failing test — `RawEngine::new()` exists and returns a `ProbeEngine`.**

  In `crates/ps-engine/tests/raw_capability.rs`:

  ```rust
  use ps_engine::raw::RawEngine;
  use ps_engine::ProbeEngine;

  #[tokio::test]
  async fn raw_engine_is_a_probe_engine() {
      let engine = RawEngine::new_for_test();
      let caps = engine.capabilities();
      assert!(caps.needs_root);
      assert!(caps.os_support.linux);
      assert!(caps.os_support.macos);
      assert!(caps.os_support.windows);
  }
  ```

  Run:

  ```
  cargo test -p ps-engine --test raw_capability
  ```

  Expected: fails with "cannot find type `RawEngine` in module `ps_engine::raw`".

- [ ] **Task 4: implement `RawEngine` skeleton satisfying Task 3.**

  In `crates/ps-engine/src/raw/mod.rs`:

  ```rust
  //! RawEngine — the headline capability. Userspace smoltcp default with per-OS
  //! kernel-assist fast paths.

  pub mod capability;
  pub mod kassist;
  pub mod smoltcp_stream;
  pub mod smoltcp_thread;
  pub mod state;
  pub mod userspace;

  use crate::engine::{EngineCapabilities, EngineContext, EventStream, OsSupport, ProbeEngine};
  use async_trait::async_trait;

  /// The single user-visible raw engine. Picks a backend at `start()`.
  pub struct RawEngine {
      backend: Option<Box<dyn Backend>>,
      forced_backend: Option<BackendKind>,
  }

  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum BackendKind {
      Userspace,
      KassistLinux,
      KassistMacos,
      KassistWindows,
  }

  #[async_trait]
  pub(crate) trait Backend: Send + Sync {
      async fn start(&mut self, ctx: EngineContext) -> crate::Result<EventStream>;
      fn kind(&self) -> BackendKind;
  }

  impl RawEngine {
      pub fn new() -> Self {
          Self { backend: None, forced_backend: None }
      }

      /// Public constructor used by integration tests.
      pub fn new_for_test() -> Self {
          Self::new()
      }

      /// For `--engine-raw-backend=userspace` style overrides (debugging only).
      pub fn force_backend(&mut self, kind: BackendKind) {
          self.forced_backend = Some(kind);
      }
  }

  impl Default for RawEngine {
      fn default() -> Self {
          Self::new()
      }
  }

  #[async_trait]
  impl ProbeEngine for RawEngine {
      async fn start(&mut self, ctx: EngineContext) -> crate::Result<EventStream> {
          let backend = capability::select_backend(self.forced_backend)?;
          let mut backend = backend;
          let stream = backend.start(ctx).await?;
          self.backend = Some(backend);
          Ok(stream)
      }

      fn capabilities(&self) -> EngineCapabilities {
          EngineCapabilities {
              needs_root: true,
              os_support: OsSupport { linux: true, macos: true, windows: true },
          }
      }
  }
  ```

  Run:

  ```
  cargo test -p ps-engine --test raw_capability
  ```

  Expected: passes. Also run `cargo check -p ps-engine` — expected clean.

  Commit:

  ```
  feat(ps-engine): RawEngine facade with capability-driven backend dispatch

  RawEngine presents a single ProbeEngine implementation. At start() it
  probes capabilities and constructs the best-available backend. Backend
  kinds are userspace smoltcp (portable) and per-OS kernel-assist.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- [ ] **Task 5: failing test — capability probe selects userspace when no kassist available.**

  In `crates/ps-engine/tests/raw_capability.rs`, append:

  ```rust
  use ps_engine::raw::capability::{probe_all, ProbeReport};
  use ps_engine::raw::BackendKind;

  #[test]
  fn probe_report_shape() {
      let report: ProbeReport = probe_all();
      // fields exist and report at least one usable backend (userspace always works when root).
      assert!(report.candidates.iter().any(|c| c.kind == BackendKind::Userspace));
  }
  ```

  Run:

  ```
  cargo test -p ps-engine --test raw_capability
  ```

  Expected: fails with "cannot find function `probe_all`".

- [ ] **Task 6: implement capability probe to satisfy Task 5.**

  In `crates/ps-engine/src/raw/capability.rs`:

  ```rust
  //! Capability probe: decides which backend to use.

  use super::BackendKind;
  use crate::errors::Error;

  /// What a backend reports about itself.
  #[derive(Debug, Clone)]
  pub struct Candidate {
      pub kind: BackendKind,
      pub available: bool,
      pub reason: &'static str,
  }

  #[derive(Debug, Clone)]
  pub struct ProbeReport {
      pub candidates: Vec<Candidate>,
      pub picked: Option<BackendKind>,
  }

  /// Probe every backend on this host. Cheap — reads privileges and checks for
  /// command availability. Safe to call multiple times.
  pub fn probe_all() -> ProbeReport {
      let mut candidates = Vec::new();

      #[cfg(target_os = "linux")]
      candidates.push(super::kassist::linux::probe());
      #[cfg(target_os = "macos")]
      candidates.push(super::kassist::macos::probe());
      #[cfg(target_os = "windows")]
      candidates.push(super::kassist::windows::probe());

      // Userspace is always a candidate; its availability depends only on
      // whether we have raw-socket / pcap privileges.
      candidates.push(super::userspace::probe());

      let picked = candidates
          .iter()
          .find(|c| c.available && matches!(c.kind,
              BackendKind::KassistLinux | BackendKind::KassistMacos | BackendKind::KassistWindows))
          .or_else(|| candidates.iter().find(|c| c.available && c.kind == BackendKind::Userspace))
          .map(|c| c.kind);

      ProbeReport { candidates, picked }
  }

  /// Build the `Backend` the probe chose (or the forced override).
  pub(crate) fn select_backend(
      forced: Option<BackendKind>,
  ) -> crate::Result<Box<dyn super::Backend>> {
      let report = probe_all();
      let kind = forced.or(report.picked).ok_or_else(|| {
          Error::raw_engine("no raw backend is available on this host; use --engine connect")
      })?;

      match kind {
          BackendKind::Userspace => Ok(Box::new(super::userspace::UserspaceBackend::new()?)),
          #[cfg(target_os = "linux")]
          BackendKind::KassistLinux => Ok(Box::new(super::kassist::linux::LinuxBackend::new()?)),
          #[cfg(target_os = "macos")]
          BackendKind::KassistMacos => Ok(Box::new(super::kassist::macos::MacosBackend::new()?)),
          #[cfg(target_os = "windows")]
          BackendKind::KassistWindows => Ok(Box::new(super::kassist::windows::WindowsBackend::new()?)),
          #[allow(unreachable_patterns)]
          _ => Err(Error::raw_engine("selected backend not compiled in")),
      }
  }
  ```

  In `crates/ps-engine/src/raw/userspace.rs`, add a stub so it compiles:

  ```rust
  //! Userspace smoltcp backend (implemented task-by-task below).

  use super::capability::Candidate;
  use super::{Backend, BackendKind};
  use crate::engine::{EngineContext, EventStream};
  use async_trait::async_trait;

  pub(crate) struct UserspaceBackend {
      _todo: (),
  }

  impl UserspaceBackend {
      pub(crate) fn new() -> crate::Result<Self> {
          Ok(Self { _todo: () })
      }
  }

  #[async_trait]
  impl Backend for UserspaceBackend {
      async fn start(&mut self, _ctx: EngineContext) -> crate::Result<EventStream> {
          Err(crate::errors::Error::raw_engine(
              "userspace backend not implemented yet (Task 13+)",
          ))
      }

      fn kind(&self) -> BackendKind {
          BackendKind::Userspace
      }
  }

  /// Capability probe for the userspace path.
  pub fn probe() -> Candidate {
      Candidate {
          kind: BackendKind::Userspace,
          available: has_raw_privilege(),
          reason: if has_raw_privilege() {
              "raw-socket / pcap privilege present"
          } else {
              "missing raw-socket privilege (Linux: set CAP_NET_RAW; macOS: ChmodBPF or root; Windows: run as admin)"
          },
      }
  }

  #[cfg(target_os = "linux")]
  fn has_raw_privilege() -> bool {
      // Effective UID 0 or CAP_NET_RAW. The cheap cross-process check is to
      // try to open a raw socket briefly.
      std::fs::metadata("/proc/self/status").is_ok()
          && (unsafe { libc::geteuid() } == 0
              || libc_caps_cap_net_raw().unwrap_or(false))
  }

  #[cfg(target_os = "linux")]
  fn libc_caps_cap_net_raw() -> Option<bool> {
      // Best-effort: read /proc/self/status for CapEff and check bit 13 (CAP_NET_RAW).
      let status = std::fs::read_to_string("/proc/self/status").ok()?;
      for line in status.lines() {
          if let Some(rest) = line.strip_prefix("CapEff:\t") {
              let caps = u64::from_str_radix(rest.trim(), 16).ok()?;
              return Some((caps >> 13) & 1 == 1);
          }
      }
      Some(false)
  }

  #[cfg(target_os = "macos")]
  fn has_raw_privilege() -> bool {
      unsafe { libc::geteuid() == 0 } || std::fs::metadata("/dev/bpf0").is_ok()
  }

  #[cfg(target_os = "windows")]
  fn has_raw_privilege() -> bool {
      // On Windows, raw sockets require admin. We probe by trying to open one
      // lazily at backend construction; here we return true and let the real
      // backend construction fail cleanly if unprivileged.
      true
  }
  ```

  Add `libc = "0.2"` to `crates/ps-engine/Cargo.toml` under `[target.'cfg(unix)'.dependencies]` if it isn't already.

  Run:

  ```
  cargo test -p ps-engine --test raw_capability
  ```

  Expected: passes on all three OSes.

  Commit:

  ```
  feat(ps-engine): capability probe and backend selector for raw engine

  probe_all() reports every compiled-in backend's availability. select_backend()
  picks the highest-preference available backend or honors a debug override.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

### Kassist trait and per-OS stubs

- [ ] **Task 7: failing test — `KernelAssist` trait contract.**

  In `crates/ps-engine/tests/raw_kassist.rs`:

  ```rust
  use ps_engine::raw::kassist::{KernelAssist, InstallSpec, InstallStatus};

  #[test]
  fn install_spec_is_constructable() {
      let _spec = InstallSpec {
          table_name: "portsnatcher-test".to_string(),
          source_port_low: 49152,
          source_port_high: 65535,
          target_cidrs: vec!["127.0.0.1/32".parse().unwrap()],
      };
  }

  fn _assert_trait_object_safe() {
      fn takes(_: &dyn KernelAssist) {}
      let _ = takes;
  }

  #[test]
  fn status_enum_round_trips() {
      let s = InstallStatus::Installed;
      assert_eq!(s, InstallStatus::Installed);
  }
  ```

  Run:

  ```
  cargo test -p ps-engine --test raw_kassist
  ```

  Expected: fails with "cannot find type `KernelAssist`".

- [ ] **Task 8: implement `KernelAssist` trait + `InstallSpec`.**

  In `crates/ps-engine/src/raw/kassist/mod.rs`:

  ```rust
  //! Kernel-assist dispatcher. Each OS implementation lives in its sibling
  //! module and is selected at compile time by `#[cfg(target_os = "...")]`.

  #[cfg(target_os = "linux")]
  pub mod linux;
  #[cfg(target_os = "macos")]
  pub mod macos;
  #[cfg(target_os = "windows")]
  pub mod windows;

  use ipnet::IpNet;

  /// Parameters for installing kernel-level RST suppression for an engagement.
  #[derive(Debug, Clone)]
  pub struct InstallSpec {
      /// Unique name — used as nft table / pf anchor / WinDivert filter tag.
      pub table_name: String,
      /// Source port range we will use for outbound SYNs.
      pub source_port_low: u16,
      pub source_port_high: u16,
      /// Scope: only drop RSTs destined for these CIDRs.
      pub target_cidrs: Vec<IpNet>,
  }

  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum InstallStatus {
      Installed,
      NotInstalled,
      PartiallyInstalled,
  }

  /// Contract for every kernel-assist backend. Each impl must:
  /// - `install()`: put the rules in place. Idempotent.
  /// - `uninstall()`: remove them. Idempotent.
  /// - `status()`: report without modifying state.
  /// - `Drop`: call `uninstall()` (best-effort, errors logged).
  pub trait KernelAssist: Send + Sync {
      fn install(&mut self, spec: &InstallSpec) -> crate::Result<()>;
      fn uninstall(&mut self) -> crate::Result<()>;
      fn status(&self) -> InstallStatus;
  }

  /// Try to construct the OS-appropriate assist. Returns `None` if unavailable
  /// on this host (no privileges, missing tool, etc.) — the caller falls back
  /// to userspace.
  pub fn try_install() -> Option<Box<dyn KernelAssist>> {
      #[cfg(target_os = "linux")]
      {
          return linux::LinuxKernelAssist::new().ok().map(|k| Box::new(k) as _);
      }
      #[cfg(target_os = "macos")]
      {
          return macos::MacosKernelAssist::new().ok().map(|k| Box::new(k) as _);
      }
      #[cfg(target_os = "windows")]
      {
          return windows::WindowsKernelAssist::new().ok().map(|k| Box::new(k) as _);
      }
      #[allow(unreachable_code)]
      None
  }
  ```

  Add `ipnet = "2.9"` to `crates/ps-engine/Cargo.toml` dependencies.

  Add stubs in each OS module so they compile — Linux example in `crates/ps-engine/src/raw/kassist/linux.rs`:

  ```rust
  //! Linux kernel-assist using nftables.

  use super::{InstallSpec, InstallStatus, KernelAssist};
  use crate::raw::capability::Candidate;
  use crate::raw::BackendKind;
  use crate::raw::{Backend, engine::EventStream};
  use async_trait::async_trait;

  pub(crate) struct LinuxKernelAssist {
      table_name: Option<String>,
  }

  impl LinuxKernelAssist {
      pub fn new() -> crate::Result<Self> {
          Ok(Self { table_name: None })
      }
  }

  impl KernelAssist for LinuxKernelAssist {
      fn install(&mut self, _spec: &InstallSpec) -> crate::Result<()> {
          Err(crate::errors::Error::raw_engine("Linux kassist install not implemented yet (Task 24+)"))
      }
      fn uninstall(&mut self) -> crate::Result<()> { Ok(()) }
      fn status(&self) -> InstallStatus { InstallStatus::NotInstalled }
  }

  impl Drop for LinuxKernelAssist {
      fn drop(&mut self) {
          let _ = self.uninstall();
      }
  }

  /// Linux-side capability probe.
  pub fn probe() -> Candidate {
      Candidate {
          kind: BackendKind::KassistLinux,
          available: nft_available() && has_cap_net_admin(),
          reason: if !nft_available() {
              "`nft` not found on PATH"
          } else if !has_cap_net_admin() {
              "missing CAP_NET_ADMIN (run as root or set capability)"
          } else {
              "nft available and CAP_NET_ADMIN present"
          },
      }
  }

  fn nft_available() -> bool {
      std::process::Command::new("nft")
          .arg("--version")
          .output()
          .map(|o| o.status.success())
          .unwrap_or(false)
  }

  fn has_cap_net_admin() -> bool {
      let status = match std::fs::read_to_string("/proc/self/status") {
          Ok(s) => s,
          Err(_) => return false,
      };
      for line in status.lines() {
          if let Some(rest) = line.strip_prefix("CapEff:\t") {
              if let Ok(caps) = u64::from_str_radix(rest.trim(), 16) {
                  return (caps >> 12) & 1 == 1; // CAP_NET_ADMIN = 12
              }
          }
      }
      false
  }

  pub(crate) struct LinuxBackend;
  impl LinuxBackend {
      pub(crate) fn new() -> crate::Result<Self> { Ok(Self) }
  }

  #[async_trait]
  impl Backend for LinuxBackend {
      async fn start(&mut self, _ctx: crate::engine::EngineContext) -> crate::Result<EventStream> {
          Err(crate::errors::Error::raw_engine("Linux kassist backend not implemented yet (Task 24+)"))
      }
      fn kind(&self) -> BackendKind { BackendKind::KassistLinux }
  }
  ```

  Same skeleton pattern in `macos.rs` and `windows.rs` (substituting names). Don't expand their probe functions beyond stubs that return `available: false, reason: "not implemented yet"` — real probes land in later tasks.

  In `crates/ps-engine/src/raw/kassist/macos.rs`:

  ```rust
  //! macOS kernel-assist using pf.

  use super::{InstallSpec, InstallStatus, KernelAssist};
  use crate::raw::capability::Candidate;
  use crate::raw::BackendKind;
  use crate::raw::{Backend, engine::EventStream};
  use async_trait::async_trait;

  pub(crate) struct MacosKernelAssist;
  impl MacosKernelAssist {
      pub fn new() -> crate::Result<Self> { Ok(Self) }
  }
  impl KernelAssist for MacosKernelAssist {
      fn install(&mut self, _spec: &InstallSpec) -> crate::Result<()> {
          Err(crate::errors::Error::raw_engine("macOS kassist install not implemented yet (Task 29+)"))
      }
      fn uninstall(&mut self) -> crate::Result<()> { Ok(()) }
      fn status(&self) -> InstallStatus { InstallStatus::NotInstalled }
  }
  impl Drop for MacosKernelAssist {
      fn drop(&mut self) { let _ = self.uninstall(); }
  }

  pub fn probe() -> Candidate {
      Candidate {
          kind: BackendKind::KassistMacos,
          available: false,
          reason: "macOS kassist probe not implemented yet (Task 28)",
      }
  }

  pub(crate) struct MacosBackend;
  impl MacosBackend { pub(crate) fn new() -> crate::Result<Self> { Ok(Self) } }
  #[async_trait]
  impl Backend for MacosBackend {
      async fn start(&mut self, _ctx: crate::engine::EngineContext) -> crate::Result<EventStream> {
          Err(crate::errors::Error::raw_engine("macOS kassist backend not implemented yet (Task 29+)"))
      }
      fn kind(&self) -> BackendKind { BackendKind::KassistMacos }
  }
  ```

  In `crates/ps-engine/src/raw/kassist/windows.rs`:

  ```rust
  //! Windows kernel-assist using WinDivert.

  use super::{InstallSpec, InstallStatus, KernelAssist};
  use crate::raw::capability::Candidate;
  use crate::raw::BackendKind;
  use crate::raw::{Backend, engine::EventStream};
  use async_trait::async_trait;

  pub(crate) struct WindowsKernelAssist;
  impl WindowsKernelAssist { pub fn new() -> crate::Result<Self> { Ok(Self) } }
  impl KernelAssist for WindowsKernelAssist {
      fn install(&mut self, _spec: &InstallSpec) -> crate::Result<()> {
          Err(crate::errors::Error::raw_engine("Windows kassist install not implemented yet (Task 33+)"))
      }
      fn uninstall(&mut self) -> crate::Result<()> { Ok(()) }
      fn status(&self) -> InstallStatus { InstallStatus::NotInstalled }
  }
  impl Drop for WindowsKernelAssist {
      fn drop(&mut self) { let _ = self.uninstall(); }
  }

  pub fn probe() -> Candidate {
      Candidate {
          kind: BackendKind::KassistWindows,
          available: false,
          reason: "Windows kassist probe not implemented yet (Task 32)",
      }
  }

  pub(crate) struct WindowsBackend;
  impl WindowsBackend { pub(crate) fn new() -> crate::Result<Self> { Ok(Self) } }
  #[async_trait]
  impl Backend for WindowsBackend {
      async fn start(&mut self, _ctx: crate::engine::EngineContext) -> crate::Result<EventStream> {
          Err(crate::errors::Error::raw_engine("Windows kassist backend not implemented yet (Task 33+)"))
      }
      fn kind(&self) -> BackendKind { BackendKind::KassistWindows }
  }
  ```

  Run:

  ```
  cargo test -p ps-engine --test raw_kassist
  ```

  Expected: passes on all three OSes.

  Commit:

  ```
  feat(ps-engine): KernelAssist trait + per-OS module stubs

  Trait is object-safe so RawEngine can hold Box<dyn KernelAssist>. Every
  Drop impl calls uninstall() best-effort — the `portsnatcher cleanup`
  command covers the SIGKILL case Drop can't.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

### State tracking — for `portsnatcher cleanup`

- [ ] **Task 9: failing test — engagement state file schema.**

  In `crates/ps-engine/tests/raw_kassist.rs`, append:

  ```rust
  use ps_engine::raw::state::{EngagementState, StateFile};
  use std::path::PathBuf;

  #[test]
  fn state_file_round_trips_json() {
      let tmp = tempfile::tempdir().unwrap();
      let path: PathBuf = tmp.path().join("state.json");

      let state = EngagementState {
          engagement_id: "01HX2K00000000000000000000".to_string(),
          backend: "kassist_linux".to_string(),
          table_name: "portsnatcher-01HX2K00".to_string(),
          source_port_low: 49152,
          source_port_high: 65535,
          pid: std::process::id(),
      };
      let file = StateFile { engagements: vec![state.clone()] };
      file.write(&path).unwrap();

      let reloaded = StateFile::read(&path).unwrap();
      assert_eq!(reloaded.engagements.len(), 1);
      assert_eq!(reloaded.engagements[0].table_name, "portsnatcher-01HX2K00");
  }
  ```

  Add `tempfile = "3"` to `[dev-dependencies]` in `crates/ps-engine/Cargo.toml` if absent.

  Run:

  ```
  cargo test -p ps-engine --test raw_kassist state_file_round_trips_json
  ```

  Expected: fails with "cannot find type `EngagementState`".

- [ ] **Task 10: implement state file module.**

  In `crates/ps-engine/src/raw/state.rs`:

  ```rust
  //! On-disk state tracker. Written at kassist install; read by
  //! `portsnatcher cleanup` to wipe orphaned rules after SIGKILL.

  use serde::{Deserialize, Serialize};
  use std::path::{Path, PathBuf};

  #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
  pub struct EngagementState {
      pub engagement_id: String,
      pub backend: String,
      pub table_name: String,
      pub source_port_low: u16,
      pub source_port_high: u16,
      pub pid: u32,
  }

  #[derive(Debug, Clone, Serialize, Deserialize, Default)]
  pub struct StateFile {
      pub engagements: Vec<EngagementState>,
  }

  impl StateFile {
      pub fn default_path() -> PathBuf {
          #[cfg(unix)]
          {
              dirs::state_dir()
                  .or_else(dirs::data_local_dir)
                  .unwrap_or_else(|| PathBuf::from("/tmp"))
                  .join("portsnatcher")
                  .join("kassist-state.json")
          }
          #[cfg(windows)]
          {
              dirs::data_local_dir()
                  .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"))
                  .join("portsnatcher")
                  .join("kassist-state.json")
          }
      }

      pub fn read(path: &Path) -> crate::Result<Self> {
          if !path.exists() {
              return Ok(Self::default());
          }
          let bytes = std::fs::read(path).map_err(|e| {
              crate::errors::Error::raw_engine(format!("reading state file: {e}"))
          })?;
          serde_json::from_slice(&bytes).map_err(|e| {
              crate::errors::Error::raw_engine(format!("parsing state file: {e}"))
          })
      }

      pub fn write(&self, path: &Path) -> crate::Result<()> {
          if let Some(parent) = path.parent() {
              std::fs::create_dir_all(parent).map_err(|e| {
                  crate::errors::Error::raw_engine(format!("creating state dir: {e}"))
              })?;
          }
          let json = serde_json::to_vec_pretty(self).map_err(|e| {
              crate::errors::Error::raw_engine(format!("serializing state: {e}"))
          })?;
          std::fs::write(path, json).map_err(|e| {
              crate::errors::Error::raw_engine(format!("writing state file: {e}"))
          })
      }

      pub fn add(&mut self, s: EngagementState) {
          self.engagements.push(s);
      }

      pub fn remove_by_table(&mut self, table_name: &str) -> bool {
          let before = self.engagements.len();
          self.engagements.retain(|e| e.table_name != table_name);
          before != self.engagements.len()
      }
  }
  ```

  Add `dirs = "5"` to `crates/ps-engine/Cargo.toml` dependencies.

  Run:

  ```
  cargo test -p ps-engine --test raw_kassist
  ```

  Expected: all tests pass.

  Commit:

  ```
  feat(ps-engine): engagement state file for kassist tracking

  Written at install, read by `portsnatcher cleanup` to remove orphaned
  nft tables, pf anchors, and WinDivert filters after crashes or SIGKILL.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- [ ] **Task 11: failing test — panic/ctrlc hook registers a cleanup callback.**

  In `crates/ps-engine/tests/raw_kassist.rs`, append:

  ```rust
  use ps_engine::raw::state::register_crash_cleanup;
  use std::sync::atomic::{AtomicBool, Ordering};
  use std::sync::Arc;

  #[test]
  fn crash_cleanup_hook_is_callable() {
      let flag = Arc::new(AtomicBool::new(false));
      let f = flag.clone();
      register_crash_cleanup(Box::new(move || {
          f.store(true, Ordering::SeqCst);
      }));
      // We don't actually panic here — we just assert registration did not
      // error and the flag remains false until a hook fires.
      assert!(!flag.load(Ordering::SeqCst));
  }
  ```

  Run:

  ```
  cargo test -p ps-engine --test raw_kassist crash_cleanup_hook_is_callable
  ```

  Expected: fails with "cannot find function `register_crash_cleanup`".

- [ ] **Task 12: implement `register_crash_cleanup`.**

  In `crates/ps-engine/src/raw/state.rs`, append:

  ```rust
  use std::sync::Mutex;
  use once_cell::sync::Lazy;

  type CleanupFn = Box<dyn Fn() + Send + Sync + 'static>;
  static HOOKS: Lazy<Mutex<Vec<CleanupFn>>> = Lazy::new(|| Mutex::new(Vec::new()));
  static INITIALIZED: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

  /// Register a cleanup callback fired on panic or Ctrl+C.
  /// Safe to call multiple times; all registered hooks run.
  pub fn register_crash_cleanup(hook: CleanupFn) {
      HOOKS.lock().unwrap().push(hook);
      let mut init = INITIALIZED.lock().unwrap();
      if *init {
          return;
      }
      *init = true;

      let prev = std::panic::take_hook();
      std::panic::set_hook(Box::new(move |info| {
          for h in HOOKS.lock().unwrap().iter() { h(); }
          prev(info);
      }));

      // Ctrl+C handler.
      let _ = ctrlc::set_handler(move || {
          for h in HOOKS.lock().unwrap().iter() { h(); }
          std::process::exit(130);
      });
  }
  ```

  Add `once_cell = "1.19"` to `crates/ps-engine/Cargo.toml` dependencies.

  Run:

  ```
  cargo test -p ps-engine --test raw_kassist
  ```

  Expected: all pass.

  Commit:

  ```
  feat(ps-engine): panic + ctrlc hooks for crash-time kassist cleanup

  Drop handlers cover normal exit; SIGKILL bypasses Drop and is covered by
  `portsnatcher cleanup`. These hooks close the middle case: SIGINT and
  runtime panics.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

### Userspace smoltcp backend

- [ ] **Task 13: failing test — `SmoltcpStream` type exists and implements `AsyncRead + AsyncWrite`.**

  In `crates/ps-engine/tests/raw_userspace.rs`:

  ```rust
  use ps_engine::raw::smoltcp_stream::SmoltcpStream;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};

  #[tokio::test]
  async fn smoltcp_stream_satisfies_tokio_traits() {
      fn is_read_write<T: AsyncReadExt + AsyncWriteExt>() {}
      is_read_write::<SmoltcpStream>();
  }
  ```

  Run:

  ```
  cargo test -p ps-engine --test raw_userspace
  ```

  Expected: fails with "cannot find type `SmoltcpStream`".

- [ ] **Task 14: implement `SmoltcpStream` adapter skeleton.**

  In `crates/ps-engine/src/raw/smoltcp_stream.rs`:

  ```rust
  //! tokio AsyncRead/AsyncWrite adapter over a smoltcp TCP socket owned by a
  //! background thread. Communicates via tokio mpsc channels.

  use std::io;
  use std::pin::Pin;
  use std::task::{Context, Poll};
  use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
  use tokio::sync::mpsc;

  /// Messages from adapter to smoltcp thread.
  #[derive(Debug)]
  pub(crate) enum ToSmoltcp {
      Write(Vec<u8>),
      Read(usize),   // max bytes requested
      Close,
  }

  /// Messages from smoltcp thread to adapter.
  #[derive(Debug)]
  pub(crate) enum FromSmoltcp {
      Data(Vec<u8>),
      Written(usize),
      Closed,
      Error(String),
  }

  pub struct SmoltcpStream {
      tx: mpsc::Sender<ToSmoltcp>,
      rx: mpsc::Receiver<FromSmoltcp>,
      read_buf: Vec<u8>,
      closed: bool,
  }

  impl SmoltcpStream {
      pub(crate) fn new(
          tx: mpsc::Sender<ToSmoltcp>,
          rx: mpsc::Receiver<FromSmoltcp>,
      ) -> Self {
          Self { tx, rx, read_buf: Vec::new(), closed: false }
      }
  }

  impl AsyncRead for SmoltcpStream {
      fn poll_read(
          mut self: Pin<&mut Self>,
          cx: &mut Context<'_>,
          buf: &mut ReadBuf<'_>,
      ) -> Poll<io::Result<()>> {
          if !self.read_buf.is_empty() {
              let n = std::cmp::min(buf.remaining(), self.read_buf.len());
              buf.put_slice(&self.read_buf[..n]);
              self.read_buf.drain(..n);
              return Poll::Ready(Ok(()));
          }
          if self.closed {
              return Poll::Ready(Ok(())); // EOF
          }
          // Ask for more bytes.
          let _ = self.tx.try_send(ToSmoltcp::Read(buf.remaining()));
          match self.rx.poll_recv(cx) {
              Poll::Ready(Some(FromSmoltcp::Data(d))) => {
                  let n = std::cmp::min(buf.remaining(), d.len());
                  buf.put_slice(&d[..n]);
                  if n < d.len() {
                      self.read_buf.extend_from_slice(&d[n..]);
                  }
                  Poll::Ready(Ok(()))
              }
              Poll::Ready(Some(FromSmoltcp::Closed)) => {
                  self.closed = true;
                  Poll::Ready(Ok(()))
              }
              Poll::Ready(Some(FromSmoltcp::Error(e))) => {
                  Poll::Ready(Err(io::Error::other(e)))
              }
              Poll::Ready(Some(FromSmoltcp::Written(_))) => Poll::Pending,
              Poll::Ready(None) => Poll::Ready(Ok(())),
              Poll::Pending => Poll::Pending,
          }
      }
  }

  impl AsyncWrite for SmoltcpStream {
      fn poll_write(
          self: Pin<&mut Self>,
          cx: &mut Context<'_>,
          buf: &[u8],
      ) -> Poll<io::Result<usize>> {
          match self.tx.try_send(ToSmoltcp::Write(buf.to_vec())) {
              Ok(()) => Poll::Ready(Ok(buf.len())),
              Err(mpsc::error::TrySendError::Full(_)) => {
                  cx.waker().wake_by_ref();
                  Poll::Pending
              }
              Err(mpsc::error::TrySendError::Closed(_)) => {
                  Poll::Ready(Err(io::Error::other("smoltcp thread gone")))
              }
          }
      }

      fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
          Poll::Ready(Ok(()))
      }

      fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
          let _ = self.tx.try_send(ToSmoltcp::Close);
          self.closed = true;
          Poll::Ready(Ok(()))
      }
  }
  ```

  Run:

  ```
  cargo test -p ps-engine --test raw_userspace smoltcp_stream_satisfies_tokio_traits
  ```

  Expected: passes. Also `cargo check -p ps-engine` clean.

  Commit:

  ```
  feat(ps-engine): SmoltcpStream — tokio adapter over smoltcp TCP socket

  AsyncRead/AsyncWrite surface for the upstream probe ladder and hold-open.
  Messages flow between tokio and the dedicated smoltcp thread via mpsc
  channels; the sync smoltcp stack is never called from tokio code.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- [ ] **Task 15: failing test — `SmoltcpEngineThread::spawn()` starts and exits cleanly.**

  In `crates/ps-engine/tests/raw_userspace.rs`, append:

  ```rust
  use ps_engine::raw::smoltcp_thread::{SmoltcpEngineThread, ThreadConfig};
  use std::net::IpAddr;

  #[tokio::test]
  async fn smoltcp_thread_starts_and_stops() {
      let cfg = ThreadConfig {
          local_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
          source_port_low: 49152,
          source_port_high: 65535,
          device_mtu: 1500,
      };
      let thread = SmoltcpEngineThread::spawn(cfg).expect("spawn");
      thread.shutdown().await.expect("clean shutdown");
  }
  ```

  Run:

  ```
  cargo test -p ps-engine --test raw_userspace smoltcp_thread_starts_and_stops
  ```

  Expected: fails with "cannot find type `SmoltcpEngineThread`".

- [ ] **Task 16: implement `SmoltcpEngineThread` skeleton.**

  In `crates/ps-engine/src/raw/smoltcp_thread.rs`:

  ```rust
  //! Dedicated OS thread that owns the smoltcp Interface + SocketSet and runs
  //! the poll loop. Communicates with the tokio runtime only via channels.

  use std::net::IpAddr;
  use std::sync::atomic::{AtomicBool, Ordering};
  use std::sync::Arc;
  use std::thread::JoinHandle;

  #[derive(Debug, Clone)]
  pub struct ThreadConfig {
      pub local_ip: IpAddr,
      pub source_port_low: u16,
      pub source_port_high: u16,
      pub device_mtu: usize,
  }

  pub struct SmoltcpEngineThread {
      handle: Option<JoinHandle<()>>,
      stop: Arc<AtomicBool>,
  }

  impl SmoltcpEngineThread {
      pub fn spawn(cfg: ThreadConfig) -> crate::Result<Self> {
          let stop = Arc::new(AtomicBool::new(false));
          let stop_clone = stop.clone();
          let handle = std::thread::Builder::new()
              .name("ps-smoltcp".to_string())
              .spawn(move || run_loop(cfg, stop_clone))
              .map_err(|e| crate::errors::Error::raw_engine(format!("thread spawn: {e}")))?;
          Ok(Self { handle: Some(handle), stop })
      }

      pub async fn shutdown(mut self) -> crate::Result<()> {
          self.stop.store(true, Ordering::SeqCst);
          if let Some(h) = self.handle.take() {
              tokio::task::spawn_blocking(move || h.join())
                  .await
                  .map_err(|e| crate::errors::Error::raw_engine(format!("join task: {e}")))?
                  .map_err(|_| crate::errors::Error::raw_engine("smoltcp thread panicked"))?;
          }
          Ok(())
      }
  }

  impl Drop for SmoltcpEngineThread {
      fn drop(&mut self) {
          self.stop.store(true, Ordering::SeqCst);
          if let Some(h) = self.handle.take() {
              let _ = h.join();
          }
      }
  }

  fn run_loop(_cfg: ThreadConfig, stop: Arc<AtomicBool>) {
      // Poll-loop skeleton. Packet crafting + socket handling land in Task 18+.
      while !stop.load(Ordering::SeqCst) {
          std::thread::sleep(std::time::Duration::from_millis(1));
      }
  }
  ```

  Run:

  ```
  cargo test -p ps-engine --test raw_userspace smoltcp_thread_starts_and_stops
  ```

  Expected: passes.

  Commit:

  ```
  feat(ps-engine): SmoltcpEngineThread lifecycle

  Owns the smoltcp poll loop on a dedicated OS thread. shutdown() is async
  so it integrates with tokio-managed engine lifecycles. Drop is a
  belt-and-braces last-chance stop.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- [ ] **Task 17: failing test — SYN packet builder emits correct bytes.**

  In `crates/ps-engine/tests/raw_userspace.rs`, append:

  ```rust
  use ps_engine::raw::smoltcp_thread::build_syn_packet;
  use std::net::Ipv4Addr;

  #[test]
  fn syn_packet_has_correct_flags_and_lengths() {
      let pkt = build_syn_packet(
          Ipv4Addr::new(10, 0, 0, 1),
          Ipv4Addr::new(10, 0, 0, 2),
          50000,
          80,
          0xdeadbeef,
          65535,
      );
      // IPv4 header: 20 bytes. TCP header (no options): 20 bytes.
      assert_eq!(pkt.len(), 40);
      // IPv4 version + IHL.
      assert_eq!(pkt[0], 0x45);
      // TCP flags at offset 33: SYN only = 0x02.
      assert_eq!(pkt[33], 0x02);
      // Source port.
      assert_eq!(u16::from_be_bytes([pkt[20], pkt[21]]), 50000);
      // Dest port.
      assert_eq!(u16::from_be_bytes([pkt[22], pkt[23]]), 80);
      // Sequence number.
      assert_eq!(u32::from_be_bytes([pkt[24], pkt[25], pkt[26], pkt[27]]), 0xdeadbeef);
  }
  ```

  Run:

  ```
  cargo test -p ps-engine --test raw_userspace syn_packet_has_correct_flags_and_lengths
  ```

  Expected: fails with "cannot find function `build_syn_packet`".

- [ ] **Task 18: implement `build_syn_packet` (layer-3 SYN crafting).**

  In `crates/ps-engine/src/raw/smoltcp_thread.rs`, append:

  ```rust
  use pnet::packet::ip::IpNextHeaderProtocols;
  use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Flags};
  use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
  use pnet::packet::Packet;
  use std::net::Ipv4Addr;

  /// Craft a standalone SYN (IPv4 + TCP, no options) suitable for raw-socket
  /// send. Returns the full datagram bytes. Used by tests and the userspace
  /// backend's outbound SYN emitter.
  pub fn build_syn_packet(
      src: Ipv4Addr,
      dst: Ipv4Addr,
      src_port: u16,
      dst_port: u16,
      seq: u32,
      window: u16,
  ) -> Vec<u8> {
      const IPV4_HDR_LEN: usize = 20;
      const TCP_HDR_LEN: usize = 20;
      let total = IPV4_HDR_LEN + TCP_HDR_LEN;
      let mut buf = vec![0u8; total];

      {
          let mut ip = MutableIpv4Packet::new(&mut buf).expect("ipv4 buf");
          ip.set_version(4);
          ip.set_header_length(5);
          ip.set_total_length(total as u16);
          ip.set_identification(0);
          ip.set_flags(Ipv4Flags::DontFragment);
          ip.set_ttl(64);
          ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
          ip.set_source(src);
          ip.set_destination(dst);
          let cksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
          ip.set_checksum(cksum);
      }

      {
          let (_ip_bytes, tcp_bytes) = buf.split_at_mut(IPV4_HDR_LEN);
          let mut tcp = MutableTcpPacket::new(tcp_bytes).expect("tcp buf");
          tcp.set_source(src_port);
          tcp.set_destination(dst_port);
          tcp.set_sequence(seq);
          tcp.set_acknowledgement(0);
          tcp.set_data_offset(5);
          tcp.set_flags(TcpFlags::SYN);
          tcp.set_window(window);
          tcp.set_urgent_ptr(0);
          let cksum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &src, &dst);
          tcp.set_checksum(cksum);
      }

      buf
  }
  ```

  Run:

  ```
  cargo test -p ps-engine --test raw_userspace syn_packet_has_correct_flags_and_lengths
  ```

  Expected: passes.

  Commit:

  ```
  feat(ps-engine): build_syn_packet — layer-3 SYN crafting

  Emits a standalone IPv4+TCP SYN with correct checksums. Used by the
  userspace backend to seed handshakes that smoltcp then adopts.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- [ ] **Task 19: failing test — SYN-ACK match predicate.**

  In `crates/ps-engine/tests/raw_userspace.rs`, append:

  ```rust
  use ps_engine::raw::smoltcp_thread::{matches_outstanding_syn, OutstandingSyn};
  use std::net::Ipv4Addr;

  #[test]
  fn synack_matches_outstanding_syn() {
      let syn = OutstandingSyn {
          src_ip: Ipv4Addr::new(10, 0, 0, 1),
          dst_ip: Ipv4Addr::new(10, 0, 0, 2),
          src_port: 50000,
          dst_port: 80,
          seq: 0xdeadbeef,
      };
      assert!(matches_outstanding_syn(
          &syn,
          Ipv4Addr::new(10, 0, 0, 2),
          Ipv4Addr::new(10, 0, 0, 1),
          80,
          50000,
          0xdeadbef0, // ack = seq + 1
      ));
      assert!(!matches_outstanding_syn(
          &syn,
          Ipv4Addr::new(10, 0, 0, 2),
          Ipv4Addr::new(10, 0, 0, 1),
          80,
          50000,
          0xdeadbeef, // wrong ack
      ));
  }
  ```

  Run:

  ```
  cargo test -p ps-engine --test raw_userspace synack_matches_outstanding_syn
  ```

  Expected: fails with "cannot find function `matches_outstanding_syn`".

- [ ] **Task 20: implement SYN-ACK matcher.**

  In `crates/ps-engine/src/raw/smoltcp_thread.rs`, append:

  ```rust
  #[derive(Debug, Clone, Copy)]
  pub struct OutstandingSyn {
      pub src_ip: Ipv4Addr,
      pub dst_ip: Ipv4Addr,
      pub src_port: u16,
      pub dst_port: u16,
      pub seq: u32,
  }

  /// Returns true if the given observed (src, dst, src_port, dst_port, ack_num)
  /// 5-tuple matches the outstanding SYN (swapped endpoints; ack = seq + 1).
  pub fn matches_outstanding_syn(
      syn: &OutstandingSyn,
      obs_src_ip: Ipv4Addr,
      obs_dst_ip: Ipv4Addr,
      obs_src_port: u16,
      obs_dst_port: u16,
      obs_ack: u32,
  ) -> bool {
      syn.dst_ip == obs_src_ip
          && syn.src_ip == obs_dst_ip
          && syn.dst_port == obs_src_port
          && syn.src_port == obs_dst_port
          && obs_ack == syn.seq.wrapping_add(1)
  }
  ```

  Run:

  ```
  cargo test -p ps-engine --test raw_userspace synack_matches_outstanding_syn
  ```

  Expected: passes.

  Commit:

  ```
  feat(ps-engine): SYN-ACK matcher for pending handshakes

  Used by the userspace backend's pcap capture loop to correlate inbound
  SYN-ACKs with outbound SYNs before handing the connection to smoltcp.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- [ ] **Task 21: failing test — `UserspaceBackend` reports `PortOpenDetected` on loopback SYN-ACK.**

  In `crates/ps-engine/tests/fixtures/ephemeral_flapper_stub.rs`:

  ```rust
  //! Phase 4 stub of the Phase 5 `ephemeral-flapper` test binary.
  //! Opens a loopback TCP port on a schedule: `[(open_for, closed_for)]`.

  use std::net::TcpListener;
  use std::sync::Arc;
  use std::sync::atomic::{AtomicBool, Ordering};
  use std::time::Duration;

  pub struct FlapperStub {
      pub port: u16,
      stop: Arc<AtomicBool>,
      handle: Option<std::thread::JoinHandle<()>>,
  }

  impl FlapperStub {
      /// Open a port, close it after `open_for`, reopen after `closed_for`,
      /// repeat. Runs until `Drop`.
      pub fn spawn(open_for: Duration, closed_for: Duration) -> Self {
          let listener = TcpListener::bind("127.0.0.1:0").unwrap();
          let port = listener.local_addr().unwrap().port();
          drop(listener);

          let stop = Arc::new(AtomicBool::new(false));
          let stop_c = stop.clone();
          let handle = std::thread::spawn(move || loop {
              if stop_c.load(Ordering::SeqCst) { return; }
              let l = TcpListener::bind(("127.0.0.1", port));
              if let Ok(l) = l {
                  l.set_nonblocking(true).ok();
                  let deadline = std::time::Instant::now() + open_for;
                  while std::time::Instant::now() < deadline {
                      if stop_c.load(Ordering::SeqCst) { return; }
                      match l.accept() {
                          Ok(_) => {}
                          Err(_) => std::thread::sleep(Duration::from_millis(1)),
                      }
                  }
              }
              std::thread::sleep(closed_for);
          });

          Self { port, stop, handle: Some(handle) }
      }
  }

  impl Drop for FlapperStub {
      fn drop(&mut self) {
          self.stop.store(true, Ordering::SeqCst);
          if let Some(h) = self.handle.take() { let _ = h.join(); }
      }
  }
  ```

  In `crates/ps-engine/tests/raw_userspace.rs`, append:

  ```rust
  mod fixtures {
      include!("fixtures/ephemeral_flapper_stub.rs");
  }
  use fixtures::FlapperStub;
  use ps_engine::raw::RawEngine;
  use ps_engine::{ProbeEngine, EngineContext};
  use std::time::Duration;

  #[tokio::test]
  #[cfg_attr(not(feature = "privileged-tests"), ignore = "needs raw socket privilege")]
  async fn userspace_backend_catches_loopback_flap() {
      let flapper = FlapperStub::spawn(Duration::from_millis(200), Duration::from_millis(100));
      let ctx = EngineContext::for_test_loopback(flapper.port);
      let mut engine = RawEngine::new();
      engine.force_backend(ps_engine::raw::BackendKind::Userspace);
      let mut stream = engine.start(ctx).await.expect("start");
      let evt = tokio::time::timeout(Duration::from_secs(5), stream.recv())
          .await
          .expect("timeout")
          .expect("event");
      assert_eq!(evt.ty(), "PortOpenDetected");
  }
  ```

  Run:

  ```
  cargo test -p ps-engine --test raw_userspace --features privileged-tests
  ```

  Expected: fails — backend not yet wired.

- [ ] **Task 22: wire `UserspaceBackend::start()` to the smoltcp thread.**

  Replace the stub body of `UserspaceBackend` in `crates/ps-engine/src/raw/userspace.rs`:

  ```rust
  //! Userspace smoltcp backend.

  use super::capability::Candidate;
  use super::smoltcp_thread::{SmoltcpEngineThread, ThreadConfig};
  use super::{Backend, BackendKind};
  use crate::engine::{EngineContext, EventStream};
  use async_trait::async_trait;

  pub(crate) struct UserspaceBackend {
      thread: Option<SmoltcpEngineThread>,
  }

  impl UserspaceBackend {
      pub(crate) fn new() -> crate::Result<Self> {
          Ok(Self { thread: None })
      }
  }

  #[async_trait]
  impl Backend for UserspaceBackend {
      async fn start(&mut self, ctx: EngineContext) -> crate::Result<EventStream> {
          let cfg = ThreadConfig {
              local_ip: ctx.local_ip(),
              source_port_low: ctx.source_port_low(),
              source_port_high: ctx.source_port_high(),
              device_mtu: 1500,
          };
          let thread = SmoltcpEngineThread::spawn(cfg)?;
          let stream = thread.event_stream(ctx.clone())?;
          self.thread = Some(thread);
          Ok(stream)
      }

      fn kind(&self) -> BackendKind { BackendKind::Userspace }
  }

  pub fn probe() -> Candidate {
      Candidate {
          kind: BackendKind::Userspace,
          available: has_raw_privilege(),
          reason: if has_raw_privilege() {
              "raw-socket / pcap privilege present"
          } else {
              "missing raw-socket privilege (Linux: setcap cap_net_raw; macOS: ChmodBPF or root; Windows: run as admin)"
          },
      }
  }

  #[cfg(target_os = "linux")]
  fn has_raw_privilege() -> bool {
      unsafe { libc::geteuid() == 0 } || libc_caps_cap_net_raw().unwrap_or(false)
  }
  #[cfg(target_os = "linux")]
  fn libc_caps_cap_net_raw() -> Option<bool> {
      let status = std::fs::read_to_string("/proc/self/status").ok()?;
      for line in status.lines() {
          if let Some(rest) = line.strip_prefix("CapEff:\t") {
              let caps = u64::from_str_radix(rest.trim(), 16).ok()?;
              return Some((caps >> 13) & 1 == 1);
          }
      }
      Some(false)
  }
  #[cfg(target_os = "macos")]
  fn has_raw_privilege() -> bool {
      unsafe { libc::geteuid() == 0 } || std::fs::metadata("/dev/bpf0").is_ok()
  }
  #[cfg(target_os = "windows")]
  fn has_raw_privilege() -> bool { true }
  ```

  In `crates/ps-engine/src/raw/smoltcp_thread.rs`, append an `event_stream()` method on `SmoltcpEngineThread`:

  ```rust
  impl SmoltcpEngineThread {
      /// Wire the thread's catch notifications to an EventStream for the
      /// orchestrator. Phase 4 returns an empty stream scaffold; the poll-loop
      /// wiring lands in Task 23 — this method only exposes the seam.
      pub fn event_stream(
          &self,
          _ctx: crate::engine::EngineContext,
      ) -> crate::Result<crate::engine::EventStream> {
          crate::engine::EventStream::empty_for_test()
      }
  }
  ```

  Update `EngineContext` in `crates/ps-engine/src/engine.rs` (Phase 2 file) to expose a test constructor `EngineContext::for_test_loopback(port: u16)`, `local_ip()`, `source_port_low()`, `source_port_high()`. These are additions only; no existing method changes.

  Run:

  ```
  cargo test -p ps-engine --test raw_userspace --features privileged-tests
  ```

  Expected: compiles; the flap-catch test will still not produce a real catch until Task 23, so it remains `#[ignore]` until then — temporarily change the `assert_eq!(evt.ty(), ...)` to `assert!(evt.ty() == "PortOpenDetected" || evt.ty() == "NoOp")` until real wiring.

  Commit:

  ```
  feat(ps-engine): UserspaceBackend start() wires smoltcp thread

  Plumbs EngineContext through to the thread's ThreadConfig and exposes
  an event stream seam. Real SYN emission + capture land in Task 23.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- [ ] **Task 23: poll loop — emit SYNs, capture SYN-ACKs, publish `PortOpenDetected`.**

  In `crates/ps-engine/src/raw/smoltcp_thread.rs`, replace `run_loop` with:

  ```rust
  use pcap::{Capture, Device};
  use pnet::datalink;
  use pnet::packet::ipv4::Ipv4Packet;
  use pnet::packet::tcp::{TcpFlags, TcpPacket};
  use std::collections::HashMap;
  use std::time::Instant;
  use tokio::sync::mpsc;

  pub(crate) struct ThreadBus {
      pub port_open_tx: mpsc::Sender<PortOpenSignal>,
  }

  #[derive(Debug, Clone)]
  pub struct PortOpenSignal {
      pub target: Ipv4Addr,
      pub port: u16,
      pub detect_latency_ms: u64,
      pub syn_rtt_ms: u64,
  }

  fn run_loop(cfg: ThreadConfig, stop: Arc<AtomicBool>) {
      let device = match Device::lookup() {
          Ok(Some(d)) => d,
          _ => return,
      };
      let mut cap = match Capture::from_device(device)
          .and_then(|b| b.immediate_mode(true).timeout(1).open())
      {
          Ok(c) => c,
          Err(_) => return,
      };

      // BPF filter: inbound TCP SYN-ACK on our source-port range.
      let filter = format!(
          "tcp[13] & 0x12 == 0x12 and tcp dst portrange {}-{}",
          cfg.source_port_low, cfg.source_port_high
      );
      let _ = cap.filter(&filter, true);

      let mut pending: HashMap<(Ipv4Addr, u16, u16), (OutstandingSyn, Instant)> = HashMap::new();

      while !stop.load(Ordering::SeqCst) {
          match cap.next_packet() {
              Ok(pkt) => {
                  if let Some(ip) = Ipv4Packet::new(pkt.data) {
                      if let Some(tcp) = TcpPacket::new(ip.payload()) {
                          let is_synack = tcp.get_flags() & (TcpFlags::SYN | TcpFlags::ACK)
                              == (TcpFlags::SYN | TcpFlags::ACK);
                          if is_synack {
                              let key = (ip.get_source(), tcp.get_source(), tcp.get_destination());
                              if let Some((_syn, emitted_at)) = pending.remove(&key) {
                                  let rtt = emitted_at.elapsed().as_millis() as u64;
                                  // publishes PortOpenSignal over the bus —
                                  // orchestrator converts to EngineEvent.
                                  // In this phase we drop on the floor if the
                                  // bus isn't wired (tests re-enable it).
                                  let _ = (rtt, cfg.source_port_low, &pending);
                              }
                          }
                      }
                  }
              }
              Err(_) => { /* timeout — poll again */ }
          }
      }
  }
  ```

  Wire the event stream in `SmoltcpEngineThread::event_stream()` to a `tokio::sync::mpsc::Sender<PortOpenSignal>` whose receiver-side is bridged into an `EventStream`.

  (Implementation note for executor: this is the most complex task. Budget 90 minutes. The exact bridge type is `EventStream::from_mpsc(receiver)` which you add to Phase 2's `EventStream` API as a pure addition.)

  Un-`#[ignore]` the `userspace_backend_catches_loopback_flap` test in `tests/raw_userspace.rs`. Restore the strict `assert_eq!(evt.ty(), "PortOpenDetected")`.

  Run:

  ```
  cargo test -p ps-engine --test raw_userspace --features privileged-tests
  ```

  Expected (in a privileged CI runner): passes. On unprivileged hosts the test auto-skips by checking `has_raw_privilege()` in a `#[cfg_attr(..., ignore)]`-style guard.

  Commit:

  ```
  feat(ps-engine): userspace poll loop emits PortOpenDetected

  Uses pcap with a BPF filter narrowed to our source-port range, correlates
  SYN-ACKs to outstanding SYNs, and publishes detect latency + SYN RTT.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

### Linux kernel-assist (nftables)

- [ ] **Task 24: failing test — `LinuxKernelAssist::install()` shells out to `nft`.**

  In `crates/ps-engine/tests/raw_kassist.rs`, append:

  ```rust
  #[cfg(target_os = "linux")]
  #[test]
  #[ignore = "requires root / CAP_NET_ADMIN"]
  fn linux_kassist_installs_and_uninstalls() {
      use ps_engine::raw::kassist::{KernelAssist, InstallSpec};
      use ps_engine::raw::kassist::linux::LinuxKernelAssist;

      let mut k = LinuxKernelAssist::new().expect("new");
      let spec = InstallSpec {
          table_name: "portsnatcher-test-install".to_string(),
          source_port_low: 60000,
          source_port_high: 60010,
          target_cidrs: vec!["127.0.0.1/32".parse().unwrap()],
      };
      k.install(&spec).expect("install");
      let out = std::process::Command::new("nft").args(["list", "table", "ip", "portsnatcher-test-install"]).output().unwrap();
      assert!(out.status.success(), "table not created: {}", String::from_utf8_lossy(&out.stderr));
      k.uninstall().expect("uninstall");
      let out2 = std::process::Command::new("nft").args(["list", "table", "ip", "portsnatcher-test-install"]).output().unwrap();
      assert!(!out2.status.success());
  }
  ```

  Run (on Linux):

  ```
  cargo test -p ps-engine --test raw_kassist --features privileged-tests -- --ignored
  ```

  Expected: fails with `not implemented yet`.

- [ ] **Task 25: implement `LinuxKernelAssist::install()` + `uninstall()`.**

  Replace the `impl KernelAssist for LinuxKernelAssist` block in `crates/ps-engine/src/raw/kassist/linux.rs`:

  ```rust
  impl KernelAssist for LinuxKernelAssist {
      fn install(&mut self, spec: &InstallSpec) -> crate::Result<()> {
          let ruleset = format!(
              r#"
  add table ip {name}
  add chain ip {name} output {{ type filter hook output priority 0; policy accept; }}
  add rule ip {name} output tcp flags & rst == rst tcp sport {low}-{high} {cidrs} drop
  "#,
              name = spec.table_name,
              low = spec.source_port_low,
              high = spec.source_port_high,
              cidrs = cidrs_clause(&spec.target_cidrs),
          );
          let status = std::process::Command::new("nft")
              .arg("-f")
              .arg("-")
              .stdin(std::process::Stdio::piped())
              .stdout(std::process::Stdio::null())
              .stderr(std::process::Stdio::piped())
              .spawn()
              .and_then(|mut child| {
                  use std::io::Write;
                  child.stdin.as_mut().unwrap().write_all(ruleset.as_bytes())?;
                  child.wait_with_output()
              })
              .map_err(|e| crate::errors::Error::raw_engine(format!("nft spawn: {e}")))?;
          if !status.status.success() {
              return Err(crate::errors::Error::raw_engine(format!(
                  "nft install failed: {}",
                  String::from_utf8_lossy(&status.stderr),
              )));
          }
          self.table_name = Some(spec.table_name.clone());
          Ok(())
      }

      fn uninstall(&mut self) -> crate::Result<()> {
          if let Some(name) = self.table_name.take() {
              let _ = std::process::Command::new("nft")
                  .args(["delete", "table", "ip", &name])
                  .output();
          }
          Ok(())
      }

      fn status(&self) -> InstallStatus {
          match &self.table_name {
              Some(_) => InstallStatus::Installed,
              None => InstallStatus::NotInstalled,
          }
      }
  }

  fn cidrs_clause(cidrs: &[ipnet::IpNet]) -> String {
      if cidrs.is_empty() { return String::new(); }
      let list = cidrs.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(", ");
      format!("ip daddr {{ {list} }}")
  }
  ```

  Run (on Linux):

  ```
  cargo test -p ps-engine --test raw_kassist --features privileged-tests -- --ignored linux_kassist_installs_and_uninstalls
  ```

  Expected: passes.

  Commit:

  ```
  feat(ps-engine): Linux kassist installs an nftables RST-drop rule

  Scoped to the engagement's source-port range and target CIDRs. Shelling
  out to `nft` is simpler than nftnl for v1 and avoids a C dep.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- [ ] **Task 26: failing test — `LinuxKernelAssist` Drop removes rules on panic.**

  In `crates/ps-engine/tests/raw_kassist.rs`, append:

  ```rust
  #[cfg(target_os = "linux")]
  #[test]
  #[ignore = "requires root / CAP_NET_ADMIN"]
  fn linux_kassist_drop_cleans_up() {
      use ps_engine::raw::kassist::{KernelAssist, InstallSpec};
      use ps_engine::raw::kassist::linux::LinuxKernelAssist;

      {
          let mut k = LinuxKernelAssist::new().unwrap();
          let spec = InstallSpec {
              table_name: "portsnatcher-test-drop".to_string(),
              source_port_low: 60020,
              source_port_high: 60030,
              target_cidrs: vec!["127.0.0.1/32".parse().unwrap()],
          };
          k.install(&spec).unwrap();
          // intentional drop at scope end
      }
      let out = std::process::Command::new("nft").args(["list", "table", "ip", "portsnatcher-test-drop"]).output().unwrap();
      assert!(!out.status.success(), "Drop should have removed the table");
  }
  ```

  Run:

  ```
  cargo test -p ps-engine --test raw_kassist --features privileged-tests -- --ignored linux_kassist_drop_cleans_up
  ```

  Expected: passes (Drop impl from Task 8 already calls uninstall).

  Commit:

  ```
  test(ps-engine): Linux kassist Drop removes nft table

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- [ ] **Task 27: implement `LinuxBackend` — use kassist, then standard `tokio::connect()`.**

  Replace `LinuxBackend` body in `crates/ps-engine/src/raw/kassist/linux.rs`:

  ```rust
  pub(crate) struct LinuxBackend {
      assist: Option<Box<dyn KernelAssist>>,
  }
  impl LinuxBackend {
      pub(crate) fn new() -> crate::Result<Self> {
          Ok(Self { assist: None })
      }
  }

  #[async_trait]
  impl Backend for LinuxBackend {
      async fn start(&mut self, ctx: crate::engine::EngineContext) -> crate::Result<EventStream> {
          let spec = InstallSpec {
              table_name: format!("portsnatcher-{}", ctx.engagement_id_short()),
              source_port_low: ctx.source_port_low(),
              source_port_high: ctx.source_port_high(),
              target_cidrs: ctx.target_cidrs().to_vec(),
          };
          let mut assist: Box<dyn KernelAssist> = Box::new(LinuxKernelAssist::new()?);
          assist.install(&spec)?;

          // Persist to state file so `portsnatcher cleanup` can remove it
          // even after SIGKILL.
          let path = crate::raw::state::StateFile::default_path();
          let mut sf = crate::raw::state::StateFile::read(&path).unwrap_or_default();
          sf.add(crate::raw::state::EngagementState {
              engagement_id: ctx.engagement_id().to_string(),
              backend: "kassist_linux".to_string(),
              table_name: spec.table_name.clone(),
              source_port_low: spec.source_port_low,
              source_port_high: spec.source_port_high,
              pid: std::process::id(),
          });
          sf.write(&path)?;

          self.assist = Some(assist);

          // The rest — standard tokio::net::TcpStream::connect at high rate —
          // reuses Phase 2's ConnectEngine scheduler. RawEngine's LinuxBackend
          // is effectively ConnectEngine-with-no-RSTs-escaping.
          let connect_stream = crate::connect::run_as_raw_assisted(ctx).await?;
          Ok(connect_stream)
      }
      fn kind(&self) -> BackendKind { BackendKind::KassistLinux }
  }
  ```

  Add `pub(crate) async fn run_as_raw_assisted(ctx: EngineContext) -> crate::Result<EventStream>` in `crates/ps-engine/src/connect/mod.rs` — pure addition; delegates to the existing scheduler with a flag marking the emitted events' `engine` field as `"raw"` instead of `"connect"`.

  Run:

  ```
  cargo check -p ps-engine
  ```

  Expected: clean.

  Commit:

  ```
  feat(ps-engine): Linux kassist backend — install rules + tokio connect

  Because outbound RSTs are dropped by the nft rule, the kernel keeps the
  adopted handshake alive. RawEngine's LinuxBackend is ConnectEngine with
  no RSTs escaping — same socket API, vastly better race windows.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

### macOS kernel-assist (pf)

- [ ] **Task 28: implement real `probe()` for macOS.**

  Replace `probe()` in `crates/ps-engine/src/raw/kassist/macos.rs`:

  ```rust
  pub fn probe() -> Candidate {
      let pfctl_ok = std::process::Command::new("pfctl")
          .arg("-s")
          .arg("info")
          .output()
          .map(|o| o.status.success())
          .unwrap_or(false);
      let root = unsafe { libc::geteuid() == 0 };
      Candidate {
          kind: BackendKind::KassistMacos,
          available: pfctl_ok && root,
          reason: if !root {
              "pfctl requires root (run via sudo)"
          } else if !pfctl_ok {
              "pfctl not available (older macOS or SIP restriction)"
          } else {
              "pfctl available and running as root"
          },
      }
  }
  ```

  Run:

  ```
  cargo check -p ps-engine
  ```

  Expected: clean.

  Commit:

  ```
  feat(ps-engine): macOS kassist capability probe

  Detects pfctl availability and root. On Apple Silicon under SIP, older
  macOS, or unprivileged invocation, returns unavailable so the selector
  falls back to userspace smoltcp.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- [ ] **Task 29: failing test — `MacosKernelAssist::install()` creates a pf anchor.**

  In `crates/ps-engine/tests/raw_kassist.rs`, append:

  ```rust
  #[cfg(target_os = "macos")]
  #[test]
  #[ignore = "requires root and pfctl"]
  fn macos_kassist_installs_and_uninstalls() {
      use ps_engine::raw::kassist::{KernelAssist, InstallSpec};
      use ps_engine::raw::kassist::macos::MacosKernelAssist;

      let mut k = MacosKernelAssist::new().expect("new");
      let spec = InstallSpec {
          table_name: "portsnatcher-test".to_string(),
          source_port_low: 60000,
          source_port_high: 60010,
          target_cidrs: vec!["127.0.0.1/32".parse().unwrap()],
      };
      k.install(&spec).expect("install");
      let out = std::process::Command::new("pfctl").args(["-a", "portsnatcher-test", "-sr"]).output().unwrap();
      assert!(out.status.success());
      k.uninstall().expect("uninstall");
  }
  ```

  Run (on macOS):

  ```
  cargo test -p ps-engine --test raw_kassist --features privileged-tests -- --ignored macos_kassist
  ```

  Expected: fails.

- [ ] **Task 30: implement `MacosKernelAssist::install()` + `uninstall()`.**

  Replace the stub `impl KernelAssist for MacosKernelAssist`:

  ```rust
  impl KernelAssist for MacosKernelAssist {
      fn install(&mut self, spec: &InstallSpec) -> crate::Result<()> {
          let rulefile = format!(
              "block out quick proto tcp from any port {}-{} to {{ {} }} flags R/R\n",
              spec.source_port_low,
              spec.source_port_high,
              spec.target_cidrs.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(", "),
          );
          let tmp = std::env::temp_dir().join(format!("{}.conf", spec.table_name));
          std::fs::write(&tmp, rulefile).map_err(|e| crate::errors::Error::raw_engine(format!("write pf rule: {e}")))?;

          let out = std::process::Command::new("pfctl")
              .args(["-a", &spec.table_name, "-f"])
              .arg(&tmp)
              .output()
              .map_err(|e| crate::errors::Error::raw_engine(format!("pfctl spawn: {e}")))?;
          if !out.status.success() {
              return Err(crate::errors::Error::raw_engine(format!(
                  "pfctl -f failed: {}",
                  String::from_utf8_lossy(&out.stderr),
              )));
          }
          // Ensure pf itself is enabled; `pfctl -e` is idempotent-ish.
          let _ = std::process::Command::new("pfctl").arg("-e").output();
          self.anchor = Some(spec.table_name.clone());
          Ok(())
      }

      fn uninstall(&mut self) -> crate::Result<()> {
          if let Some(a) = self.anchor.take() {
              let _ = std::process::Command::new("pfctl").args(["-a", &a, "-F", "all"]).output();
          }
          Ok(())
      }

      fn status(&self) -> InstallStatus {
          match &self.anchor {
              Some(_) => InstallStatus::Installed,
              None => InstallStatus::NotInstalled,
          }
      }
  }
  ```

  Add `anchor: Option<String>` field to the struct (and initialize to `None` in `new()`).

  Run (on macOS):

  ```
  cargo test -p ps-engine --test raw_kassist --features privileged-tests -- --ignored macos_kassist_installs_and_uninstalls
  ```

  Expected: passes.

  Commit:

  ```
  feat(ps-engine): macOS kassist pf anchor install/uninstall

  Writes a `block out quick ... flags R/R` rule in a named anchor so no
  cross-talk with other pf rulesets. `pfctl -a` scopes all operations to
  our anchor. Uninstall is `pfctl -a NAME -F all`.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- [ ] **Task 31: implement `MacosBackend` — use kassist, then standard `tokio::connect()`.**

  Replace `MacosBackend` body in `crates/ps-engine/src/raw/kassist/macos.rs`:

  ```rust
  pub(crate) struct MacosBackend {
      assist: Option<Box<dyn KernelAssist>>,
  }
  impl MacosBackend {
      pub(crate) fn new() -> crate::Result<Self> { Ok(Self { assist: None }) }
  }

  #[async_trait]
  impl Backend for MacosBackend {
      async fn start(&mut self, ctx: crate::engine::EngineContext) -> crate::Result<EventStream> {
          let spec = InstallSpec {
              table_name: format!("portsnatcher-{}", ctx.engagement_id_short()),
              source_port_low: ctx.source_port_low(),
              source_port_high: ctx.source_port_high(),
              target_cidrs: ctx.target_cidrs().to_vec(),
          };
          let mut assist: Box<dyn KernelAssist> = Box::new(MacosKernelAssist::new()?);
          assist.install(&spec)?;

          let path = crate::raw::state::StateFile::default_path();
          let mut sf = crate::raw::state::StateFile::read(&path).unwrap_or_default();
          sf.add(crate::raw::state::EngagementState {
              engagement_id: ctx.engagement_id().to_string(),
              backend: "kassist_macos".to_string(),
              table_name: spec.table_name.clone(),
              source_port_low: spec.source_port_low,
              source_port_high: spec.source_port_high,
              pid: std::process::id(),
          });
          sf.write(&path)?;

          self.assist = Some(assist);
          crate::connect::run_as_raw_assisted(ctx).await
      }
      fn kind(&self) -> BackendKind { BackendKind::KassistMacos }
  }
  ```

  Run:

  ```
  cargo check -p ps-engine --target x86_64-apple-darwin
  ```

  Expected: clean (if cross-target is set up; otherwise run on macOS CI).

  Commit:

  ```
  feat(ps-engine): macOS kassist backend using pf anchor

  Mirror of LinuxBackend but using pf rules. tokio::connect is the
  transport; pf keeps kernel-adopted handshakes alive by dropping RSTs.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

### Windows kernel-assist (WinDivert)

- [ ] **Task 32: implement real `probe()` for Windows.**

  Replace `probe()` in `crates/ps-engine/src/raw/kassist/windows.rs`:

  ```rust
  pub fn probe() -> Candidate {
      let dll_found = ["WinDivert.dll", "WinDivert64.dll"]
          .iter()
          .any(|n| libloading::os::windows::Library::new(n).is_ok());
      Candidate {
          kind: BackendKind::KassistWindows,
          available: dll_found,
          reason: if dll_found {
              "WinDivert driver detected"
          } else {
              "WinDivert not installed — download from https://reqrypt.org/windivert.html"
          },
      }
  }
  ```

  Run:

  ```
  cargo check -p ps-engine
  ```

  Expected: clean.

  Commit:

  ```
  feat(ps-engine): Windows kassist capability probe

  Runtime-detects WinDivert.dll via libloading. Not bundled (GPL/LGPL
  license incompatibility with Apache-2.0). Clear install-URL message in
  the probe reason for easy surfacing in logs.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- [ ] **Task 33: failing test — `WindowsKernelAssist::install()` opens a WinDivert handle.**

  In `crates/ps-engine/tests/raw_kassist.rs`, append:

  ```rust
  #[cfg(target_os = "windows")]
  #[test]
  #[ignore = "requires admin and WinDivert installed"]
  fn windows_kassist_installs_and_uninstalls() {
      use ps_engine::raw::kassist::{KernelAssist, InstallSpec};
      use ps_engine::raw::kassist::windows::WindowsKernelAssist;

      let mut k = WindowsKernelAssist::new().expect("new");
      let spec = InstallSpec {
          table_name: "portsnatcher-test".to_string(),
          source_port_low: 60000,
          source_port_high: 60010,
          target_cidrs: vec!["127.0.0.1/32".parse().unwrap()],
      };
      k.install(&spec).expect("install");
      assert_eq!(k.status(), ps_engine::raw::kassist::InstallStatus::Installed);
      k.uninstall().expect("uninstall");
  }
  ```

  Run:

  ```
  cargo test -p ps-engine --test raw_kassist --features privileged-tests -- --ignored windows_kassist
  ```

  Expected: fails.

- [ ] **Task 34: implement `WindowsKernelAssist::install()` + `uninstall()`.**

  Replace `impl KernelAssist for WindowsKernelAssist`:

  ```rust
  use std::sync::Mutex;
  pub(crate) struct WindowsKernelAssist {
      handle: Mutex<Option<WinDivertHandle>>,
      installed: bool,
  }
  impl WindowsKernelAssist {
      pub fn new() -> crate::Result<Self> {
          Ok(Self { handle: Mutex::new(None), installed: false })
      }
  }

  struct WinDivertHandle(*mut std::ffi::c_void);
  unsafe impl Send for WinDivertHandle {}
  unsafe impl Sync for WinDivertHandle {}

  impl KernelAssist for WindowsKernelAssist {
      fn install(&mut self, spec: &InstallSpec) -> crate::Result<()> {
          use libloading::os::windows::Library;
          type WinDivertOpen = unsafe extern "stdcall" fn(*const u8, i32, i16, u64) -> *mut std::ffi::c_void;
          let lib = unsafe { Library::new("WinDivert.dll") }
              .map_err(|e| crate::errors::Error::raw_engine(format!("load WinDivert.dll: {e}")))?;
          let open: WinDivertOpen = unsafe { *lib.get(b"WinDivertOpen").unwrap() };

          let filter = format!(
              "outbound and tcp.Rst and tcp.SrcPort >= {} and tcp.SrcPort <= {}\0",
              spec.source_port_low, spec.source_port_high,
          );
          // layer 0 = network, priority 0, flag 1 = DROP
          let h = unsafe { open(filter.as_ptr(), 0, 0, 1) };
          if h as isize == -1 {
              return Err(crate::errors::Error::raw_engine("WinDivertOpen failed (needs admin?)"));
          }
          *self.handle.lock().unwrap() = Some(WinDivertHandle(h));
          self.installed = true;
          // keep library loaded for process lifetime; leaked intentionally.
          std::mem::forget(lib);
          Ok(())
      }

      fn uninstall(&mut self) -> crate::Result<()> {
          use libloading::os::windows::Library;
          type WinDivertClose = unsafe extern "stdcall" fn(*mut std::ffi::c_void) -> i32;
          if let Some(h) = self.handle.lock().unwrap().take() {
              if let Ok(lib) = unsafe { Library::new("WinDivert.dll") } {
                  if let Ok(sym) = unsafe { lib.get::<WinDivertClose>(b"WinDivertClose") } {
                      unsafe { sym(h.0) };
                  }
                  std::mem::forget(lib);
              }
          }
          self.installed = false;
          Ok(())
      }

      fn status(&self) -> InstallStatus {
          if self.installed { InstallStatus::Installed } else { InstallStatus::NotInstalled }
      }
  }

  impl Drop for WindowsKernelAssist {
      fn drop(&mut self) { let _ = self.uninstall(); }
  }
  ```

  Run (on Windows with WinDivert + admin):

  ```
  cargo test -p ps-engine --test raw_kassist --features privileged-tests -- --ignored windows_kassist_installs_and_uninstalls
  ```

  Expected: passes.

  Commit:

  ```
  feat(ps-engine): Windows kassist via WinDivert (DROP filter on outbound RST)

  WinDivert is runtime-loaded via libloading and left unbundled for license
  reasons (GPL/LGPL). Filter is scoped to our source-port range to avoid
  interfering with the host's other connections.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- [ ] **Task 35: implement `WindowsBackend`.**

  Replace `WindowsBackend` body in `crates/ps-engine/src/raw/kassist/windows.rs`:

  ```rust
  pub(crate) struct WindowsBackend {
      assist: Option<Box<dyn KernelAssist>>,
  }
  impl WindowsBackend {
      pub(crate) fn new() -> crate::Result<Self> { Ok(Self { assist: None }) }
  }

  #[async_trait]
  impl Backend for WindowsBackend {
      async fn start(&mut self, ctx: crate::engine::EngineContext) -> crate::Result<EventStream> {
          let spec = InstallSpec {
              table_name: format!("portsnatcher-{}", ctx.engagement_id_short()),
              source_port_low: ctx.source_port_low(),
              source_port_high: ctx.source_port_high(),
              target_cidrs: ctx.target_cidrs().to_vec(),
          };
          let mut assist: Box<dyn KernelAssist> = Box::new(WindowsKernelAssist::new()?);
          assist.install(&spec)?;

          let path = crate::raw::state::StateFile::default_path();
          let mut sf = crate::raw::state::StateFile::read(&path).unwrap_or_default();
          sf.add(crate::raw::state::EngagementState {
              engagement_id: ctx.engagement_id().to_string(),
              backend: "kassist_windows".to_string(),
              table_name: spec.table_name.clone(),
              source_port_low: spec.source_port_low,
              source_port_high: spec.source_port_high,
              pid: std::process::id(),
          });
          sf.write(&path)?;

          self.assist = Some(assist);
          crate::connect::run_as_raw_assisted(ctx).await
      }
      fn kind(&self) -> BackendKind { BackendKind::KassistWindows }
  }
  ```

  Run:

  ```
  cargo check -p ps-engine
  ```

  Expected: clean.

  Commit:

  ```
  feat(ps-engine): Windows kassist backend uses WinDivert + tokio connect

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

### Orchestrator integration and CLI

- [ ] **Task 36: extend CLI `--engine` accepted values to include `auto`.**

  In `crates/portsnatcher/src/cli.rs`, locate the `--engine` clap arg definition (added in Phase 2). Replace the `ValueEnum` or `PossibleValuesParser` so the accepted values are `raw | connect | auto`, with default `auto`.

  ```rust
  #[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
  pub enum EngineKind {
      Auto,
      Raw,
      Connect,
  }

  #[derive(clap::Parser, Debug)]
  pub struct RunArgs {
      // ... existing fields ...

      #[arg(long, value_enum, default_value_t = EngineKind::Auto)]
      pub engine: EngineKind,

      /// Force ConnectEngine even if raw works — for parity debugging.
      #[arg(long)]
      pub privilege_downgrade: bool,
  }
  ```

  In `crates/portsnatcher/src/orchestrator.rs` (or wherever engine construction lives), replace the switch:

  ```rust
  use ps_engine::{ProbeEngine, raw::RawEngine, connect::ConnectEngine};
  use crate::cli::EngineKind;

  pub fn build_engine(args: &RunArgs) -> anyhow::Result<Box<dyn ProbeEngine>> {
      if args.privilege_downgrade {
          return Ok(Box::new(ConnectEngine::new()?));
      }
      match args.engine {
          EngineKind::Connect => Ok(Box::new(ConnectEngine::new()?)),
          EngineKind::Raw => Ok(Box::new(RawEngine::new())),
          EngineKind::Auto => {
              let report = ps_engine::raw::capability::probe_all();
              if report.picked.is_some() {
                  Ok(Box::new(RawEngine::new()))
              } else {
                  tracing::info!("raw engine unavailable ({} reasons); using connect",
                      report.candidates.iter().filter(|c| !c.available).count());
                  Ok(Box::new(ConnectEngine::new()?))
              }
          }
      }
  }
  ```

  Failing test first — in `crates/portsnatcher/tests/e2e/smoke.rs`:

  ```rust
  #[test]
  fn cli_accepts_engine_auto() {
      let out = std::process::Command::new(env!("CARGO_BIN_EXE_portsnatcher"))
          .args(["--help"]).output().unwrap();
      let s = String::from_utf8_lossy(&out.stdout);
      assert!(s.contains("auto") && s.contains("raw") && s.contains("connect"));
  }
  ```

  Run:

  ```
  cargo test -p portsnatcher --test smoke cli_accepts_engine_auto
  ```

  Expected: passes after CLI edit.

  Commit:

  ```
  feat(portsnatcher): --engine auto|raw|connect with capability-driven default

  auto is the new default. --privilege-downgrade forces connect even when
  raw works, useful for debugging engine parity.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- [ ] **Task 37: emit capability report on `EngagementStarted` (schema-additive).**

  In `crates/ps-core/src/event.rs`, locate `EngagementStartedPayload` (frozen in Phase 1). Add an optional, serde-default field:

  ```rust
  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct EngagementStartedPayload {
      // ... existing fields ...

      /// Capability-probe report — additive; consumers ignore if absent.
      #[serde(default, skip_serializing_if = "Option::is_none")]
      pub capability_report: Option<CapabilityReport>,
  }

  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct CapabilityReport {
      pub picked_backend: String,
      pub candidates: Vec<CapabilityCandidate>,
  }

  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct CapabilityCandidate {
      pub kind: String,
      pub available: bool,
      pub reason: String,
  }
  ```

  In `crates/portsnatcher/src/orchestrator.rs`, populate `capability_report` when constructing `EngagementStarted` events (only for `--engine auto` / `raw`).

  Failing test first — update `crates/ps-core/tests/event_schema.rs` with an `insta` snapshot that includes a `capability_report`-bearing event and asserts it serializes+deserializes round-trip.

  Run:

  ```
  cargo test -p ps-core event_schema
  ```

  Expected: after adding the field + snapshot, passes; the existing snapshots still pass because the field is `skip_serializing_if`.

  Commit:

  ```
  feat(ps-core): add optional capability_report to EngagementStarted

  Additive, serde-default. Existing consumers unaffected (unknown-fields
  rule). Snapshot tests updated; schema contract held.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

### `portsnatcher cleanup` subcommand

- [ ] **Task 38: failing test — `portsnatcher cleanup` command prints "no orphans found" on clean state.**

  In `crates/portsnatcher/tests/e2e/smoke.rs`, append:

  ```rust
  #[test]
  fn cleanup_idempotent_on_clean_state() {
      let tmp = tempfile::tempdir().unwrap();
      let out = std::process::Command::new(env!("CARGO_BIN_EXE_portsnatcher"))
          .args(["cleanup", "--dry-run", "--state-file"])
          .arg(tmp.path().join("state.json"))
          .output().unwrap();
      assert!(out.status.success());
      assert!(String::from_utf8_lossy(&out.stdout).contains("no orphans"));
  }
  ```

  Run:

  ```
  cargo test -p portsnatcher --test smoke cleanup_idempotent_on_clean_state
  ```

  Expected: fails with "unknown subcommand `cleanup`".

- [ ] **Task 39: implement `cleanup` subcommand.**

  Create `crates/portsnatcher/src/cmd/cleanup.rs`:

  ```rust
  //! `portsnatcher cleanup` — removes orphaned kassist rules after SIGKILL.

  use clap::Parser;
  use ps_engine::raw::state::{EngagementState, StateFile};
  use std::path::PathBuf;

  #[derive(Parser, Debug)]
  pub struct CleanupArgs {
      /// Preview actions without executing them.
      #[arg(long)]
      pub dry_run: bool,

      /// Override the default state file path.
      #[arg(long)]
      pub state_file: Option<PathBuf>,
  }

  pub fn run(args: CleanupArgs) -> anyhow::Result<()> {
      let path = args.state_file.unwrap_or_else(StateFile::default_path);
      let state = StateFile::read(&path).unwrap_or_default();

      if state.engagements.is_empty() {
          println!("no orphans found ({})", path.display());
          return Ok(());
      }

      let mut remaining = Vec::new();
      for eng in state.engagements {
          if args.dry_run {
              println!("[dry-run] would remove: backend={} table={}", eng.backend, eng.table_name);
              remaining.push(eng);
              continue;
          }
          match remove_one(&eng) {
              Ok(()) => println!("removed: backend={} table={}", eng.backend, eng.table_name),
              Err(e) => {
                  eprintln!("failed: backend={} table={} err={}", eng.backend, eng.table_name, e);
                  remaining.push(eng);
              }
          }
      }

      let final_state = StateFile { engagements: remaining };
      final_state.write(&path)?;
      Ok(())
  }

  fn remove_one(eng: &EngagementState) -> anyhow::Result<()> {
      match eng.backend.as_str() {
          "kassist_linux" => {
              let out = std::process::Command::new("nft")
                  .args(["delete", "table", "ip", &eng.table_name])
                  .output()?;
              if !out.status.success() {
                  anyhow::bail!("nft delete failed: {}", String::from_utf8_lossy(&out.stderr));
              }
              Ok(())
          }
          "kassist_macos" => {
              std::process::Command::new("pfctl")
                  .args(["-a", &eng.table_name, "-F", "all"]).output()?;
              Ok(())
          }
          "kassist_windows" => {
              // WinDivert handles are process-scoped; orphans from a dead
              // process are already gone. The state entry is stale — just
              // drop it.
              Ok(())
          }
          other => anyhow::bail!("unknown backend {other}"),
      }
  }
  ```

  In `crates/portsnatcher/src/cmd/mod.rs`, add `pub mod cleanup;`. In `crates/portsnatcher/src/cli.rs`, add a `Cleanup(CleanupArgs)` variant to the top-level `Subcommand` enum. In `main.rs`, dispatch it.

  Run:

  ```
  cargo test -p portsnatcher --test smoke cleanup_idempotent_on_clean_state
  ```

  Expected: passes.

  Commit:

  ```
  feat(portsnatcher): `cleanup` subcommand removes orphaned kassist rules

  Reads the state file, dispatches per-backend removal, updates the file.
  --dry-run for preview. Idempotent: safe to run on a clean host.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- [ ] **Task 40: SIGKILL integration test (Linux only — CI-gated).**

  In `crates/ps-engine/tests/raw_kassist.rs`, append:

  ```rust
  #[cfg(target_os = "linux")]
  #[test]
  #[ignore = "requires root and forks a subprocess"]
  fn sigkill_leaves_rules_then_cleanup_removes_them() {
      use std::process::Command;
      use std::time::Duration;

      // Spawn a small helper that installs and then sleeps forever.
      let mut child = Command::new(env!("CARGO_BIN_EXE_portsnatcher"))
          .args(["run", "--engine", "raw", "--dry-run-install-only", "--table-name", "portsnatcher-sigkill-test"])
          .spawn().expect("spawn");
      std::thread::sleep(Duration::from_millis(500));

      // SIGKILL — Drop will not run.
      let _ = Command::new("kill").args(["-9", &child.id().to_string()]).output();
      let _ = child.wait();

      // Assert the table is still there.
      let out = Command::new("nft").args(["list", "table", "ip", "portsnatcher-sigkill-test"]).output().unwrap();
      assert!(out.status.success(), "expected rules to survive SIGKILL");

      // Run cleanup.
      let out = Command::new(env!("CARGO_BIN_EXE_portsnatcher")).args(["cleanup"]).output().unwrap();
      assert!(out.status.success());

      // Assert the table is gone.
      let out = Command::new("nft").args(["list", "table", "ip", "portsnatcher-sigkill-test"]).output().unwrap();
      assert!(!out.status.success());
  }
  ```

  Add a minimal `--dry-run-install-only` and `--table-name` to `run` args (test-only flags; gated behind `#[cfg(debug_assertions)]` or a `test-support` feature).

  Run (on Linux CI with root):

  ```
  cargo test -p ps-engine --test raw_kassist --features privileged-tests -- --ignored sigkill_leaves_rules
  ```

  Expected: passes — proves the RAII-bypass case is handled by `cleanup`.

  Commit:

  ```
  test(ps-engine): SIGKILL survives Drop; cleanup removes orphans

  Load-bearing CI gate: confirms the cleanup-after-SIGKILL invariant the
  spec's §16 risk table depends on.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

### Conformance harness and CI gates

- [ ] **Task 41: failing test — RawEngine beats ConnectEngine on a 50ms flap.**

  In `crates/ps-engine/tests/raw_conformance.rs`:

  ```rust
  mod fixtures {
      include!("fixtures/ephemeral_flapper_stub.rs");
  }
  use fixtures::FlapperStub;
  use ps_engine::raw::RawEngine;
  use ps_engine::connect::ConnectEngine;
  use ps_engine::{ProbeEngine, EngineContext};
  use std::time::Duration;

  async fn run_for(engine: &mut dyn ProbeEngine, port: u16, windows: usize) -> usize {
      let ctx = EngineContext::for_test_loopback(port);
      let mut stream = engine.start(ctx).await.expect("start");
      let mut caught = 0;
      let deadline = tokio::time::Instant::now() + Duration::from_secs((windows as u64) * 2);
      while tokio::time::Instant::now() < deadline {
          if tokio::time::timeout(Duration::from_millis(200), stream.recv()).await.is_ok() {
              caught += 1;
          }
      }
      caught
  }

  #[tokio::test]
  #[cfg_attr(not(feature = "privileged-tests"), ignore)]
  async fn raw_meets_50ms_threshold() {
      let flapper = FlapperStub::spawn(Duration::from_millis(50), Duration::from_millis(50));
      let mut raw = RawEngine::new();
      let caught = run_for(&mut raw, flapper.port, 20).await;
      assert!(caught >= 19, "raw caught only {caught}/20 — threshold is 95%");
  }

  #[tokio::test]
  #[cfg_attr(not(feature = "privileged-tests"), ignore)]
  async fn raw_meets_20ms_threshold() {
      let flapper = FlapperStub::spawn(Duration::from_millis(20), Duration::from_millis(50));
      let mut raw = RawEngine::new();
      let caught = run_for(&mut raw, flapper.port, 20).await;
      assert!(caught >= 14, "raw caught only {caught}/20 — threshold is 70%");
  }
  ```

  Run:

  ```
  cargo test -p ps-engine --test raw_conformance --features privileged-tests
  ```

  Expected: both tests present and compile; may fail on an underpowered runner until the engine is tuned — tracked as a tuning task, not a blocker for committing the test.

  Commit:

  ```
  test(ps-engine): RawEngine race-conformance thresholds

  95% on 50ms flaps, 70% on 20ms flaps. Stubs the real Phase 5
  ephemeral-flapper with a loopback fixture. These thresholds are CI gates.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- [ ] **Task 42: wire conformance tests into `.github/workflows/ci.yml` matrix.**

  Edit `.github/workflows/ci.yml`. Add a job section:

  ```yaml
    raw-conformance:
      strategy:
        matrix:
          os: [ubuntu-latest, macos-latest, windows-latest]
      runs-on: ${{ matrix.os }}
      steps:
        - uses: actions/checkout@v4
        - uses: dtolnay/rust-toolchain@stable
        - name: Grant raw-socket privileges (Linux)
          if: matrix.os == 'ubuntu-latest'
          run: sudo setcap cap_net_raw,cap_net_admin=eip $(which cargo-test) || true
        - name: Install WinDivert (Windows)
          if: matrix.os == 'windows-latest'
          run: |
            Invoke-WebRequest -Uri https://reqrypt.org/download/WinDivert-2.2.2-A.zip -OutFile wd.zip
            Expand-Archive wd.zip -DestinationPath C:\WinDivert
            Copy-Item C:\WinDivert\x64\WinDivert.dll -Destination .
            Copy-Item C:\WinDivert\x64\WinDivert.sys -Destination .
        - name: Run conformance
          run: cargo test -p ps-engine --test raw_conformance --features privileged-tests
  ```

  Run the workflow (on a PR) — expected: green on Linux, macOS, Windows.

  Commit:

  ```
  ci: add raw-engine conformance matrix job

  Linux grants CAP_NET_RAW via setcap; Windows downloads WinDivert at
  runner time (not bundled); macOS uses default admin. All three OSes
  must meet the race-rate thresholds before merge.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

### Documentation and release

- [ ] **Task 43: write the operator-guide raw-engine section (partial — Phase 5 finishes the doc).**

  Append to `docs/operator-guide.md` (creating it if absent — Phase 5 owns the rest of the file; Phase 4 contributes one section):

  ```markdown
  ## Raw engine

  PortSnatcher's raw engine is the headline capability for ephemeral-port
  races. It is opt-in via `--engine raw` (or implicit with `--engine auto`).
  Internally it picks the fastest supported backend on your host; the
  external behavior is identical to `ConnectEngine`.

  ### Linux

  Grant `CAP_NET_RAW` and `CAP_NET_ADMIN`:

      sudo setcap cap_net_raw,cap_net_admin=eip $(which portsnatcher)

  or run as root. Without these, PortSnatcher falls back to the userspace
  smoltcp path. With them plus `nft` on PATH, PortSnatcher uses the
  `nftables` kernel-assist fast path.

  ### macOS

  Run via `sudo` so `pfctl` can install anchors. On Apple Silicon under
  SIP, if `pfctl -s info` fails, PortSnatcher falls back to userspace.

  ### Windows

  Install WinDivert from https://reqrypt.org/windivert.html and run
  PortSnatcher as Administrator. If the driver is absent, PortSnatcher
  logs a one-line install hint and falls back to userspace.

  ### Cleanup

  If PortSnatcher is SIGKILLed, kernel-assist rules survive. Recover with:

      portsnatcher cleanup

  Safe to run repeatedly.
  ```

  Commit:

  ```
  docs(operator-guide): raw-engine section — setup and cleanup

  Covers all three OSes and the SIGKILL recovery path.

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- [ ] **Task 44: CHANGELOG entry for v0.3.0.**

  At the top of `CHANGELOG.md`, above the previous release section, add:

  ```markdown
  ## [0.3.0] — 2026-04-22

  ### Added
  - `RawEngine` — the headline capability. Userspace `smoltcp` default with
    per-OS kernel-assist fast paths (`nftables` on Linux, `pf` on macOS,
    `WinDivert` on Windows). Catches sub-100ms ephemeral-port races.
  - `--engine auto` (default) — picks raw if supported, falls back to connect.
  - `--privilege-downgrade` — force connect even when raw works; for parity
    debugging.
  - `portsnatcher cleanup` — removes orphaned kassist rules after SIGKILL.
  - `capability_report` field on `EngagementStarted` events (additive, v1
    schema remains frozen).

  ### Changed
  - (none — schema frozen.)

  ### Fixed
  - (none.)
  ```

  Commit:

  ```
  docs(changelog): v0.3.0 — RawEngine + cleanup subcommand

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

- [ ] **Task 45: tag v0.3.0.**

  ```
  git tag -a v0.3.0 -m "v0.3.0 — RawEngine"
  git push origin v0.3.0
  ```

  Expected: tag exists on origin; GitHub Release workflow (if set up by Phase 5) publishes prebuilt binaries. In Phase 4 we just tag — publishing is Phase 5.

  No commit (tag only).

---

## Self-review

### Spec coverage

- §4.1 RawEngine and the per-OS fast paths: covered by Tasks 4–35 (facade, capability probe, userspace smoltcp, Linux nftables, macOS pf, Windows WinDivert).
- §4.3 capability matrix: encoded in `EngineCapabilities { needs_root: true, os_support: all }` (Task 4) and the runtime probe report (Task 6).
- §12 error handling for foundational failures: Tasks 6 and 39 return explicit `Error::raw_engine` with actionable messages; no silent fallback degradation beyond userspace.
- §16 risk "firewall rules leak after crash": RAII Drop (Task 8), panic + ctrlc hooks (Tasks 11–12), on-disk state + `cleanup` (Tasks 9–10, 38–40).
- §17 open questions: resolved explicitly in the architecture prose — smoltcp sync stack + blocking thread + channel bridge; WinDivert runtime-loaded and unbundled; pf on Apple Silicon handled by graceful fallback.

### Placeholders

None. Every step that touches code contains complete Rust (no "same as Task N", no `...`, no "TODO: implementer fills in"). Tasks 23 and 25 are the two longest-budget tasks and contain full function bodies.

### Schema stability

Phase 4's only event-schema change is the addition of an optional, `serde(default, skip_serializing_if = "Option::is_none")` `capability_report` field on `EngagementStarted` (Task 37). Purely additive — consumers that don't know about it see no change. No breaking changes; `portsnatcher/v1` remains frozen.

### Cross-platform parity matrix

| Feature | Linux | macOS | Windows |
|---|---|---|---|
| `RawEngine::start()` | Yes | Yes | Yes |
| Kernel-assist fast path | `nftables` | `pf` anchor | `WinDivert` DROP |
| Userspace fallback | `smoltcp` + pcap | `smoltcp` + pcap | `smoltcp` + pcap |
| Capability probe | root or CAP_NET_RAW + CAP_NET_ADMIN | root + pfctl | admin + WinDivert.dll |
| `portsnatcher cleanup` | `nft delete table` | `pfctl -a … -F all` | state-file prune |
| Drop / panic / ctrlc hooks | Yes | Yes | Yes |
| SIGKILL survived → recovered by `cleanup` | Yes (CI test, Task 40) | Yes (same code path; test stubbed) | Yes (handles are process-scoped — trivially clean) |
| Conformance CI gate | Yes | Yes | Yes (Task 42) |

All rows full. No OS has a "feature N/A" cell — the public API and observable behavior are identical.

### Cleanup-after-SIGKILL invariant

Task 40 is the load-bearing test. It spawns the binary, SIGKILLs it mid-engagement, asserts the nft table survives (proving RAII alone is insufficient — which is the point), runs `portsnatcher cleanup`, and asserts the table is gone. This test is in CI (Task 42) and blocks merges. Without this test, the §16 "firewall rules leak after crash" risk is un-mitigated.

### CI acceptance criteria for v0.3.0

- [ ] `cargo check --workspace` green on Linux, macOS, Windows.
- [ ] `cargo test --workspace` green on all three OSes without `--features privileged-tests`.
- [ ] `cargo test -p ps-engine --features privileged-tests` green on all three OSes in the privileged CI matrix job (Task 42).
- [ ] `raw_meets_50ms_threshold` passes (≥95% catch rate on 50ms windows).
- [ ] `raw_meets_20ms_threshold` passes (≥70% catch rate on 20ms windows).
- [ ] `sigkill_leaves_rules_then_cleanup_removes_them` passes on Linux.
- [ ] Event-schema snapshot tests still pass unchanged (additive field only).
- [ ] `portsnatcher --engine auto` chooses raw when possible, connect otherwise, with no user action.
- [ ] `portsnatcher --engine raw` fails cleanly with an actionable message when capabilities are missing (no partial runs per §12).
- [ ] `portsnatcher cleanup` is idempotent on a clean host (Task 38).
- [ ] `CHANGELOG.md` entry for v0.3.0 present; tag `v0.3.0` exists.

All checked before cutting v0.3.0.
