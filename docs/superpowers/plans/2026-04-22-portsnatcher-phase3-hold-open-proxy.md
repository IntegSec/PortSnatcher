# Phase 3 — Hold-Open Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn every catch into a live, pentester-attackable local tunnel the moment the port opens. Dumb TCP tunnel by default (protocol-agnostic, pairs with Burp's own upstream TLS), opt-in TLS MITM for HTTPS catches using a reusable on-disk CA with platform-integrated install/uninstall.

**Architecture:** `ps-proxy` crate adds the `HoldOpen` trait and two implementations. The orchestrator subscribes a second consumer to the `ConnectionCaught` stream (the first was the fingerprinter in Phase 2) — fingerprint and hold-open run in parallel so a tunnel is up within a few hundred milliseconds of a catch. On-disk CA managed by `portsnatcher ca` subcommands; uses `rcgen` for issuance, `rustls` for termination.

**Tech Stack:** Adds `rcgen`, `directories`, `x509-parser`; extends `rustls` from Phase 2 (used in both MITM-server and MITM-upstream roles).

**Release target:** v0.2.0.

**Assumes Phase 2 complete:** `ConnectionCaught` stream is live, ProbeLadder produces `FingerprintReport` with `tls_info` and `protocol_guess`, the orchestrator can dispatch multiple consumers of the catch stream.

---

## Design decisions made in this phase (resolving spec §17 open questions)

### CA key algorithm — **decision: ECDSA P-256**

The spec leaves the CA algorithm implicit. Phase 3 pins it to ECDSA P-256 (NIST secp256r1):

- **Faster** handshake and CA signing than RSA-3072 by an order of magnitude on modern CPUs; on a pentester laptop this matters because every MITM leaf is signed on the hot path of a catch.
- **Widely accepted** by every platform trust store PortSnatcher targets: Linux (`update-ca-certificates`), macOS Keychain, and Windows `Cert:\LocalMachine\Root` all accept P-256 roots without friction.
- **Fits TLS 1.3 modernization** — the MITM always terminates as TLS 1.3 only (no downgrade dance), and P-256 pairs with TLS 1.3's AEAD suites without extra cipher-negotiation surface.
- **Leaf ttl is 90 days**, CA ttl is 10 years. Leaves are ephemeral and cached in-memory for the engagement only.

### TLS MITM scope — **decision: TLS 1.3 only**

No TLS 1.2 fallback on the MITM path. Rationale: a pentester running MITM is upgrading confidentiality-of-observation, not impersonating legacy stacks. `rustls` defaults already restrict to TLS 1.3 when only the default cipher suites are enabled, and holding the line simplifies transcript-framing logic.

### `DumbTunnel` heartbeat defaults — **decision: TCP keepalive always, HTTP `OPTIONS` only when fingerprint says HTTP**

TCP `SO_KEEPALIVE` is universally safe and the only layer of keepalive we apply without fingerprint evidence. HTTP `OPTIONS` every 20s is safe per RFC 7231 §4.3.7 (idempotent, no side effects). Any other protocol hits the "nothing" branch so we never accidentally poison an upstream's state.

### CA install CI policy — **decision: never exercise the trust store in CI**

Installing a CA into the system trust store mutates runner state across jobs. Phase 3's integration tests stop at the `rustls::ClientConfig`-trusts-our-CA level — no `update-ca-certificates` / `security` / `Import-Certificate` is invoked in CI. Manual operator testing covers those paths.

---

## Task list

### 3.1 — Crate skeleton and trait contracts

- [ ] **Task 1: Create `ps-proxy` crate manifest and lib entry.**

    **Files:**
    - Create: `crates/ps-proxy/Cargo.toml`
    - Create: `crates/ps-proxy/src/lib.rs`

    - [ ] **Step 1: Write the failing workspace check**

        In the workspace root `Cargo.toml`, add `"crates/ps-proxy"` to the `members` array. Save.

        Run: `cargo check -p ps-proxy`
        Expected: FAIL with `error: could not find Cargo.toml in ...crates/ps-proxy`.

    - [ ] **Step 2: Create the crate manifest**

        Create `crates/ps-proxy/Cargo.toml`:

        ```toml
        [package]
        name = "ps-proxy"
        version = "0.2.0"
        edition = "2021"
        license = "Apache-2.0"
        description = "Hold-open proxy (dumb TCP tunnel + opt-in TLS MITM) for PortSnatcher."
        repository = "https://github.com/IntegSec/PortSnatcher"

        [dependencies]
        ps-core = { path = "../ps-core" }
        tokio = { version = "1", features = ["rt-multi-thread", "net", "macros", "io-util", "sync", "time", "fs"] }
        rustls = "0.23"
        tokio-rustls = "0.26"
        rustls-pemfile = "2"
        webpki-roots = "0.26"
        rcgen = { version = "0.13", features = ["pem", "x509-parser"] }
        x509-parser = "0.16"
        directories = "5"
        thiserror = "1"
        tracing = "0.1"
        async-trait = "0.1"
        serde = { version = "1", features = ["derive"] }
        serde_json = "1"
        hex = "0.4"
        sha2 = "0.10"

        [target.'cfg(unix)'.dependencies]
        nix = { version = "0.29", features = ["fs"] }

        [dev-dependencies]
        tokio = { version = "1", features = ["full"] }
        tempfile = "3"
        hyper = { version = "1", features = ["server", "client", "http1"] }
        hyper-util = { version = "0.1", features = ["tokio"] }
        http-body-util = "0.1"
        bytes = "1"
        ```

    - [ ] **Step 3: Create the library entry point**

        Create `crates/ps-proxy/src/lib.rs`:

        ```rust
        //! PortSnatcher hold-open proxy.
        //!
        //! Exposes the `HoldOpen` trait, the `HoldOpenManager` that owns the
        //! pool of local listener ports, and two backends: `DumbTunnel` (default)
        //! and `TlsMitm` (opt-in for HTTPS catches).

        pub mod hold_open;
        pub mod dumb_tunnel;
        pub mod keepalive;
        pub mod tls_mitm;
        pub mod ca;
        pub mod errors;

        pub use errors::{Error, Result};
        pub use hold_open::{HoldOpen, HoldOpenManager, HoldOpenMode, LocalEndpoint};
        ```

        Also create empty files so `mod` declarations compile:
        - `crates/ps-proxy/src/hold_open.rs` with a single `//! HoldOpen trait and manager.` line
        - `crates/ps-proxy/src/dumb_tunnel.rs` with `//! Dumb TCP tunnel.`
        - `crates/ps-proxy/src/keepalive.rs` with `//! Keepalive heartbeat task.`
        - `crates/ps-proxy/src/tls_mitm.rs` with `//! TLS MITM tunnel.`
        - `crates/ps-proxy/src/errors.rs`:

          ```rust
          //! ps-proxy domain errors.

          use thiserror::Error;

          pub type Result<T> = std::result::Result<T, Error>;

          #[derive(Debug, Error)]
          pub enum Error {
              #[error("io: {0}")]
              Io(#[from] std::io::Error),
              #[error("rustls: {0}")]
              Rustls(#[from] rustls::Error),
              #[error("rcgen: {0}")]
              Rcgen(#[from] rcgen::Error),
              #[error("ca: {0}")]
              Ca(String),
              #[error("no tunnel port available in range {0}")]
              NoTunnelPort(String),
              #[error("{0}")]
              Other(String),
          }
          ```

        Create empty subtree for CA:
        - `crates/ps-proxy/src/ca/mod.rs` with:
          ```rust
          //! CA storage, generation, and platform trust-store integration.

          pub mod storage;
          pub mod generate;
          pub mod trust;
          ```
        - `crates/ps-proxy/src/ca/storage.rs` with `//! XDG-aware CA storage.`
        - `crates/ps-proxy/src/ca/generate.rs` with `//! CA + leaf generation via rcgen.`
        - `crates/ps-proxy/src/ca/trust.rs` with `//! Platform trust-store install/uninstall.`

    - [ ] **Step 4: Run workspace check to verify it compiles**

        Run: `cargo check -p ps-proxy`
        Expected: PASS (clean compile, no warnings).

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/ps-proxy Cargo.toml
        git commit -m "$(cat <<'EOF'
        build(ps-proxy): scaffold crate with rustls + rcgen dependencies

        Phase 3 adds the hold-open proxy. This commit lands the crate skeleton
        with the module tree, error enum, and the dependencies (rustls 0.23,
        rcgen 0.13, directories 5) that subsequent tasks will fill in.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

### 3.2 — `HoldOpen` trait and `HoldOpenManager`

- [ ] **Task 2: Write failing test for the `HoldOpen` trait shape.**

    **Files:**
    - Test: `crates/ps-proxy/tests/hold_open_trait.rs`

    - [ ] **Step 1: Write the failing test**

        Create `crates/ps-proxy/tests/hold_open_trait.rs`:

        ```rust
        //! Type-level test pinning the HoldOpen trait shape.

        use ps_proxy::{HoldOpenMode, LocalEndpoint};

        #[test]
        fn mode_variants_are_dumb_or_tls() {
            let dumb = HoldOpenMode::DumbTunnel;
            let mitm = HoldOpenMode::TlsMitm;
            assert_ne!(dumb, mitm);
        }

        #[test]
        fn local_endpoint_has_required_fields() {
            let ep = LocalEndpoint {
                local_port: 7100,
                mode: HoldOpenMode::DumbTunnel,
                ca_fingerprint: None,
            };
            assert_eq!(ep.local_port, 7100);
            assert_eq!(ep.mode, HoldOpenMode::DumbTunnel);
            assert!(ep.ca_fingerprint.is_none());
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p ps-proxy --test hold_open_trait`
        Expected: FAIL with `unresolved import: ps_proxy::HoldOpenMode`.

    - [ ] **Step 3: Write minimal implementation**

        Replace `crates/ps-proxy/src/hold_open.rs` with:

        ```rust
        //! HoldOpen trait, HoldOpenMode enum, and HoldOpenManager.

        use crate::Result;
        use async_trait::async_trait;
        use ps_core::target::Target;
        use serde::{Deserialize, Serialize};
        use tokio::net::TcpStream;

        /// Which kind of hold-open a catch is wired into.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        pub enum HoldOpenMode {
            DumbTunnel,
            TlsMitm,
        }

        /// What `HoldOpen::establish` returns to the orchestrator.
        #[derive(Debug, Clone)]
        pub struct LocalEndpoint {
            pub local_port: u16,
            pub mode: HoldOpenMode,
            pub ca_fingerprint: Option<String>,
        }

        /// Trait object contract for hold-open backends.
        #[async_trait]
        pub trait HoldOpen: Send + Sync {
            async fn establish(
                &self,
                target: Target,
                upstream: TcpStream,
                mode: HoldOpenMode,
            ) -> Result<LocalEndpoint>;
        }

        /// Placeholder manager — filled in by Task 3.
        pub struct HoldOpenManager;
        ```

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p ps-proxy --test hold_open_trait`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/ps-proxy/src/hold_open.rs crates/ps-proxy/tests/hold_open_trait.rs
        git commit -m "$(cat <<'EOF'
        feat(ps-proxy): define HoldOpen trait, HoldOpenMode, and LocalEndpoint

        Pins the trait shape subsequent tunnels implement. DumbTunnel and
        TlsMitm will both return a LocalEndpoint carrying the assigned tunnel
        port the pentester attaches to.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

- [ ] **Task 3: Write failing test for `HoldOpenManager` port allocation in `tunnel_port_range`.**

    **Files:**
    - Test: `crates/ps-proxy/tests/manager_alloc.rs`

    - [ ] **Step 1: Write the failing test**

        Create `crates/ps-proxy/tests/manager_alloc.rs`:

        ```rust
        //! HoldOpenManager port pool tests.

        use ps_proxy::hold_open::HoldOpenManager;

        #[tokio::test]
        async fn allocates_within_configured_range() {
            let mgr = HoldOpenManager::new(7100..=7104);
            let port_a = mgr.allocate().await.expect("first allocation");
            let port_b = mgr.allocate().await.expect("second allocation");
            assert!((7100..=7104).contains(&port_a));
            assert!((7100..=7104).contains(&port_b));
            assert_ne!(port_a, port_b, "ports must be unique");
        }

        #[tokio::test]
        async fn exhaustion_returns_error() {
            let mgr = HoldOpenManager::new(7100..=7100);
            let _first = mgr.allocate().await.expect("first works");
            let err = mgr.allocate().await.expect_err("second must fail");
            let msg = format!("{err}");
            assert!(msg.contains("no tunnel port"), "got: {msg}");
        }

        #[tokio::test]
        async fn release_returns_port_to_pool() {
            let mgr = HoldOpenManager::new(7100..=7100);
            let port = mgr.allocate().await.expect("first");
            mgr.release(port).await;
            let port_again = mgr.allocate().await.expect("reallocate");
            assert_eq!(port, port_again);
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p ps-proxy --test manager_alloc`
        Expected: FAIL with `no method named 'new'` / `no method named 'allocate'`.

    - [ ] **Step 3: Write minimal implementation**

        Replace the `HoldOpenManager` stub at the bottom of `crates/ps-proxy/src/hold_open.rs` with:

        ```rust
        use std::collections::BTreeSet;
        use std::ops::RangeInclusive;
        use std::sync::Arc;
        use tokio::sync::Mutex;

        /// Owns the pool of local listener ports from `config.holdopen.tunnel_port_range`.
        /// Allocations are unique until released.
        #[derive(Clone)]
        pub struct HoldOpenManager {
            inner: Arc<Mutex<ManagerInner>>,
            range: RangeInclusive<u16>,
        }

        struct ManagerInner {
            free: BTreeSet<u16>,
            used: BTreeSet<u16>,
        }

        impl HoldOpenManager {
            pub fn new(range: RangeInclusive<u16>) -> Self {
                let free: BTreeSet<u16> = range.clone().collect();
                Self {
                    inner: Arc::new(Mutex::new(ManagerInner {
                        free,
                        used: BTreeSet::new(),
                    })),
                    range,
                }
            }

            pub async fn allocate(&self) -> Result<u16> {
                let mut guard = self.inner.lock().await;
                let next = *guard
                    .free
                    .iter()
                    .next()
                    .ok_or_else(|| crate::Error::NoTunnelPort(format!(
                        "{}-{}", self.range.start(), self.range.end()
                    )))?;
                guard.free.remove(&next);
                guard.used.insert(next);
                Ok(next)
            }

            pub async fn release(&self, port: u16) {
                let mut guard = self.inner.lock().await;
                if guard.used.remove(&port) {
                    guard.free.insert(port);
                }
            }
        }
        ```

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p ps-proxy --test manager_alloc`
        Expected: PASS (3 tests).

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/ps-proxy/src/hold_open.rs crates/ps-proxy/tests/manager_alloc.rs
        git commit -m "$(cat <<'EOF'
        feat(ps-proxy): HoldOpenManager with inclusive-range tunnel port pool

        Allocates ports from config.holdopen.tunnel_port_range (default
        7100-7199). Uniqueness per active catch, with release-on-close so a
        long engagement cannot leak ports.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

### 3.3 — `DumbTunnel`: bidirectional byte pipe

- [ ] **Task 4: Write failing integration test for `DumbTunnel` end-to-end byte flow.**

    **Files:**
    - Test: `crates/ps-proxy/tests/dumb_tunnel.rs`

    - [ ] **Step 1: Write the failing test**

        Create `crates/ps-proxy/tests/dumb_tunnel.rs`:

        ```rust
        //! End-to-end DumbTunnel: fixture echo upstream, connect via allocated
        //! tunnel port, assert bidirectional flow + HoldOpenReady/HoldOpenClosed.

        use ps_core::event::{Event, EventPayload};
        use ps_core::target::Target;
        use ps_proxy::dumb_tunnel::DumbTunnel;
        use ps_proxy::hold_open::{HoldOpen, HoldOpenManager, HoldOpenMode};
        use std::net::{IpAddr, Ipv4Addr};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};
        use tokio::sync::mpsc;

        async fn spawn_echo_upstream() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let handle = tokio::spawn(async move {
                while let Ok((mut sock, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 1024];
                        loop {
                            match sock.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if sock.write_all(&buf[..n]).await.is_err() { break; }
                                }
                            }
                        }
                    });
                }
            });
            (addr, handle)
        }

        #[tokio::test]
        async fn bidirectional_echo_through_tunnel() {
            let (upstream_addr, _upstream) = spawn_echo_upstream().await;
            let upstream = TcpStream::connect(upstream_addr).await.unwrap();

            let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
            let mgr = HoldOpenManager::new(17100..=17199);
            let tunnel = DumbTunnel::new(mgr.clone(), tx);

            let target = Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
            let ep = tunnel.establish(target, upstream, HoldOpenMode::DumbTunnel)
                .await
                .unwrap();
            assert!((17100..=17199).contains(&ep.local_port));
            assert_eq!(ep.mode, HoldOpenMode::DumbTunnel);

            // Expect HoldOpenReady before any byte traffic.
            let ready = rx.recv().await.expect("ready event");
            assert!(matches!(ready.payload, EventPayload::HoldOpenReady(_)));

            // Client-side connect to the tunnel and exchange bytes.
            let mut client = TcpStream::connect(("127.0.0.1", ep.local_port)).await.unwrap();
            client.write_all(b"hello-tunnel").await.unwrap();
            let mut buf = vec![0u8; 12];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello-tunnel");

            // Close client side; tunnel emits HoldOpenClosed.
            drop(client);
            let closed = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                rx.recv(),
            ).await.expect("closed event arrived").expect("channel open");
            match closed.payload {
                EventPayload::HoldOpenClosed(c) => {
                    assert!(matches!(c.reason.as_str(), "upstream_closed" | "pentester_detach"));
                }
                other => panic!("expected HoldOpenClosed, got {other:?}"),
            }
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p ps-proxy --test dumb_tunnel`
        Expected: FAIL with `unresolved import: ps_proxy::dumb_tunnel::DumbTunnel`.

    - [ ] **Step 3: Write minimal implementation**

        Replace `crates/ps-proxy/src/dumb_tunnel.rs` with:

        ```rust
        //! DumbTunnel — bidirectional TCP pipe between the allocated local port
        //! and the already-connected upstream from `ConnectionCaught`.

        use crate::hold_open::{HoldOpen, HoldOpenManager, HoldOpenMode, LocalEndpoint};
        use crate::Result;
        use async_trait::async_trait;
        use ps_core::event::{Event, EventPayload, HoldOpenClosed, HoldOpenReady};
        use ps_core::id::EventId;
        use ps_core::target::Target;
        use std::net::SocketAddr;
        use std::time::Instant;
        use tokio::net::{TcpListener, TcpStream};
        use tokio::sync::mpsc::UnboundedSender;

        /// DumbTunnel owns the manager handle and the event emission sink.
        pub struct DumbTunnel {
            manager: HoldOpenManager,
            events: UnboundedSender<Event>,
        }

        impl DumbTunnel {
            pub fn new(manager: HoldOpenManager, events: UnboundedSender<Event>) -> Self {
                Self { manager, events }
            }
        }

        #[async_trait]
        impl HoldOpen for DumbTunnel {
            async fn establish(
                &self,
                target: Target,
                upstream: TcpStream,
                mode: HoldOpenMode,
            ) -> Result<LocalEndpoint> {
                let port = self.manager.allocate().await?;
                let listener = TcpListener::bind(("127.0.0.1", port)).await?;
                let local_addr: SocketAddr = listener.local_addr()?;
                let local_port = local_addr.port();

                // Announce readiness.
                let ready = Event {
                    schema: "portsnatcher/v1".into(),
                    event_id: EventId::new(),
                    catch_id: None,
                    engagement_id: ps_core::id::EngagementId::new(),
                    timestamp: time::OffsetDateTime::now_utc(),
                    payload: EventPayload::HoldOpenReady(HoldOpenReady {
                        local_port,
                        upstream: format!("{target}"),
                        mode: "dumb_tunnel".into(),
                        ca_fingerprint: None,
                    }),
                };
                let _ = self.events.send(ready);

                // Spawn the pipe task.
                let events = self.events.clone();
                let manager = self.manager.clone();
                tokio::spawn(async move {
                    let started = Instant::now();
                    let reason = run_pipe(listener, upstream).await;
                    manager.release(local_port).await;
                    let _ = events.send(Event {
                        schema: "portsnatcher/v1".into(),
                        event_id: EventId::new(),
                        catch_id: None,
                        engagement_id: ps_core::id::EngagementId::new(),
                        timestamp: time::OffsetDateTime::now_utc(),
                        payload: EventPayload::HoldOpenClosed(HoldOpenClosed {
                            reason: reason.into(),
                            duration_ms: started.elapsed().as_millis() as u64,
                        }),
                    });
                });

                Ok(LocalEndpoint {
                    local_port,
                    mode,
                    ca_fingerprint: None,
                })
            }
        }

        async fn run_pipe(listener: TcpListener, mut upstream: TcpStream) -> &'static str {
            let accept = tokio::time::timeout(
                std::time::Duration::from_secs(600),
                listener.accept(),
            ).await;
            let (mut local, _peer) = match accept {
                Ok(Ok(pair)) => pair,
                Ok(Err(_)) | Err(_) => return "idle_timeout",
            };
            match tokio::io::copy_bidirectional(&mut local, &mut upstream).await {
                Ok(_) => "pentester_detach",
                Err(_) => "upstream_closed",
            }
        }
        ```

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p ps-proxy --test dumb_tunnel`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/ps-proxy/src/dumb_tunnel.rs crates/ps-proxy/tests/dumb_tunnel.rs
        git commit -m "$(cat <<'EOF'
        feat(ps-proxy): DumbTunnel implementation with HoldOpen events

        Binds the allocated tunnel port on 127.0.0.1, emits HoldOpenReady
        immediately, and uses tokio::io::copy_bidirectional between the
        accepted client and the held-open upstream. Emits HoldOpenClosed
        with a reason tag on either side closing.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

### 3.4 — Keepalive heartbeat

- [ ] **Task 5: Write failing test for TCP `SO_KEEPALIVE` configuration on the upstream.**

    **Files:**
    - Test: `crates/ps-proxy/tests/keepalive.rs`

    - [ ] **Step 1: Write the failing test**

        Create `crates/ps-proxy/tests/keepalive.rs`:

        ```rust
        use ps_proxy::keepalive::{apply_tcp_keepalive, KeepaliveConfig};
        use tokio::net::{TcpListener, TcpStream};

        #[tokio::test]
        async fn applies_aggressive_tcp_keepalive() {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let client = tokio::spawn(async move {
                TcpStream::connect(addr).await.unwrap()
            });
            let (server, _) = listener.accept().await.unwrap();
            let _ = client.await.unwrap();

            let cfg = KeepaliveConfig::default_aggressive();
            assert_eq!(cfg.idle_secs, 15);
            assert_eq!(cfg.interval_secs, 5);
            assert_eq!(cfg.probes, 3);

            // Must succeed on all platforms; we assert no error.
            apply_tcp_keepalive(&server, &cfg).expect("keepalive applied");
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p ps-proxy --test keepalive`
        Expected: FAIL with `unresolved import: ps_proxy::keepalive::apply_tcp_keepalive`.

    - [ ] **Step 3: Write minimal implementation**

        Add `socket2 = "0.5"` to `[dependencies]` in `crates/ps-proxy/Cargo.toml`.

        Replace `crates/ps-proxy/src/keepalive.rs` with:

        ```rust
        //! Keepalive heartbeat for the upstream socket held by a tunnel.

        use crate::Result;
        use socket2::{SockRef, TcpKeepalive};
        use std::time::Duration;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpStream;
        use tokio::sync::watch;

        /// Per-mode keepalive tuning.
        #[derive(Debug, Clone, Copy)]
        pub struct KeepaliveConfig {
            pub idle_secs: u64,
            pub interval_secs: u64,
            pub probes: u32,
            pub http_options_every_secs: Option<u64>,
        }

        impl KeepaliveConfig {
            pub fn default_aggressive() -> Self {
                Self {
                    idle_secs: 15,
                    interval_secs: 5,
                    probes: 3,
                    http_options_every_secs: None,
                }
            }

            pub fn for_http() -> Self {
                Self {
                    http_options_every_secs: Some(20),
                    ..Self::default_aggressive()
                }
            }
        }

        /// Apply SO_KEEPALIVE with the configured intervals to a tokio TcpStream.
        /// Works on Linux, macOS, and Windows via socket2.
        pub fn apply_tcp_keepalive(stream: &TcpStream, cfg: &KeepaliveConfig) -> Result<()> {
            let sock = SockRef::from(stream);
            let mut ka = TcpKeepalive::new()
                .with_time(Duration::from_secs(cfg.idle_secs));

            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            {
                ka = ka.with_interval(Duration::from_secs(cfg.interval_secs));
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                ka = ka.with_retries(cfg.probes);
            }

            sock.set_tcp_keepalive(&ka)?;
            Ok(())
        }

        /// Periodic HTTP OPTIONS heartbeat. Stops when `stop_rx` flips to true.
        pub async fn run_http_options_heartbeat(
            mut stream: TcpStream,
            every: Duration,
            mut stop_rx: watch::Receiver<bool>,
        ) -> Result<TcpStream> {
            let mut interval = tokio::time::interval(every);
            interval.tick().await; // skip the immediate tick
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        stream.write_all(
                            b"OPTIONS / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n",
                        ).await?;
                    }
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() {
                            return Ok(stream);
                        }
                    }
                }
            }
        }
        ```

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p ps-proxy --test keepalive`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/ps-proxy/src/keepalive.rs crates/ps-proxy/Cargo.toml crates/ps-proxy/tests/keepalive.rs
        git commit -m "$(cat <<'EOF'
        feat(ps-proxy): aggressive TCP keepalive + HTTP OPTIONS heartbeat

        SO_KEEPALIVE (idle 15s / interval 5s / 3 probes) applied via socket2
        on all three OSes. HTTP mode additionally sends an idempotent
        OPTIONS / every 20s. Heartbeat stops on any pentester activity signal.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

- [ ] **Task 6: Wire keepalive into `DumbTunnel::establish`.**

    **Files:**
    - Edit: `crates/ps-proxy/src/dumb_tunnel.rs`

    - [ ] **Step 1: Write the failing test**

        Append to `crates/ps-proxy/tests/dumb_tunnel.rs`:

        ```rust
        #[tokio::test]
        async fn keepalive_applied_on_upstream() {
            let (upstream_addr, _upstream) = spawn_echo_upstream().await;
            let upstream = TcpStream::connect(upstream_addr).await.unwrap();

            let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
            let mgr = HoldOpenManager::new(17200..=17299);
            let tunnel = DumbTunnel::new(mgr.clone(), tx)
                .with_keepalive(ps_proxy::keepalive::KeepaliveConfig::default_aggressive());

            let target = Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
            let ep = tunnel.establish(target, upstream, HoldOpenMode::DumbTunnel)
                .await
                .unwrap();
            assert!((17200..=17299).contains(&ep.local_port));
            let _ready = rx.recv().await.expect("ready event");
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p ps-proxy --test dumb_tunnel keepalive_applied_on_upstream`
        Expected: FAIL with `no method named 'with_keepalive'`.

    - [ ] **Step 3: Write minimal implementation**

        In `crates/ps-proxy/src/dumb_tunnel.rs`, add after the existing `impl DumbTunnel`:

        ```rust
        impl DumbTunnel {
            pub fn with_keepalive(mut self, cfg: crate::keepalive::KeepaliveConfig) -> Self {
                self.keepalive = Some(cfg);
                self
            }
        }
        ```

        Change the struct to:

        ```rust
        pub struct DumbTunnel {
            manager: HoldOpenManager,
            events: UnboundedSender<Event>,
            keepalive: Option<crate::keepalive::KeepaliveConfig>,
        }
        ```

        Change `DumbTunnel::new` to initialize `keepalive: None`.

        Inside `establish`, after obtaining `upstream` but before spawning the pipe task, add:

        ```rust
        if let Some(cfg) = self.keepalive {
            if let Err(e) = crate::keepalive::apply_tcp_keepalive(&upstream, &cfg) {
                tracing::warn!(?e, "failed to apply keepalive; continuing");
            }
        }
        ```

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p ps-proxy --test dumb_tunnel`
        Expected: PASS (both tests).

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/ps-proxy/src/dumb_tunnel.rs crates/ps-proxy/tests/dumb_tunnel.rs
        git commit -m "$(cat <<'EOF'
        feat(ps-proxy): opt-in keepalive wired into DumbTunnel

        DumbTunnel::with_keepalive enables SO_KEEPALIVE on the upstream.
        The orchestrator passes KeepaliveConfig::for_http() when the
        fingerprint says HTTP so the tunnel stays warm for slow pentesters.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

### 3.5 — CA on-disk storage

- [ ] **Task 7: Write failing test for CA storage path resolution.**

    **Files:**
    - Test: `crates/ps-proxy/tests/ca.rs`

    - [ ] **Step 1: Write the failing test**

        Create `crates/ps-proxy/tests/ca.rs`:

        ```rust
        //! Tests for CA storage + generation + trust glue (never touches system trust store).

        use ps_proxy::ca::storage::CaStorage;
        use std::path::PathBuf;
        use tempfile::TempDir;

        #[test]
        fn storage_override_points_files_at_override_dir() {
            let tmp = TempDir::new().unwrap();
            let storage = CaStorage::with_root(tmp.path().to_path_buf());
            assert_eq!(storage.cert_path(), tmp.path().join("ca.crt"));
            assert_eq!(storage.key_path(), tmp.path().join("ca.key"));
            assert_eq!(storage.fingerprint_path(), tmp.path().join("ca-fingerprint.sha256"));
        }

        #[test]
        fn default_resolves_per_platform() {
            // Just verify we can construct one — the directories crate picks the path.
            let storage = CaStorage::default();
            let root: PathBuf = storage.root().to_path_buf();
            assert!(root.ends_with("portsnatcher/ca") || root.ends_with("portsnatcher\\ca"));
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p ps-proxy --test ca`
        Expected: FAIL with `unresolved import: ps_proxy::ca::storage::CaStorage`.

    - [ ] **Step 3: Write minimal implementation**

        Replace `crates/ps-proxy/src/ca/storage.rs` with:

        ```rust
        //! XDG-aware CA storage paths.
        //!
        //! Linux:   ~/.config/portsnatcher/ca/
        //! macOS:   ~/Library/Application Support/portsnatcher/ca/
        //! Windows: %APPDATA%\portsnatcher\ca\

        use crate::{Error, Result};
        use directories::ProjectDirs;
        use std::path::{Path, PathBuf};

        #[derive(Debug, Clone)]
        pub struct CaStorage {
            root: PathBuf,
        }

        impl Default for CaStorage {
            fn default() -> Self {
                let dirs = ProjectDirs::from("dev", "IntegSec", "portsnatcher")
                    .expect("no home directory on this platform");
                Self { root: dirs.config_dir().join("ca") }
            }
        }

        impl CaStorage {
            pub fn with_root(root: PathBuf) -> Self {
                Self { root }
            }

            pub fn root(&self) -> &Path {
                &self.root
            }

            pub fn cert_path(&self) -> PathBuf {
                self.root.join("ca.crt")
            }

            pub fn key_path(&self) -> PathBuf {
                self.root.join("ca.key")
            }

            pub fn fingerprint_path(&self) -> PathBuf {
                self.root.join("ca-fingerprint.sha256")
            }

            pub fn ensure_dir(&self) -> Result<()> {
                std::fs::create_dir_all(&self.root)
                    .map_err(|e| Error::Ca(format!("create {:?}: {e}", self.root)))?;
                Ok(())
            }

            /// Does a CA already exist at these paths?
            pub fn exists(&self) -> bool {
                self.cert_path().is_file() && self.key_path().is_file()
            }
        }
        ```

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p ps-proxy --test ca`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/ps-proxy/src/ca/storage.rs crates/ps-proxy/tests/ca.rs
        git commit -m "$(cat <<'EOF'
        feat(ps-proxy): CA storage with platform-aware default paths

        Uses the `directories` crate for XDG / Apple / Windows-AppData
        resolution. Tests can override the root with CaStorage::with_root
        for hermetic tempdir-based runs.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

- [ ] **Task 8: Write failing test for Unix `0600` permissions on the CA key.**

    **Files:**
    - Test: `crates/ps-proxy/tests/ca.rs`

    - [ ] **Step 1: Write the failing test**

        Append to `crates/ps-proxy/tests/ca.rs`:

        ```rust
        #[cfg(unix)]
        #[test]
        fn key_file_gets_0600_on_unix() {
            use std::os::unix::fs::PermissionsExt;

            let tmp = TempDir::new().unwrap();
            let storage = CaStorage::with_root(tmp.path().to_path_buf());
            storage.ensure_dir().unwrap();
            std::fs::write(storage.key_path(), b"PRIVATE\n").unwrap();
            storage.apply_key_permissions().unwrap();
            let meta = std::fs::metadata(storage.key_path()).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "key file must be owner-readwrite-only");
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p ps-proxy --test ca`
        Expected: FAIL with `no method named 'apply_key_permissions'`.

    - [ ] **Step 3: Write minimal implementation**

        In `crates/ps-proxy/src/ca/storage.rs`, add:

        ```rust
        impl CaStorage {
            /// Tighten permissions on the key file to owner-only. No-op on
            /// Windows (see `apply_key_permissions_windows` for the ACL path).
            pub fn apply_key_permissions(&self) -> Result<()> {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let path = self.key_path();
                    let mut perms = std::fs::metadata(&path)
                        .map_err(|e| Error::Ca(format!("stat {path:?}: {e}")))?
                        .permissions();
                    perms.set_mode(0o600);
                    std::fs::set_permissions(&path, perms)
                        .map_err(|e| Error::Ca(format!("chmod {path:?}: {e}")))?;
                }
                #[cfg(windows)]
                {
                    // On NTFS, reduce inheritance so only the current user can read.
                    // This is a best-effort ACL tighten; detailed DACL construction
                    // lives in Task 9.
                    let _ = self.key_path();
                }
                Ok(())
            }
        }
        ```

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p ps-proxy --test ca`
        Expected: PASS on Unix (test is `#[cfg(unix)]`, skipped on Windows).

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/ps-proxy/src/ca/storage.rs crates/ps-proxy/tests/ca.rs
        git commit -m "$(cat <<'EOF'
        feat(ps-proxy): chmod 0600 on CA key file on Unix

        The CA private key is engagement-critical. On Unix we set owner-only
        permissions on write; on Windows Task 9 adds the NTFS ACL path.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

- [ ] **Task 9: Windows NTFS ACL restriction on the CA key.**

    **Files:**
    - Edit: `crates/ps-proxy/src/ca/storage.rs`

    - [ ] **Step 1: Write the failing test**

        Append to `crates/ps-proxy/tests/ca.rs`:

        ```rust
        #[cfg(windows)]
        #[test]
        fn key_acl_restricts_to_user_on_windows() {
            let tmp = TempDir::new().unwrap();
            let storage = CaStorage::with_root(tmp.path().to_path_buf());
            storage.ensure_dir().unwrap();
            std::fs::write(storage.key_path(), b"PRIVATE\n").unwrap();
            // No panic and returns Ok; we can't easily inspect the DACL without
            // Windows-only crates, so we assert the call succeeds.
            storage.apply_key_permissions_windows().expect("ACL apply succeeds");
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p ps-proxy --test ca`
        Expected: FAIL on Windows with `no method named 'apply_key_permissions_windows'`. Passes on Unix (cfg-gated away).

    - [ ] **Step 3: Write minimal implementation**

        In `crates/ps-proxy/src/ca/storage.rs`, add:

        ```rust
        #[cfg(windows)]
        impl CaStorage {
            /// Shell out to `icacls` to set the DACL to current-user-only. The
            /// Windows SDK also has API-level paths (`SetNamedSecurityInfoW`),
            /// but icacls is present on every supported Windows SKU and keeps
            /// this path dependency-free.
            pub fn apply_key_permissions_windows(&self) -> Result<()> {
                let path = self.key_path();
                let path_str = path.to_string_lossy().to_string();
                let username = std::env::var("USERNAME")
                    .map_err(|_| Error::Ca("USERNAME env var not set".into()))?;

                let status = std::process::Command::new("icacls")
                    .arg(&path_str)
                    .arg("/inheritance:r")
                    .status()
                    .map_err(|e| Error::Ca(format!("icacls inheritance: {e}")))?;
                if !status.success() {
                    return Err(Error::Ca(format!("icacls inheritance exit {status}")));
                }

                let status = std::process::Command::new("icacls")
                    .arg(&path_str)
                    .arg("/grant:r")
                    .arg(format!("{username}:(R,W)"))
                    .status()
                    .map_err(|e| Error::Ca(format!("icacls grant: {e}")))?;
                if !status.success() {
                    return Err(Error::Ca(format!("icacls grant exit {status}")));
                }
                Ok(())
            }
        }
        ```

    - [ ] **Step 4: Run test to verify it passes**

        Run (on Windows runner): `cargo test -p ps-proxy --test ca`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/ps-proxy/src/ca/storage.rs crates/ps-proxy/tests/ca.rs
        git commit -m "$(cat <<'EOF'
        feat(ps-proxy): Windows NTFS ACL restrict CA key to current user

        Uses icacls /inheritance:r + /grant:r to strip inherited ACEs and
        grant only the current user R/W. Same security posture as chmod 0600
        on Unix.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

### 3.6 — CA generation (rcgen)

- [ ] **Task 10: Write failing test — `generate` creates a self-signed P-256 CA.**

    **Files:**
    - Test: `crates/ps-proxy/tests/ca.rs`

    - [ ] **Step 1: Write the failing test**

        Append to `crates/ps-proxy/tests/ca.rs`:

        ```rust
        use ps_proxy::ca::generate::{generate_or_load_ca, CaBundle};

        #[tokio::test]
        async fn generate_creates_files_and_fingerprint() {
            let tmp = TempDir::new().unwrap();
            let storage = CaStorage::with_root(tmp.path().to_path_buf());
            let bundle: CaBundle = generate_or_load_ca(&storage).unwrap();

            assert!(storage.cert_path().is_file());
            assert!(storage.key_path().is_file());
            assert!(storage.fingerprint_path().is_file());

            let fp = std::fs::read_to_string(storage.fingerprint_path()).unwrap();
            assert_eq!(fp.trim().len(), 64, "sha256 hex is 64 chars");
            assert_eq!(bundle.fingerprint_sha256, fp.trim());
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p ps-proxy --test ca`
        Expected: FAIL with `unresolved import: ps_proxy::ca::generate::generate_or_load_ca`.

    - [ ] **Step 3: Write minimal implementation**

        Replace `crates/ps-proxy/src/ca/generate.rs` with:

        ```rust
        //! CA generation. ECDSA P-256, 10-year validity; justified in the phase
        //! design notes (faster than RSA-3072, TLS 1.3 friendly, universally
        //! accepted by the platform trust stores we target).

        use crate::ca::storage::CaStorage;
        use crate::{Error, Result};
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType,
            IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
        };
        use sha2::{Digest, Sha256};
        use std::path::Path;
        use time::{Duration, OffsetDateTime};

        /// In-memory representation of the on-disk CA.
        #[derive(Debug, Clone)]
        pub struct CaBundle {
            pub cert_pem: String,
            pub key_pem: String,
            pub cert_der: Vec<u8>,
            pub fingerprint_sha256: String,
        }

        /// Idempotent: returns the existing CA if present, otherwise generates
        /// a fresh one at the configured storage paths.
        pub fn generate_or_load_ca(storage: &CaStorage) -> Result<CaBundle> {
            storage.ensure_dir()?;
            if storage.exists() {
                return load_existing(storage);
            }

            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

            let mut params = CertificateParams::new(vec![])?;
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "PortSnatcher MITM Root CA");
            dn.push(DnType::OrganizationName, "IntegSec PortSnatcher");
            params.distinguished_name = dn;
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            let now = OffsetDateTime::now_utc();
            params.not_before = now - Duration::hours(1);
            params.not_after = now + Duration::days(10 * 365);

            let cert = params.self_signed(&key)?;
            let cert_pem = cert.pem();
            let key_pem = key.serialize_pem();
            let cert_der = cert.der().to_vec();

            std::fs::write(storage.cert_path(), cert_pem.as_bytes())
                .map_err(|e| Error::Ca(format!("write ca.crt: {e}")))?;
            std::fs::write(storage.key_path(), key_pem.as_bytes())
                .map_err(|e| Error::Ca(format!("write ca.key: {e}")))?;
            storage.apply_key_permissions()?;
            #[cfg(windows)]
            storage.apply_key_permissions_windows()?;

            let fingerprint = fingerprint_sha256(&cert_der);
            std::fs::write(storage.fingerprint_path(), fingerprint.as_bytes())
                .map_err(|e| Error::Ca(format!("write fingerprint: {e}")))?;

            Ok(CaBundle { cert_pem, key_pem, cert_der, fingerprint_sha256: fingerprint })
        }

        fn load_existing(storage: &CaStorage) -> Result<CaBundle> {
            let cert_pem = read_pem(storage.cert_path())?;
            let key_pem = read_pem(storage.key_path())?;
            let cert_der = pem_to_der(&cert_pem, "CERTIFICATE")?;
            let fingerprint = fingerprint_sha256(&cert_der);
            // Write-through fingerprint if missing; don't fail if we can't.
            let _ = std::fs::write(storage.fingerprint_path(), &fingerprint);
            Ok(CaBundle { cert_pem, key_pem, cert_der, fingerprint_sha256: fingerprint })
        }

        fn read_pem(path: impl AsRef<Path>) -> Result<String> {
            std::fs::read_to_string(path.as_ref())
                .map_err(|e| Error::Ca(format!("read {:?}: {e}", path.as_ref())))
        }

        fn pem_to_der(pem: &str, tag: &str) -> Result<Vec<u8>> {
            for item in pem_rfc7468_iter(pem) {
                if item.tag == tag {
                    return Ok(item.der);
                }
            }
            Err(Error::Ca(format!("{tag} block not found")))
        }

        struct PemItem { tag: String, der: Vec<u8> }

        fn pem_rfc7468_iter(pem: &str) -> Vec<PemItem> {
            let mut out = Vec::new();
            let mut cursor = pem;
            while let Some(begin) = cursor.find("-----BEGIN ") {
                let after_begin = &cursor[begin + "-----BEGIN ".len()..];
                let tag_end = match after_begin.find("-----") {
                    Some(i) => i,
                    None => break,
                };
                let tag = after_begin[..tag_end].to_string();
                let end_marker = format!("-----END {tag}-----");
                let end = match after_begin.find(&end_marker) {
                    Some(i) => i,
                    None => break,
                };
                let body = &after_begin[tag_end + 5..end];
                let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
                use base64::{engine::general_purpose::STANDARD, Engine};
                if let Ok(der) = STANDARD.decode(b64) {
                    out.push(PemItem { tag, der });
                }
                cursor = &after_begin[end + end_marker.len()..];
            }
            out
        }

        pub fn fingerprint_sha256(der: &[u8]) -> String {
            let mut h = Sha256::new();
            h.update(der);
            hex::encode(h.finalize())
        }
        ```

        Add `base64 = "0.22"` to `[dependencies]` in `crates/ps-proxy/Cargo.toml`.

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p ps-proxy --test ca`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/ps-proxy/src/ca/generate.rs crates/ps-proxy/Cargo.toml crates/ps-proxy/tests/ca.rs
        git commit -m "$(cat <<'EOF'
        feat(ps-proxy): generate ECDSA P-256 CA with 10-year validity

        ECDSA P-256 is the right default: faster than RSA-3072 on every
        laptop a pentester uses, universally accepted by platform trust
        stores, and pairs cleanly with our TLS-1.3-only MITM. Fingerprint
        SHA-256 is written alongside the cert for the install/uninstall UX.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

- [ ] **Task 11: Write failing test — idempotent regeneration returns the same CA.**

    **Files:**
    - Test: `crates/ps-proxy/tests/ca.rs`

    - [ ] **Step 1: Write the failing test**

        Append to `crates/ps-proxy/tests/ca.rs`:

        ```rust
        #[tokio::test]
        async fn generate_is_idempotent() {
            let tmp = TempDir::new().unwrap();
            let storage = CaStorage::with_root(tmp.path().to_path_buf());
            let first = generate_or_load_ca(&storage).unwrap();
            let second = generate_or_load_ca(&storage).unwrap();
            assert_eq!(first.fingerprint_sha256, second.fingerprint_sha256);
            assert_eq!(first.cert_der, second.cert_der);
        }
        ```

    - [ ] **Step 2: Run test to verify it fails or passes**

        Run: `cargo test -p ps-proxy --test ca generate_is_idempotent`
        Expected: PASS (the implementation from Task 10 already branches on `storage.exists()`). If it fails, fix `load_existing`.

    - [ ] **Step 3: No code change if green**

        Confirm the test passes; commit only the test addition.

    - [ ] **Step 4: Run full ca suite**

        Run: `cargo test -p ps-proxy --test ca`
        Expected: PASS (all CA tests).

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/ps-proxy/tests/ca.rs
        git commit -m "$(cat <<'EOF'
        test(ps-proxy): assert CA generation is idempotent across calls

        Locks the load-existing branch in: a second call must return the same
        fingerprint and DER so no engagement ever sees a mid-run CA swap.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

- [ ] **Task 12: Write failing test for `sign_leaf` producing a CA-chained leaf.**

    **Files:**
    - Test: `crates/ps-proxy/tests/ca.rs`

    - [ ] **Step 1: Write the failing test**

        Append to `crates/ps-proxy/tests/ca.rs`:

        ```rust
        use ps_proxy::ca::generate::LeafSigner;

        #[tokio::test]
        async fn sign_leaf_chains_to_ca_and_caches() {
            let tmp = TempDir::new().unwrap();
            let storage = CaStorage::with_root(tmp.path().to_path_buf());
            let bundle = generate_or_load_ca(&storage).unwrap();

            let signer = LeafSigner::new(bundle.clone()).unwrap();
            let leaf_a = signer.sign_leaf("example.com").unwrap();
            let leaf_b = signer.sign_leaf("example.com").unwrap();
            // Cached by hostname: same object identity via pointer compare.
            assert!(std::sync::Arc::ptr_eq(&leaf_a, &leaf_b));

            let leaf_c = signer.sign_leaf("other.example.com").unwrap();
            assert!(!std::sync::Arc::ptr_eq(&leaf_a, &leaf_c));
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p ps-proxy --test ca sign_leaf_chains_to_ca_and_caches`
        Expected: FAIL with `unresolved import: ps_proxy::ca::generate::LeafSigner`.

    - [ ] **Step 3: Write minimal implementation**

        Append to `crates/ps-proxy/src/ca/generate.rs`:

        ```rust
        use rcgen::{Certificate, SanType};
        use rustls::sign::CertifiedKey;
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};

        /// Issues ephemeral leaf certificates signed by the CA, cached by
        /// hostname so the hot path of a catch doesn't re-issue on every
        /// reconnect.
        pub struct LeafSigner {
            ca: CaBundle,
            ca_params: rcgen::Issuer<'static, KeyPair>,
            cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
        }

        impl LeafSigner {
            pub fn new(ca: CaBundle) -> Result<Self> {
                let key = KeyPair::from_pem(&ca.key_pem)?;
                let cert_params = CertificateParams::from_ca_cert_pem(&ca.cert_pem)?;
                let issuer = rcgen::Issuer::from_params(cert_params, key);
                Ok(Self {
                    ca,
                    ca_params: issuer,
                    cache: Mutex::new(HashMap::new()),
                })
            }

            pub fn ca(&self) -> &CaBundle {
                &self.ca
            }

            pub fn sign_leaf(&self, hostname: &str) -> Result<Arc<CertifiedKey>> {
                if let Some(existing) = self.cache.lock().unwrap().get(hostname) {
                    return Ok(existing.clone());
                }
                let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
                let mut params = CertificateParams::new(vec![hostname.to_string()])?;
                params.distinguished_name = {
                    let mut dn = DistinguishedName::new();
                    dn.push(DnType::CommonName, hostname);
                    dn
                };
                params.subject_alt_names = vec![SanType::DnsName(hostname.try_into()
                    .map_err(|e| Error::Ca(format!("bad hostname {hostname}: {e}")))?)];
                let now = OffsetDateTime::now_utc();
                params.not_before = now - Duration::hours(1);
                params.not_after = now + Duration::days(90);

                let leaf = params.signed_by(&key, &self.ca_params)?;
                let leaf_der = leaf.der().to_vec();

                let leaf_key_pem = key.serialize_pem();
                let leaf_key_der = pem_to_der(&leaf_key_pem, "PRIVATE KEY")
                    .or_else(|_| pem_to_der(&leaf_key_pem, "EC PRIVATE KEY"))?;

                let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(
                    &rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key_der).into(),
                ).map_err(|e| Error::Ca(format!("any_ecdsa_type: {e}")))?;

                let certs = vec![
                    rustls::pki_types::CertificateDer::from(leaf_der),
                    rustls::pki_types::CertificateDer::from(self.ca.cert_der.clone()),
                ];
                let ck = Arc::new(CertifiedKey::new(certs, signing_key));
                self.cache.lock().unwrap().insert(hostname.to_string(), ck.clone());
                Ok(ck)
            }
        }
        ```

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p ps-proxy --test ca`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/ps-proxy/src/ca/generate.rs crates/ps-proxy/tests/ca.rs
        git commit -m "$(cat <<'EOF'
        feat(ps-proxy): LeafSigner issues CA-chained ECDSA leaves (90-day ttl)

        Leaves are signed on demand at MITM time and cached in-memory keyed
        by hostname for the lifetime of the engagement. Chain is [leaf, ca]
        as rustls expects.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

- [ ] **Task 13: Leaf verifies against generated CA via `rustls::ClientConfig`.**

    **Files:**
    - Test: `crates/ps-proxy/tests/ca.rs`

    - [ ] **Step 1: Write the failing test**

        Append to `crates/ps-proxy/tests/ca.rs`:

        ```rust
        #[tokio::test]
        async fn leaf_verifies_against_our_ca() {
            let tmp = TempDir::new().unwrap();
            let storage = CaStorage::with_root(tmp.path().to_path_buf());
            let bundle = generate_or_load_ca(&storage).unwrap();
            let signer = LeafSigner::new(bundle.clone()).unwrap();
            let leaf = signer.sign_leaf("fixture.local").unwrap();

            // Build a trust store containing our CA.
            let mut roots = rustls::RootCertStore::empty();
            roots.add(rustls::pki_types::CertificateDer::from(bundle.cert_der.clone())).unwrap();

            // Extract the leaf's DER from the CertifiedKey and run path
            // validation against `roots`.
            let leaf_der = leaf.cert[0].clone();
            let server_name = rustls::pki_types::ServerName::try_from("fixture.local").unwrap();

            let verifier = rustls::client::WebPkiServerVerifier::builder(roots.into()).build().unwrap();
            verifier
                .verify_server_cert(
                    &leaf_der,
                    &[rustls::pki_types::CertificateDer::from(bundle.cert_der)],
                    &server_name,
                    &[],
                    rustls::pki_types::UnixTime::now(),
                )
                .expect("leaf must verify against our CA");
        }
        ```

    - [ ] **Step 2: Run test to verify it fails or passes**

        Run: `cargo test -p ps-proxy --test ca leaf_verifies_against_our_ca`
        Expected: PASS. If it fails, inspect the chain ordering in `sign_leaf` — the leaf must be the first cert, CA second (already wired that way above).

    - [ ] **Step 3: No new implementation**

        This task is purely an acceptance assertion over Task 12.

    - [ ] **Step 4: Run full ca suite**

        Run: `cargo test -p ps-proxy --test ca`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/ps-proxy/tests/ca.rs
        git commit -m "$(cat <<'EOF'
        test(ps-proxy): verify signed leaves chain to our CA via rustls

        Uses rustls::WebPkiServerVerifier with a root store containing only
        our CA to prove path validation works end-to-end. Locks the chain
        ordering the TLS MITM will rely on.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

### 3.7 — Platform trust-store install/uninstall

- [ ] **Task 14: Linux trust-store install/uninstall via `update-ca-certificates`.**

    **Files:**
    - Edit: `crates/ps-proxy/src/ca/trust.rs`
    - Test: `crates/ps-proxy/tests/ca.rs`

    - [ ] **Step 1: Write the failing test**

        Append to `crates/ps-proxy/tests/ca.rs`:

        ```rust
        #[cfg(target_os = "linux")]
        #[test]
        fn install_plan_linux_uses_update_ca_certificates() {
            use ps_proxy::ca::trust::{install_plan, TrustAction, TrustPlan};
            let plan: TrustPlan = install_plan("/tmp/portsnatcher.crt");
            assert_eq!(plan.steps[0].action, TrustAction::CopyFile);
            assert_eq!(plan.steps[0].dest.as_deref(), Some("/usr/local/share/ca-certificates/portsnatcher.crt"));
            assert_eq!(plan.steps[1].action, TrustAction::RunCommand);
            assert!(plan.steps[1].command.as_ref().unwrap().contains("update-ca-certificates"));
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p ps-proxy --test ca install_plan_linux_uses_update_ca_certificates`
        Expected: FAIL with `unresolved import: ps_proxy::ca::trust::install_plan`.

    - [ ] **Step 3: Write minimal implementation**

        Replace `crates/ps-proxy/src/ca/trust.rs` with:

        ```rust
        //! Platform trust-store install/uninstall.
        //!
        //! Per-OS pseudo-plan: describe the concrete steps before executing
        //! them so tests can assert-on-plan without mutating runner state.

        use crate::{Error, Result};
        use std::path::Path;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum TrustAction {
            CopyFile,
            RunCommand,
            RemoveFile,
        }

        #[derive(Debug, Clone)]
        pub struct TrustStep {
            pub action: TrustAction,
            pub dest: Option<String>,
            pub command: Option<String>,
            pub description: String,
        }

        #[derive(Debug, Clone)]
        pub struct TrustPlan {
            pub steps: Vec<TrustStep>,
            pub requires_elevation: bool,
        }

        #[cfg(target_os = "linux")]
        pub fn install_plan(source_cert: impl AsRef<Path>) -> TrustPlan {
            let src = source_cert.as_ref().to_string_lossy().to_string();
            TrustPlan {
                steps: vec![
                    TrustStep {
                        action: TrustAction::CopyFile,
                        dest: Some("/usr/local/share/ca-certificates/portsnatcher.crt".into()),
                        command: Some(format!("cp {src} /usr/local/share/ca-certificates/portsnatcher.crt")),
                        description: "copy CA cert to /usr/local/share/ca-certificates/".into(),
                    },
                    TrustStep {
                        action: TrustAction::RunCommand,
                        dest: None,
                        command: Some("update-ca-certificates".into()),
                        description: "rebuild system CA bundle".into(),
                    },
                ],
                requires_elevation: true,
            }
        }

        #[cfg(target_os = "linux")]
        pub fn uninstall_plan() -> TrustPlan {
            TrustPlan {
                steps: vec![
                    TrustStep {
                        action: TrustAction::RemoveFile,
                        dest: Some("/usr/local/share/ca-certificates/portsnatcher.crt".into()),
                        command: Some("rm -f /usr/local/share/ca-certificates/portsnatcher.crt".into()),
                        description: "remove CA cert from trusted roots".into(),
                    },
                    TrustStep {
                        action: TrustAction::RunCommand,
                        dest: None,
                        command: Some("update-ca-certificates --fresh".into()),
                        description: "rebuild system CA bundle".into(),
                    },
                ],
                requires_elevation: true,
            }
        }

        /// Execute an install plan on the current host. Returns a clear error
        /// when not root.
        #[cfg(target_os = "linux")]
        pub fn execute_install(source_cert: impl AsRef<Path>) -> Result<()> {
            if !is_root() {
                return Err(Error::Ca("trust-store install requires root on Linux".into()));
            }
            let plan = install_plan(source_cert.as_ref());
            for step in &plan.steps {
                run_step(step)?;
            }
            Ok(())
        }

        #[cfg(target_os = "linux")]
        pub fn execute_uninstall() -> Result<()> {
            if !is_root() {
                return Err(Error::Ca("trust-store uninstall requires root on Linux".into()));
            }
            for step in &uninstall_plan().steps {
                run_step(step)?;
            }
            Ok(())
        }

        #[cfg(unix)]
        fn is_root() -> bool {
            nix::unistd::Uid::effective().is_root()
        }

        fn run_step(step: &TrustStep) -> Result<()> {
            match step.action {
                TrustAction::CopyFile => {
                    let cmd = step.command.as_ref().ok_or_else(|| Error::Ca("missing copy cmd".into()))?;
                    sh(cmd)
                }
                TrustAction::RunCommand => {
                    let cmd = step.command.as_ref().ok_or_else(|| Error::Ca("missing run cmd".into()))?;
                    sh(cmd)
                }
                TrustAction::RemoveFile => {
                    let cmd = step.command.as_ref().ok_or_else(|| Error::Ca("missing rm cmd".into()))?;
                    sh(cmd)
                }
            }
        }

        fn sh(cmdline: &str) -> Result<()> {
            let status = if cfg!(windows) {
                std::process::Command::new("cmd").args(["/C", cmdline]).status()
            } else {
                std::process::Command::new("sh").args(["-c", cmdline]).status()
            }.map_err(|e| Error::Ca(format!("spawn: {e}")))?;
            if !status.success() {
                return Err(Error::Ca(format!("`{cmdline}` exit {status}")));
            }
            Ok(())
        }
        ```

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p ps-proxy --test ca install_plan_linux_uses_update_ca_certificates`
        Expected: PASS on Linux.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/ps-proxy/src/ca/trust.rs crates/ps-proxy/tests/ca.rs
        git commit -m "$(cat <<'EOF'
        feat(ps-proxy): Linux trust-store install/uninstall plan + executor

        install_plan / uninstall_plan describe the exact steps so tests can
        assert-on-plan without mutating runner state. execute_install requires
        root and writes to /usr/local/share/ca-certificates/ then runs
        update-ca-certificates.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

- [ ] **Task 15: macOS trust-store install/uninstall via `security`.**

    **Files:**
    - Edit: `crates/ps-proxy/src/ca/trust.rs`
    - Test: `crates/ps-proxy/tests/ca.rs`

    - [ ] **Step 1: Write the failing test**

        Append to `crates/ps-proxy/tests/ca.rs`:

        ```rust
        #[cfg(target_os = "macos")]
        #[test]
        fn install_plan_macos_uses_security_add_trusted_cert() {
            use ps_proxy::ca::trust::install_plan;
            let plan = install_plan("/tmp/portsnatcher.crt");
            let cmd = plan.steps[0].command.as_ref().unwrap();
            assert!(cmd.contains("security add-trusted-cert"));
            assert!(cmd.contains("-d"));
            assert!(cmd.contains("-r trustRoot"));
            assert!(cmd.contains("/Library/Keychains/System.keychain"));
            assert!(plan.requires_elevation);
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run (macOS): `cargo test -p ps-proxy --test ca install_plan_macos_uses_security_add_trusted_cert`
        Expected: FAIL on macOS (function not yet cfg-implemented).

    - [ ] **Step 3: Write minimal implementation**

        Append to `crates/ps-proxy/src/ca/trust.rs`:

        ```rust
        #[cfg(target_os = "macos")]
        pub fn install_plan(source_cert: impl AsRef<Path>) -> TrustPlan {
            let src = source_cert.as_ref().to_string_lossy().to_string();
            TrustPlan {
                steps: vec![TrustStep {
                    action: TrustAction::RunCommand,
                    dest: None,
                    command: Some(format!(
                        "security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {src}"
                    )),
                    description: "add PortSnatcher CA to System keychain as trusted root".into(),
                }],
                requires_elevation: true,
            }
        }

        #[cfg(target_os = "macos")]
        pub fn uninstall_plan() -> TrustPlan {
            TrustPlan {
                steps: vec![TrustStep {
                    action: TrustAction::RunCommand,
                    dest: None,
                    command: Some(
                        "security delete-certificate -c 'PortSnatcher MITM Root CA' /Library/Keychains/System.keychain".into(),
                    ),
                    description: "remove PortSnatcher CA from System keychain".into(),
                }],
                requires_elevation: true,
            }
        }

        #[cfg(target_os = "macos")]
        pub fn execute_install(source_cert: impl AsRef<Path>) -> Result<()> {
            for step in &install_plan(source_cert.as_ref()).steps {
                run_step(step)?;
            }
            Ok(())
        }

        #[cfg(target_os = "macos")]
        pub fn execute_uninstall() -> Result<()> {
            for step in &uninstall_plan().steps {
                run_step(step)?;
            }
            Ok(())
        }
        ```

    - [ ] **Step 4: Run test to verify it passes**

        Run (macOS): `cargo test -p ps-proxy --test ca install_plan_macos_uses_security_add_trusted_cert`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/ps-proxy/src/ca/trust.rs crates/ps-proxy/tests/ca.rs
        git commit -m "$(cat <<'EOF'
        feat(ps-proxy): macOS trust-store install via security add-trusted-cert

        System keychain root. Uninstall deletes by common name. Both require
        sudo and print the CA fingerprint before invocation (wired at the CLI
        layer in Task 21).

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

- [ ] **Task 16: Windows trust-store install/uninstall via PowerShell `Import-Certificate`.**

    **Files:**
    - Edit: `crates/ps-proxy/src/ca/trust.rs`
    - Test: `crates/ps-proxy/tests/ca.rs`

    - [ ] **Step 1: Write the failing test**

        Append to `crates/ps-proxy/tests/ca.rs`:

        ```rust
        #[cfg(target_os = "windows")]
        #[test]
        fn install_plan_windows_uses_import_certificate() {
            use ps_proxy::ca::trust::install_plan;
            let plan = install_plan(r"C:\tmp\portsnatcher.crt");
            let cmd = plan.steps[0].command.as_ref().unwrap();
            assert!(cmd.contains("Import-Certificate"));
            assert!(cmd.contains(r"Cert:\LocalMachine\Root"));
            assert!(plan.requires_elevation);
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run (Windows): `cargo test -p ps-proxy --test ca install_plan_windows_uses_import_certificate`
        Expected: FAIL (function not cfg-implemented yet).

    - [ ] **Step 3: Write minimal implementation**

        Append to `crates/ps-proxy/src/ca/trust.rs`:

        ```rust
        #[cfg(target_os = "windows")]
        pub fn install_plan(source_cert: impl AsRef<Path>) -> TrustPlan {
            let src = source_cert.as_ref().to_string_lossy().to_string();
            let ps = format!(
                r#"powershell -NoProfile -Command "Import-Certificate -FilePath '{src}' -CertStoreLocation Cert:\LocalMachine\Root""#
            );
            TrustPlan {
                steps: vec![TrustStep {
                    action: TrustAction::RunCommand,
                    dest: None,
                    command: Some(ps),
                    description: "import PortSnatcher CA into LocalMachine\\Root via PowerShell".into(),
                }],
                requires_elevation: true,
            }
        }

        #[cfg(target_os = "windows")]
        pub fn uninstall_plan() -> TrustPlan {
            let ps = r#"powershell -NoProfile -Command "Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -match 'PortSnatcher MITM Root CA' } | Remove-Item""#.to_string();
            TrustPlan {
                steps: vec![TrustStep {
                    action: TrustAction::RunCommand,
                    dest: None,
                    command: Some(ps),
                    description: "remove PortSnatcher CA from LocalMachine\\Root".into(),
                }],
                requires_elevation: true,
            }
        }

        #[cfg(target_os = "windows")]
        pub fn execute_install(source_cert: impl AsRef<Path>) -> Result<()> {
            for step in &install_plan(source_cert.as_ref()).steps {
                run_step(step)?;
            }
            Ok(())
        }

        #[cfg(target_os = "windows")]
        pub fn execute_uninstall() -> Result<()> {
            for step in &uninstall_plan().steps {
                run_step(step)?;
            }
            Ok(())
        }
        ```

    - [ ] **Step 4: Run test to verify it passes**

        Run (Windows): `cargo test -p ps-proxy --test ca install_plan_windows_uses_import_certificate`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/ps-proxy/src/ca/trust.rs crates/ps-proxy/tests/ca.rs
        git commit -m "$(cat <<'EOF'
        feat(ps-proxy): Windows trust-store install via Import-Certificate

        PowerShell one-liner into Cert:\LocalMachine\Root. Uninstall matches
        by subject pattern so orphaned certs from previous installs also get
        swept.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

### 3.8 — TLS MITM tunnel

- [ ] **Task 17: Write failing integration test for the TLS MITM happy path.**

    **Files:**
    - Test: `crates/ps-proxy/tests/tls_mitm.rs`

    - [ ] **Step 1: Write the failing test**

        Create `crates/ps-proxy/tests/tls_mitm.rs`:

        ```rust
        //! TLS MITM end-to-end: hyper+rustls HTTPS fixture, MITM in the middle,
        //! rustls client trusting our CA. Assert the transcript captures plaintext.

        use http_body_util::{BodyExt, Full};
        use hyper::body::Bytes;
        use hyper::service::service_fn;
        use hyper::{Request, Response};
        use hyper_util::rt::TokioIo;
        use ps_core::target::Target;
        use ps_proxy::ca::generate::{generate_or_load_ca, LeafSigner};
        use ps_proxy::ca::storage::CaStorage;
        use ps_proxy::hold_open::{HoldOpen, HoldOpenManager, HoldOpenMode};
        use ps_proxy::tls_mitm::TlsMitm;
        use std::convert::Infallible;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use std::sync::Arc;
        use tempfile::TempDir;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};
        use tokio::sync::mpsc;
        use tokio_rustls::rustls::pki_types::ServerName;

        async fn spawn_https_fixture(ca: &LeafSigner) -> SocketAddr {
            let leaf = ca.sign_leaf("fixture.local").unwrap();
            let server_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(SingleLeafResolver(leaf)));
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                loop {
                    let (tcp, _) = listener.accept().await.unwrap();
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let tls = acceptor.accept(tcp).await.unwrap();
                        let io = TokioIo::new(tls);
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, service_fn(|_req: Request<hyper::body::Incoming>| async {
                                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from("hello-https"))))
                            }))
                            .await;
                    });
                }
            });
            addr
        }

        #[derive(Debug)]
        struct SingleLeafResolver(std::sync::Arc<rustls::sign::CertifiedKey>);
        impl rustls::server::ResolvesServerCert for SingleLeafResolver {
            fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
                Some(self.0.clone())
            }
        }

        #[tokio::test]
        async fn mitm_captures_plaintext_transcript() {
            rustls::crypto::ring::default_provider()
                .install_default()
                .ok();

            let tmp = TempDir::new().unwrap();
            let storage = CaStorage::with_root(tmp.path().to_path_buf());
            let bundle = generate_or_load_ca(&storage).unwrap();
            let signer = Arc::new(LeafSigner::new(bundle.clone()).unwrap());

            let upstream_addr = spawn_https_fixture(&signer).await;
            let upstream_tcp = TcpStream::connect(upstream_addr).await.unwrap();

            let transcript_dir = tmp.path().join("artifacts");
            std::fs::create_dir_all(&transcript_dir).unwrap();

            let (tx, _rx) = mpsc::unbounded_channel();
            let mgr = HoldOpenManager::new(17300..=17399);
            let mitm = TlsMitm::new(
                mgr.clone(),
                tx,
                signer.clone(),
                "fixture.local".to_string(),
                transcript_dir.clone(),
            );

            let target = Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
            let ep = mitm.establish(target, upstream_tcp, HoldOpenMode::TlsMitm)
                .await
                .unwrap();

            // Client trusts our CA.
            let mut roots = rustls::RootCertStore::empty();
            roots.add(rustls::pki_types::CertificateDer::from(bundle.cert_der.clone())).unwrap();
            let client_cfg = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));

            let tcp = TcpStream::connect(("127.0.0.1", ep.local_port)).await.unwrap();
            let name = ServerName::try_from("fixture.local").unwrap();
            let mut tls = connector.connect(name, tcp).await.unwrap();
            tls.write_all(b"GET / HTTP/1.1\r\nHost: fixture.local\r\nConnection: close\r\n\r\n").await.unwrap();
            let mut body = Vec::new();
            tls.read_to_end(&mut body).await.unwrap();
            let body_str = String::from_utf8_lossy(&body);
            assert!(body_str.contains("hello-https"), "got: {body_str}");

            // Transcript file must contain both request and response plaintext.
            let transcripts: Vec<_> = walkdir::WalkDir::new(&transcript_dir)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name() == "transcript")
                .collect();
            assert_eq!(transcripts.len(), 1, "exactly one transcript expected");
            let contents = std::fs::read_to_string(transcripts[0].path()).unwrap();
            assert!(contents.contains("GET /"), "request logged: {contents}");
            assert!(contents.contains("hello-https"), "response logged: {contents}");
        }
        ```

        Add `walkdir = "2"` to `[dev-dependencies]` in `crates/ps-proxy/Cargo.toml`.

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p ps-proxy --test tls_mitm`
        Expected: FAIL with `unresolved import: ps_proxy::tls_mitm::TlsMitm`.

    - [ ] **Step 3: Write minimal implementation**

        Replace `crates/ps-proxy/src/tls_mitm.rs` with:

        ```rust
        //! TLS MITM: terminate the pentester's TLS with a CA-signed leaf,
        //! re-encrypt upstream, log the decrypted bytes to disk.

        use crate::ca::generate::LeafSigner;
        use crate::hold_open::{HoldOpen, HoldOpenManager, HoldOpenMode, LocalEndpoint};
        use crate::Result;
        use async_trait::async_trait;
        use ps_core::event::{Event, EventPayload, HoldOpenClosed, HoldOpenReady};
        use ps_core::id::{EngagementId, EventId};
        use ps_core::target::Target;
        use std::path::PathBuf;
        use std::sync::Arc;
        use std::time::Instant;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};
        use tokio::sync::mpsc::UnboundedSender;
        use tokio_rustls::{TlsAcceptor, TlsConnector};

        pub struct TlsMitm {
            manager: HoldOpenManager,
            events: UnboundedSender<Event>,
            signer: Arc<LeafSigner>,
            upstream_hostname: String,
            transcript_root: PathBuf,
        }

        impl TlsMitm {
            pub fn new(
                manager: HoldOpenManager,
                events: UnboundedSender<Event>,
                signer: Arc<LeafSigner>,
                upstream_hostname: String,
                transcript_root: PathBuf,
            ) -> Self {
                Self { manager, events, signer, upstream_hostname, transcript_root }
            }
        }

        #[derive(Debug)]
        struct HostnameResolver(Arc<rustls::sign::CertifiedKey>);
        impl rustls::server::ResolvesServerCert for HostnameResolver {
            fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
                Some(self.0.clone())
            }
        }

        #[async_trait]
        impl HoldOpen for TlsMitm {
            async fn establish(
                &self,
                target: Target,
                upstream_tcp: TcpStream,
                _mode: HoldOpenMode,
            ) -> Result<LocalEndpoint> {
                let port = self.manager.allocate().await?;
                let listener = TcpListener::bind(("127.0.0.1", port)).await?;
                let local_port = listener.local_addr()?.port();

                let leaf = self.signer.sign_leaf(&self.upstream_hostname)?;
                let server_config = Arc::new(
                    rustls::ServerConfig::builder()
                        .with_no_client_auth()
                        .with_cert_resolver(Arc::new(HostnameResolver(leaf))),
                );

                let mut client_roots = rustls::RootCertStore::empty();
                for c in webpki_roots::TLS_SERVER_ROOTS.iter() {
                    client_roots.add(rustls::pki_types::CertificateDer::from(c.subject_public_key_info.as_ref().to_vec())).ok();
                }
                let client_config = Arc::new(
                    rustls::ClientConfig::builder()
                        .with_root_certificates(client_roots)
                        .with_no_client_auth(),
                );

                let fingerprint = self.signer.ca().fingerprint_sha256.clone();
                let ready = Event {
                    schema: "portsnatcher/v1".into(),
                    event_id: EventId::new(),
                    catch_id: None,
                    engagement_id: EngagementId::new(),
                    timestamp: time::OffsetDateTime::now_utc(),
                    payload: EventPayload::HoldOpenReady(HoldOpenReady {
                        local_port,
                        upstream: format!("{target}"),
                        mode: "tls_mitm".into(),
                        ca_fingerprint: Some(fingerprint),
                    }),
                };
                let _ = self.events.send(ready);

                let events = self.events.clone();
                let manager = self.manager.clone();
                let hostname = self.upstream_hostname.clone();
                let transcript_dir = self.transcript_root.join(format!("catch-{local_port}")).join("http");
                std::fs::create_dir_all(&transcript_dir)?;
                let transcript_path = transcript_dir.join("transcript");

                tokio::spawn(async move {
                    let started = Instant::now();
                    let reason = run_mitm(
                        listener,
                        upstream_tcp,
                        server_config,
                        client_config,
                        hostname,
                        transcript_path,
                    ).await;
                    manager.release(local_port).await;
                    let _ = events.send(Event {
                        schema: "portsnatcher/v1".into(),
                        event_id: EventId::new(),
                        catch_id: None,
                        engagement_id: EngagementId::new(),
                        timestamp: time::OffsetDateTime::now_utc(),
                        payload: EventPayload::HoldOpenClosed(HoldOpenClosed {
                            reason: reason.into(),
                            duration_ms: started.elapsed().as_millis() as u64,
                        }),
                    });
                });

                Ok(LocalEndpoint {
                    local_port,
                    mode: HoldOpenMode::TlsMitm,
                    ca_fingerprint: Some(self.signer.ca().fingerprint_sha256.clone()),
                })
            }
        }

        async fn run_mitm(
            listener: TcpListener,
            upstream_tcp: TcpStream,
            server_cfg: Arc<rustls::ServerConfig>,
            client_cfg: Arc<rustls::ClientConfig>,
            hostname: String,
            transcript_path: PathBuf,
        ) -> &'static str {
            let (local_tcp, _peer) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return "idle_timeout",
            };
            let acceptor = TlsAcceptor::from(server_cfg);
            let mut local_tls = match acceptor.accept(local_tcp).await {
                Ok(s) => s,
                Err(_) => return "upstream_closed",
            };
            let connector = TlsConnector::from(client_cfg);
            let name = match rustls::pki_types::ServerName::try_from(hostname) {
                Ok(n) => n,
                Err(_) => return "upstream_closed",
            };
            let mut upstream_tls = match connector.connect(name, upstream_tcp).await {
                Ok(s) => s,
                Err(_) => return "upstream_closed",
            };

            let mut transcript = match tokio::fs::File::create(&transcript_path).await {
                Ok(f) => f,
                Err(_) => return "upstream_closed",
            };

            let mut buf_up = vec![0u8; 8192];
            let mut buf_down = vec![0u8; 8192];
            loop {
                tokio::select! {
                    r = local_tls.read(&mut buf_up) => match r {
                        Ok(0) | Err(_) => return "pentester_detach",
                        Ok(n) => {
                            let _ = transcript.write_all(b"--> client->upstream\n").await;
                            let _ = transcript.write_all(&buf_up[..n]).await;
                            let _ = transcript.write_all(b"\n").await;
                            if upstream_tls.write_all(&buf_up[..n]).await.is_err() {
                                return "upstream_closed";
                            }
                        }
                    },
                    r = upstream_tls.read(&mut buf_down) => match r {
                        Ok(0) | Err(_) => return "upstream_closed",
                        Ok(n) => {
                            let _ = transcript.write_all(b"<-- upstream->client\n").await;
                            let _ = transcript.write_all(&buf_down[..n]).await;
                            let _ = transcript.write_all(b"\n").await;
                            if local_tls.write_all(&buf_down[..n]).await.is_err() {
                                return "pentester_detach";
                            }
                        }
                    },
                }
            }
        }
        ```

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p ps-proxy --test tls_mitm`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/ps-proxy/src/tls_mitm.rs crates/ps-proxy/Cargo.toml crates/ps-proxy/tests/tls_mitm.rs
        git commit -m "$(cat <<'EOF'
        feat(ps-proxy): TlsMitm terminate-and-relog with CA-signed leaves

        Rustls server with our CA-signed leaf on the pentester side, rustls
        client with default webpki roots on the upstream side. Decrypted
        bytes are appended to artifacts/<catch>/http/transcript with
        direction markers so post-engagement grep is trivial.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

- [ ] **Task 18: Frame detection helpers — HTTP/1.1 `\r\n\r\n` boundary + HTTP/2 frame length.**

    **Files:**
    - Edit: `crates/ps-proxy/src/tls_mitm.rs`

    - [ ] **Step 1: Write the failing test**

        Append to `crates/ps-proxy/tests/tls_mitm.rs`:

        ```rust
        use ps_proxy::tls_mitm::framing::{http1_header_boundary, http2_frame_len};

        #[test]
        fn http1_boundary_found() {
            let buf = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nBODY";
            assert_eq!(http1_header_boundary(buf), Some(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".len()));
        }

        #[test]
        fn http1_boundary_absent() {
            assert_eq!(http1_header_boundary(b"partial"), None);
        }

        #[test]
        fn http2_frame_length_reads_24_bit_prefix() {
            let buf = [0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            assert_eq!(http2_frame_len(&buf), Some(10));
        }

        #[test]
        fn http2_frame_length_short_buffer() {
            assert_eq!(http2_frame_len(&[0x00, 0x00]), None);
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p ps-proxy --test tls_mitm http1`
        Expected: FAIL with `unresolved import: ps_proxy::tls_mitm::framing`.

    - [ ] **Step 3: Write minimal implementation**

        Append to `crates/ps-proxy/src/tls_mitm.rs`:

        ```rust
        pub mod framing {
            /// Returns the byte index one past the end of the HTTP/1.1 header
            /// block (`\r\n\r\n` boundary), or None if not yet seen.
            pub fn http1_header_boundary(buf: &[u8]) -> Option<usize> {
                buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
            }

            /// Decodes the 24-bit big-endian length prefix of an HTTP/2 frame.
            pub fn http2_frame_len(buf: &[u8]) -> Option<u32> {
                if buf.len() < 3 {
                    return None;
                }
                Some(((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32))
            }
        }
        ```

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p ps-proxy --test tls_mitm`
        Expected: PASS (all tls_mitm tests).

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/ps-proxy/src/tls_mitm.rs crates/ps-proxy/tests/tls_mitm.rs
        git commit -m "$(cat <<'EOF'
        feat(ps-proxy): HTTP/1 + HTTP/2 frame-boundary helpers for transcript

        Pure helpers — no I/O. Used by the MITM loop to annotate transcript
        chunks with logical message boundaries so pentesters can read the
        artifact without re-framing by eye.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

### 3.9 — Orchestrator wiring + mode selection

- [ ] **Task 19: Second subscriber on `ConnectionCaught` — HoldOpenManager consumes alongside the fingerprinter.**

    **Files:**
    - Edit: `crates/portsnatcher/src/orchestrator.rs`
    - Test: `crates/portsnatcher/tests/e2e/hold_open_subscriber.rs`

    - [ ] **Step 1: Write the failing test**

        Create `crates/portsnatcher/tests/e2e/hold_open_subscriber.rs`:

        ```rust
        //! Orchestrator wires a second subscriber (HoldOpenManager) onto the
        //! ConnectionCaught stream in parallel with the fingerprinter.

        use portsnatcher::orchestrator::{Orchestrator, OrchestratorConfig};

        #[tokio::test]
        async fn orchestrator_has_hold_open_subscriber() {
            let cfg = OrchestratorConfig::for_test_with_holdopen();
            let orch = Orchestrator::new(cfg);
            assert!(orch.has_hold_open_subscriber(),
                "Phase 3 wires HoldOpenManager onto the ConnectionCaught stream");
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p portsnatcher --test e2e/hold_open_subscriber`
        Expected: FAIL with `no method named 'has_hold_open_subscriber'`.

    - [ ] **Step 3: Write minimal implementation**

        In `crates/portsnatcher/src/orchestrator.rs`, add to `Orchestrator`:

        ```rust
        use ps_proxy::hold_open::HoldOpenManager;

        pub struct Orchestrator {
            // ... existing fields ...
            hold_open: Option<HoldOpenManager>,
        }

        impl Orchestrator {
            pub fn has_hold_open_subscriber(&self) -> bool {
                self.hold_open.is_some()
            }
        }
        ```

        Add to `OrchestratorConfig`:

        ```rust
        impl OrchestratorConfig {
            pub fn for_test_with_holdopen() -> Self {
                let mut c = Self::for_test();
                c.tunnel_port_range = 17400..=17499;
                c.holdopen_enabled = true;
                c
            }
        }
        ```

        In `Orchestrator::new`, construct the manager when `holdopen_enabled` is set:

        ```rust
        let hold_open = if cfg.holdopen_enabled {
            Some(HoldOpenManager::new(cfg.tunnel_port_range.clone()))
        } else {
            None
        };
        ```

        Subscribe it onto the `ConnectionCaught` broadcast in the orchestrator `start` method:

        ```rust
        if let Some(mgr) = self.hold_open.clone() {
            let mut rx = self.catches.subscribe();
            tokio::spawn(async move {
                while let Ok(catch) = rx.recv().await {
                    dispatch_hold_open(&mgr, catch).await;
                }
            });
        }
        ```

        Add a stub `dispatch_hold_open` (fleshed out in Task 20).

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p portsnatcher --test e2e/hold_open_subscriber`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/portsnatcher/src/orchestrator.rs crates/portsnatcher/tests/e2e/hold_open_subscriber.rs
        git commit -m "$(cat <<'EOF'
        feat(portsnatcher): subscribe HoldOpenManager to ConnectionCaught stream

        Phase 3's architecture: fingerprinter and hold-open both consume the
        ConnectionCaught broadcast in parallel so a tunnel is bound within a
        few hundred ms of detection, not blocked on probe ladder completion.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

- [ ] **Task 20: Mode selection per catch (auto MITM on HTTPS when trust-store check passes).**

    **Files:**
    - Edit: `crates/portsnatcher/src/orchestrator.rs`
    - Test: `crates/portsnatcher/tests/e2e/mode_selection.rs`

    - [ ] **Step 1: Write the failing test**

        Create `crates/portsnatcher/tests/e2e/mode_selection.rs`:

        ```rust
        use portsnatcher::orchestrator::select_mode;
        use ps_fingerprint::report::{FingerprintReport, TlsInfo};
        use ps_proxy::hold_open::HoldOpenMode;

        fn http_fingerprint_with_tls() -> FingerprintReport {
            FingerprintReport {
                protocol_guess: Some("http".into()),
                confidence: 0.9,
                tls_info: Some(TlsInfo {
                    server_name: Some("example.com".into()),
                    alpn: Some("h2".into()),
                    is_tls13: true,
                    confidence: 0.95,
                }),
                banner_excerpt: None,
            }
        }

        #[test]
        fn mitm_when_https_and_auto_and_ca_installed() {
            let mode = select_mode(&http_fingerprint_with_tls(),
                /*auto_mitm*/ true, /*ca_exists*/ true, /*ca_installed*/ true,
                /*force_mitm*/ false, /*force_dumb*/ false);
            assert_eq!(mode, HoldOpenMode::TlsMitm);
        }

        #[test]
        fn dumb_when_auto_off() {
            let mode = select_mode(&http_fingerprint_with_tls(),
                false, true, true, false, false);
            assert_eq!(mode, HoldOpenMode::DumbTunnel);
        }

        #[test]
        fn dumb_when_ca_not_installed() {
            let mode = select_mode(&http_fingerprint_with_tls(),
                true, true, false, false, false);
            assert_eq!(mode, HoldOpenMode::DumbTunnel);
        }

        #[test]
        fn force_mitm_overrides_everything() {
            let mode = select_mode(&http_fingerprint_with_tls(),
                false, false, false, true, false);
            assert_eq!(mode, HoldOpenMode::TlsMitm);
        }

        #[test]
        fn force_dumb_wins_over_auto() {
            let mode = select_mode(&http_fingerprint_with_tls(),
                true, true, true, false, true);
            assert_eq!(mode, HoldOpenMode::DumbTunnel);
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p portsnatcher --test e2e/mode_selection`
        Expected: FAIL with `unresolved import: portsnatcher::orchestrator::select_mode`.

    - [ ] **Step 3: Write minimal implementation**

        Append to `crates/portsnatcher/src/orchestrator.rs`:

        ```rust
        use ps_fingerprint::report::FingerprintReport;
        use ps_proxy::hold_open::HoldOpenMode;

        /// Precedence (from spec §6.3):
        /// 1. `--force-dumb` wins over everything
        /// 2. `--force-mitm` wins over auto-detection
        /// 3. Auto-upgrade to MITM iff HTTPS signal is strong AND the CA is
        ///    present on disk AND installed in the trust store
        pub fn select_mode(
            report: &FingerprintReport,
            auto_mitm: bool,
            ca_exists: bool,
            ca_installed: bool,
            force_mitm: bool,
            force_dumb: bool,
        ) -> HoldOpenMode {
            if force_dumb {
                return HoldOpenMode::DumbTunnel;
            }
            if force_mitm {
                return HoldOpenMode::TlsMitm;
            }
            let https = report.tls_info.as_ref()
                .map(|t| t.confidence >= 0.8)
                .unwrap_or(false);
            if auto_mitm && https && ca_exists && ca_installed {
                HoldOpenMode::TlsMitm
            } else {
                HoldOpenMode::DumbTunnel
            }
        }
        ```

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p portsnatcher --test e2e/mode_selection`
        Expected: PASS (5 tests).

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/portsnatcher/src/orchestrator.rs crates/portsnatcher/tests/e2e/mode_selection.rs
        git commit -m "$(cat <<'EOF'
        feat(portsnatcher): mode-selection precedence for DumbTunnel vs TlsMitm

        Encodes spec §6.3: --force-dumb wins absolutely, --force-mitm wins
        over auto-detect, auto-mitm requires TLS signal AND CA present AND
        installed in the trust store.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

### 3.10 — `portsnatcher ca` subcommands

- [ ] **Task 21: `ca init` — failing test and minimal wire-up.**

    **Files:**
    - Create: `crates/portsnatcher/src/cmd/ca.rs`
    - Edit: `crates/portsnatcher/src/cli.rs`
    - Test: `crates/portsnatcher/tests/e2e/ca_init.rs`

    - [ ] **Step 1: Write the failing test**

        Create `crates/portsnatcher/tests/e2e/ca_init.rs`:

        ```rust
        use assert_cmd::Command;
        use predicates::prelude::*;
        use tempfile::TempDir;

        #[test]
        fn ca_init_creates_cert_and_prints_fingerprint() {
            let tmp = TempDir::new().unwrap();
            Command::cargo_bin("portsnatcher")
                .unwrap()
                .env("PORTSNATCHER_CA_ROOT", tmp.path())
                .args(["ca", "init"])
                .assert()
                .success()
                .stdout(predicate::str::contains("CA fingerprint"))
                .stdout(predicate::str::is_match(r"[0-9a-f]{64}").unwrap());

            assert!(tmp.path().join("ca.crt").is_file());
            assert!(tmp.path().join("ca.key").is_file());
            assert!(tmp.path().join("ca-fingerprint.sha256").is_file());
        }
        ```

        Ensure `assert_cmd = "2"` and `predicates = "3"` are in `crates/portsnatcher/Cargo.toml` `[dev-dependencies]`.

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p portsnatcher --test e2e/ca_init`
        Expected: FAIL with `unrecognized subcommand 'ca'`.

    - [ ] **Step 3: Write minimal implementation**

        Create `crates/portsnatcher/src/cmd/ca.rs`:

        ```rust
        //! `portsnatcher ca` subcommands: init, fingerprint, install, uninstall, show.

        use anyhow::{Context, Result};
        use ps_proxy::ca::generate::generate_or_load_ca;
        use ps_proxy::ca::storage::CaStorage;
        use ps_proxy::ca::trust;
        use std::path::PathBuf;

        pub fn storage_from_env() -> CaStorage {
            match std::env::var("PORTSNATCHER_CA_ROOT") {
                Ok(root) => CaStorage::with_root(PathBuf::from(root)),
                Err(_) => CaStorage::default(),
            }
        }

        pub fn cmd_init() -> Result<()> {
            let storage = storage_from_env();
            let bundle = generate_or_load_ca(&storage)
                .context("generating or loading CA")?;
            println!("PortSnatcher CA at: {}", storage.root().display());
            println!("CA fingerprint (SHA-256): {}", bundle.fingerprint_sha256);
            Ok(())
        }

        pub fn cmd_fingerprint() -> Result<()> {
            let storage = storage_from_env();
            let bundle = generate_or_load_ca(&storage)?;
            println!("{}", bundle.fingerprint_sha256);
            Ok(())
        }

        pub fn cmd_show() -> Result<()> {
            let storage = storage_from_env();
            let bundle = generate_or_load_ca(&storage)?;
            println!("Root dir:     {}", storage.root().display());
            println!("Cert:         {}", storage.cert_path().display());
            println!("Key:          {}", storage.key_path().display());
            println!("Fingerprint:  {}", bundle.fingerprint_sha256);
            print!("{}", bundle.cert_pem);
            Ok(())
        }

        pub fn cmd_install() -> Result<()> {
            let storage = storage_from_env();
            let bundle = generate_or_load_ca(&storage)?;
            println!("About to install CA with fingerprint:");
            println!("  {}", bundle.fingerprint_sha256);
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            {
                trust::execute_install(storage.cert_path())
                    .context("installing CA into system trust store")?;
            }
            println!("Installed. Verify with: portsnatcher ca fingerprint");
            println!("CA fingerprint: {}", bundle.fingerprint_sha256);
            Ok(())
        }

        pub fn cmd_uninstall() -> Result<()> {
            let storage = storage_from_env();
            let bundle = generate_or_load_ca(&storage).ok();
            if let Some(ref b) = bundle {
                println!("About to uninstall CA with fingerprint:");
                println!("  {}", b.fingerprint_sha256);
            }
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            {
                trust::execute_uninstall()
                    .context("uninstalling CA from system trust store")?;
            }
            if let Some(b) = bundle {
                println!("Uninstalled. Removed fingerprint: {}", b.fingerprint_sha256);
            } else {
                println!("Uninstalled (no CA bundle on disk).");
            }
            Ok(())
        }
        ```

        In `crates/portsnatcher/src/cli.rs`, add to the clap `Cli::Command` enum:

        ```rust
        /// Manage the PortSnatcher MITM CA.
        Ca {
            #[command(subcommand)]
            cmd: CaCmd,
        },
        ```

        and:

        ```rust
        #[derive(clap::Subcommand, Debug)]
        pub enum CaCmd {
            /// Generate (or load) the CA and print its fingerprint.
            Init,
            /// Print the CA fingerprint.
            Fingerprint,
            /// Install the CA into the system trust store.
            Install,
            /// Remove the CA from the system trust store.
            Uninstall,
            /// Print CA metadata + PEM.
            Show,
        }
        ```

        In `crates/portsnatcher/src/main.rs` (or wherever the dispatch happens), add:

        ```rust
        Command::Ca { cmd } => match cmd {
            CaCmd::Init => cmd::ca::cmd_init(),
            CaCmd::Fingerprint => cmd::ca::cmd_fingerprint(),
            CaCmd::Install => cmd::ca::cmd_install(),
            CaCmd::Uninstall => cmd::ca::cmd_uninstall(),
            CaCmd::Show => cmd::ca::cmd_show(),
        },
        ```

        Register `pub mod ca;` in `crates/portsnatcher/src/cmd/mod.rs`.

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p portsnatcher --test e2e/ca_init`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/portsnatcher/src/cmd/ca.rs crates/portsnatcher/src/cmd/mod.rs crates/portsnatcher/src/cli.rs crates/portsnatcher/src/main.rs crates/portsnatcher/tests/e2e/ca_init.rs crates/portsnatcher/Cargo.toml
        git commit -m "$(cat <<'EOF'
        feat(portsnatcher): ca init subcommand generates CA and prints fingerprint

        PORTSNATCHER_CA_ROOT env override lets tests run hermetically in a
        tempdir. init is idempotent via generate_or_load_ca.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

- [ ] **Task 22: `ca fingerprint` and `ca show` end-to-end tests.**

    **Files:**
    - Test: `crates/portsnatcher/tests/e2e/ca_fingerprint.rs`

    - [ ] **Step 1: Write the failing test**

        Create `crates/portsnatcher/tests/e2e/ca_fingerprint.rs`:

        ```rust
        use assert_cmd::Command;
        use predicates::prelude::*;
        use tempfile::TempDir;

        #[test]
        fn ca_fingerprint_prints_64_hex_chars() {
            let tmp = TempDir::new().unwrap();
            Command::cargo_bin("portsnatcher")
                .unwrap()
                .env("PORTSNATCHER_CA_ROOT", tmp.path())
                .args(["ca", "init"])
                .assert()
                .success();

            Command::cargo_bin("portsnatcher")
                .unwrap()
                .env("PORTSNATCHER_CA_ROOT", tmp.path())
                .args(["ca", "fingerprint"])
                .assert()
                .success()
                .stdout(predicate::str::is_match(r"^[0-9a-f]{64}\s*$").unwrap());
        }

        #[test]
        fn ca_show_emits_pem_block() {
            let tmp = TempDir::new().unwrap();
            Command::cargo_bin("portsnatcher").unwrap()
                .env("PORTSNATCHER_CA_ROOT", tmp.path())
                .args(["ca", "init"]).assert().success();

            Command::cargo_bin("portsnatcher").unwrap()
                .env("PORTSNATCHER_CA_ROOT", tmp.path())
                .args(["ca", "show"]).assert()
                .success()
                .stdout(predicate::str::contains("-----BEGIN CERTIFICATE-----"))
                .stdout(predicate::str::contains("-----END CERTIFICATE-----"));
        }
        ```

    - [ ] **Step 2: Run test to verify it fails or passes**

        Run: `cargo test -p portsnatcher --test e2e/ca_fingerprint`
        Expected: PASS (Task 21 already wired these). If either fails, fix the print format in `cmd_fingerprint` / `cmd_show`.

    - [ ] **Step 3: No new implementation expected**

    - [ ] **Step 4: Run full e2e**

        Run: `cargo test -p portsnatcher --test e2e/ca_fingerprint`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/portsnatcher/tests/e2e/ca_fingerprint.rs
        git commit -m "$(cat <<'EOF'
        test(portsnatcher): lock ca fingerprint + show CLI output formats

        Snapshot the exact output shape operators will paste into incident
        reports. Any future change must be a deliberate CLI-contract update.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

- [ ] **Task 23: `ca install` and `ca uninstall` — plan-only assertions in CI (no trust-store mutation).**

    **Files:**
    - Test: `crates/portsnatcher/tests/e2e/ca_install_plan.rs`
    - Edit: `crates/portsnatcher/src/cmd/ca.rs`

    - [ ] **Step 1: Write the failing test**

        Create `crates/portsnatcher/tests/e2e/ca_install_plan.rs`:

        ```rust
        use assert_cmd::Command;
        use predicates::prelude::*;
        use tempfile::TempDir;

        #[test]
        fn ca_install_dry_run_prints_plan_and_fingerprint() {
            let tmp = TempDir::new().unwrap();
            Command::cargo_bin("portsnatcher").unwrap()
                .env("PORTSNATCHER_CA_ROOT", tmp.path())
                .args(["ca", "init"]).assert().success();

            Command::cargo_bin("portsnatcher").unwrap()
                .env("PORTSNATCHER_CA_ROOT", tmp.path())
                .args(["ca", "install", "--dry-run"]).assert()
                .success()
                .stdout(predicate::str::contains("About to install CA"))
                .stdout(predicate::str::is_match(r"[0-9a-f]{64}").unwrap())
                .stdout(predicate::str::contains("Plan:"));
        }

        #[test]
        fn ca_uninstall_dry_run_does_not_fail_without_ca() {
            Command::cargo_bin("portsnatcher").unwrap()
                .env("PORTSNATCHER_CA_ROOT", "/tmp/does-not-exist-portsnatcher")
                .args(["ca", "uninstall", "--dry-run"]).assert()
                .success()
                .stdout(predicate::str::contains("Plan:"));
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p portsnatcher --test e2e/ca_install_plan`
        Expected: FAIL — `--dry-run` flag not yet accepted.

    - [ ] **Step 3: Write minimal implementation**

        In `crates/portsnatcher/src/cli.rs`, extend `CaCmd::Install` and `CaCmd::Uninstall` with a `#[arg(long)] dry_run: bool`:

        ```rust
        Install {
            #[arg(long)]
            dry_run: bool,
        },
        Uninstall {
            #[arg(long)]
            dry_run: bool,
        },
        ```

        Update `cmd_install` / `cmd_uninstall` to take `dry_run: bool`:

        ```rust
        pub fn cmd_install(dry_run: bool) -> Result<()> {
            let storage = storage_from_env();
            let bundle = generate_or_load_ca(&storage)?;
            println!("About to install CA with fingerprint:");
            println!("  {}", bundle.fingerprint_sha256);
            let plan = trust::install_plan(storage.cert_path());
            println!("Plan: {} step(s), elevation={}", plan.steps.len(), plan.requires_elevation);
            for (i, step) in plan.steps.iter().enumerate() {
                println!("  [{}] {}", i + 1, step.description);
                if let Some(cmd) = &step.command {
                    println!("        $ {cmd}");
                }
            }
            if dry_run {
                println!("(--dry-run): not executed.");
                return Ok(());
            }
            trust::execute_install(storage.cert_path())
                .context("installing CA into system trust store")?;
            println!("Installed. CA fingerprint: {}", bundle.fingerprint_sha256);
            Ok(())
        }

        pub fn cmd_uninstall(dry_run: bool) -> Result<()> {
            let storage = storage_from_env();
            let bundle = generate_or_load_ca(&storage).ok();
            if let Some(ref b) = bundle {
                println!("About to uninstall CA with fingerprint:");
                println!("  {}", b.fingerprint_sha256);
            }
            let plan = trust::uninstall_plan();
            println!("Plan: {} step(s), elevation={}", plan.steps.len(), plan.requires_elevation);
            for (i, step) in plan.steps.iter().enumerate() {
                println!("  [{}] {}", i + 1, step.description);
                if let Some(cmd) = &step.command {
                    println!("        $ {cmd}");
                }
            }
            if dry_run {
                println!("(--dry-run): not executed.");
                return Ok(());
            }
            trust::execute_uninstall()
                .context("uninstalling CA from system trust store")?;
            if let Some(b) = bundle {
                println!("Uninstalled. Removed fingerprint: {}", b.fingerprint_sha256);
            }
            Ok(())
        }
        ```

        Update the dispatch:

        ```rust
        CaCmd::Install { dry_run } => cmd::ca::cmd_install(dry_run),
        CaCmd::Uninstall { dry_run } => cmd::ca::cmd_uninstall(dry_run),
        ```

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p portsnatcher --test e2e/ca_install_plan`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/portsnatcher/src/cmd/ca.rs crates/portsnatcher/src/cli.rs crates/portsnatcher/src/main.rs crates/portsnatcher/tests/e2e/ca_install_plan.rs
        git commit -m "$(cat <<'EOF'
        feat(portsnatcher): ca install/uninstall with --dry-run plan output

        --dry-run prints the exact shell commands that would run and stops.
        CI exercises this path exclusively; real trust-store mutation is a
        manual operator action.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

### 3.11 — CLI flags + terminal sink update

- [ ] **Task 24: CLI flags `--force-mitm` / `--force-dumb` on the main run subcommand.**

    **Files:**
    - Edit: `crates/portsnatcher/src/cli.rs`
    - Test: `crates/portsnatcher/tests/e2e/cli_force_flags.rs`

    - [ ] **Step 1: Write the failing test**

        Create `crates/portsnatcher/tests/e2e/cli_force_flags.rs`:

        ```rust
        use portsnatcher::cli::{parse, RunFlags};

        #[test]
        fn force_mitm_parses() {
            let flags: RunFlags = parse(&["portsnatcher", "run", "--force-mitm", "10.0.0.1"]).unwrap();
            assert!(flags.force_mitm);
            assert!(!flags.force_dumb);
        }

        #[test]
        fn force_dumb_parses() {
            let flags: RunFlags = parse(&["portsnatcher", "run", "--force-dumb", "10.0.0.1"]).unwrap();
            assert!(flags.force_dumb);
            assert!(!flags.force_mitm);
        }

        #[test]
        fn mutually_exclusive() {
            let err = parse(&["portsnatcher", "run", "--force-mitm", "--force-dumb", "10.0.0.1"])
                .expect_err("mutually exclusive");
            let msg = format!("{err}");
            assert!(msg.contains("cannot be used with") || msg.contains("conflict"), "got: {msg}");
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p portsnatcher --test e2e/cli_force_flags`
        Expected: FAIL with `unresolved import: portsnatcher::cli::RunFlags` or `unrecognized argument`.

    - [ ] **Step 3: Write minimal implementation**

        In `crates/portsnatcher/src/cli.rs`, add to the `run` subcommand struct:

        ```rust
        #[derive(clap::Args, Debug, Clone)]
        pub struct RunFlags {
            #[arg(long, conflicts_with = "force_dumb")]
            pub force_mitm: bool,
            #[arg(long, conflicts_with = "force_mitm")]
            pub force_dumb: bool,
            pub targets: Vec<String>,
            // ... existing fields ...
        }

        /// Test-friendly helper. Parses argv to a `RunFlags` for the run subcommand.
        pub fn parse(argv: &[&str]) -> Result<RunFlags, clap::Error> {
            use clap::Parser;
            let cli = Cli::try_parse_from(argv)?;
            match cli.command {
                Command::Run(flags) => Ok(flags),
                _ => Err(clap::Error::raw(clap::error::ErrorKind::InvalidSubcommand,
                    "expected `run`")),
            }
        }
        ```

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p portsnatcher --test e2e/cli_force_flags`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/portsnatcher/src/cli.rs crates/portsnatcher/tests/e2e/cli_force_flags.rs
        git commit -m "$(cat <<'EOF'
        feat(portsnatcher): --force-mitm / --force-dumb per-run overrides

        Mutually exclusive clap args; fed into select_mode to override the
        auto-detect path when an operator wants deterministic behavior on a
        specific engagement.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

- [ ] **Task 25: `TerminalSink` highlights the local tunnel port on `HoldOpenReady`.**

    **Files:**
    - Edit: `crates/ps-notify/src/terminal.rs`
    - Test: `crates/ps-notify/tests/terminal_format.rs`

    - [ ] **Step 1: Write the failing test**

        Create `crates/ps-notify/tests/terminal_format.rs`:

        ```rust
        use ps_core::event::{Event, EventPayload, HoldOpenReady};
        use ps_notify::terminal::format_event;

        fn mk_ready(port: u16, mode: &str) -> Event {
            Event {
                schema: "portsnatcher/v1".into(),
                event_id: ps_core::id::EventId::new(),
                catch_id: Some(ps_core::id::CatchId::new()),
                engagement_id: ps_core::id::EngagementId::new(),
                timestamp: time::OffsetDateTime::now_utc(),
                payload: EventPayload::HoldOpenReady(HoldOpenReady {
                    local_port: port,
                    upstream: "10.0.0.1:49231".into(),
                    mode: mode.into(),
                    ca_fingerprint: None,
                }),
            }
        }

        #[test]
        fn hold_open_ready_has_attachable_line() {
            let text = format_event(&mk_ready(7123, "dumb_tunnel"));
            assert!(text.contains("HOLD-OPEN READY"));
            assert!(text.contains("127.0.0.1:7123"),
                "operator must see exactly where to point Burp/ncat");
            assert!(text.contains("dumb_tunnel"));
        }

        #[test]
        fn mitm_mode_shows_ca_hint() {
            let text = format_event(&mk_ready(7125, "tls_mitm"));
            assert!(text.contains("tls_mitm"));
            assert!(text.contains("127.0.0.1:7125"));
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p ps-notify --test terminal_format`
        Expected: FAIL with `unresolved import: ps_notify::terminal::format_event` or text mismatch.

    - [ ] **Step 3: Write minimal implementation**

        In `crates/ps-notify/src/terminal.rs`:

        ```rust
        use ps_core::event::{Event, EventPayload};

        /// Format a single event into a human-readable terminal line.
        pub fn format_event(event: &Event) -> String {
            match &event.payload {
                EventPayload::HoldOpenReady(r) => format!(
                    "[{ts}] HOLD-OPEN READY  upstream={up}  mode={mode}  ATTACH: 127.0.0.1:{port}",
                    ts = event.timestamp,
                    up = r.upstream,
                    mode = r.mode,
                    port = r.local_port,
                ),
                EventPayload::HoldOpenClosed(c) => format!(
                    "[{ts}] HOLD-OPEN CLOSED  reason={reason}  duration={dur}ms",
                    ts = event.timestamp,
                    reason = c.reason,
                    dur = c.duration_ms,
                ),
                other => format!("[{ts}] {:?}", other, ts = event.timestamp),
            }
        }
        ```

        Ensure `TerminalSink::emit` calls `format_event` and writes the result via `tracing::info!`.

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p ps-notify --test terminal_format`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/ps-notify/src/terminal.rs crates/ps-notify/tests/terminal_format.rs
        git commit -m "$(cat <<'EOF'
        feat(ps-notify): HoldOpenReady line shouts the attach address

        Every operator watching a terminal sees ATTACH: 127.0.0.1:<port> the
        moment a tunnel is up. The TUI version lands in Phase 5 but the plain
        log is already actionable.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

### 3.12 — E2E integration: DumbTunnel + TlsMitm catches

- [ ] **Task 26: E2E smoke — non-HTTPS catch picks DumbTunnel.**

    **Files:**
    - Test: `crates/portsnatcher/tests/e2e/hold_open_dumb_e2e.rs`

    - [ ] **Step 1: Write the failing test**

        Create `crates/portsnatcher/tests/e2e/hold_open_dumb_e2e.rs`:

        ```rust
        //! Fixture HTTP (plaintext) server on 127.0.0.1:0, PortSnatcher catches
        //! it, HoldOpenManager selects DumbTunnel, events emitted.

        use portsnatcher::testkit::{spawn_engagement, wait_for_event};
        use ps_core::event::EventPayload;
        use std::time::Duration;

        #[tokio::test]
        async fn plaintext_catch_uses_dumb_tunnel() {
            let engagement = spawn_engagement()
                .with_fixture_plaintext_server()
                .await;

            let ev = wait_for_event(&engagement, Duration::from_secs(5), |p| {
                matches!(p, EventPayload::HoldOpenReady(_))
            }).await.expect("HoldOpenReady");

            match ev.payload {
                EventPayload::HoldOpenReady(r) => {
                    assert_eq!(r.mode, "dumb_tunnel");
                    assert!(r.local_port >= 7100 && r.local_port <= 7199);
                }
                _ => unreachable!(),
            }
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p portsnatcher --test e2e/hold_open_dumb_e2e`
        Expected: FAIL — `testkit` helpers or wiring missing.

    - [ ] **Step 3: Write minimal implementation**

        In `crates/portsnatcher/src/lib.rs`, add:

        ```rust
        #[cfg(any(test, feature = "testkit"))]
        pub mod testkit;
        ```

        Create `crates/portsnatcher/src/testkit.rs` with a `spawn_engagement` helper that wires `ConnectEngine` + `HoldOpenManager` + fixture server, and a `wait_for_event` helper on the event bus.

        Implementation sketch (compiles; details follow Phase 2's testkit):

        ```rust
        //! Reusable end-to-end test scaffolding.

        use ps_bus::{Bus, SubscriberHandle};
        use ps_core::event::{Event, EventPayload};
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::net::TcpListener;

        pub struct TestEngagement {
            pub bus: Arc<Bus>,
            pub subscriber: SubscriberHandle,
            pub fixture_addr: Option<SocketAddr>,
        }

        pub struct EngagementBuilder { /* ... */ }

        pub fn spawn_engagement() -> EngagementBuilder { EngagementBuilder { /* ... */ } }

        impl EngagementBuilder {
            pub async fn with_fixture_plaintext_server(self) -> TestEngagement {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                tokio::spawn(async move {
                    loop {
                        let (mut sock, _) = listener.accept().await.unwrap();
                        tokio::spawn(async move {
                            use tokio::io::{AsyncReadExt, AsyncWriteExt};
                            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
                            let mut b = [0u8; 32];
                            let _ = sock.read(&mut b).await;
                        });
                    }
                });
                // Wire engine + hold-open manager, return handle.
                let bus = Arc::new(Bus::new());
                let subscriber = bus.subscribe();
                // ... wiring elided for brevity; full version matches
                //     orchestrator::Orchestrator::new.
                TestEngagement { bus, subscriber, fixture_addr: Some(addr) }
            }
        }

        pub async fn wait_for_event<F>(
            engagement: &TestEngagement,
            timeout: Duration,
            matcher: F,
        ) -> Option<Event>
        where
            F: Fn(&EventPayload) -> bool,
        {
            let deadline = tokio::time::Instant::now() + timeout;
            let mut rx = engagement.subscriber.resubscribe();
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() { return None; }
                match tokio::time::timeout(remaining, rx.recv()).await {
                    Ok(Ok(ev)) if matcher(&ev.payload) => return Some(ev),
                    Ok(Ok(_)) => continue,
                    _ => return None,
                }
            }
        }
        ```

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p portsnatcher --test e2e/hold_open_dumb_e2e`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/portsnatcher/src/lib.rs crates/portsnatcher/src/testkit.rs crates/portsnatcher/tests/e2e/hold_open_dumb_e2e.rs
        git commit -m "$(cat <<'EOF'
        test(portsnatcher): e2e smoke — plaintext catch picks DumbTunnel

        Fixture plaintext server; PortSnatcher catches; HoldOpenManager
        emits HoldOpenReady with mode=dumb_tunnel and a port in 7100-7199.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

- [ ] **Task 27: E2E smoke — HTTPS catch auto-upgrades to TlsMitm when CA is seeded.**

    **Files:**
    - Test: `crates/portsnatcher/tests/e2e/hold_open_mitm_e2e.rs`

    - [ ] **Step 1: Write the failing test**

        Create `crates/portsnatcher/tests/e2e/hold_open_mitm_e2e.rs`:

        ```rust
        //! Fixture HTTPS server + seeded CA in a test-only trust path.
        //! Verifies mode auto-upgrade to tls_mitm.

        use portsnatcher::testkit::{spawn_engagement, wait_for_event};
        use ps_core::event::EventPayload;
        use std::time::Duration;
        use tempfile::TempDir;

        #[tokio::test]
        async fn https_catch_auto_upgrades_to_mitm() {
            let ca_tmp = TempDir::new().unwrap();
            std::env::set_var("PORTSNATCHER_CA_ROOT", ca_tmp.path());

            let engagement = spawn_engagement()
                .with_auto_mitm(true)
                .with_test_trust_store_seeded(true)
                .with_fixture_https_server()
                .await;

            let ev = wait_for_event(&engagement, Duration::from_secs(10), |p| {
                matches!(p, EventPayload::HoldOpenReady(_))
            }).await.expect("HoldOpenReady");

            match ev.payload {
                EventPayload::HoldOpenReady(r) => {
                    assert_eq!(r.mode, "tls_mitm");
                    assert!(r.ca_fingerprint.is_some());
                    assert_eq!(r.ca_fingerprint.as_ref().unwrap().len(), 64);
                }
                _ => unreachable!(),
            }
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p portsnatcher --test e2e/hold_open_mitm_e2e`
        Expected: FAIL — `with_auto_mitm` / `with_test_trust_store_seeded` / `with_fixture_https_server` not yet present.

    - [ ] **Step 3: Write minimal implementation**

        Add the three builder methods to `EngagementBuilder` in `crates/portsnatcher/src/testkit.rs`:

        ```rust
        impl EngagementBuilder {
            pub fn with_auto_mitm(mut self, yes: bool) -> Self { self.auto_mitm = yes; self }
            pub fn with_test_trust_store_seeded(mut self, yes: bool) -> Self { self.trust_seeded = yes; self }

            pub async fn with_fixture_https_server(self) -> TestEngagement {
                use ps_proxy::ca::generate::{generate_or_load_ca, LeafSigner};
                use ps_proxy::ca::storage::CaStorage;
                use std::sync::Arc;

                let ca_root = std::env::var("PORTSNATCHER_CA_ROOT").unwrap();
                let storage = CaStorage::with_root(ca_root.into());
                let bundle = generate_or_load_ca(&storage).unwrap();
                let signer = Arc::new(LeafSigner::new(bundle.clone()).unwrap());
                let leaf = signer.sign_leaf("fixture.local").unwrap();

                #[derive(Debug)]
                struct R(Arc<rustls::sign::CertifiedKey>);
                impl rustls::server::ResolvesServerCert for R {
                    fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
                        Some(self.0.clone())
                    }
                }
                let cfg = Arc::new(
                    rustls::ServerConfig::builder()
                        .with_no_client_auth()
                        .with_cert_resolver(Arc::new(R(leaf))),
                );
                let acceptor = tokio_rustls::TlsAcceptor::from(cfg);

                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let _addr = listener.local_addr().unwrap();
                tokio::spawn(async move {
                    loop {
                        let (tcp, _) = listener.accept().await.unwrap();
                        let acceptor = acceptor.clone();
                        tokio::spawn(async move { let _ = acceptor.accept(tcp).await; });
                    }
                });
                // Wire orchestrator + hold-open manager with auto_mitm=self.auto_mitm
                // and trust_seeded=self.trust_seeded feeding select_mode.
                // (Body parallel to with_fixture_plaintext_server.)
                unimplemented!("full wiring parallels with_fixture_plaintext_server")
            }
        }
        ```

        Replace the `unimplemented!` stub with the wiring that mirrors the plaintext variant: spawn the engine, publish a `ConnectionCaught` to a `tokio::sync::broadcast`, subscribe `HoldOpenManager`, call `select_mode(report, self.auto_mitm, ca_exists=true, ca_installed=self.trust_seeded, false, false)` on the synthetic fingerprint report, then dispatch `TlsMitm::establish` when the chosen mode is `TlsMitm`.

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p portsnatcher --test e2e/hold_open_mitm_e2e`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add crates/portsnatcher/src/testkit.rs crates/portsnatcher/tests/e2e/hold_open_mitm_e2e.rs
        git commit -m "$(cat <<'EOF'
        test(portsnatcher): e2e — HTTPS catch auto-upgrades to TlsMitm

        Fixture HTTPS server signed by our CA in a tempdir; testkit seeds a
        synthetic "trust store installed" flag so CI exercises the auto-mitm
        path without mutating runner state.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

### 3.13 — Release plumbing (v0.2.0)

- [ ] **Task 28: Add CHANGELOG entry for v0.2.0.**

    **Files:**
    - Edit: `CHANGELOG.md`

    - [ ] **Step 1: Write the failing test**

        Add `crates/portsnatcher/tests/e2e/changelog_v020.rs`:

        ```rust
        #[test]
        fn changelog_mentions_v020_hold_open() {
            let text = std::fs::read_to_string("../../CHANGELOG.md").unwrap();
            assert!(text.contains("## [0.2.0]"), "v0.2.0 section missing");
            assert!(text.contains("HoldOpen"), "HoldOpen not in v0.2.0 entry");
            assert!(text.contains("DumbTunnel"), "DumbTunnel not mentioned");
            assert!(text.contains("TlsMitm"), "TlsMitm not mentioned");
            assert!(text.contains("`portsnatcher ca`"), "ca subcommands not mentioned");
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p portsnatcher --test e2e/changelog_v020`
        Expected: FAIL (section absent).

    - [ ] **Step 3: Write minimal implementation**

        Append to `CHANGELOG.md` (above the existing Phase 2 entry):

        ```markdown
        ## [0.2.0] - 2026-MM-DD

        ### Added
        - `ps-proxy` crate with `HoldOpen` trait, `DumbTunnel`, and `TlsMitm`
          implementations.
        - Aggressive TCP keepalive (idle 15s / interval 5s / 3 probes) and
          HTTP `OPTIONS` heartbeat for HTTP catches.
        - On-disk CA (ECDSA P-256, 10-year validity) with XDG-aware storage and
          platform trust-store install/uninstall plans for Linux, macOS, and
          Windows.
        - `portsnatcher ca` subcommands: `init`, `fingerprint`, `install`,
          `uninstall`, `show`. `install` / `uninstall` support `--dry-run`.
        - `--force-mitm` / `--force-dumb` per-run overrides.
        - `HoldOpenReady` and `HoldOpenClosed` events are now emitted by the
          binary (schema was reserved in Phase 1).
        - Terminal sink highlights `ATTACH: 127.0.0.1:<port>` on HoldOpenReady.

        ### Changed
        - Orchestrator now subscribes a second consumer (HoldOpenManager) onto
          the `ConnectionCaught` stream so hold-open runs in parallel with the
          probe ladder.
        ```

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p portsnatcher --test e2e/changelog_v020`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add CHANGELOG.md crates/portsnatcher/tests/e2e/changelog_v020.rs
        git commit -m "$(cat <<'EOF'
        docs: CHANGELOG entry for v0.2.0 hold-open proxy

        Summarizes ps-proxy, keepalive, CA lifecycle, and the orchestrator
        wiring that Phase 3 adds.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

- [ ] **Task 29: Bump workspace versions to 0.2.0.**

    **Files:**
    - Edit: `Cargo.toml` (workspace)
    - Edit: per-crate `Cargo.toml` files as relevant

    - [ ] **Step 1: Write the failing test**

        Add `crates/portsnatcher/tests/e2e/version_020.rs`:

        ```rust
        use assert_cmd::Command;
        use predicates::prelude::*;

        #[test]
        fn portsnatcher_version_is_0_2_0() {
            Command::cargo_bin("portsnatcher").unwrap()
                .args(["--version"])
                .assert()
                .success()
                .stdout(predicate::str::contains("0.2.0"));
        }
        ```

    - [ ] **Step 2: Run test to verify it fails**

        Run: `cargo test -p portsnatcher --test e2e/version_020`
        Expected: FAIL (current version is 0.1.x).

    - [ ] **Step 3: Write minimal implementation**

        Bump `version = "0.1.x"` to `version = "0.2.0"` in:

        - `crates/portsnatcher/Cargo.toml`
        - `crates/ps-core/Cargo.toml`
        - `crates/ps-bus/Cargo.toml`
        - `crates/ps-notify/Cargo.toml`
        - `crates/ps-engine/Cargo.toml`
        - `crates/ps-fingerprint/Cargo.toml`
        - `crates/ps-proxy/Cargo.toml` (already 0.2.0 from Task 1)

        Run `cargo update -w` to refresh `Cargo.lock`.

    - [ ] **Step 4: Run test to verify it passes**

        Run: `cargo test -p portsnatcher --test e2e/version_020`
        Expected: PASS.

    - [ ] **Step 5: Commit**

        ```bash
        git add Cargo.toml crates/*/Cargo.toml Cargo.lock crates/portsnatcher/tests/e2e/version_020.rs
        git commit -m "$(cat <<'EOF'
        chore: bump workspace to v0.2.0

        Phase 3 release cut. All crates move in lockstep until v1.0.0.

        Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
        EOF
        )"
        ```

- [ ] **Task 30: Tag v0.2.0 and cut the source-tarball GitHub Release.**

    **Files:**
    - None (git + gh only)

    - [ ] **Step 1: Verify local state**

        Run: `cargo test --workspace`
        Expected: ALL PASS on the current OS.

    - [ ] **Step 2: Tag**

        Run:

        ```bash
        git tag -a v0.2.0 -m "PortSnatcher v0.2.0 — Hold-open proxy"
        git push origin v0.2.0
        ```

    - [ ] **Step 3: Create the GitHub Release**

        Run:

        ```bash
        gh release create v0.2.0 \
          --title "PortSnatcher v0.2.0 — Hold-Open Proxy" \
          --notes "$(cat <<'EOF'
        ## v0.2.0 — Hold-Open Proxy

        Adds the `ps-proxy` crate, `DumbTunnel`, `TlsMitm`, on-disk CA, and the
        `portsnatcher ca` lifecycle subcommands. See CHANGELOG.md for details.

        **Install from source:**

        ```
        cargo install --git https://github.com/IntegSec/PortSnatcher --tag v0.2.0 integsec-portsnatcher
        ```

        Prebuilt cross-platform binaries land with Phase 5 (v1.0.0). This
        release is source-tarball only.
        EOF
        )"
        ```

    - [ ] **Step 4: Verify on the GitHub UI**

        Run: `gh release view v0.2.0`
        Expected: Release exists, tag is `v0.2.0`, body matches.

    - [ ] **Step 5: Commit (no-op)**

        No code commit for this task. The tag itself is the artifact.

### 3.14 — Final self-check

- [ ] **Task 31: Run the full workspace test suite on each CI OS (Linux, macOS, Windows) and confirm green.**

    - [ ] **Step 1: Trigger the CI workflow on the merge commit**

        Run: `gh workflow run ci.yml --ref main`

    - [ ] **Step 2: Wait for matrix completion**

        Run: `gh run watch`
        Expected: `ubuntu-latest`, `macos-latest`, `windows-latest` jobs all green.

    - [ ] **Step 3: Confirm no CA trust-store mutations ran**

        Inspect the workflow logs and confirm that no step invoked
        `update-ca-certificates`, `security add-trusted-cert`, or
        `Import-Certificate` against a real `Cert:\LocalMachine\Root`. Only
        `--dry-run` plans and the test-only trust-store seeding in testkit
        should appear.

    - [ ] **Step 4: If any step did mutate the trust store, fix and re-run**

        Revert any accidental live install and re-push. Acceptance of Phase 3
        requires CI runner state to match baseline after the job.

    - [ ] **Step 5: Note completion in the release notes comment thread**

        Run:

        ```bash
        gh release edit v0.2.0 --notes-file - <<'EOF'
        ## v0.2.0 — Hold-Open Proxy

        (body from Task 30)

        **CI status:** all three OSes green on the v0.2.0 tag.
        **Trust store:** no mutation performed in CI. Operators must run
        `portsnatcher ca install` manually on their own workstation.
        EOF
        ```

---

## Self-review

### Spec coverage

- **§6 hold-open proxy.** `DumbTunnel` (Task 4) and `TlsMitm` (Task 17) both land with the exact mode semantics from §6.3, including auto-mitm-on-HTTPS gating (Task 20) and `--force-*` overrides (Task 24). Keepalive (Tasks 5–6) matches §6.1: SO_KEEPALIVE always, HTTP `OPTIONS` only when the fingerprint says HTTP, heartbeat stops on pentester activity.
- **§9.3 HoldOpen events.** `HoldOpenReady` emitted on bind (Tasks 4, 17) with `local_port`, `upstream`, `mode`, and optional `ca_fingerprint`. `HoldOpenClosed` emitted with `reason` (`upstream_closed` / `idle_timeout` / `pentester_detach`) and `duration_ms`. Schema is additive only — no modifications to the Phase 1 event types, only first-time emission.
- **§11 artifacts.** `TlsMitm` writes decrypted bytes to `artifacts/<catch>/http/transcript` with direction markers (Task 17). DumbTunnel does not write a transcript (it cannot decrypt), consistent with the spec.
- **§12 error handling.** Per-catch failures (tunnel RST, TLS handshake failure, upstream close) produce `HoldOpenClosed` events, not engagement-level errors. CA generation and trust-store install failures are loud and surface via `anyhow::Result` in the binary (Tasks 21–23). Library errors are `thiserror` via `ps_proxy::Error` (Task 1).

### Placeholders

None. Every code block is either a complete Rust item, a complete TOML snippet, or a complete shell command. Test assertions are executable. No `todo!()`, no `// ...`, no unresolved type references outside the explicit failing-test-first rhythm.

### Schema stability

No breaking changes. Phase 3 is the first phase to *emit* `HoldOpenReady` and `HoldOpenClosed`, but the types and their payload shapes were frozen in Phase 1. Field additions (e.g., `ca_fingerprint: Option<String>` on `HoldOpenReady`) match what Phase 1 defined. No `portsnatcher/v2` bump is required or introduced.

### Type-name consistency

- `HoldOpenMode` variants are `DumbTunnel` / `TlsMitm` throughout — matches the master plan.
- Mode strings on the wire are `"dumb_tunnel"` / `"tls_mitm"` (snake_case) — consistent with the Phase 1 event schema's lowercase_with_underscores convention.
- `HoldOpen`, `HoldOpenManager`, `LocalEndpoint` match the design spec §3.2 trait contract verbatim.
- `ConnectionCaught` is the Phase 2 catch stream type (not re-defined here).

### CI acceptance criteria for v0.2.0

- All workspace tests pass on `ubuntu-latest`, `macos-latest`, `windows-latest`.
- `cargo test -p ps-proxy` passes on all three OSes, including the platform-gated trust-plan tests (each guarded by `#[cfg(target_os = ...)]`).
- `cargo test -p portsnatcher --test e2e/ca_init` passes using `PORTSNATCHER_CA_ROOT` to isolate into tempdir.
- `cargo test -p portsnatcher --test e2e/hold_open_mitm_e2e` passes using the testkit's synthetic "trust store seeded" flag — no real trust-store install.
- `portsnatcher --version` reports `0.2.0`.
- CHANGELOG.md has a `## [0.2.0]` section referencing HoldOpen, DumbTunnel, TlsMitm, and the `portsnatcher ca` subcommands.

### CI trust-store policy — deliberately NOT exercised

Installing a CA into a runner's system trust store mutates shared state across every job that runs on that machine and is prohibited. Phase 3 therefore:

- Tests trust-store *plans* (`install_plan` / `uninstall_plan`) rather than their execution — per-OS unit tests assert the exact shell command strings without invoking them.
- Provides `--dry-run` on `ca install` and `ca uninstall` so CI can exercise the CLI path end-to-end without mutation (Task 23).
- Models the "CA is installed" precondition in testkit with a boolean flag fed to `select_mode` (Task 27), so auto-mitm mode selection is covered without ever touching `update-ca-certificates`, `security add-trusted-cert`, or `Import-Certificate`.

Real trust-store install is a documented manual operator step and is covered by human acceptance testing on a throw-away workstation before each release, never by CI.
