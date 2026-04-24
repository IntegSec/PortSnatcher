//! RawEngine's userspace backend.
//!
//! # Platform behaviour
//!
//! - **Linux (v1.2+):** delegates to [`crate::raw::syn_race::SynRace`] —
//!   a real AF_PACKET SYN spray + pcap SYN-ACK receive + kernel-connect
//!   handoff. Sub-100ms detection of ephemeral ports. Requires
//!   `CAP_NET_RAW`. Falls back to the connect-labelled scheduler below
//!   if SynRace's startup fails for any reason.
//!
//! - **macOS / Windows:** still the connect-labelled-raw scheduler. The
//!   v1.3+ plan is a BPF (macOS) and WinDivert-driven (Windows) port of
//!   SynRace. Until then we warn loudly that the "raw" label is nominal
//!   on these platforms.
//!
//! The common `start()` entry point probes raw-socket capability
//! up-front so callers see a single consistent error surface when the
//! process lacks the privileges the engine needs.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use futures::stream::{FuturesUnordered, StreamExt};
use futures::FutureExt;
use ps_bus::broadcast::BusSender;
use ps_core::engagement::Engagement;
use ps_core::event::payload::{EventBody, ScopeViolationBlocked};
use ps_core::event::Event;
use ps_core::target::Target;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::timeout;

use crate::engine::{ConnectionCaught, EngineCapabilities, EngineContext, EngineHandle};

/// Greppable marker for the v1.2 Linux integration. On macOS/Windows
/// this is still a documented simplification; the marker lets reviewers
/// `grep BACKEND_STATUS` to audit the real state per platform.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub const BACKEND_STATUS: &str =
    "linux: SynRace (pnet raw SYN spray + pcap + connect handoff) since v1.2";

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub const BACKEND_STATUS: &str =
    "non-linux: connect-labelled-raw scheduler; smoltcp/BPF/WinDivert port is v1.3+";

const CONNECT_TIMEOUT: Duration = Duration::from_millis(800);
const IDLE_SLEEP: Duration = Duration::from_millis(5);
const INITIAL_BACKOFF_MS: u64 = 100;
const MAX_BACKOFF_MS: u64 = 32_000;

/// Opaque handle for the userspace backend. Wraps the stop signal.
///
/// Held inside `raw::Backend::Userspace` so the `RawEngine` carries
/// whichever backend was picked at `start()` time.
pub struct Handle {
    /// `watch::Sender` used to signal the scheduler loop to stop.
    /// Kept public-in-crate so `raw::engine` can inspect it if needed.
    #[allow(dead_code)]
    pub(crate) stop_tx: watch::Sender<bool>,
}

/// Probe whether we can open a raw socket. Returns `Ok(())` if we can,
/// `Err` with the underlying OS error otherwise. The socket is closed
/// immediately — this is a pure capability probe.
///
/// On Linux this typically requires `CAP_NET_RAW`. On macOS it requires
/// root. On Windows it requires Administrator (even then, some OS
/// revisions restrict raw TCP; the full userspace backend therefore
/// falls back to a WinDivert-or-nothing path on Windows).
pub fn raw_socket_probe() -> std::io::Result<()> {
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
    drop(sock);
    Ok(())
}

/// Start the userspace backend and return an `EngineHandle`.
///
/// Up-front, checks raw-socket capability: if the OS refuses (EPERM /
/// EACCES) we bail with a clear error message rather than silently
/// falling back to a non-raw path. The RawEngine is defined to need
/// elevated privileges — if we lack them the caller should either
/// escalate or choose a different engine.
///
/// On Linux, dispatches to the real SYN-race engine. On macOS/Windows
/// (and on Linux if SYN-race startup fails), falls back to a
/// connect-labelled scheduler that emits `engine = "raw"` events —
/// preserves the public interface while the BPF/WinDivert ports are
/// being written.
pub async fn start(ctx: EngineContext) -> anyhow::Result<EngineHandle> {
    // Capability gate. Note: this probe may succeed on Windows even when
    // raw TCP is effectively blocked by the stack; that's fine, because
    // a subsequent send/recv will surface a clean error at that point.
    if let Err(e) = raw_socket_probe() {
        match e.raw_os_error() {
            // POSIX EPERM / EACCES — definitely a permissions problem.
            Some(1) | Some(13) => {
                anyhow::bail!(
                    "raw engine requires CAP_NET_RAW / admin (raw socket open failed: {e})"
                );
            }
            _ => {
                anyhow::bail!(
                    "raw engine requires CAP_NET_RAW / admin (raw socket probe failed: {e})"
                );
            }
        }
    }

    let (stop_tx, stop_rx) = watch::channel(false);
    let caps = EngineCapabilities {
        needs_root: true,
        min_detect_latency_ms: 10,
        supported: true,
    };

    // v1.2+ Linux path: try the real SYN race. If it can't initialise
    // (missing CAP_NET_RAW, no default interface, etc.) fall through to
    // the connect-labelled-raw scheduler that v1.0-v1.1 shipped.
    #[cfg(target_os = "linux")]
    {
        match crate::raw::syn_race::SynRace::start(ctx.clone()).await {
            Ok(race_handle) => {
                let mut rx = stop_rx;
                tokio::spawn(async move {
                    // Hold the race handle alive until stop is signalled;
                    // its Drop impl tears down sender/receiver/handoff.
                    let _guard = race_handle;
                    let _ = rx.changed().await;
                });
                return Ok(EngineHandle::new(stop_tx, caps));
            }
            Err(e) => {
                tracing::warn!(
                    "SYN-race startup failed ({e:#}); falling back to connect-labelled-raw"
                );
                // Fall through to the legacy scheduler on this branch.
            }
        }
    }

    tokio::spawn(async move {
        run_scheduler(ctx, stop_rx).await;
    });

    Ok(EngineHandle::new(stop_tx, caps))
}

/// Scheduler loop: mirrors `connect::scheduler::run` but emits events
/// labelled `engine = "raw"`. Used when `SynRace` can't initialise
/// (missing CAP_NET_RAW, non-Linux OS, or no IPv4 interface).
async fn run_scheduler(ctx: EngineContext, mut stop: watch::Receiver<bool>) {
    use std::sync::Arc;

    use crate::port_state::{Observation, PortStateTracker};

    let engagement = ctx.engagement.clone();
    let rate = ctx.rate_limiter.clone();
    let catch_tx = ctx.catch_tx.clone();
    let bus = ctx.bus.clone();
    let plan = ctx.plan.clone();

    if plan.is_empty() {
        tracing::warn!("raw userspace scheduler started with empty plan");
        return;
    }

    let tracker = Arc::new(PortStateTracker::new(engagement.id, "raw"));

    let mut backoff: HashMap<(IpAddr, u16), (Instant, u32)> = HashMap::new();
    let mut in_flight: FuturesUnordered<
        std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    > = FuturesUnordered::new();

    let mut cursor = 0usize;

    loop {
        if *stop.borrow_and_update() {
            break;
        }

        while in_flight.next().now_or_never().flatten().is_some() {}

        let (ip, port) = plan[cursor % plan.len()];
        cursor = cursor.wrapping_add(1);

        if let Some((next_attempt, _)) = backoff.get(&(ip, port)) {
            if *next_attempt > Instant::now() {
                tokio::time::sleep(IDLE_SLEEP).await;
                continue;
            }
        }

        let target = Target::new(ip, port);
        match engagement
            .scope_guard
            .allow(&target, time::OffsetDateTime::now_utc())
        {
            Ok(_) => {}
            Err(violation) => {
                emit_scope_blocked(&bus, &engagement, &target, &violation.to_string());
                tokio::time::sleep(IDLE_SLEEP).await;
                continue;
            }
        }

        if !rate.try_acquire(ip) {
            tokio::time::sleep(IDLE_SLEEP).await;
            continue;
        }

        let bus_c = bus.clone();
        let catch_tx_c = catch_tx.clone();
        let tracker_c = Arc::clone(&tracker);
        let target_cloned = target.clone();
        let fut = async move {
            let addr = SocketAddr::new(target_cloned.ip, target_cloned.port);
            let start = Instant::now();
            match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    let detect_latency = start.elapsed();
                    let detect_ms = detect_latency.as_millis() as u64;
                    let catch_id = tracker_c
                        .observe(ip, port, Observation::Open, detect_ms, &bus_c)
                        .unwrap_or_default();
                    let _ = catch_tx_c
                        .send(ConnectionCaught {
                            catch_id,
                            target: target_cloned,
                            engine: "raw",
                            detect_latency_ms: detect_ms,
                            stream,
                        })
                        .await;
                }
                Ok(Err(e)) if matches!(e.kind(), std::io::ErrorKind::ConnectionRefused) => {
                    tracker_c.observe(ip, port, Observation::Closed, 0, &bus_c);
                }
                _ => {
                    tracker_c.observe(ip, port, Observation::Transient, 0, &bus_c);
                }
            }
        };

        in_flight.push(Box::pin(fut));

        let entry = backoff.entry((ip, port)).or_insert((Instant::now(), 0));
        let new_n = (entry.1 + 1).min(8);
        let delay_ms = (INITIAL_BACKOFF_MS << (new_n - 1).min(9)).min(MAX_BACKOFF_MS);
        entry.0 = Instant::now() + Duration::from_millis(delay_ms);
        entry.1 = new_n;

        if in_flight.len() >= 512 {
            let _ = in_flight.next().await;
        }
    }

    while in_flight.next().await.is_some() {}
    drop(catch_tx);
}

fn emit_scope_blocked(bus: &BusSender, engagement: &Engagement, target: &Target, reason: &str) {
    let event = Event::new(
        engagement.id,
        None,
        EventBody::ScopeViolationBlocked(ScopeViolationBlocked {
            attempted_target: target.ip.to_string(),
            attempted_port: target.port,
            reason: reason.to_owned(),
        }),
    );
    bus.send(event);
}

// Handle is exported for symmetry with the kassist backend but is not
// yet wired back into `RawEngine::backend` in the v0.3.0-alpha cut.
// Once the real smoltcp stack lands, `start()` will fill the
// `raw::Backend::Userspace(Handle { .. })` variant.
