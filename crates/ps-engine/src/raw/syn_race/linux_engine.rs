//! `SynRace` — the Linux-only SYN-race engine.
//!
//! Orchestrates a sender task, a pcap receiver thread, and a handoff
//! task that translates raw SYN-ACK hits into [`ConnectionCaught`]
//! events by completing a regular `tokio::net::TcpStream::connect()`.
//!
//! Flow:
//! ```text
//!   sender task (tokio)  ──spawn_blocking──>  raw SYN on the wire
//!                                                    │
//!                                           remote SYN-ACK arrives
//!                                                    │
//!   receiver thread (std)  ──pnet datalink──>  SynAckHit (mpsc)
//!                                                    │
//!   handoff task (tokio)  ──emit PortOpenDetected + tokio connect──>
//!                                                    │
//!                                         ConnectionCaught → downstream
//! ```

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use ps_bus::broadcast::BusSender;
use ps_core::engagement::Engagement;
use ps_core::event::payload::{EventBody, PortOpenDetected, ScopeViolationBlocked};
use ps_core::event::Event;
use ps_core::id::CatchId;
use ps_core::target::Target;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self};
use tokio::sync::watch;
use tokio::time::timeout;

use super::port_pool::PortPool;
use super::receiver::{self, RecvConfig, SynAckHit};
use super::sender::{self, SynSender};
use crate::engine::{ConnectionCaught, EngineContext};

/// v1.2 default SYN spray rate — caps aggregate SYN rate at a value
/// roughly 50× the connect engine's external-profile default. Higher
/// values are possible but start to drop packets on consumer NICs.
const DEFAULT_TARGET_PPS: u32 = 10_000;

/// Timeout on the kernel-side handoff connect. Short because a real
/// SYN-ACK means the service is up; if kernel connect times out here,
/// the service closed between our SYN-ACK and our handoff.
const HANDOFF_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

/// Entry point for the orchestrator.
pub struct SynRace;

impl SynRace {
    /// Bring up the SYN race for this engagement. Returns when the
    /// sender / receiver / handoff loops have all been spawned.
    ///
    /// Errors surface only for *capability* issues (no raw socket, no
    /// default interface, empty target plan). Per-packet failures are
    /// logged at `tracing::warn` and the engagement continues.
    pub async fn start(ctx: EngineContext) -> anyhow::Result<SynRaceHandle> {
        // IPv4-only targets from the plan; SynRace doesn't do v6 yet.
        let (v4_plan, targets) = split_v4(&ctx.plan);
        if v4_plan.is_empty() {
            anyhow::bail!("SynRace requires at least one IPv4 target in the plan");
        }

        let iface = receiver::default_interface()
            .context("no non-loopback IPv4 interface available for pcap")?;
        let first_target = v4_plan[0].0;
        let src_ip = sender::discover_local_ipv4(first_target)
            .context("discover local IPv4 via UDP-connect trick")?;

        let pool = Arc::new(PortPool::default_range());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (stop_tx, stop_rx) = watch::channel(false);

        // Receiver first, so any SYN-ACKs from in-flight sprays don't
        // get dropped before we're listening.
        let (hit_tx, mut hit_rx) = mpsc::unbounded_channel::<SynAckHit>();
        let recv_handle = receiver::spawn(
            RecvConfig {
                interface: iface,
                targets: Arc::new(targets),
                port_pool_bounds: pool.bounds(),
                shutdown: Arc::clone(&shutdown),
            },
            hit_tx,
        )
        .context("spawn syn-race receiver")?;

        // Sender task.
        let sender_ctx = SenderCtx {
            ctx: ctx.clone(),
            src_ip,
            plan: v4_plan,
            pool: Arc::clone(&pool),
            stop: stop_rx.clone(),
        };
        let sender_task = tokio::spawn(sender_loop(sender_ctx));

        // Handoff task: drains SynAckHit, emits PortOpenDetected,
        // spawns kernel connect for the real TCP stream.
        let handoff_ctx = ctx.clone();
        let handoff_stop = stop_rx.clone();
        let handoff_task = tokio::spawn(async move {
            let mut stop = handoff_stop;
            loop {
                tokio::select! {
                    _ = stop.changed() => {
                        if *stop.borrow() { break; }
                    }
                    got = hit_rx.recv() => {
                        let Some(hit) = got else { break };
                        spawn_handoff(handoff_ctx.clone(), hit);
                    }
                }
            }
        });

        Ok(SynRaceHandle {
            stop_tx,
            shutdown,
            recv_handle: Some(recv_handle),
            sender_task: Some(sender_task),
            handoff_task: Some(handoff_task),
        })
    }
}

/// Active handle on a running race. Dropping it halts the loops.
pub struct SynRaceHandle {
    stop_tx: watch::Sender<bool>,
    shutdown: Arc<AtomicBool>,
    recv_handle: Option<std::thread::JoinHandle<()>>,
    sender_task: Option<tokio::task::JoinHandle<()>>,
    handoff_task: Option<tokio::task::JoinHandle<()>>,
}

impl SynRaceHandle {
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = self.stop_tx.send(true);
    }
}

impl Drop for SynRaceHandle {
    fn drop(&mut self) {
        self.stop();
        if let Some(h) = self.sender_task.take() {
            h.abort();
        }
        if let Some(h) = self.handoff_task.take() {
            h.abort();
        }
        if let Some(h) = self.recv_handle.take() {
            // Give the receiver a moment to notice the shutdown flag.
            let _ = h.join();
        }
    }
}

// ---------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------

struct SenderCtx {
    ctx: EngineContext,
    src_ip: Ipv4Addr,
    plan: Vec<(Ipv4Addr, u16)>,
    pool: Arc<PortPool>,
    stop: watch::Receiver<bool>,
}

async fn sender_loop(mut s: SenderCtx) {
    // Open the raw socket in a blocking task so pnet's send path stays
    // on a dedicated thread. We share the sender behind a std::sync Mutex
    // and call send_syn via spawn_blocking per SYN; at 10k pps per host
    // the blocking-pool overhead is negligible and the code stays simple.
    let sender = match tokio::task::spawn_blocking({
        let src_ip = s.src_ip;
        move || SynSender::open(src_ip)
    })
    .await
    {
        Ok(Ok(s)) => std::sync::Arc::new(std::sync::Mutex::new(s)),
        Ok(Err(e)) => {
            tracing::error!("SynRace sender failed to open raw socket: {e:#}");
            return;
        }
        Err(e) => {
            tracing::error!("SynRace sender spawn_blocking panicked: {e:#}");
            return;
        }
    };

    let min_interval = Duration::from_nanos(1_000_000_000u64 / DEFAULT_TARGET_PPS as u64);
    let mut next_due = Instant::now();
    let mut cursor: usize = 0;

    loop {
        if *s.stop.borrow_and_update() {
            break;
        }

        // Cycle through the plan.
        let (ip, port) = s.plan[cursor % s.plan.len()];
        cursor = cursor.wrapping_add(1);

        // Scope + rate checks.
        let target = Target::new(IpAddr::V4(ip), port);
        match s
            .ctx
            .engagement
            .scope_guard
            .allow(&target, time::OffsetDateTime::now_utc())
        {
            Ok(_) => {}
            Err(violation) => {
                emit_scope_blocked(
                    &s.ctx.bus,
                    &s.ctx.engagement,
                    &target,
                    &violation.to_string(),
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
                continue;
            }
        }
        if !s.ctx.rate_limiter.try_acquire(IpAddr::V4(ip)) {
            tokio::time::sleep(Duration::from_millis(1)).await;
            continue;
        }

        // Pace the sprays.
        let now = Instant::now();
        if now < next_due {
            tokio::time::sleep(next_due - now).await;
        }
        next_due = Instant::now() + min_interval;

        let src_port = s.pool.next_port();
        let isn = rand_u32();
        let sender = std::sync::Arc::clone(&sender);
        let _ = tokio::task::spawn_blocking(move || {
            let mut guard = sender.lock().expect("SynSender mutex poisoned");
            if let Err(e) = guard.send_syn(src_port, ip, port, isn) {
                tracing::debug!("send_syn {ip}:{port} from sp={src_port}: {e:#}");
            }
        })
        .await;
    }
}

fn spawn_handoff(ctx: EngineContext, hit: SynAckHit) {
    let bus = ctx.bus.clone();
    let engagement_id = ctx.engagement.id;
    let catch_tx = ctx.catch_tx.clone();
    let target_ip = IpAddr::V4(hit.target_ip);
    let target = Target::new(target_ip, hit.target_port);
    let catch_id = CatchId::new();
    let detect_start = Instant::now();

    // Emit PortOpenDetected immediately — this is the "fast detection"
    // win. Even if the handoff connect fails below, we've already
    // logged the open port.
    bus.send(Event::new(
        engagement_id,
        Some(catch_id),
        EventBody::PortOpenDetected(PortOpenDetected {
            target: hit.target_ip.to_string(),
            port: hit.target_port,
            detect_latency_ms: 0,
            engine: "raw".into(),
            syn_rtt_ms: None,
        }),
    ));

    tokio::spawn(async move {
        let addr = SocketAddr::new(target_ip, hit.target_port);
        match timeout(HANDOFF_CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let _ = catch_tx
                    .send(ConnectionCaught {
                        catch_id,
                        target,
                        engine: "raw",
                        detect_latency_ms: detect_start.elapsed().as_millis() as u64,
                        stream,
                    })
                    .await;
            }
            Ok(Err(e)) => {
                tracing::debug!("raw handoff connect to {addr} failed after SYN-ACK: {e:#}");
            }
            Err(_) => {
                tracing::debug!("raw handoff connect to {addr} timed out");
            }
        }
    });
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

fn split_v4(plan: &[(IpAddr, u16)]) -> (Vec<(Ipv4Addr, u16)>, HashSet<Ipv4Addr>) {
    let mut out = Vec::with_capacity(plan.len());
    let mut set = HashSet::new();
    for (ip, port) in plan {
        if let IpAddr::V4(v4) = ip {
            out.push((*v4, *port));
            set.insert(*v4);
        }
    }
    (out, set)
}

/// Small RNG helper — not cryptographically strong, just needs to
/// spread across the u32 space so stale reply matching doesn't collide.
fn rand_u32() -> u32 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::sync::atomic::AtomicU64;
    use std::time::SystemTime;

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut h = DefaultHasher::new();
    SystemTime::now().hash(&mut h);
    COUNTER.fetch_add(1, Ordering::Relaxed).hash(&mut h);
    h.finish() as u32
}
