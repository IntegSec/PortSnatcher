//! Scheduler: iterates (target, port) pairs, consults ScopeGuard + rate
//! limiter before every attempt, publishes `PortOpenDetected` /
//! `PortClosedDetected` (via [`PortStateTracker`]) and
//! `ScopeViolationBlocked` events, re-probes closed ports on backoff.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::{FuturesUnordered, StreamExt};
use futures::FutureExt;
use ps_bus::broadcast::BusSender;
use ps_core::engagement::Engagement;
use ps_core::event::payload::{EventBody, ScopeViolationBlocked};
use ps_core::event::Event;
use ps_core::target::Target;
use tokio::sync::{mpsc, watch};

use crate::engine::{ConnectionCaught, EngineContext};
use crate::port_state::{Observation, PortStateTracker};
use crate::rate::RateLimiter;

use super::worker::{attempt, AttemptOutcome};

const CONNECT_TIMEOUT: Duration = Duration::from_millis(800);
const IDLE_SLEEP: Duration = Duration::from_millis(5);
const INITIAL_BACKOFF_MS: u64 = 100;
const MAX_BACKOFF_MS: u64 = 32_000;

pub async fn run(ctx: EngineContext, mut stop: watch::Receiver<bool>) {
    let engagement = ctx.engagement.clone();
    let rate = ctx.rate_limiter.clone();
    let catch_tx = ctx.catch_tx.clone();
    let bus = ctx.bus.clone();
    let plan = ctx.plan.clone();

    if plan.is_empty() {
        tracing::warn!("connect scheduler started with empty plan");
        return;
    }

    let tracker = Arc::new(PortStateTracker::new(engagement.id, "connect"));

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

        let bus = bus.clone();
        let catch_tx = catch_tx.clone();
        let tracker = Arc::clone(&tracker);
        let target_cloned = target.clone();
        let fut = async move {
            let outcome = attempt(target_cloned.clone(), CONNECT_TIMEOUT).await;
            match outcome {
                AttemptOutcome::Caught {
                    stream,
                    detect_latency,
                } => {
                    let detect_ms = detect_latency.as_millis() as u64;
                    // State tracker emits PortOpenDetected on transition
                    // from not-Open → Open and hands us a CatchId. On a
                    // re-catch of an already-Open port, returns None —
                    // but we still need to hand the stream downstream
                    // so the fingerprinter can re-probe (its cache will
                    // short-circuit most of the work).
                    let catch_id = tracker
                        .observe(ip, port, Observation::Open, detect_ms, &bus)
                        .unwrap_or_default();
                    let _ = catch_tx
                        .send(ConnectionCaught {
                            catch_id,
                            target: target_cloned,
                            engine: "connect",
                            detect_latency_ms: detect_ms,
                            stream,
                        })
                        .await;
                }
                AttemptOutcome::Closed => {
                    tracker.observe(ip, port, Observation::Closed, 0, &bus);
                }
                AttemptOutcome::Transient => {
                    tracker.observe(ip, port, Observation::Transient, 0, &bus);
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

// Suppress "unused" while the orchestrator wiring in Phase 2 lands; the
// types are re-exported via the lib.rs.
#[allow(dead_code)]
fn _ensure_types_used(_rl: &RateLimiter, _tx: &mpsc::Sender<ConnectionCaught>) {}
