//! Scheduler: iterates (target, port) pairs, consults ScopeGuard + rate
//! limiter before every attempt, publishes PortOpenDetected and
//! ScopeViolationBlocked events, re-probes closed ports on backoff.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::{FuturesUnordered, StreamExt};
use futures::FutureExt;
use ps_bus::broadcast::BusSender;
use ps_core::engagement::Engagement;
use ps_core::event::payload::{EventBody, PortOpenDetected, ScopeViolationBlocked};
use ps_core::event::Event;
use ps_core::id::CatchId;
use ps_core::target::Target;
use tokio::sync::{mpsc, watch};

use crate::engine::{ConnectionCaught, EngineContext};
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

    let mut backoff: HashMap<(IpAddr, u16), (Instant, u32)> = HashMap::new();
    let mut in_flight: FuturesUnordered<
        std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    > = FuturesUnordered::new();

    let mut cursor = 0usize;

    loop {
        if *stop.borrow_and_update() {
            break;
        }

        // Drain completed attempts.
        while in_flight.next().now_or_never().flatten().is_some() {}

        let (ip, port) = plan[cursor % plan.len()];
        cursor = cursor.wrapping_add(1);

        // Honour backoff window.
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

        let engagement = engagement.clone();
        let bus = bus.clone();
        let catch_tx = catch_tx.clone();
        let target_cloned = target.clone();
        let fut = async move {
            let outcome = attempt(target_cloned.clone(), CONNECT_TIMEOUT).await;
            match outcome {
                AttemptOutcome::Caught {
                    stream,
                    detect_latency,
                } => {
                    let catch_id = CatchId::new();
                    emit_port_open(&bus, &engagement, &target_cloned, &catch_id, detect_latency);
                    let _ = catch_tx
                        .send(ConnectionCaught {
                            catch_id,
                            target: target_cloned,
                            engine: "connect",
                            detect_latency_ms: detect_latency.as_millis() as u64,
                            stream,
                        })
                        .await;
                }
                AttemptOutcome::Closed | AttemptOutcome::Transient => {}
            }
        };

        in_flight.push(Box::pin(fut));

        // Register/advance backoff for this (ip, port). Successful catches
        // also reset backoff in the next iteration via the removal below.
        let entry = backoff.entry((ip, port)).or_insert((Instant::now(), 0));
        let new_n = (entry.1 + 1).min(8);
        let delay_ms = (INITIAL_BACKOFF_MS << (new_n - 1).min(9)).min(MAX_BACKOFF_MS);
        entry.0 = Instant::now() + Duration::from_millis(delay_ms);
        entry.1 = new_n;

        // Cap concurrency to keep file-descriptor pressure bounded.
        if in_flight.len() >= 512 {
            let _ = in_flight.next().await;
        }
    }

    // Drain outstanding connects before returning.
    while in_flight.next().await.is_some() {}

    // `catch_tx` is dropped here automatically, signalling downstream.
    drop(catch_tx);
}

fn emit_port_open(
    bus: &BusSender,
    engagement: &Engagement,
    target: &Target,
    catch_id: &CatchId,
    detect_latency: Duration,
) {
    let event = Event::new(
        engagement.id,
        Some(*catch_id),
        EventBody::PortOpenDetected(PortOpenDetected {
            target: target.ip.to_string(),
            port: target.port,
            detect_latency_ms: detect_latency.as_millis() as u64,
            engine: "connect".into(),
            syn_rtt_ms: None,
        }),
    );
    bus.send(event);
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
