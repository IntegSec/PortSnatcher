//! Per-`(target_ip, target_port)` state machine driving event-stream
//! dedup and Open↔Closed transition emission.
//!
//! Each engine instance constructs **its own** `PortStateTracker`;
//! callers are ConnectEngine's scheduler, RawEngine's userspace
//! fallback scheduler, and the Linux SynRace handoff. There is no
//! cross-engine shared tracker today — only one engine runs per
//! engagement, so divergence isn't possible. If a future engagement
//! ever runs multiple engines concurrently against the same plan,
//! plumb a single `Arc<PortStateTracker>` through `EngineContext`
//! to keep state coherent.
//!
//! Emits:
//! - [`PortOpenDetected`] on `Unknown`/`Closed`/`Flapping` → `Open`
//! - [`PortClosedDetected`] on `Open` → `Closed` (or repeated
//!   transient-failure windows interpreted as closed)
//!
//! Re-catching an already-open port no longer produces fresh
//! `PortOpenDetected` events — the v1.2.1 "port 443 pile-up" in the
//! JSONL log was exactly this problem.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use ps_bus::broadcast::BusSender;
use ps_core::event::payload::{EventBody, PortClosedDetected, PortOpenDetected};
use ps_core::event::Event;
use ps_core::id::{CatchId, EngagementId};

/// How many consecutive transient (timeout) attempts before we call a
/// previously-open port closed. 2 is a reasonable default: one miss
/// could be transient, two in a row is "gone."
const TRANSIENT_CLOSE_THRESHOLD: u32 = 2;

/// Observation verdict fed into the tracker.
#[derive(Debug, Clone, Copy)]
pub enum Observation {
    /// Connect succeeded; port is reachable.
    Open,
    /// Connect refused (kernel RST); port is definitively closed.
    Closed,
    /// Connect timed out or returned ambiguous error; might be
    /// filtered OR transiently unreachable. Multiple in a row get
    /// interpreted as Closed once they pass `TRANSIENT_CLOSE_THRESHOLD`.
    Transient,
}

/// Internal state per `(ip, port)`.
#[derive(Debug, Clone, Copy)]
enum State {
    Unknown,
    Open {
        since: Instant,
    },
    Closed,
    /// Was Open, we've seen N transient failures since; N is tracked.
    WaitingForClose {
        since_open: Instant,
        misses: u32,
    },
}

/// Thread-safe Open/Closed tracker with event emission.
#[derive(Debug)]
pub struct PortStateTracker {
    inner: Mutex<HashMap<(IpAddr, u16), State>>,
    engine: &'static str,
    engagement_id: EngagementId,
}

impl PortStateTracker {
    pub fn new(engagement_id: EngagementId, engine: &'static str) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            engine,
            engagement_id,
        }
    }

    /// Feed a single observation for `(ip, port)`. If the transition
    /// warrants an event, push it onto `bus`. Returns the fresh
    /// `CatchId` when the observation is the first-seen-open for this
    /// `(ip, port)` (i.e. when [`PortOpenDetected`] just fired); that
    /// catch_id is what the caller passes downstream so the ladder and
    /// the hold-open get a consistent grouping.
    pub fn observe(
        &self,
        ip: IpAddr,
        port: u16,
        obs: Observation,
        detect_latency_ms: u64,
        bus: &BusSender,
    ) -> Option<CatchId> {
        // Recover from a poisoned guard rather than panicking the
        // observation hot path — the critical section below is
        // hashmap ops + Instant::now() and can't leave inconsistent
        // state. A panicking observer thread elsewhere shouldn't
        // freeze every subsequent observation.
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let prev = map.get(&(ip, port)).copied().unwrap_or(State::Unknown);

        let (next, fired_open, fired_closed_with) = match (prev, obs) {
            // Open transitions — only emit when the consumer has
            // *previously* observed a Closed for this port. The
            // WaitingForClose → Open recovery is purely internal
            // (we never emitted PortClosedDetected for it because
            // the transient threshold wasn't reached), so re-emitting
            // here would spuriously look like a flap to consumers.
            (State::Unknown, Observation::Open) | (State::Closed, Observation::Open) => (
                State::Open {
                    since: Instant::now(),
                },
                true,
                None,
            ),
            (State::WaitingForClose { since_open, .. }, Observation::Open) => {
                (State::Open { since: since_open }, false, None)
            }
            (State::Open { since }, Observation::Open) => (State::Open { since }, false, None),

            // Close transitions.
            (State::Open { since }, Observation::Closed)
            | (
                State::WaitingForClose {
                    since_open: since, ..
                },
                Observation::Closed,
            ) => {
                let was_open_for_ms =
                    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX);
                (
                    State::Closed,
                    false,
                    Some(("connection_refused", was_open_for_ms)),
                )
            }
            (State::Open { since }, Observation::Transient) => (
                State::WaitingForClose {
                    since_open: since,
                    misses: 1,
                },
                false,
                None,
            ),
            (State::WaitingForClose { since_open, misses }, Observation::Transient) => {
                let n = misses + 1;
                if n >= TRANSIENT_CLOSE_THRESHOLD {
                    let was_open_for_ms =
                        u64::try_from(since_open.elapsed().as_millis()).unwrap_or(u64::MAX);
                    (
                        State::Closed,
                        false,
                        Some(("transient_timeout", was_open_for_ms)),
                    )
                } else {
                    (
                        State::WaitingForClose {
                            since_open,
                            misses: n,
                        },
                        false,
                        None,
                    )
                }
            }

            // No-op transitions from not-open states.
            (State::Unknown, Observation::Closed | Observation::Transient) => {
                (State::Closed, false, None)
            }
            (State::Closed, Observation::Closed | Observation::Transient) => {
                (State::Closed, false, None)
            }
        };

        map.insert((ip, port), next);
        drop(map);

        let mut fresh_catch_id = None;
        if fired_open {
            let catch_id = CatchId::new();
            fresh_catch_id = Some(catch_id);
            bus.send(Event::new(
                self.engagement_id,
                Some(catch_id),
                EventBody::PortOpenDetected(PortOpenDetected {
                    target: ip.to_string(),
                    port,
                    detect_latency_ms,
                    engine: self.engine.to_owned(),
                    syn_rtt_ms: None,
                }),
            ));
        }
        if let Some((reason, was_open_for_ms)) = fired_closed_with {
            bus.send(Event::new(
                self.engagement_id,
                None,
                EventBody::PortClosedDetected(PortClosedDetected {
                    target: ip.to_string(),
                    port,
                    reason: reason.to_owned(),
                    was_open_for_ms: Some(was_open_for_ms),
                }),
            ));
        }

        fresh_catch_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_bus() -> (BusSender, ps_bus::broadcast::BusReceiver) {
        BusSender::new(64)
    }

    #[tokio::test]
    async fn first_open_emits_once() {
        let (bus, mut rx) = new_bus();
        let t = PortStateTracker::new(EngagementId::new(), "connect");
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let cid = t.observe(ip, 443, Observation::Open, 12, &bus);
        assert!(cid.is_some());
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev.body, EventBody::PortOpenDetected(_)));

        // Re-observe open — should NOT emit a second event.
        let cid = t.observe(ip, 443, Observation::Open, 12, &bus);
        assert!(cid.is_none());
    }

    #[tokio::test]
    async fn open_then_closed_emits_closed() {
        let (bus, mut rx) = new_bus();
        let t = PortStateTracker::new(EngagementId::new(), "connect");
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        t.observe(ip, 443, Observation::Open, 10, &bus);
        rx.recv().await.unwrap(); // drain open
        t.observe(ip, 443, Observation::Closed, 5, &bus);
        let ev = rx.recv().await.unwrap();
        assert!(
            matches!(ev.body, EventBody::PortClosedDetected(_)),
            "expected PortClosedDetected, got {:?}",
            ev.body
        );
    }

    #[tokio::test]
    async fn two_transients_after_open_emits_closed() {
        let (bus, mut rx) = new_bus();
        let t = PortStateTracker::new(EngagementId::new(), "connect");
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        t.observe(ip, 443, Observation::Open, 10, &bus);
        rx.recv().await.unwrap();
        assert!(t
            .observe(ip, 443, Observation::Transient, 0, &bus)
            .is_none());
        // First transient alone shouldn't fire.
        let second = t.observe(ip, 443, Observation::Transient, 0, &bus);
        assert!(second.is_none());
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev.body, EventBody::PortClosedDetected(_)));
    }

    #[tokio::test]
    async fn flap_open_closed_open_fires_both_plus_open() {
        let (bus, mut rx) = new_bus();
        let t = PortStateTracker::new(EngagementId::new(), "connect");
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        t.observe(ip, 443, Observation::Open, 10, &bus);
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev.body, EventBody::PortOpenDetected(_)));

        t.observe(ip, 443, Observation::Closed, 5, &bus);
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev.body, EventBody::PortClosedDetected(_)));

        t.observe(ip, 443, Observation::Open, 10, &bus);
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev.body, EventBody::PortOpenDetected(_)));
    }

    /// One transient followed by an Open should reset us back to
    /// Open (the `(WaitingForClose, Observation::Open)` arm) without
    /// emitting any extra event. Catches future refactors that would
    /// drop this resilience.
    #[tokio::test]
    async fn one_transient_then_open_resets_without_emit() {
        let (bus, mut rx) = new_bus();
        let t = PortStateTracker::new(EngagementId::new(), "connect");
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        t.observe(ip, 443, Observation::Open, 10, &bus);
        rx.recv().await.unwrap(); // drain initial open

        // One transient — not enough to flip closed.
        assert!(t
            .observe(ip, 443, Observation::Transient, 0, &bus)
            .is_none());
        // Recovery — should NOT emit a fresh PortOpenDetected (we
        // never emitted PortClosedDetected, so this is the same
        // open-streak from the consumer's perspective).
        assert!(t.observe(ip, 443, Observation::Open, 10, &bus).is_none());
        // Bus should now be empty — try_recv returns Empty.
        assert!(matches!(
            rx.try_recv(),
            Err(ps_bus::broadcast::BusError::Empty)
        ));
    }

    /// The `engine` label fed at construction time must be the one
    /// that round-trips on emitted PortOpenDetected. Catches
    /// future copy-paste mistakes where one engine emits with another
    /// engine's tag.
    #[tokio::test]
    async fn engine_label_round_trips_on_port_open_detected() {
        let (bus, mut rx) = new_bus();
        let t = PortStateTracker::new(EngagementId::new(), "raw");
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        t.observe(ip, 22, Observation::Open, 7, &bus);
        let ev = rx.recv().await.unwrap();
        match ev.body {
            EventBody::PortOpenDetected(p) => {
                assert_eq!(p.engine, "raw");
                assert_eq!(p.detect_latency_ms, 7);
                assert_eq!(p.target, "10.0.0.1");
                assert_eq!(p.port, 22);
            }
            other => panic!("expected PortOpenDetected, got {other:?}"),
        }
    }
}
