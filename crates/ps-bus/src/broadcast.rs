//! Thin wrapper over `tokio::sync::broadcast` typed for `Event`.

use ps_core::event::Event;
use tokio::sync::broadcast;

/// Sending end of the bus. Cloneable; every clone shares the same
/// underlying channel. Drop all senders to close the bus.
#[derive(Clone, Debug)]
pub struct BusSender {
    inner: broadcast::Sender<Event>,
}

/// Receiving end. Each `subscribe()` produces an independent receiver
/// with its own slot; missed events surface as `BusError::Lagged`.
pub struct BusReceiver {
    inner: broadcast::Receiver<Event>,
}

#[derive(Debug, thiserror::Error)]
pub enum BusError {
    #[error("bus closed")]
    Closed,
    #[error("no buffered events available")]
    Empty,
    #[error("subscriber lagged behind by {0} events")]
    Lagged(u64),
}

impl BusSender {
    pub fn new(capacity: usize) -> (Self, BusReceiver) {
        let (tx, rx) = broadcast::channel(capacity);
        (Self { inner: tx }, BusReceiver { inner: rx })
    }

    pub fn send(&self, event: Event) {
        // Send returns Err only when there are no receivers; we ignore
        // it because a bus with no listeners is a valid, common state.
        let _ = self.inner.send(event);
    }

    pub fn subscribe(&self) -> BusReceiver {
        BusReceiver {
            inner: self.inner.subscribe(),
        }
    }

    pub fn receiver_count(&self) -> usize {
        self.inner.receiver_count()
    }
}

impl BusReceiver {
    pub async fn recv(&mut self) -> Result<Event, BusError> {
        match self.inner.recv().await {
            Ok(ev) => Ok(ev),
            Err(broadcast::error::RecvError::Closed) => Err(BusError::Closed),
            Err(broadcast::error::RecvError::Lagged(n)) => Err(BusError::Lagged(n)),
        }
    }

    /// Non-blocking receive — returns the next buffered event if one
    /// is immediately available. Used by the sink dispatcher to drain
    /// residual events during a clean shutdown without awaiting.
    pub fn try_recv(&mut self) -> Result<Event, BusError> {
        use broadcast::error::TryRecvError;
        match self.inner.try_recv() {
            Ok(ev) => Ok(ev),
            Err(TryRecvError::Empty) => Err(BusError::Empty),
            Err(TryRecvError::Closed) => Err(BusError::Closed),
            Err(TryRecvError::Lagged(n)) => Err(BusError::Lagged(n)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ps_core::event::payload::{EngagementStarted, EventBody};
    use ps_core::id::EngagementId;

    fn dummy_event() -> Event {
        Event::new(
            EngagementId::new(),
            None,
            EventBody::EngagementStarted(EngagementStarted {
                profile: "internal".into(),
                engine: "connect".into(),
                targets: vec![],
                ports: "all".into(),
                rate_cap_pps: 0,
                dry_run: false,
            }),
        )
    }

    #[tokio::test]
    async fn fan_out_to_two_subscribers() {
        let (tx, mut rx_a) = BusSender::new(8);
        let mut rx_b = tx.subscribe();
        let ev = dummy_event();
        tx.send(ev.clone());
        let got_a = rx_a.recv().await.unwrap();
        let got_b = rx_b.recv().await.unwrap();
        assert_eq!(got_a.engagement_id, ev.engagement_id);
        assert_eq!(got_b.engagement_id, ev.engagement_id);
    }

    #[tokio::test]
    async fn send_with_no_receivers_does_not_panic() {
        let (tx, _) = BusSender::new(8);
        // Drop the receiver; sending must remain a no-op.
        tx.send(dummy_event());
        assert_eq!(tx.receiver_count(), 0);
    }
}
