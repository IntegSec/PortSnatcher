//! Core engine abstractions.

use std::sync::Arc;

use async_trait::async_trait;
use ps_core::engagement::Engagement;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::rate::RateLimiter;

/// Per-engine capabilities reported to the orchestrator.
#[derive(Debug, Clone, Copy)]
pub struct EngineCapabilities {
    pub needs_root: bool,
    pub min_detect_latency_ms: u64,
    pub supported: bool,
}

/// Inputs every engine needs.
#[derive(Clone)]
pub struct EngineContext {
    pub engagement: Engagement,
    pub rate_limiter: Arc<RateLimiter>,
    pub catch_tx: mpsc::Sender<ConnectionCaught>,
    pub bus: ps_bus::broadcast::BusSender,
    /// Explicit (target, port) pairs to probe. Phase 2 passes these in
    /// from the orchestrator; Phase 4's RawEngine may generate its own.
    pub plan: Vec<(std::net::IpAddr, u16)>,
}

/// One successful catch handed to downstream consumers.
pub struct ConnectionCaught {
    pub catch_id: ps_core::id::CatchId,
    pub target: ps_core::target::Target,
    pub engine: &'static str,
    pub detect_latency_ms: u64,
    pub stream: TcpStream,
}

/// Control handle owned by the orchestrator.
pub struct EngineHandle {
    stop_tx: tokio::sync::watch::Sender<bool>,
    pub capabilities: EngineCapabilities,
}

impl EngineHandle {
    pub fn new(stop_tx: tokio::sync::watch::Sender<bool>, caps: EngineCapabilities) -> Self {
        Self {
            stop_tx,
            capabilities: caps,
        }
    }

    pub fn stop(&self) {
        let _ = self.stop_tx.send(true);
    }
}

#[async_trait]
pub trait ProbeEngine: Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> EngineCapabilities;
    async fn start(self: Box<Self>, ctx: EngineContext) -> anyhow::Result<EngineHandle>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_is_debug() {
        let c = EngineCapabilities {
            needs_root: false,
            min_detect_latency_ms: 50,
            supported: true,
        };
        assert!(format!("{c:?}").contains("needs_root"));
    }

    #[test]
    fn handle_stop_notifies() {
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        let h = EngineHandle::new(
            tx,
            EngineCapabilities {
                needs_root: false,
                min_detect_latency_ms: 50,
                supported: true,
            },
        );
        h.stop();
        assert!(*rx.borrow_and_update());
    }
}
