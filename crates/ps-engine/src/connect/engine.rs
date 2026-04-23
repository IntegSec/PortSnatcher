//! `ConnectEngine`: async connect-based ProbeEngine implementation.

use async_trait::async_trait;
use tokio::sync::watch;

use crate::engine::{EngineCapabilities, EngineContext, EngineHandle, ProbeEngine};

pub struct ConnectEngine;

impl ConnectEngine {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ConnectEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProbeEngine for ConnectEngine {
    fn name(&self) -> &'static str {
        "connect"
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            needs_root: false,
            min_detect_latency_ms: 50,
            supported: true,
        }
    }

    async fn start(self: Box<Self>, ctx: EngineContext) -> anyhow::Result<EngineHandle> {
        let (stop_tx, stop_rx) = watch::channel(false);
        let caps = self.capabilities();
        tokio::spawn(async move {
            super::scheduler::run(ctx, stop_rx).await;
        });
        Ok(EngineHandle::new(stop_tx, caps))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_are_unprivileged() {
        let e = ConnectEngine::new();
        let caps = e.capabilities();
        assert!(!caps.needs_root);
        assert!(caps.supported);
    }
}
