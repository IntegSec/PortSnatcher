//! `EventSink` trait. All concrete sinks implement this interface.

use async_trait::async_trait;
use ps_core::event::Event;

#[async_trait]
pub trait EventSink: Send + Sync {
    async fn emit(&self, event: &Event);
    fn name(&self) -> &'static str;
}
