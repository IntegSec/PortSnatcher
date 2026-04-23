//! Terminal sink: emits a structured `tracing::info!` per event.

use async_trait::async_trait;
use ps_core::event::Event;

use crate::sink::EventSink;

#[derive(Debug, Default)]
pub struct TerminalSink;

#[async_trait]
impl EventSink for TerminalSink {
    fn name(&self) -> &'static str {
        "terminal"
    }

    async fn emit(&self, event: &Event) {
        // Pull the discriminator out of the body via JSON so we don't
        // hard-couple to the EventBody enum's variant names here.
        let kind = match serde_json::to_value(&event.body) {
            Ok(v) => v
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("Event")
                .to_owned(),
            Err(_) => "Event".to_owned(),
        };
        tracing::info!(
            schema = %event.schema,
            engagement = %event.engagement_id,
            catch = ?event.catch_id,
            "{kind}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ps_core::event::payload::{EngagementStarted, EventBody};
    use ps_core::id::EngagementId;

    #[tokio::test]
    async fn emits_without_panic() {
        let sink = TerminalSink;
        let ev = Event::new(
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
        );
        sink.emit(&ev).await;
    }
}
