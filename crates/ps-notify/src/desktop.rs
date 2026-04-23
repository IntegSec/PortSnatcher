//! Desktop sink: native OS toast via `notify-rust`.
//!
//! Toasts can fail in headless environments (CI, containers without a
//! notification daemon). Failures are logged and swallowed — the
//! engagement continues regardless.

use async_trait::async_trait;
use ps_core::event::Event;

use crate::sink::EventSink;

#[derive(Debug, Default)]
pub struct DesktopSink {
    app_name: String,
}

impl DesktopSink {
    pub fn new() -> Self {
        Self {
            app_name: "PortSnatcher".to_owned(),
        }
    }
}

#[async_trait]
impl EventSink for DesktopSink {
    fn name(&self) -> &'static str {
        "desktop"
    }

    async fn emit(&self, event: &Event) {
        let body = format_event(event);
        let app = self.app_name.clone();
        // notify-rust is sync and may block on platform notification IPC,
        // so dispatch through spawn_blocking.
        let _ = tokio::task::spawn_blocking(move || {
            if let Err(e) = notify_rust::Notification::new()
                .summary(&app)
                .body(&body)
                .show()
            {
                tracing::debug!("desktop toast suppressed (likely headless): {e:#}");
            }
        })
        .await;
    }
}

fn format_event(event: &Event) -> String {
    match serde_json::to_value(&event.body) {
        Ok(v) => v
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("Event")
            .to_owned(),
        Err(_) => "Event".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructs() {
        let _ = DesktopSink::new();
    }
}
