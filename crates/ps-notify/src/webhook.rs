//! Webhook sink: HTTP POST per event with bounded retries.

use std::time::Duration;

use async_trait::async_trait;
use ps_core::event::Event;

use crate::sink::EventSink;

#[derive(Debug)]
pub struct WebhookSink {
    url: String,
    client: reqwest::Client,
    max_attempts: u32,
}

impl WebhookSink {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("reqwest client builds with default config"),
            max_attempts: 3,
        }
    }

    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts;
        self
    }
}

#[async_trait]
impl EventSink for WebhookSink {
    fn name(&self) -> &'static str {
        "webhook"
    }

    async fn emit(&self, event: &Event) {
        let body = match serde_json::to_string(event) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("webhook serialize failed: {e:#}");
                return;
            }
        };
        let mut delay = Duration::from_millis(100);
        for attempt in 1..=self.max_attempts {
            let resp = self
                .client
                .post(&self.url)
                .header("content-type", "application/json")
                .body(body.clone())
                .send()
                .await;
            match resp {
                Ok(r) if r.status().is_success() => return,
                Ok(r) => {
                    tracing::warn!(
                        "webhook {} attempt {attempt} returned status {}",
                        self.url,
                        r.status()
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "webhook {} attempt {attempt} failed: {e:#}",
                        self.url
                    );
                }
            }
            if attempt < self.max_attempts {
                tokio::time::sleep(delay).await;
                delay *= 4;
            }
        }
        tracing::error!("webhook {} gave up after {} attempts", self.url, self.max_attempts);
    }
}
