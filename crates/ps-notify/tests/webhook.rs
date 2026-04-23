//! Webhook sink integration test: real HTTP via httpmock + retry behaviour.

use httpmock::prelude::*;
use ps_core::event::payload::{EngagementStarted, EventBody};
use ps_core::event::Event;
use ps_core::id::EngagementId;
use ps_notify::sink::EventSink;
use ps_notify::WebhookSink;

fn ev() -> Event {
    Event::new(
        EngagementId::new(),
        None,
        EventBody::EngagementStarted(EngagementStarted {
            profile: "ctf".into(),
            engine: "connect".into(),
            targets: vec![],
            ports: "all".into(),
            rate_cap_pps: 0,
            dry_run: false,
        }),
    )
}

#[tokio::test]
async fn posts_event_body_to_webhook() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(POST).path("/hook");
        then.status(204);
    });
    let sink = WebhookSink::new(server.url("/hook"));
    sink.emit(&ev()).await;
    mock.assert_hits(1);
}

#[tokio::test]
async fn retries_on_5xx_then_succeeds() {
    let server = MockServer::start();
    let fail = server.mock(|when, then| {
        when.method(POST).path("/hook");
        then.status(500);
    });
    let sink = WebhookSink::new(server.url("/hook")).with_max_attempts(3);
    sink.emit(&ev()).await;
    // We expect exactly max_attempts hits (all returning 500).
    fail.assert_hits(3);
}
