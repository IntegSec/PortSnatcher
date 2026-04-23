//! SSE endpoint integration test: real HTTP, real subscriber, real bus.

use std::time::Duration;

use ps_bus::auth::AuthToken;
use ps_bus::broadcast::BusSender;
use ps_bus::server::{run, ServerState};
use ps_core::event::payload::{EngagementStarted, EventBody};
use ps_core::event::Event;
use ps_core::id::EngagementId;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

fn ev(profile: &str) -> Event {
    Event::new(
        EngagementId::new(),
        None,
        EventBody::EngagementStarted(EngagementStarted {
            profile: profile.into(),
            engine: "connect".into(),
            targets: vec![],
            ports: "all".into(),
            rate_cap_pps: 0,
            dry_run: false,
        }),
    )
}

#[tokio::test]
async fn sse_streams_events_with_valid_bearer() {
    let (tx, _rx) = BusSender::new(64);
    let token = AuthToken::generate();
    let token_value = token.0.clone();
    let shutdown = CancellationToken::new();
    let bind = "127.0.0.1:0".parse().unwrap();
    let actual = run(
        bind,
        ServerState {
            bus: tx.clone(),
            token,
        },
        shutdown.clone(),
    )
    .await
    .unwrap();

    // Give axum a moment to actually start serving.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let url = format!("http://{actual}/events");
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {token_value}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Send a couple of events and read them off the stream.
    tokio::spawn({
        let tx = tx.clone();
        async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            tx.send(ev("internal"));
            tx.send(ev("external"));
        }
    });

    let mut stream = resp.bytes_stream();
    let mut received = String::new();
    let collect = timeout(Duration::from_secs(2), async {
        use futures::StreamExt;
        while let Some(Ok(chunk)) = stream.next().await {
            received.push_str(&String::from_utf8_lossy(&chunk));
            if received.matches("\"EngagementStarted\"").count() >= 2 {
                break;
            }
        }
    })
    .await;
    assert!(collect.is_ok(), "did not receive 2 events within 2s");
    assert!(received.contains("internal"));
    assert!(received.contains("external"));

    shutdown.cancel();
}

#[tokio::test]
async fn sse_rejects_missing_bearer() {
    let (tx, _rx) = BusSender::new(64);
    let token = AuthToken::generate();
    let shutdown = CancellationToken::new();
    let bind = "127.0.0.1:0".parse().unwrap();
    let actual = run(bind, ServerState { bus: tx, token }, shutdown.clone())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{actual}/events"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    shutdown.cancel();
}
