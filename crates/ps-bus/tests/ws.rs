//! WebSocket endpoint integration test.

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use ps_bus::auth::AuthToken;
use ps_bus::broadcast::BusSender;
use ps_bus::server::{run, ServerState};
use ps_core::event::payload::{EngagementStarted, EventBody};
use ps_core::event::Event;
use ps_core::id::EngagementId;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

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
async fn ws_streams_events_with_valid_bearer() {
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
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut request = format!("ws://{actual}/events/ws")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {token_value}").parse().unwrap(),
    );
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();

    // Push two events through the bus.
    tx.send(ev());
    tx.send(ev());

    let mut got = 0;
    let collect = timeout(Duration::from_secs(2), async {
        while let Some(Ok(msg)) = socket.next().await {
            if let Message::Text(text) = msg {
                if text.contains("\"EngagementStarted\"") {
                    got += 1;
                    if got == 2 {
                        break;
                    }
                }
            }
        }
    })
    .await;
    assert!(collect.is_ok(), "WS did not deliver 2 events within 2s");
    assert_eq!(got, 2);

    let _ = socket.send(Message::Close(None)).await;
    shutdown.cancel();
}

#[tokio::test]
async fn ws_rejects_missing_bearer() {
    let (tx, _rx) = BusSender::new(64);
    let token = AuthToken::generate();
    let shutdown = CancellationToken::new();
    let bind = "127.0.0.1:0".parse().unwrap();
    let actual = run(bind, ServerState { bus: tx, token }, shutdown.clone())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let request = format!("ws://{actual}/events/ws")
        .into_client_request()
        .unwrap();
    let result = tokio_tungstenite::connect_async(request).await;
    assert!(result.is_err(), "WS should fail handshake with no bearer");
    shutdown.cancel();
}
