//! HTTP server exposing the bus over Server-Sent Events and WebSocket.
//!
//! Both endpoints emit the same JSON event stream. Auth is `Authorization:
//! Bearer <token>` on the SSE GET; for WebSocket, the token is also in
//! the upgrade request's `Authorization` header.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use futures::stream::Stream;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::auth::AuthToken;
use crate::broadcast::BusSender;

#[derive(Clone)]
pub struct ServerState {
    pub bus: BusSender,
    pub token: AuthToken,
}

pub async fn run(
    bind: SocketAddr,
    state: ServerState,
    shutdown: CancellationToken,
) -> std::io::Result<SocketAddr> {
    let app = Router::new()
        .route("/events", get(sse_handler))
        .route("/events/ws", get(ws_handler))
        .with_state(Arc::new(state));

    let listener = TcpListener::bind(bind).await?;
    let actual = listener.local_addr()?;
    tokio::spawn(async move {
        let serve = axum::serve(listener, app)
            .with_graceful_shutdown(async move { shutdown.cancelled().await });
        if let Err(e) = serve.await {
            tracing::warn!("bus server exited: {e:#}");
        }
    });
    Ok(actual)
}

async fn sse_handler(State(state): State<Arc<ServerState>>, headers: HeaderMap) -> Response {
    if !authorised(&headers, &state.token) {
        return (StatusCode::UNAUTHORIZED, "unauthorised").into_response();
    }
    let receiver = state.bus.subscribe();
    let stream = sse_stream(receiver);
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

fn sse_stream(
    rx: crate::broadcast::BusReceiver,
) -> impl Stream<Item = Result<SseEvent, Infallible>> {
    futures::stream::unfold(rx, |mut rx| async move {
        match rx.recv().await {
            Ok(ev) => {
                let json = serde_json::to_string(&ev).unwrap_or_default();
                Some((Ok(SseEvent::default().data(json)), rx))
            }
            Err(_) => None,
        }
    })
}

async fn ws_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    if !authorised(&headers, &state.token) {
        return (StatusCode::UNAUTHORIZED, "unauthorised").into_response();
    }
    let bus = state.bus.clone();
    upgrade.on_upgrade(move |socket| ws_loop(socket, bus.subscribe()))
}

async fn ws_loop(mut socket: WebSocket, mut rx: crate::broadcast::BusReceiver) {
    while let Ok(ev) = rx.recv().await {
        let Ok(json) = serde_json::to_string(&ev) else {
            continue;
        };
        if socket.send(Message::Text(json)).await.is_err() {
            break;
        }
    }
}

fn authorised(headers: &HeaderMap, token: &AuthToken) -> bool {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| token.matches(v))
        .unwrap_or(false)
}
