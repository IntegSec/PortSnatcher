//! PortSnatcher event bus: in-process broadcast + external SSE/WebSocket server.
//!
//! Every PortSnatcher subsystem speaks events via this bus. The internal
//! `tokio::sync::broadcast` channel fans an event out to every subscriber
//! synchronously; the HTTP server re-publishes the same stream over SSE
//! and WebSocket so external consumers (Burp extension, custom tooling)
//! can attach without IPC.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod broadcast;
pub mod auth;
pub mod server;

pub use broadcast::{BusReceiver, BusSender};
pub use auth::AuthToken;
