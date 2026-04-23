//! PortSnatcher notification sinks. Every sink implements [`EventSink`];
//! the orchestrator dispatches events to all configured sinks in parallel.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod sink;
pub mod terminal;
pub mod jsonl;
pub mod webhook;
pub mod desktop;

pub use sink::EventSink;
pub use terminal::TerminalSink;
pub use jsonl::JsonlSink;
pub use webhook::WebhookSink;
pub use desktop::DesktopSink;
