//! PortSnatcher notification sinks. Every sink implements [`EventSink`];
//! the orchestrator dispatches events to all configured sinks in parallel.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod desktop;
pub mod jsonl;
pub mod sink;
pub mod terminal;
pub mod webhook;

pub use desktop::DesktopSink;
pub use jsonl::JsonlSink;
pub use sink::EventSink;
pub use terminal::TerminalSink;
pub use webhook::WebhookSink;
