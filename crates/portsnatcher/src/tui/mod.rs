//! Terminal UI for PortSnatcher.
//!
//! Subscribes to the in-process event bus and renders a four-panel
//! ratatui layout: catches table, holds list, rate gauge, event log.
//!
//! The TUI is a plain [`ps_notify::EventSink`]-style consumer of
//! [`ps_bus`] — it owns no orchestration state. All mutations to the
//! on-screen model go through [`app::TuiApp::apply`], which keeps the
//! model deterministic and directly unit-testable.
//!
//! Public entry point: [`run`]. The main binary is expected to wire a
//! `--tui` flag that dispatches to it. This module does not touch
//! `main.rs`; that wiring lives in Phase 5's integration commit.

pub mod app;
pub mod runtime;
pub mod widgets;

#[allow(unused_imports)]
pub use app::{CatchRow, HoldRow, TuiApp};
#[allow(unused_imports)]
pub use runtime::run;
