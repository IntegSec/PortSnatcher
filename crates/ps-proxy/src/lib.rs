//! PortSnatcher hold-open proxy.
//!
//! Phase 3 of PortSnatcher: after a catch, the orchestrator hands the
//! held-open upstream `TcpStream` to one of the [`HoldOpen`] backends
//! defined here. Each backend binds a loopback listener port from a
//! pool managed by [`HoldOpenManager`] and exposes it to the pentester
//! until either side closes, at which point a `HoldOpenClosed` event
//! is emitted on the bus.
//!
//! Two backends ship in v0.2.0:
//!
//! - [`DumbTunnel`] — default. Bidirectional TCP pipe between the
//!   loopback listener and the upstream socket. Protocol-agnostic.
//! - [`TlsMitm`] — opt-in for HTTPS catches. Terminates the pentester's
//!   TLS with a CA-signed ephemeral leaf, re-encrypts upstream with the
//!   system trust roots, and logs plaintext to disk.
//!
//! The on-disk CA ([`Ca`]) is generated once per install and reused
//! across engagements; [`ca::trust`] exposes platform-specific
//! install/uninstall into the system trust store.

#![warn(missing_docs)]

pub mod ca;
pub mod dumb_tunnel;
pub mod hold_open;
pub mod keepalive;
pub mod tls_mitm;

pub use ca::{Ca, CaFingerprint};
pub use dumb_tunnel::DumbTunnel;
pub use hold_open::{HoldOpen, HoldOpenManager, HoldOpenMode, LocalEndpoint};
pub use tls_mitm::TlsMitm;
