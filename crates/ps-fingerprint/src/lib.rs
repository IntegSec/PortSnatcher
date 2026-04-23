//! PortSnatcher fingerprinter.
//!
//! This crate walks a fresh-connection `ProbeLadder` across a catch,
//! emitting `ProbeAttempted` → `FingerprintCaptured` → `CatchComplete`
//! events and persisting a per-engagement `FingerprintCache` of the
//! strongest observation per `(IpAddr, port)`.
//!
//! See the Phase 2 plan and the design spec §5 (probe ladder) and §11
//! (artifacts) for the contract this crate satisfies.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod cache;
pub mod ladder;
pub mod probes;
pub mod report;

pub use cache::{CacheError, FingerprintCache};
pub use ladder::ProbeLadder;
pub use probes::{Fingerprinter, ProbeContext, ProbeOutcome, Protocol};
pub use report::{FingerprintReport, ProbeRunRecord, TlsInfo};
