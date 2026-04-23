//! RawEngine — the headline capability. Userspace smoltcp is the portable
//! default; per-OS kernel fast-paths (nftables on Linux, pf on macOS,
//! WinDivert on Windows) are transparently preferred when available.
//!
//! External behaviour is identical regardless of which backend is active:
//! the kassist backends are purely opt-in optimizations.
//!
//! See `docs/superpowers/plans/2026-04-22-portsnatcher-phase4-raw-engine.md`
//! for the full design and §17 architectural decisions.

mod engine;
pub mod kassist;
pub mod userspace;

pub use engine::{Backend, CapabilityReport, RawEngine};
