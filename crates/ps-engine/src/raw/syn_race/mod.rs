//! Linux SYN-race engine (v1.2.0+).
//!
//! Sprays crafted TCP SYN packets via an `AF_PACKET` raw socket at high
//! rate (limited by [`crate::rate::RateLimiter`]), sniffs inbound SYN-ACK
//! replies through `pnet::datalink`, and immediately hands off to a
//! standard `tokio::net::TcpStream::connect()` when a SYN-ACK matches an
//! outstanding spray. The net effect is **sub-100ms detection** of an
//! ephemeral port opening — the connect-engine's polled `connect()`
//! sweeps can't compete on a 200ms window.
//!
//! The design consciously keeps userspace TCP out of the picture:
//! a full `smoltcp` TCP stack + TUN device would catch slightly more
//! races but triples the surface area to test and forces platform-
//! specific packet-injection plumbing that doesn't exist yet on
//! macOS/Windows. See the v1 design spec §4.1 option (b): kernel TCP
//! stack + nftables RST-drop side channel.
//!
//! # Safety and capabilities
//!
//! - Raw socket send requires `CAP_NET_RAW`.
//! - `pnet::datalink::channel` reading the wire requires `CAP_NET_RAW`
//!   or `CAP_NET_ADMIN`, depending on the backend the OS picks.
//! - The `kassist::linux` nftables "drop outbound RST" rule is applied
//!   in parallel from the [`crate::raw::kassist`] path; when it's in
//!   place the kernel stops RST'ing stray SYN-ACKs from our race
//!   sprays, which keeps target servers from tearing down the
//!   half-opens before our handoff `connect()` arrives.

pub mod packet;

// Phase 2 of the v1.2 work adds the Linux-only sender/receiver/port_pool
// modules plus a `SynRace` orchestrator type. Phase 1 lands only the
// platform-agnostic packet-math so CI can validate it without needing
// CAP_NET_RAW or an interface it can drive.
