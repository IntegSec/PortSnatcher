//! Keepalive helpers for hold-open tunnels.
//!
//! Two helpers:
//!
//! - [`apply_tcp_keepalive`] sets `SO_KEEPALIVE` on an upstream stream via
//!   `socket2`, with tuning that works on Linux, macOS, and Windows.
//! - [`options_heartbeat_frame`] returns the bytes of a zero-side-effect
//!   HTTP `OPTIONS /` request the orchestrator can write every 20 seconds
//!   when the fingerprint says HTTP. v0.2.0 leaves the scheduling to the
//!   orchestrator; this helper just exposes the write.

use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;

/// How often to send an HTTP `OPTIONS /` heartbeat for HTTP catches.
pub const DEFAULT_HTTP_HEARTBEAT_EVERY: Duration = Duration::from_secs(20);

/// Frame bytes for the HTTP `OPTIONS` heartbeat the orchestrator writes
/// when the catch is HTTP. Kept deliberately minimal and
/// side-effect-free per RFC 7231 §4.3.7.
pub const HTTP_OPTIONS_FRAME: &[u8] =
    b"OPTIONS / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n";

/// Apply aggressive `SO_KEEPALIVE` (idle 15s / interval 5s / 3 probes)
/// to a `tokio::net::TcpStream`. Errors if the platform rejects the
/// socket option; the caller typically logs and continues.
pub fn apply_tcp_keepalive(stream: &TcpStream) -> std::io::Result<()> {
    let sock = SockRef::from(stream);
    let mut ka = TcpKeepalive::new().with_time(Duration::from_secs(15));

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        ka = ka.with_interval(Duration::from_secs(5));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        ka = ka.with_retries(3);
    }

    sock.set_tcp_keepalive(&ka)
}

/// Return a reference to the canned HTTP `OPTIONS` heartbeat frame.
///
/// The orchestrator is responsible for calling this on its own
/// heartbeat cadence (default: every [`DEFAULT_HTTP_HEARTBEAT_EVERY`]).
pub fn options_heartbeat_frame() -> &'static [u8] {
    HTTP_OPTIONS_FRAME
}

/// Write the HTTP `OPTIONS` heartbeat frame to a stream. Convenience
/// wrapper so the orchestrator doesn't have to import `AsyncWriteExt`.
pub async fn send_http_options_heartbeat(stream: &mut TcpStream) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    stream.write_all(HTTP_OPTIONS_FRAME).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn keepalive_applies_cleanly_on_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        let _ = client.await.unwrap();
        apply_tcp_keepalive(&server).expect("keepalive applies cleanly");
    }

    #[test]
    fn heartbeat_frame_is_well_formed() {
        let f = options_heartbeat_frame();
        assert!(f.starts_with(b"OPTIONS / HTTP/1.1\r\n"));
        assert!(f.ends_with(b"\r\n\r\n"));
    }
}
