//! [`HoldOpen`] trait, [`HoldOpenMode`] / [`LocalEndpoint`] types, and the
//! [`HoldOpenManager`] that owns the pool of loopback tunnel ports and the
//! shared [`Ca`](crate::ca::Ca).

use std::ops::RangeInclusive;
use std::sync::Arc;

use async_trait::async_trait;
use ps_bus::broadcast::BusSender;
use ps_core::id::{CatchId, EngagementId};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};

use crate::ca::Ca;

/// Default tunnel port range when none is configured: `7100..=7199`.
pub const DEFAULT_PORT_RANGE: RangeInclusive<u16> = 7100..=7199;

/// Selects a hold-open backend for a given catch. Stringifies as
/// `"dumb_tunnel"` or `"tls_mitm"` on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HoldOpenMode {
    /// Bidirectional TCP pipe — see [`crate::DumbTunnel`].
    DumbTunnel,
    /// TLS-terminating MITM — see [`crate::TlsMitm`].
    TlsMitm,
}

impl HoldOpenMode {
    /// Wire tag used in the `HoldOpenReady` event's `mode` field.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::DumbTunnel => "dumb_tunnel",
            Self::TlsMitm => "tls_mitm",
        }
    }
}

/// The loopback endpoint a hold-open backend exposes to the pentester.
///
/// Returned from [`HoldOpen::establish`]; the orchestrator stores it on
/// the in-memory catch record and surfaces it via the TUI.
#[derive(Debug, Clone)]
pub struct LocalEndpoint {
    /// Bound port on `127.0.0.1`.
    pub local_port: u16,
    /// The active mode (same enum the backend was constructed with).
    pub mode: HoldOpenMode,
    /// SHA-256 fingerprint of the MITM CA (hex, 64 chars) — `None` for
    /// a `DumbTunnel`.
    pub ca_fingerprint: Option<String>,
}

/// Trait object contract for hold-open backends.
///
/// `establish` is one-shot: it binds a loopback listener, spawns the
/// pipe task, emits `HoldOpenReady`, and returns. The backend consumes
/// itself (`self: Box<Self>`) so each call owns exactly one tunnel.
#[async_trait]
pub trait HoldOpen: Send + Sync {
    /// Start the hold-open tunnel for the given catch.
    ///
    /// Arguments:
    /// - `catch_id`: correlates emitted events back to the catch record.
    /// - `upstream`: already-connected upstream TCP stream from `ConnectionCaught`.
    /// - `upstream_addr`: the remote address for logging / the `HoldOpenReady.upstream` field.
    /// - `upstream_hostname`: SNI/Host hint (for TLS MITM leaf generation); `None` if not known.
    /// - `bus`: event bus; the backend emits `HoldOpenReady` and later
    ///   `HoldOpenClosed` from a spawned task.
    /// - `engagement_id`: engagement that owns the emitted events.
    async fn establish(
        self: Box<Self>,
        catch_id: CatchId,
        upstream: TcpStream,
        upstream_addr: std::net::SocketAddr,
        upstream_hostname: Option<String>,
        bus: BusSender,
        engagement_id: EngagementId,
    ) -> anyhow::Result<LocalEndpoint>;
}

/// Shared state every hold-open backend needs: the tunnel-port range
/// and a handle to the MITM CA.
#[derive(Clone)]
pub struct HoldOpenManager {
    /// Inclusive port range the backends are allowed to bind on
    /// `127.0.0.1`. Default: [`DEFAULT_PORT_RANGE`].
    pub port_range: RangeInclusive<u16>,
    /// Shared CA used by [`TlsMitm`](crate::TlsMitm) for leaf issuance.
    /// `DumbTunnel` never touches it.
    pub ca: Arc<Ca>,
}

impl HoldOpenManager {
    /// Build a manager from an explicit port range and CA handle.
    pub fn new(port_range: RangeInclusive<u16>, ca: Arc<Ca>) -> Self {
        Self { port_range, ca }
    }

    /// Parse a `"<start>-<end>"` string into a [`HoldOpenManager`].
    ///
    /// `"7100-7199"` yields the default range. Returns an error on
    /// malformed input or an inverted range.
    pub fn from_range_str(range: &str, ca: Arc<Ca>) -> anyhow::Result<Self> {
        let (lo, hi) = range
            .split_once('-')
            .ok_or_else(|| anyhow::anyhow!("port range must be '<start>-<end>', got {range:?}"))?;
        let lo: u16 = lo
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("bad port range start {lo:?}: {e}"))?;
        let hi: u16 = hi
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("bad port range end {hi:?}: {e}"))?;
        if lo > hi {
            anyhow::bail!("port range start ({lo}) > end ({hi})");
        }
        Ok(Self::new(lo..=hi, ca))
    }

    /// Bind a loopback [`TcpListener`] on the first port in `port_range`
    /// that is free. Returns the listener and the chosen port.
    ///
    /// Every port in the range is tried in order; on exhaustion this
    /// returns an error summarising the range.
    pub async fn bind_loopback(&self) -> anyhow::Result<(TcpListener, u16)> {
        for port in self.port_range.clone() {
            match TcpListener::bind(("127.0.0.1", port)).await {
                Ok(listener) => return Ok((listener, port)),
                Err(_) => continue,
            }
        }
        Err(anyhow::anyhow!(
            "no tunnel port available in range {}-{}",
            self.port_range.start(),
            self.port_range.end()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_wire_tags() {
        assert_eq!(HoldOpenMode::DumbTunnel.as_wire(), "dumb_tunnel");
        assert_eq!(HoldOpenMode::TlsMitm.as_wire(), "tls_mitm");
    }

    #[test]
    fn local_endpoint_holds_fields() {
        let ep = LocalEndpoint {
            local_port: 7100,
            mode: HoldOpenMode::DumbTunnel,
            ca_fingerprint: None,
        };
        assert_eq!(ep.local_port, 7100);
        assert_eq!(ep.mode, HoldOpenMode::DumbTunnel);
        assert!(ep.ca_fingerprint.is_none());
    }

    #[test]
    fn range_parse_roundtrip() {
        // Need a Ca to hand in; use a tempdir-backed one.
        let tmp = tempfile::TempDir::new().unwrap();
        let ca = Arc::new(Ca::new_or_load(tmp.path()).unwrap());
        let mgr = HoldOpenManager::from_range_str("7100-7199", ca.clone()).unwrap();
        assert_eq!(mgr.port_range, 7100..=7199);
        assert!(HoldOpenManager::from_range_str("nope", ca.clone()).is_err());
        assert!(HoldOpenManager::from_range_str("8000-7000", ca).is_err());
    }
}
