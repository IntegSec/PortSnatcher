//! [`DumbTunnel`] — protocol-agnostic TCP passthrough.
//!
//! After a catch, binds a loopback listener from
//! [`HoldOpenManager::bind_loopback`], emits `HoldOpenReady`, waits for a
//! single client attach, and runs [`tokio::io::copy_bidirectional`]
//! between the client and the upstream socket handed in by the engine.
//!
//! This is the default hold-open mode — it stays out of the way of the
//! upstream protocol entirely, which lets the pentester attach Burp (and
//! do their own upstream TLS), `ncat`, or custom tooling unchanged.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ps_bus::broadcast::BusSender;
use ps_core::event::payload::{EventBody, HoldOpenClosed, HoldOpenReady};
use ps_core::event::Event;
use ps_core::id::{CatchId, EngagementId};
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;

use crate::hold_open::{HoldOpen, HoldOpenManager, HoldOpenMode, LocalEndpoint};
use crate::keepalive;

/// Protocol hint used to choose a keepalive strategy. Forward-compatible:
/// v0.2.0 only acts on `Http`; other variants fall through to plain
/// `SO_KEEPALIVE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// HTTP/1.x — orchestrator may choose to emit `OPTIONS /` heartbeats.
    Http,
    /// TLS wrapping some inner protocol (the MITM backend usually
    /// handles this, but `DumbTunnel` still understands the hint).
    Tls,
    /// Any other protocol. No application-layer keepalive is sent.
    Other,
}

/// How long `DumbTunnel` waits for the pentester to attach before
/// declaring the tunnel idle and closing it.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Dumb TCP passthrough hold-open backend.
pub struct DumbTunnel {
    manager: Arc<HoldOpenManager>,
    /// Protocol hint from the fingerprinter. The hint is carried on the
    /// struct so the orchestrator can select between keepalive
    /// strategies without `DumbTunnel` growing a config grab-bag.
    pub keepalive_hint: Option<Protocol>,
    idle_timeout: Duration,
}

impl DumbTunnel {
    /// Build a `DumbTunnel` that binds from `manager`'s port range.
    pub fn new(manager: Arc<HoldOpenManager>) -> Self {
        Self {
            manager,
            keepalive_hint: None,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }

    /// Attach a protocol hint (e.g. `Http` from the fingerprinter).
    pub fn with_keepalive_hint(mut self, hint: Protocol) -> Self {
        self.keepalive_hint = Some(hint);
        self
    }

    /// Override the "nobody attached yet" timeout. Exposed primarily
    /// for tests.
    pub fn with_idle_timeout(mut self, idle: Duration) -> Self {
        self.idle_timeout = idle;
        self
    }
}

#[async_trait]
impl HoldOpen for DumbTunnel {
    async fn establish(
        self: Box<Self>,
        _catch_id: CatchId,
        upstream: TcpStream,
        upstream_addr: std::net::SocketAddr,
        _upstream_hostname: Option<String>,
        bus: BusSender,
        engagement_id: EngagementId,
    ) -> anyhow::Result<LocalEndpoint> {
        let (listener, local_port) = self.manager.bind_loopback().await?;

        // Best-effort keepalive on the upstream. Doesn't fail the establish.
        if let Err(e) = keepalive::apply_tcp_keepalive(&upstream) {
            tracing::warn!(error = %e, "failed to apply TCP keepalive on upstream; continuing");
        }

        // Emit HoldOpenReady _before_ accepting — the TUI/event consumer
        // displays the tunnel port so the pentester can attach.
        bus.send(Event::new(
            engagement_id,
            Some(_catch_id),
            EventBody::HoldOpenReady(HoldOpenReady {
                local_port,
                upstream: upstream_addr.to_string(),
                mode: HoldOpenMode::DumbTunnel.as_wire().to_string(),
                ca_fingerprint: None,
            }),
        ));

        let idle_timeout = self.idle_timeout;
        let endpoint = LocalEndpoint {
            local_port,
            mode: HoldOpenMode::DumbTunnel,
            ca_fingerprint: None,
        };

        tokio::spawn(async move {
            let started = Instant::now();
            let reason = run_pipe(listener, upstream, idle_timeout).await;
            bus.send(Event::new(
                engagement_id,
                Some(_catch_id),
                EventBody::HoldOpenClosed(HoldOpenClosed {
                    reason: reason.to_string(),
                    duration_ms: started.elapsed().as_millis() as u64,
                }),
            ));
        });

        Ok(endpoint)
    }
}

/// Wait for exactly one client attach, then pipe bytes until either
/// side closes. Returns a `reason` string used by `HoldOpenClosed`.
async fn run_pipe(
    listener: tokio::net::TcpListener,
    mut upstream: TcpStream,
    idle_timeout: Duration,
) -> &'static str {
    let accept = tokio::time::timeout(idle_timeout, listener.accept()).await;
    let (mut local, _peer) = match accept {
        Ok(Ok(pair)) => pair,
        Ok(Err(_)) => return "accept_error",
        Err(_) => return "idle_timeout",
    };
    match copy_bidirectional(&mut local, &mut upstream).await {
        Ok(_) => "pentester_detach",
        Err(_) => "upstream_closed",
    }
}
