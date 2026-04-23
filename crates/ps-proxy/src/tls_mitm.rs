//! [`TlsMitm`] — TLS-terminating hold-open for HTTPS catches.
//!
//! - Binds a loopback listener via [`HoldOpenManager::bind_loopback`].
//! - On the pentester side, serves a rustls `ServerConfig` whose cert
//!   resolver returns a CA-signed leaf for the upstream hostname.
//! - On the upstream side, wraps the already-connected `TcpStream` with
//!   `tokio_rustls::TlsConnector` using the webpki default roots.
//! - Copies bytes bidirectionally after both handshakes succeed and
//!   appends plaintext to
//!   `<artifacts>/<catch_id>/http/transcript.log` as direction-tagged
//!   chunks.
//!
//! The artifacts root is taken from the `PS_ARTIFACTS_DIR` env var when
//! set; otherwise it falls back to `./artifacts/catches/<catch_id>/`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use async_trait::async_trait;
use ps_bus::broadcast::BusSender;
use ps_core::event::payload::{EventBody, HoldOpenClosed, HoldOpenReady};
use ps_core::event::Event;
use ps_core::id::{CatchId, EngagementId};
use rustls::pki_types::ServerName;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::ca::Ca;
use crate::hold_open::{HoldOpen, HoldOpenManager, HoldOpenMode, LocalEndpoint};

/// TLS MITM backend.
pub struct TlsMitm {
    /// Shared CA used to sign the leaf handed to the pentester-side
    /// rustls server.
    pub ca: Arc<Ca>,
    /// SNI / host to use both for the issued leaf and when establishing
    /// the upstream TLS client connection.
    pub upstream_hostname: String,
    manager: Arc<HoldOpenManager>,
    /// Optional override for the upstream client root certificate
    /// store. When `None` (the default), the MITM trusts the webpki
    /// default roots exactly like a browser would. Tests use this to
    /// point the MITM at a fixture HTTPS server that isn't publicly
    /// trusted.
    upstream_roots_override: Option<RootCertStore>,
}

impl TlsMitm {
    /// Construct from a manager and upstream hostname. The CA is
    /// pulled off `manager.ca`.
    pub fn new(manager: Arc<HoldOpenManager>, upstream_hostname: String) -> Self {
        let ca = manager.ca.clone();
        Self {
            ca,
            upstream_hostname,
            manager,
            upstream_roots_override: None,
        }
    }

    /// Override the set of root certificates the upstream TLS client
    /// config will trust. Primarily used by tests that stand up a
    /// self-signed HTTPS fixture — production callers should leave
    /// this alone and rely on the webpki defaults.
    pub fn with_upstream_roots(mut self, roots: RootCertStore) -> Self {
        self.upstream_roots_override = Some(roots);
        self
    }
}

/// Resolves the static pre-signed leaf for every ClientHello.
#[derive(Debug)]
struct StaticLeafResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for StaticLeafResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

#[async_trait]
impl HoldOpen for TlsMitm {
    async fn establish(
        self: Box<Self>,
        catch_id: CatchId,
        upstream: TcpStream,
        upstream_addr: std::net::SocketAddr,
        upstream_hostname: Option<String>,
        bus: BusSender,
        engagement_id: EngagementId,
    ) -> anyhow::Result<LocalEndpoint> {
        // rustls requires a crypto provider to be installed before
        // `ServerConfig::builder()` is called. Idempotent; safe on
        // re-entry. Production callers typically install explicitly at
        // startup, but this keeps TlsMitm self-contained.
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Destructure Self so we can freely move fields into tasks.
        let Self {
            ca,
            upstream_hostname: default_hostname,
            manager,
            upstream_roots_override,
        } = *self;

        let hostname = upstream_hostname.unwrap_or(default_hostname);

        let (listener, local_port) = manager.bind_loopback().await?;

        // Pre-sign the leaf once; handshake always returns the same cert.
        let leaf = ca.sign_leaf(&hostname).context("sign MITM leaf")?;
        let server_cfg = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(StaticLeafResolver(leaf))),
        );

        // Upstream client config: webpki defaults, unless the caller
        // supplied an override (tests use this).
        let roots = if let Some(override_roots) = upstream_roots_override {
            override_roots
        } else {
            let mut r = RootCertStore::empty();
            for anchor in webpki_roots::TLS_SERVER_ROOTS.iter() {
                r.roots.push(anchor.clone());
            }
            r
        };
        let client_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        let fingerprint = ca.fingerprint_sha256.clone();
        bus.send(Event::new(
            engagement_id,
            Some(catch_id),
            EventBody::HoldOpenReady(HoldOpenReady {
                local_port,
                upstream: upstream_addr.to_string(),
                mode: HoldOpenMode::TlsMitm.as_wire().to_string(),
                ca_fingerprint: Some(fingerprint.clone()),
            }),
        ));

        let transcript_path = transcript_path_for(&catch_id);
        if let Some(parent) = transcript_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let endpoint = LocalEndpoint {
            local_port,
            mode: HoldOpenMode::TlsMitm,
            ca_fingerprint: Some(fingerprint),
        };

        let bus_task = bus.clone();
        tokio::spawn(async move {
            let started = Instant::now();
            let reason = run_mitm(
                listener,
                upstream,
                server_cfg,
                client_cfg,
                hostname,
                transcript_path,
            )
            .await;
            bus_task.send(Event::new(
                engagement_id,
                Some(catch_id),
                EventBody::HoldOpenClosed(HoldOpenClosed {
                    reason: reason.to_string(),
                    duration_ms: started.elapsed().as_millis() as u64,
                }),
            ));
        });

        Ok(endpoint)
    }
}

/// Resolve the transcript path for this catch.
fn transcript_path_for(catch_id: &CatchId) -> PathBuf {
    let root = std::env::var_os("PS_ARTIFACTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./artifacts/catches"));
    root.join(catch_id.to_string())
        .join("http")
        .join("transcript.log")
}

/// Run the pentester-side TLS accept + upstream TLS connect + byte
/// shuttle. Returns the reason string for `HoldOpenClosed`.
async fn run_mitm(
    listener: TcpListener,
    upstream_tcp: TcpStream,
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<ClientConfig>,
    hostname: String,
    transcript_path: PathBuf,
) -> &'static str {
    let (local_tcp, _peer) = match listener.accept().await {
        Ok(pair) => pair,
        Err(_) => return "idle_timeout",
    };

    let acceptor = TlsAcceptor::from(server_cfg);
    let local_tls = match acceptor.accept(local_tcp).await {
        Ok(s) => s,
        Err(_) => return "pentester_handshake_failed",
    };

    let connector = TlsConnector::from(client_cfg);
    let server_name: ServerName<'static> = match ServerName::try_from(hostname.clone()) {
        Ok(n) => n,
        Err(_) => return "bad_upstream_hostname",
    };
    let upstream_tls = match connector.connect(server_name, upstream_tcp).await {
        Ok(s) => s,
        Err(_) => return "upstream_handshake_failed",
    };

    shuttle(local_tls, upstream_tls, transcript_path).await
}

/// Shuttle bytes between the two TLS streams, logging plaintext.
async fn shuttle(
    mut local: tokio_rustls::server::TlsStream<TcpStream>,
    mut upstream: tokio_rustls::client::TlsStream<TcpStream>,
    transcript_path: PathBuf,
) -> &'static str {
    let transcript_file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&transcript_path)
        .await;
    let mut transcript = match transcript_file {
        Ok(f) => Some(f),
        Err(e) => {
            tracing::warn!(error = %e, path = %transcript_path.display(), "failed to open transcript");
            None
        }
    };

    let mut buf_up = vec![0u8; 8192];
    let mut buf_down = vec![0u8; 8192];
    let reason: &'static str = loop {
        tokio::select! {
            r = local.read(&mut buf_up) => match r {
                Ok(0) => break "pentester_detach",
                Err(_) => break "pentester_detach",
                Ok(n) => {
                    if let Some(f) = transcript.as_mut() {
                        let _ = f.write_all(b"--> client->upstream\n").await;
                        let _ = f.write_all(&buf_up[..n]).await;
                        let _ = f.write_all(b"\n").await;
                    }
                    if upstream.write_all(&buf_up[..n]).await.is_err() {
                        break "upstream_closed";
                    }
                }
            },
            r = upstream.read(&mut buf_down) => match r {
                Ok(0) => break "upstream_closed",
                Err(_) => break "upstream_closed",
                Ok(n) => {
                    if let Some(f) = transcript.as_mut() {
                        let _ = f.write_all(b"<-- upstream->client\n").await;
                        let _ = f.write_all(&buf_down[..n]).await;
                        let _ = f.write_all(b"\n").await;
                    }
                    if local.write_all(&buf_down[..n]).await.is_err() {
                        break "pentester_detach";
                    }
                }
            },
        }
    };
    // Flush the transcript file before dropping so short tests that read
    // it back immediately don't race against tokio's async buffer.
    if let Some(mut f) = transcript {
        let _ = f.flush().await;
        let _ = f.sync_all().await;
    }
    reason
}
