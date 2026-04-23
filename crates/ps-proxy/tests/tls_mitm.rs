//! TLS MITM end-to-end: hyper+rustls HTTPS fixture, MITM terminates
//! the pentester's TLS with a PortSnatcher-CA-signed leaf, re-encrypts
//! upstream, logs plaintext to a transcript. We assert the client gets
//! the response body AND that the transcript captured both a
//! well-known request header and the response body.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use ps_bus::broadcast::BusSender;
use ps_core::id::{CatchId, EngagementId};
use ps_proxy::{Ca, HoldOpen, HoldOpenManager, TlsMitm};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::convert::Infallible;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug)]
struct StaticLeafResolver(Arc<CertifiedKey>);
impl rustls::server::ResolvesServerCert for StaticLeafResolver {
    fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

async fn spawn_https_fixture(leaf: Arc<CertifiedKey>) -> std::net::SocketAddr {
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(StaticLeafResolver(leaf)));
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(tcp).await {
                    Ok(t) => t,
                    Err(_) => return,
                };
                let io = TokioIo::new(tls);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(|_req: Request<hyper::body::Incoming>| async {
                            let body = Full::new(Bytes::from("hello-mitm-transcript"));
                            Ok::<_, Infallible>(Response::new(body))
                        }),
                    )
                    .await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn mitm_terminates_and_logs_plaintext_transcript() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let tmp = TempDir::new().unwrap();
    let ca = Arc::new(Ca::new_or_load(tmp.path()).unwrap());

    // Use the SAME PortSnatcher CA to sign the fixture upstream cert.
    // Keeps the test self-contained; the MITM's upstream side is
    // pointed at a root store containing this CA via `with_upstream_roots`.
    let upstream_hostname = "fixture.local".to_string();
    let fixture_leaf = ca.sign_leaf(&upstream_hostname).unwrap();
    let upstream_addr = spawn_https_fixture(fixture_leaf).await;

    // Artifacts root — point the MITM at our tempdir via env var.
    let artifacts_dir = tmp.path().join("artifacts");
    std::env::set_var("PS_ARTIFACTS_DIR", &artifacts_dir);

    // Manager uses a distinct port range so it doesn't collide with the
    // other integration tests when run in parallel.
    let mgr = Arc::new(HoldOpenManager::new(17300..=17399, ca.clone()));

    // Root store for the MITM's upstream client (contains only our CA).
    let mut upstream_roots = RootCertStore::empty();
    upstream_roots
        .add(CertificateDer::from(ca.cert_der.clone()))
        .unwrap();

    let mitm = Box::new(
        TlsMitm::new(mgr.clone(), upstream_hostname.clone()).with_upstream_roots(upstream_roots),
    );

    // Connect upstream TCP; the MITM handles the TLS wrap itself.
    let upstream_tcp = TcpStream::connect(upstream_addr).await.unwrap();

    let (bus, mut rx) = BusSender::new(64);
    let catch_id = CatchId::new();
    let engagement_id = EngagementId::new();

    let ep = mitm
        .establish(
            catch_id,
            upstream_tcp,
            upstream_addr,
            Some(upstream_hostname.clone()),
            bus.clone(),
            engagement_id,
        )
        .await
        .unwrap();

    // Drain the HoldOpenReady event.
    let _ready = rx.recv().await.unwrap();

    // Client side: trust our CA, connect to the MITM port.
    let mut client_roots = RootCertStore::empty();
    client_roots
        .add(CertificateDer::from(ca.cert_der.clone()))
        .unwrap();
    let client_cfg = ClientConfig::builder()
        .with_root_certificates(client_roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));

    let client_tcp = TcpStream::connect(("127.0.0.1", ep.local_port))
        .await
        .unwrap();
    let server_name = ServerName::try_from(upstream_hostname.as_str())
        .unwrap()
        .to_owned();
    let mut tls = connector.connect(server_name, client_tcp).await.unwrap();

    // Send a well-known request header the transcript must capture.
    let req = b"GET / HTTP/1.1\r\nHost: fixture.local\r\nX-PS-Marker: portsnatcher-test\r\nConnection: close\r\n\r\n";
    tls.write_all(req).await.unwrap();

    // Read the full response.
    let mut resp = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut resp))
        .await
        .expect("read_to_end within timeout");
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(
        resp_str.contains("hello-mitm-transcript"),
        "response body: {resp_str}"
    );

    // Give the MITM a moment to flush transcript writes before we drop
    // the client (write-all is buffered before the tokio-rustls
    // shutdown flushes everything to disk).
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(tls);

    // Wait for the HoldOpenClosed event so we know the tunnel task is done.
    let _closed = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("closed event")
        .expect("bus open");

    // Transcript lives at <artifacts>/<catch_id>/http/transcript.log.
    let transcript_path = artifacts_dir
        .join(catch_id.to_string())
        .join("http")
        .join("transcript.log");
    let contents = std::fs::read_to_string(&transcript_path)
        .unwrap_or_else(|e| panic!("transcript missing at {}: {e}", transcript_path.display()));
    assert!(
        contents.contains("X-PS-Marker: portsnatcher-test"),
        "transcript missing request marker:\n{contents}"
    );
    assert!(
        contents.contains("hello-mitm-transcript"),
        "transcript missing response body:\n{contents}"
    );

    std::env::remove_var("PS_ARTIFACTS_DIR");
}
