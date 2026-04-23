//! `HttpHead` matches a minimal HTTP/1.1 status line.

use std::time::Duration;

use ps_core::id::{CatchId, EngagementId};
use ps_core::target::Target;
use ps_fingerprint::probes::http::HttpHead;
use ps_fingerprint::probes::{Fingerprinter, ProbeContext, ProbeOutcome, Protocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn matches_http_1_1_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        // Drain request.
        let mut buf = [0u8; 1024];
        let _ = sock.read(&mut buf).await;
        let _ = sock
            .write_all(b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 0\r\n\r\n")
            .await;
        let _ = sock.shutdown().await;
    });

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ctx = ProbeContext {
        engagement_id: EngagementId::new(),
        catch_id: CatchId::new(),
        target: Target::new("127.0.0.1".parse().unwrap(), port),
        artifacts_dir: dir.path().to_path_buf(),
        timeout: Duration::from_secs(2),
        stream: Some(stream),
    };

    let probe = HttpHead;
    match probe.probe(ctx).await {
        ProbeOutcome::Match {
            protocol,
            confidence,
            bytes,
        } => {
            assert_eq!(protocol, Protocol::Http11);
            assert!(confidence >= 0.9);
            assert!(bytes.starts_with(b"HTTP/1.1 200"));
        }
        other => panic!("expected Match, got {other:?}"),
    }
}
