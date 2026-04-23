//! `RedisPing` receives `+PONG` from a loopback fixture.

use std::time::Duration;

use ps_core::id::{CatchId, EngagementId};
use ps_core::target::Target;
use ps_fingerprint::probes::redis::RedisPing;
use ps_fingerprint::probes::{Fingerprinter, ProbeContext, ProbeOutcome, Protocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn matches_pong_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 64];
        let _ = sock.read(&mut buf).await;
        let _ = sock.write_all(b"+PONG\r\n").await;
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
        timeout: Duration::from_secs(1),
        stream: Some(stream),
    };

    let probe = RedisPing;
    match probe.probe(ctx).await {
        ProbeOutcome::Match { protocol, .. } => {
            assert_eq!(protocol, Protocol::Redis);
        }
        other => panic!("expected Match, got {other:?}"),
    }
}
