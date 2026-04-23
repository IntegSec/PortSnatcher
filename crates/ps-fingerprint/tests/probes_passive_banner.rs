//! `PassiveBanner` captures an SSH banner and writes it to `banner.bin`.

use std::time::Duration;

use ps_core::id::{CatchId, EngagementId};
use ps_core::target::Target;
use ps_fingerprint::probes::passive_banner::PassiveBanner;
use ps_fingerprint::probes::{Fingerprinter, ProbeContext, ProbeOutcome, Protocol};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

#[tokio::test]
async fn captures_ssh_banner() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let _ = sock.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await;
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
        timeout: Duration::from_millis(500),
        stream: Some(stream),
    };

    let probe = PassiveBanner;
    match probe.probe(ctx).await {
        ProbeOutcome::Match {
            protocol, bytes, ..
        } => {
            assert_eq!(protocol, Protocol::Ssh);
            assert!(bytes.starts_with(b"SSH-2.0"));
            let saved = std::fs::read(dir.path().join("banner.bin")).unwrap();
            assert_eq!(saved, bytes.as_ref());
        }
        other => panic!("expected Match, got {other:?}"),
    }
}
