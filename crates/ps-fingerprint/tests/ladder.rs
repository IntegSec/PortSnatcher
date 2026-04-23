//! Integration test: full ladder walk against a single-connection HTTP
//! fixture, asserting the ProbeAttempted → FingerprintCaptured →
//! CatchComplete sequence on the bus.

mod common;

use std::sync::Arc;

use ps_bus::broadcast::BusSender;
use ps_core::event::payload::EventBody;
use ps_core::id::CatchId;
use ps_core::target::Target;
use ps_fingerprint::cache::FingerprintCache;
use ps_fingerprint::ladder::ProbeLadder;
use ps_fingerprint::probes::passive_banner::PassiveBanner;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

#[tokio::test]
async fn ladder_emits_expected_sequence_on_http_fixture() {
    // Fixture: accept one connection, emit a valid HTTP/1.1 status line.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let _ = sock.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
        let _ = sock.shutdown().await;
    });

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let target = Target::new("127.0.0.1".parse().unwrap(), port);

    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("fp.json");
    let cache = FingerprintCache::new(cache_path);

    let ladder = ProbeLadder::new(
        vec![Arc::new(PassiveBanner)],
        dir.path().to_path_buf(),
        cache,
    );

    let engagement = common::engagement_permissive();
    let (bus, mut rx) = BusSender::new(32);

    let catch_id = CatchId::new();
    ladder
        .run(&engagement, catch_id, target, stream, &bus)
        .await;

    // Drain the first three events.
    let e1 = rx.recv().await.unwrap();
    let e2 = rx.recv().await.unwrap();
    let e3 = rx.recv().await.unwrap();

    match &e1.body {
        EventBody::ProbeAttempted(p) => {
            assert_eq!(p.probe, "passive_banner");
            assert_eq!(p.outcome, "match");
            assert!(p.bytes_captured > 0);
        }
        other => panic!("expected ProbeAttempted, got {other:?}"),
    }
    match &e2.body {
        EventBody::FingerprintCaptured(fp) => {
            assert_eq!(fp.protocol_guess.as_deref(), Some("http11"));
            assert!(fp.confidence >= 0.8);
            assert!(fp.banner_excerpt.starts_with("HTTP/1.1"));
        }
        other => panic!("expected FingerprintCaptured, got {other:?}"),
    }
    match &e3.body {
        EventBody::CatchComplete(cc) => {
            assert_eq!(cc.final_protocol.as_deref(), Some("http11"));
            assert_eq!(cc.probes_run, 1);
        }
        other => panic!("expected CatchComplete, got {other:?}"),
    }
}
