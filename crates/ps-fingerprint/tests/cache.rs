//! Integration test: cache insert → flush → reload round-trip.

use std::path::PathBuf;

use bytes::Bytes;
use ps_core::id::CatchId;
use ps_core::target::Target;
use ps_fingerprint::cache::FingerprintCache;
use ps_fingerprint::probes::Protocol;
use ps_fingerprint::report::{FingerprintReport, ProbeRunRecord};

fn sample(catch: CatchId) -> FingerprintReport {
    FingerprintReport {
        catch_id: catch,
        protocol_guess: Some(Protocol::Http11),
        confidence: 0.95,
        banner_excerpt: Bytes::from_static(b"HTTP/1.1 200 OK\r\n"),
        tls_info: None,
        probes_run: vec![ProbeRunRecord {
            probe: "http_head",
            outcome: "match",
            bytes_captured: 17,
            duration_ms: 23,
        }],
        artifacts_path: PathBuf::from("/tmp/x"),
    }
}

#[tokio::test]
async fn persists_and_reloads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fp.json");
    let target = Target::new("10.0.0.5".parse().unwrap(), 443);
    let cache = FingerprintCache::new(path.clone());
    cache.insert(target.clone(), sample(CatchId::new())).await;
    cache.flush().await.unwrap();

    let reloaded = FingerprintCache::load(path).await.unwrap();
    let got = reloaded.get(&target).await.unwrap();
    assert_eq!(got.protocol_guess, Some(Protocol::Http11));
    assert!((got.confidence - 0.95).abs() < 1e-6);
}

#[tokio::test]
async fn get_returns_none_for_missing_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fp.json");
    let cache = FingerprintCache::new(path);
    let target = Target::new("10.0.0.7".parse().unwrap(), 80);
    assert!(cache.get(&target).await.is_none());
}
