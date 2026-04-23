//! RawEngine integration test. Because raw-socket capability is unlikely
//! to be available on CI, this test asserts:
//!
//! - `RawEngine::capabilities()` reports `needs_root == true`.
//! - `start()` either succeeds (rootful) OR fails with an error message
//!   mentioning `CAP_NET_RAW` / admin (unprivileged — the expected CI
//!   path).
//!
//! We do not require the test to run as root. Either branch passes.

use std::sync::Arc;

use ps_core::config::Config;
use ps_core::engagement::Engagement;
use ps_core::id::EngagementId;
use ps_core::profile::Profile;
use ps_core::scope::file::ScopeFile;
use ps_core::scope::guard::ScopeGuard;
use ps_engine::engine::{EngineContext, ProbeEngine};
use ps_engine::raw::RawEngine;
use ps_engine::RateLimiter;
use tokio::sync::mpsc;

fn minimal_engagement() -> Engagement {
    let raw = include_str!("../../ps-core/tests/fixtures/scope-portsnatcher-ext.json");
    let sf: ScopeFile = serde_json::from_str(raw).unwrap();
    let cfg = Config::from_toml_str(r#"scope_file = "./scope.json""#).unwrap();
    let guard = ScopeGuard::builder()
        .allow_cidr("127.0.0.0/8".parse().unwrap())
        .build();
    Engagement::new(EngagementId::new(), Profile::Internal, sf, cfg, guard)
}

#[tokio::test]
async fn raw_engine_reports_root_capabilities() {
    let engine = RawEngine::new();
    let caps = engine.capabilities();
    assert!(caps.needs_root, "raw engine must report needs_root=true");
    assert!(caps.supported);
}

#[tokio::test]
async fn raw_engine_start_either_succeeds_or_errors_on_privilege() {
    let engagement = minimal_engagement();
    let (bus_tx, _bus_rx) = ps_bus::broadcast::BusSender::new(64);
    let (catch_tx, _catch_rx) = mpsc::channel(8);
    let rate = Arc::new(RateLimiter::new(10_000, 1_000));

    let ctx = EngineContext {
        engagement,
        rate_limiter: rate,
        catch_tx,
        bus: bus_tx,
        plan: vec![("127.0.0.1".parse().unwrap(), 9)],
    };

    let engine = Box::new(RawEngine::new());
    match engine.start(ctx).await {
        Ok(handle) => {
            // Rootful branch — just confirm we got a handle and stop it.
            handle.stop();
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("CAP_NET_RAW") || msg.contains("admin"),
                "expected permission error, got: {msg}"
            );
        }
    }
}

#[tokio::test]
async fn capability_report_serializes() {
    let report = RawEngine::probe_capability_report();
    let j = serde_json::to_string(&report).expect("report must be serializable");
    assert!(j.contains("smoltcp_userspace"));
    assert!(j.contains("raw_socket_available"));
}
