//! ConnectEngine integration test: real loopback fixture, real socket.

use std::sync::Arc;
use std::time::Duration;

use ps_core::config::Config;
use ps_core::engagement::Engagement;
use ps_core::id::EngagementId;
use ps_core::profile::Profile;
use ps_core::scope::file::ScopeFile;
use ps_core::scope::guard::ScopeGuard;
use ps_engine::engine::{EngineContext, ProbeEngine};
use ps_engine::{ConnectEngine, RateLimiter};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;

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
async fn catches_loopback_port() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            if listener.accept().await.is_err() {
                break;
            }
        }
    });

    let engagement = minimal_engagement();
    let (bus_tx, _bus_rx) = ps_bus::broadcast::BusSender::new(64);
    let (catch_tx, mut catch_rx) = mpsc::channel(8);
    let rate = Arc::new(RateLimiter::new(10_000, 1_000));

    let ctx = EngineContext {
        engagement,
        rate_limiter: rate,
        catch_tx,
        bus: bus_tx,
        plan: vec![("127.0.0.1".parse().unwrap(), port)],
    };

    let engine = Box::new(ConnectEngine::new());
    let handle = engine.start(ctx).await.unwrap();

    let caught = timeout(Duration::from_secs(3), catch_rx.recv())
        .await
        .expect("no catch within 3s")
        .expect("catch channel closed");
    assert_eq!(caught.target.port, port);
    handle.stop();
}
