//! `HoldOpenManager` range parsing + port allocation. Lives as an
//! integration test so it can construct a real `Ca` from the public
//! API without coupling unit tests to the rustls crypto provider.

use std::sync::Arc;

use ps_proxy::{Ca, HoldOpenManager};
use tempfile::TempDir;

fn ca() -> (Arc<Ca>, TempDir) {
    let tmp = TempDir::new().unwrap();
    let ca = Arc::new(Ca::new_or_load(tmp.path()).unwrap());
    (ca, tmp)
}

#[test]
fn range_parses_valid_string() {
    let (ca, _tmp) = ca();
    let mgr = HoldOpenManager::from_range_str("7100-7199", ca).unwrap();
    assert_eq!(mgr.port_range, 7100..=7199);
}

#[test]
fn range_rejects_malformed_input() {
    let (ca, _tmp) = ca();
    assert!(HoldOpenManager::from_range_str("nope", ca.clone()).is_err());
    assert!(HoldOpenManager::from_range_str("8000-7000", ca.clone()).is_err());
    assert!(HoldOpenManager::from_range_str("", ca).is_err());
}

#[tokio::test]
async fn bind_loopback_returns_port_in_range() {
    let (ca, _tmp) = ca();
    let mgr = HoldOpenManager::new(17900..=17999, ca);
    let (_listener, port) = mgr.bind_loopback().await.unwrap();
    assert!(mgr.port_range.contains(&port));
}
