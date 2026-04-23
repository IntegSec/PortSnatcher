//! CA storage + generation + leaf signing tests.
//!
//! None of these tests touch the system trust store — `ca::trust` is
//! covered by the per-function platform unit tests in that module and
//! is exercised manually on the operator's workstation.

use ps_proxy::Ca;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::RootCertStore;
use std::sync::Arc;
use tempfile::TempDir;

#[test]
fn new_or_load_is_idempotent() {
    let tmp = TempDir::new().unwrap();
    let first = Ca::new_or_load(tmp.path()).unwrap();
    let second = Ca::new_or_load(tmp.path()).unwrap();
    assert_eq!(first.fingerprint_sha256, second.fingerprint_sha256);
    assert_eq!(first.cert_der, second.cert_der);
    assert_eq!(first.fingerprint_sha256.len(), 64);
}

#[test]
fn new_or_load_writes_all_three_files() {
    let tmp = TempDir::new().unwrap();
    let _ca = Ca::new_or_load(tmp.path()).unwrap();
    assert!(tmp.path().join("ca.crt").is_file());
    assert!(tmp.path().join("ca.key").is_file());
    assert!(tmp.path().join("ca-fingerprint.sha256").is_file());
}

#[test]
fn sign_leaf_caches_by_hostname() {
    // Ensure the crypto provider is installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let tmp = TempDir::new().unwrap();
    let ca = Ca::new_or_load(tmp.path()).unwrap();
    let a = ca.sign_leaf("example.com").unwrap();
    let b = ca.sign_leaf("example.com").unwrap();
    assert!(Arc::ptr_eq(&a, &b), "same hostname must hit the cache");

    let c = ca.sign_leaf("other.example.com").unwrap();
    assert!(
        !Arc::ptr_eq(&a, &c),
        "different hostname must issue a fresh leaf"
    );
}

#[tokio::test]
async fn leaf_verifies_against_generated_ca() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let tmp = TempDir::new().unwrap();
    let ca = Ca::new_or_load(tmp.path()).unwrap();
    let leaf = ca.sign_leaf("example.com").unwrap();

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca.cert_der.clone()))
        .unwrap();

    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();

    let leaf_der = leaf.cert[0].clone();
    let intermediates = if leaf.cert.len() > 1 {
        leaf.cert[1..].to_vec()
    } else {
        Vec::new()
    };
    let server_name = ServerName::try_from("example.com").unwrap();

    verifier
        .verify_server_cert(
            &leaf_der,
            &intermediates,
            &server_name,
            &[],
            UnixTime::now(),
        )
        .expect("leaf must verify against the generated CA");
}
