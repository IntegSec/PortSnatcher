//! Metadata-only tests for probes without a dedicated loopback fixture:
//! assert `name()` and `techniques()` so refactors don't silently rename
//! things downstream of the `ProbeAttempted.probe` wire field.

use ps_core::technique::TechniqueTag;
use ps_fingerprint::probes::{
    http::{HttpGetRoot, HttpHead},
    mongo::MongoIsMaster,
    passive_banner::PassiveBanner,
    postgres::PostgresStartup,
    redis::RedisPing,
    smb::SmbNegotiate,
    ssh::SshBanner,
    tls_hello::TlsHello,
    Fingerprinter,
};

#[test]
fn passive_banner_metadata() {
    let p = PassiveBanner;
    assert_eq!(p.name(), "passive_banner");
    assert_eq!(p.techniques(), &[TechniqueTag::Recon]);
    assert!(!p.is_destructive());
}

#[test]
fn tls_hello_metadata() {
    let p = TlsHello;
    assert_eq!(p.name(), "tls_hello");
    assert_eq!(p.techniques(), &[TechniqueTag::Recon, TechniqueTag::SslTls]);
    assert!(!p.is_destructive());
}

#[test]
fn http_head_metadata() {
    let p = HttpHead;
    assert_eq!(p.name(), "http_head");
    assert_eq!(p.techniques(), &[TechniqueTag::Recon, TechniqueTag::WebApp]);
}

#[test]
fn http_get_root_metadata() {
    let p = HttpGetRoot;
    assert_eq!(p.name(), "http_get_root");
    assert_eq!(p.techniques(), &[TechniqueTag::WebApp]);
}

#[test]
fn ssh_banner_metadata() {
    let p = SshBanner;
    assert_eq!(p.name(), "ssh_banner");
    assert_eq!(p.techniques(), &[TechniqueTag::Recon]);
}

#[test]
fn redis_ping_metadata() {
    let p = RedisPing;
    assert_eq!(p.name(), "redis_ping");
    assert_eq!(p.techniques(), &[TechniqueTag::ApiTesting]);
}

#[test]
fn mongo_is_master_metadata() {
    let p = MongoIsMaster;
    assert_eq!(p.name(), "mongo_is_master");
    assert_eq!(p.techniques(), &[TechniqueTag::ApiTesting]);
}

#[test]
fn postgres_startup_metadata() {
    let p = PostgresStartup;
    assert_eq!(p.name(), "postgres_startup");
    assert_eq!(p.techniques(), &[TechniqueTag::ApiTesting]);
}

#[test]
fn smb_negotiate_metadata() {
    let p = SmbNegotiate;
    assert_eq!(p.name(), "smb_negotiate");
    assert_eq!(p.techniques(), &[TechniqueTag::Recon]);
}
