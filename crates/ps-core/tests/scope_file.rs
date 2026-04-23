use ps_core::scope::file::ScopeFile;

#[test]
fn parses_agentic_manifest() {
    let raw = include_str!("fixtures/scope-manifest.json");
    let sf: ScopeFile = serde_json::from_str(raw).expect("parse");
    assert_eq!(sf.engagement_id, "ENG-2025-0142");
    assert_eq!(sf.client, "Acme Corp");
    assert_eq!(sf.authorized_targets.ip_ranges.len(), 2);
    assert_eq!(sf.authorized_targets.domains.len(), 2);
    assert!(sf.portsnatcher.is_none());
}

#[test]
fn parses_integsec_fixture() {
    let raw = include_str!("fixtures/scope-test-integsec.json");
    let sf: ScopeFile = serde_json::from_str(raw).expect("parse");
    assert_eq!(sf.engagement_id, "ENG-2026-TEST-001");
    assert!(sf.authorized_targets.ip_ranges.is_empty());
}

#[test]
fn parses_portsnatcher_extension() {
    let raw = include_str!("fixtures/scope-portsnatcher-ext.json");
    let sf: ScopeFile = serde_json::from_str(raw).expect("parse");
    let ext = sf.portsnatcher.as_ref().expect("has extension");
    assert!(ext.port_policy.include.contains(&"ephemeral-iana".to_owned()));
}
