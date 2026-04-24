//! Schema-stability tests. If any of these snapshots change, the schema
//! is changing — which requires a `portsnatcher/v2` bump AND consumer
//! coordination. Regenerate only as a deliberate action:
//!   cargo insta review
//! Commit reviewed snapshots in the same PR as the schema bump.

use ps_core::event::payload::{
    CatchComplete, EngagementFinished, EngagementStarted, EventBody, FingerprintCaptured,
    HoldOpenClosed, HoldOpenReady, PortClosedDetected, PortOpenDetected, ProbeAttempted,
    RateCapEngaged, ScopeViolationBlocked, TlsInfo,
};
use ps_core::event::Event;
use ps_core::id::{CatchId, EngagementId, EventId};
use serde::Serialize;
use time::macros::datetime;

/// Stamps deterministic IDs and timestamp so snapshots are reproducible.
fn deterministic_event(body: EventBody) -> Event {
    Event {
        schema: "portsnatcher/v1".to_owned(),
        event_id: EventId("01HX2K7Z9P8R5M4N3A2B1C0D9E".parse().unwrap()),
        catch_id: Some(CatchId("01HX2K7Y9P8R5M4N3A2B1C0D9E".parse().unwrap())),
        engagement_id: EngagementId("01HX2K009P8R5M4N3A2B1C0D9E".parse().unwrap()),
        timestamp: datetime!(2026-04-22 20:30:15 UTC),
        body,
    }
}

fn to_canonical_json<T: Serialize>(v: &T) -> String {
    let value: serde_json::Value = serde_json::to_value(v).unwrap();
    serde_json::to_string_pretty(&value).unwrap()
}

#[test]
fn snapshot_engagement_started() {
    let ev = deterministic_event(EventBody::EngagementStarted(EngagementStarted {
        profile: "internal".into(),
        engine: "raw".into(),
        targets: vec!["10.0.0.0/24".into()],
        ports: "ephemeral-iana".into(),
        rate_cap_pps: 50_000,
        dry_run: false,
    }));
    insta::assert_snapshot!("engagement_started", to_canonical_json(&ev));
}

#[test]
fn snapshot_port_open_detected() {
    let ev = deterministic_event(EventBody::PortOpenDetected(PortOpenDetected {
        target: "10.0.0.1".into(),
        port: 54283,
        detect_latency_ms: 180,
        engine: "raw".into(),
        syn_rtt_ms: Some(2),
    }));
    insta::assert_snapshot!("port_open_detected", to_canonical_json(&ev));
}

#[test]
fn snapshot_port_closed_detected() {
    let ev = deterministic_event(EventBody::PortClosedDetected(PortClosedDetected {
        target: "10.0.0.1".into(),
        port: 54283,
        reason: "connection_refused".into(),
        was_open_for_ms: Some(4200),
    }));
    insta::assert_snapshot!("port_closed_detected", to_canonical_json(&ev));
}

#[test]
fn snapshot_hold_open_ready() {
    let ev = deterministic_event(EventBody::HoldOpenReady(HoldOpenReady {
        local_port: 7101,
        upstream: "10.0.0.1:54283".into(),
        mode: "dumb_tunnel".into(),
        ca_fingerprint: None,
    }));
    insta::assert_snapshot!("hold_open_ready", to_canonical_json(&ev));
}

#[test]
fn snapshot_hold_open_closed() {
    let ev = deterministic_event(EventBody::HoldOpenClosed(HoldOpenClosed {
        reason: "upstream_closed".into(),
        duration_ms: 4721,
    }));
    insta::assert_snapshot!("hold_open_closed", to_canonical_json(&ev));
}

#[test]
fn snapshot_probe_attempted() {
    let ev = deterministic_event(EventBody::ProbeAttempted(ProbeAttempted {
        probe: "tls_hello".into(),
        outcome: "match".into(),
        bytes_captured: 1234,
    }));
    insta::assert_snapshot!("probe_attempted", to_canonical_json(&ev));
}

#[test]
fn snapshot_fingerprint_captured() {
    let ev = deterministic_event(EventBody::FingerprintCaptured(FingerprintCaptured {
        protocol_guess: Some("https".into()),
        confidence: 0.95,
        banner_excerpt: "HTTP/1.1 200 OK".into(),
        tls_info: Some(TlsInfo {
            server_name: Some("example.com".into()),
            alpn: Some("h2".into()),
            cert_subject: Some("CN=example.com".into()),
            cert_issuer: Some("CN=Example CA".into()),
            not_after: Some("2027-01-01T00:00:00Z".into()),
        }),
        artifacts_path: "artifacts/01HX2K00.../catches/01HX2K7Y...".into(),
    }));
    insta::assert_snapshot!("fingerprint_captured", to_canonical_json(&ev));
}

#[test]
fn snapshot_catch_complete() {
    let ev = deterministic_event(EventBody::CatchComplete(CatchComplete {
        total_duration_ms: 1800,
        probes_run: 3,
        final_protocol: Some("http/1.1".into()),
        artifacts_path: "artifacts/01HX2K00.../catches/01HX2K7Y...".into(),
    }));
    insta::assert_snapshot!("catch_complete", to_canonical_json(&ev));
}

#[test]
fn snapshot_scope_violation_blocked() {
    let ev = deterministic_event(EventBody::ScopeViolationBlocked(ScopeViolationBlocked {
        attempted_target: "10.0.99.5".into(),
        attempted_port: 80,
        reason: "not in scope".into(),
    }));
    insta::assert_snapshot!("scope_violation_blocked", to_canonical_json(&ev));
}

#[test]
fn snapshot_rate_cap_engaged() {
    let ev = deterministic_event(EventBody::RateCapEngaged(RateCapEngaged {
        current_pps: 50_500,
        cap_pps: 50_000,
        throttled_targets: 2,
    }));
    insta::assert_snapshot!("rate_cap_engaged", to_canonical_json(&ev));
}

#[test]
fn snapshot_engagement_finished() {
    let ev = deterministic_event(EventBody::EngagementFinished(EngagementFinished {
        catches_total: 7,
        artifacts_root: "artifacts/01HX2K00...".into(),
        reason: "completed".into(),
    }));
    insta::assert_snapshot!("engagement_finished", to_canonical_json(&ev));
}
