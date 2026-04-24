//! Frozen `portsnatcher/v1` event schema. See the spec §9.
//!
//! **Stability contract:** this schema is additive-only. New fields and new
//! variants are non-breaking; removing or renaming requires a v2 bump and
//! a parallel consumer update. The `insta` snapshots in the tests
//! directory are the enforcement mechanism.

pub mod payload;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::id::{CatchId, EngagementId, EventId};

pub const SCHEMA: &str = "portsnatcher/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub schema: String,
    pub event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catch_id: Option<CatchId>,
    pub engagement_id: EngagementId,
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    #[serde(flatten)]
    pub body: payload::EventBody,
}

impl Event {
    pub fn new(
        engagement_id: EngagementId,
        catch_id: Option<CatchId>,
        body: payload::EventBody,
    ) -> Self {
        Self {
            schema: SCHEMA.to_owned(),
            event_id: EventId::new(),
            catch_id,
            engagement_id,
            timestamp: OffsetDateTime::now_utc(),
            body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::payload::{
        CatchComplete, EngagementFinished, EngagementStarted, EventBody, FingerprintCaptured,
        HoldOpenClosed, HoldOpenReady, PortClosedDetected, PortOpenDetected, ProbeAttempted,
        RateCapEngaged, ScopeViolationBlocked, TlsInfo,
    };

    #[test]
    fn envelope_round_trips() {
        let e = Event::new(
            EngagementId::new(),
            None,
            EventBody::EngagementStarted(EngagementStarted {
                profile: "internal".into(),
                engine: "connect".into(),
                targets: vec!["10.0.0.0/24".into()],
                ports: "ephemeral-iana".into(),
                rate_cap_pps: 50_000,
                dry_run: false,
            }),
        );
        let json = serde_json::to_string(&e).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema, SCHEMA);
        assert_eq!(back.engagement_id, e.engagement_id);
    }

    #[test]
    fn all_variants_round_trip() {
        let engagement_id = EngagementId::new();
        let catch_id = CatchId::new();

        let bodies = vec![
            EventBody::EngagementStarted(EngagementStarted {
                profile: "internal".into(),
                engine: "raw".into(),
                targets: vec!["10.0.0.0/24".into()],
                ports: "ephemeral-iana".into(),
                rate_cap_pps: 50_000,
                dry_run: false,
            }),
            EventBody::PortOpenDetected(PortOpenDetected {
                target: "10.0.0.1".into(),
                port: 54283,
                detect_latency_ms: 180,
                engine: "raw".into(),
                syn_rtt_ms: Some(2),
            }),
            EventBody::PortClosedDetected(PortClosedDetected {
                target: "10.0.0.1".into(),
                port: 54283,
                reason: "connection_refused".into(),
                was_open_for_ms: Some(4200),
            }),
            EventBody::HoldOpenReady(HoldOpenReady {
                local_port: 7101,
                upstream: "10.0.0.1:54283".into(),
                mode: "dumb_tunnel".into(),
                ca_fingerprint: None,
            }),
            EventBody::HoldOpenClosed(HoldOpenClosed {
                reason: "upstream_closed".into(),
                duration_ms: 4721,
            }),
            EventBody::ProbeAttempted(ProbeAttempted {
                probe: "passive_banner".into(),
                outcome: "match".into(),
                bytes_captured: 42,
            }),
            EventBody::FingerprintCaptured(FingerprintCaptured {
                protocol_guess: Some("http/1.1".into()),
                confidence: 0.95,
                banner_excerpt: "HTTP/1.1 200 OK".into(),
                tls_info: Some(TlsInfo {
                    server_name: Some("example.com".into()),
                    alpn: Some("h2".into()),
                    cert_subject: Some("CN=example.com".into()),
                    cert_issuer: Some("CN=Example CA".into()),
                    not_after: Some("2027-01-01T00:00:00Z".into()),
                }),
                artifacts_path: "artifacts/x/catches/y".into(),
            }),
            EventBody::CatchComplete(CatchComplete {
                total_duration_ms: 1800,
                probes_run: 3,
                final_protocol: Some("http/1.1".into()),
                artifacts_path: "artifacts/x/catches/y".into(),
            }),
            EventBody::ScopeViolationBlocked(ScopeViolationBlocked {
                attempted_target: "10.0.99.5".into(),
                attempted_port: 80,
                reason: "target not in scope".into(),
            }),
            EventBody::RateCapEngaged(RateCapEngaged {
                current_pps: 50_500,
                cap_pps: 50_000,
                throttled_targets: 2,
            }),
            EventBody::EngagementFinished(EngagementFinished {
                catches_total: 7,
                artifacts_root: "artifacts/x".into(),
                reason: "completed".into(),
            }),
        ];
        for body in bodies {
            let ev = Event::new(engagement_id, Some(catch_id), body.clone());
            let json = serde_json::to_string(&ev).unwrap();
            let back: Event = serde_json::from_str(&json).unwrap();
            assert_eq!(
                serde_json::to_string(&back.body).unwrap(),
                serde_json::to_string(&body).unwrap(),
                "body round-trip mismatch"
            );
        }
    }
}
