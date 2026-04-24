//! Terminal sink: emits a structured `tracing::info!` per event.
//!
//! The formatter shows the most operationally useful fields per event
//! type — e.g. `target:port` + `reason` for `ScopeViolationBlocked`,
//! `protocol` + `confidence` for `FingerprintCaptured`. The full event
//! payload is always available on the bus and in `events.jsonl`; this
//! sink is for the human watching the terminal.

use async_trait::async_trait;
use ps_core::event::payload::EventBody;
use ps_core::event::Event;

use crate::sink::EventSink;

#[derive(Debug, Default)]
pub struct TerminalSink;

#[async_trait]
impl EventSink for TerminalSink {
    fn name(&self) -> &'static str {
        "terminal"
    }

    async fn emit(&self, event: &Event) {
        let summary = summarise(&event.body);
        tracing::info!(
            engagement = %event.engagement_id,
            catch = ?event.catch_id,
            "{summary}"
        );
    }
}

/// One-line human summary of an event's payload. Kept alongside the
/// sink so it's trivially testable without TerminalSink's async
/// machinery.
pub fn summarise(body: &EventBody) -> String {
    match body {
        EventBody::EngagementStarted(p) => format!(
            "EngagementStarted  profile={} engine={} targets={:?} ports={} rate_cap_pps={} dry_run={}",
            p.profile, p.engine, p.targets, p.ports, p.rate_cap_pps, p.dry_run
        ),
        EventBody::PortOpenDetected(p) => format!(
            "PortOpenDetected   {}:{} engine={} detect_latency_ms={}",
            p.target, p.port, p.engine, p.detect_latency_ms
        ),
        EventBody::HoldOpenReady(p) => format!(
            "HoldOpenReady      upstream={} → localhost:{} mode={}",
            p.upstream, p.local_port, p.mode
        ),
        EventBody::HoldOpenClosed(p) => format!(
            "HoldOpenClosed     reason={} duration_ms={}",
            p.reason, p.duration_ms
        ),
        EventBody::ProbeAttempted(p) => format!(
            "ProbeAttempted     probe={} outcome={} bytes_captured={}",
            p.probe, p.outcome, p.bytes_captured
        ),
        EventBody::FingerprintCaptured(p) => {
            let protocol = p.protocol_guess.as_deref().unwrap_or("unknown");
            format!(
                "FingerprintCaptured protocol={} confidence={:.2} banner={:?}",
                protocol,
                p.confidence,
                truncate(&p.banner_excerpt, 80)
            )
        }
        EventBody::CatchComplete(p) => {
            let protocol = p.final_protocol.as_deref().unwrap_or("unknown");
            format!(
                "CatchComplete      protocol={} probes_run={} total_duration_ms={}",
                protocol, p.probes_run, p.total_duration_ms
            )
        }
        EventBody::ScopeViolationBlocked(p) => format!(
            "ScopeViolationBlocked  {}:{}  reason=\"{}\"",
            p.attempted_target, p.attempted_port, p.reason
        ),
        EventBody::RateCapEngaged(p) => format!(
            "RateCapEngaged     current_pps={} cap_pps={} throttled_targets={}",
            p.current_pps, p.cap_pps, p.throttled_targets
        ),
        EventBody::EngagementFinished(p) => format!(
            "EngagementFinished reason={} catches_total={} artifacts={}",
            p.reason, p.catches_total, p.artifacts_root
        ),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else {
        format!("{}…", &s[..max.min(s.len())])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ps_core::event::payload::{EngagementStarted, PortOpenDetected, ScopeViolationBlocked};
    use ps_core::id::EngagementId;

    #[tokio::test]
    async fn emits_without_panic() {
        let sink = TerminalSink;
        let ev = Event::new(
            EngagementId::new(),
            None,
            EventBody::EngagementStarted(EngagementStarted {
                profile: "internal".into(),
                engine: "connect".into(),
                targets: vec![],
                ports: "all".into(),
                rate_cap_pps: 0,
                dry_run: false,
            }),
        );
        sink.emit(&ev).await;
    }

    #[test]
    fn summary_scope_violation_includes_reason() {
        let body = EventBody::ScopeViolationBlocked(ScopeViolationBlocked {
            attempted_target: "10.0.99.5".into(),
            attempted_port: 80,
            reason: "target is not in authorized scope".into(),
        });
        let s = summarise(&body);
        assert!(s.contains("10.0.99.5:80"), "target absent in {s}");
        assert!(
            s.contains("target is not in authorized scope"),
            "reason absent in {s}"
        );
    }

    #[test]
    fn summary_port_open_includes_target_and_engine() {
        let body = EventBody::PortOpenDetected(PortOpenDetected {
            target: "38.32.112.58".into(),
            port: 443,
            detect_latency_ms: 12,
            engine: "connect".into(),
            syn_rtt_ms: None,
        });
        let s = summarise(&body);
        assert!(s.contains("38.32.112.58:443"));
        assert!(s.contains("engine=connect"));
    }
}
