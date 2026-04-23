//! Synthetic event stream for wiring validation. Emits the same
//! portsnatcher/v1 schema a real engagement does — the bus, sinks, and
//! downstream integrations can be exercised end-to-end before any actual
//! packet leaves the host.

use std::time::Duration;

use ps_bus::broadcast::BusSender;
use ps_core::event::payload::{
    CatchComplete, EngagementFinished, EngagementStarted, EventBody, FingerprintCaptured,
    PortOpenDetected,
};
use ps_core::event::Event;
use ps_core::id::{CatchId, EngagementId};
use tokio::time::sleep;

pub struct SimulationConfig {
    pub engagement_id: EngagementId,
    pub profile: String,
    pub engine: String,
    pub targets: Vec<String>,
    pub ports: String,
    pub rate_cap_pps: u32,
    pub artifacts_root: String,
    pub catch_count: usize,
    pub pace_ms: u64,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            engagement_id: EngagementId::new(),
            profile: "internal".into(),
            engine: "connect".into(),
            targets: vec!["127.0.0.1".into()],
            ports: "ephemeral-iana".into(),
            rate_cap_pps: 10_000,
            artifacts_root: "./artifacts".into(),
            catch_count: 3,
            pace_ms: 100,
        }
    }
}

pub async fn simulate(bus: &BusSender, cfg: SimulationConfig) {
    // Engagement start.
    bus.send(Event::new(
        cfg.engagement_id,
        None,
        EventBody::EngagementStarted(EngagementStarted {
            profile: cfg.profile.clone(),
            engine: cfg.engine.clone(),
            targets: cfg.targets.clone(),
            ports: cfg.ports.clone(),
            rate_cap_pps: cfg.rate_cap_pps,
            dry_run: true,
        }),
    ));

    // A few synthetic catches.
    for i in 0..cfg.catch_count {
        sleep(Duration::from_millis(cfg.pace_ms)).await;
        let catch_id = CatchId::new();
        let port = 49200 + i as u16;
        let target = cfg
            .targets
            .first()
            .cloned()
            .unwrap_or_else(|| "127.0.0.1".into());
        let catch_dir = format!("{}/catches/{catch_id}", cfg.artifacts_root);

        bus.send(Event::new(
            cfg.engagement_id,
            Some(catch_id),
            EventBody::PortOpenDetected(PortOpenDetected {
                target: target.clone(),
                port,
                detect_latency_ms: 180,
                engine: cfg.engine.clone(),
                syn_rtt_ms: None,
            }),
        ));

        sleep(Duration::from_millis(cfg.pace_ms / 2)).await;
        bus.send(Event::new(
            cfg.engagement_id,
            Some(catch_id),
            EventBody::FingerprintCaptured(FingerprintCaptured {
                protocol_guess: Some("http/1.1".into()),
                confidence: 0.9,
                banner_excerpt: "HTTP/1.1 200 OK (synthetic)".into(),
                tls_info: None,
                artifacts_path: catch_dir.clone(),
            }),
        ));

        bus.send(Event::new(
            cfg.engagement_id,
            Some(catch_id),
            EventBody::CatchComplete(CatchComplete {
                total_duration_ms: cfg.pace_ms,
                probes_run: 1,
                final_protocol: Some("http/1.1".into()),
                artifacts_path: catch_dir,
            }),
        ));
    }

    // Engagement finished.
    sleep(Duration::from_millis(cfg.pace_ms)).await;
    bus.send(Event::new(
        cfg.engagement_id,
        None,
        EventBody::EngagementFinished(EngagementFinished {
            catches_total: cfg.catch_count as u32,
            artifacts_root: cfg.artifacts_root,
            reason: "dry_run_complete".into(),
        }),
    ));
}
