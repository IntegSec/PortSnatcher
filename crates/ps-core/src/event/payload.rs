//! Every payload variant in the frozen `portsnatcher/v1` schema.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum EventBody {
    EngagementStarted(EngagementStarted),
    PortOpenDetected(PortOpenDetected),
    /// New in v1.2.2 — additive to the frozen `portsnatcher/v1` schema.
    /// Emitted when the scheduler observes an Open→Closed transition
    /// for a `(target, port)` that was previously seen open.
    PortClosedDetected(PortClosedDetected),
    HoldOpenReady(HoldOpenReady),
    HoldOpenClosed(HoldOpenClosed),
    ProbeAttempted(ProbeAttempted),
    FingerprintCaptured(FingerprintCaptured),
    CatchComplete(CatchComplete),
    ScopeViolationBlocked(ScopeViolationBlocked),
    RateCapEngaged(RateCapEngaged),
    EngagementFinished(EngagementFinished),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementStarted {
    pub profile: String,
    pub engine: String,
    pub targets: Vec<String>,
    pub ports: String,
    pub rate_cap_pps: u32,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortOpenDetected {
    pub target: String,
    pub port: u16,
    pub detect_latency_ms: u64,
    pub engine: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syn_rtt_ms: Option<u64>,
}

/// Emitted on an observed Open→Closed transition for a `(target, port)`
/// that was previously open in this engagement. New in v1.2.2; consumers
/// that don't know about it should tolerate and skip (documented v1
/// additive-evolution policy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortClosedDetected {
    pub target: String,
    pub port: u16,
    /// Why the scheduler believes the port is closed —
    /// `"connection_refused"`, `"transient_timeout"`, `"rst"`, etc.
    pub reason: String,
    /// How long (ms) the port was observed open before this transition.
    /// Useful for ephemeral-port flap analysis.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub was_open_for_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoldOpenReady {
    pub local_port: u16,
    pub upstream: String,
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoldOpenClosed {
    pub reason: String,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeAttempted {
    pub probe: String,
    pub outcome: String,
    pub bytes_captured: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintCaptured {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_guess: Option<String>,
    pub confidence: f32,
    pub banner_excerpt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_info: Option<TlsInfo>,
    pub artifacts_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub server_name: Option<String>,
    pub alpn: Option<String>,
    pub cert_subject: Option<String>,
    pub cert_issuer: Option<String>,
    pub not_after: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatchComplete {
    pub total_duration_ms: u64,
    pub probes_run: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_protocol: Option<String>,
    pub artifacts_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeViolationBlocked {
    pub attempted_target: String,
    pub attempted_port: u16,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateCapEngaged {
    pub current_pps: u32,
    pub cap_pps: u32,
    pub throttled_targets: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementFinished {
    pub catches_total: u32,
    pub artifacts_root: String,
    pub reason: String,
}
