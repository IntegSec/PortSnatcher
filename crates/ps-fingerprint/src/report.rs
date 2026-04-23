//! Fingerprint report types persisted in the cache and emitted alongside
//! `FingerprintCaptured` events.

use std::path::PathBuf;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::probes::Protocol;
use ps_core::id::CatchId;

/// The outcome of running the probe ladder against a single catch.
///
/// One `FingerprintReport` lives per `(IpAddr, port)` in
/// `FingerprintCache`. `banner_excerpt` preserves the raw bytes captured
/// by the strongest-confidence probe so downstream tooling can make
/// richer judgments than the probe itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintReport {
    /// Catch that produced this report.
    pub catch_id: CatchId,
    /// Best protocol guess across all probes, if any probe matched.
    pub protocol_guess: Option<Protocol>,
    /// Confidence of the best probe match in `[0.0, 1.0]`.
    pub confidence: f32,
    /// Raw bytes captured by the best-matching probe.
    #[serde(with = "serde_bytes")]
    pub banner_excerpt: Bytes,
    /// TLS handshake details, when a TLS-class probe succeeded.
    pub tls_info: Option<TlsInfo>,
    /// Per-probe audit trail in ladder order.
    pub probes_run: Vec<ProbeRunRecord>,
    /// Filesystem path containing raw artifacts for this catch.
    pub artifacts_path: PathBuf,
}

/// TLS handshake details captured by the `TlsHello` probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    /// SNI the client presented (when known).
    pub server_name: Option<String>,
    /// Negotiated ALPN protocol, when one was selected.
    pub alpn: Option<String>,
    /// Server leaf certificate subject DN.
    pub cert_subject: Option<String>,
    /// Server leaf certificate issuer DN.
    pub cert_issuer: Option<String>,
    /// Server leaf certificate notAfter (RFC 3339).
    pub not_after: Option<String>,
}

/// One row in the per-catch probe audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeRunRecord {
    /// Static probe identifier (matches `Fingerprinter::name`).
    pub probe: &'static str,
    /// Outcome wire tag ("match", "nomatch", "error", "skipped", ...).
    pub outcome: &'static str,
    /// Number of bytes captured by this probe.
    pub bytes_captured: usize,
    /// How long the probe's `probe()` call took.
    pub duration_ms: u64,
}
