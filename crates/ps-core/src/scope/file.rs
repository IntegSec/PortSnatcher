//! Scope file: exact JSON shape consumed by IntegSec/agentic-pentest-proxy
//! plus an optional, namespaced `portsnatcher` extension.

use std::path::Path;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::technique::TechniqueTag;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeFile {
    pub engagement_id: String,
    pub client: String,
    pub operator: String,
    pub authorized_targets: AuthorizedTargets,
    #[serde(default)]
    pub excluded_targets: Vec<String>,
    #[serde(default)]
    pub authorized_techniques: Vec<TechniqueTag>,
    #[serde(default)]
    pub excluded_techniques: Vec<TechniqueTag>,
    pub engagement_window: EngagementWindow,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portsnatcher: Option<PortsnatcherExtension>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedTargets {
    #[serde(default)]
    pub ip_ranges: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub cloud_accounts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementWindow {
    #[serde(with = "time::serde::rfc3339")]
    pub start: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub end: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortsnatcherExtension {
    pub port_policy: PortPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortPolicy {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

impl ScopeFile {
    pub fn load(path: &Path) -> Result<Self, LoadError> {
        let raw = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&raw)?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
