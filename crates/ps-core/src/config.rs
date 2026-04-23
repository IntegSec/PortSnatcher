//! TOML configuration loader. Maps to the spec §8 layout.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::profile::Profile;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub profile: Option<Profile>,
    pub scope_file: PathBuf,
    #[serde(default = "default_output_dir")]
    pub output_dir: PathBuf,
    #[serde(default)]
    pub engine: EngineConfig,
    #[serde(default)]
    pub rate: RateConfig,
    #[serde(default)]
    pub fingerprint: FingerprintConfig,
    #[serde(default)]
    pub bus: BusConfig,
    #[serde(default)]
    pub notify: NotifyConfig,
    #[serde(default)]
    pub holdopen: HoldOpenConfig,
}

fn default_output_dir() -> PathBuf {
    PathBuf::from("./artifacts")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    #[serde(default = "default_engine_kind")]
    pub kind: String,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self { kind: default_engine_kind() }
    }
}

fn default_engine_kind() -> String {
    "auto".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateConfig {
    pub global_pps: u32,
    pub per_target_pps: u32,
}

impl Default for RateConfig {
    fn default() -> Self {
        Self {
            global_pps: 10_000,
            per_target_pps: 500,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintConfig {
    #[serde(default = "default_ladder_timeout_ms")]
    pub ladder_timeout_ms: u64,
    #[serde(default = "default_protocols")]
    pub protocols: Vec<String>,
}

fn default_ladder_timeout_ms() -> u64 {
    2_000
}
fn default_protocols() -> Vec<String> {
    vec![
        "http".into(),
        "tls".into(),
        "ssh".into(),
        "redis".into(),
        "postgres".into(),
        "mongo".into(),
        "smb".into(),
    ]
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            ladder_timeout_ms: default_ladder_timeout_ms(),
            protocols: default_protocols(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusConfig {
    #[serde(default = "default_bus_listen")]
    pub listen: String,
    #[serde(default)]
    pub auth_token_file: Option<PathBuf>,
}

fn default_bus_listen() -> String {
    "127.0.0.1:7177".to_owned()
}

impl Default for BusConfig {
    fn default() -> Self {
        Self {
            listen: default_bus_listen(),
            auth_token_file: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotifyConfig {
    #[serde(default)]
    pub desktop: bool,
    #[serde(default)]
    pub webhooks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoldOpenConfig {
    #[serde(default = "default_holdopen_mode")]
    pub default_mode: String,
    #[serde(default = "default_auto_mitm")]
    pub auto_mitm_on_https: bool,
    #[serde(default = "default_tunnel_ports")]
    pub tunnel_port_range: String,
}

fn default_holdopen_mode() -> String {
    "dumb_tunnel".into()
}
fn default_auto_mitm() -> bool {
    true
}
fn default_tunnel_ports() -> String {
    "7100-7199".into()
}

impl Default for HoldOpenConfig {
    fn default() -> Self {
        Self {
            default_mode: default_holdopen_mode(),
            auto_mitm_on_https: default_auto_mitm(),
            tunnel_port_range: default_tunnel_ports(),
        }
    }
}

impl Config {
    pub fn from_toml_str(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path)?;
        Ok(Self::from_toml_str(&raw)?)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let raw = r#"
            scope_file = "./scope.json"
        "#;
        let c = Config::from_toml_str(raw).unwrap();
        assert_eq!(c.scope_file, PathBuf::from("./scope.json"));
        assert_eq!(c.rate.global_pps, 10_000);
        assert_eq!(c.bus.listen, "127.0.0.1:7177");
    }

    #[test]
    fn overrides_apply() {
        let raw = r#"
            scope_file = "./scope.json"
            [rate]
            global_pps = 1000
            per_target_pps = 200
            [bus]
            listen = "127.0.0.1:8000"
        "#;
        let c = Config::from_toml_str(raw).unwrap();
        assert_eq!(c.rate.global_pps, 1000);
        assert_eq!(c.bus.listen, "127.0.0.1:8000");
    }
}
