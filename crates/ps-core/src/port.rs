//! Port specifications: named sets, ranges, explicit ports, and mixed lists.

use std::collections::BTreeSet;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

const EPHEMERAL_IANA: (u16, u16) = (49152, 65535);
const EPHEMERAL_LINUX: (u16, u16) = (32768, 60999);
const EPHEMERAL_WINDOWS: (u16, u16) = (49152, 65535);
const EPHEMERAL_BSD: (u16, u16) = (49152, 65535);

const TOP_1000_RAW: &str = include_str!("../data/top-1000.txt");

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "PortSpecWire", into = "PortSpecWire")]
pub struct PortSpec(pub BTreeSet<u16>);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum PortSpecWire {
    Scalar(String),
    List(Vec<String>),
}

impl TryFrom<PortSpecWire> for PortSpec {
    type Error = PortSpecError;

    fn try_from(w: PortSpecWire) -> Result<Self, Self::Error> {
        let items: Vec<String> = match w {
            PortSpecWire::Scalar(s) => vec![s],
            PortSpecWire::List(v) => v,
        };
        let mut set = BTreeSet::new();
        for item in items {
            for p in expand(&item)? {
                set.insert(p);
            }
        }
        Ok(PortSpec(set))
    }
}

impl From<PortSpec> for PortSpecWire {
    fn from(ps: PortSpec) -> Self {
        PortSpecWire::List(ps.0.iter().map(|p| p.to_string()).collect())
    }
}

impl PortSpec {
    pub fn from_spec_str(s: &str) -> Result<Self, PortSpecError> {
        let mut set = BTreeSet::new();
        for item in expand(s)? {
            set.insert(item);
        }
        Ok(PortSpec(set))
    }

    pub fn contains(&self, port: u16) -> bool {
        self.0.contains(&port)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = u16> + '_ {
        self.0.iter().copied()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PortSpecError {
    #[error("unknown named port set: {0}")]
    UnknownNamedSet(String),
    #[error("invalid port number: {0}")]
    InvalidNumber(String),
    #[error("invalid range (expected lo-hi, got {0})")]
    InvalidRange(String),
    #[error("range out of order: {0}-{1}")]
    RangeOutOfOrder(u16, u16),
}

fn expand(s: &str) -> Result<Vec<u16>, PortSpecError> {
    let s = s.trim();
    match s {
        "all" => Ok((1u16..=65535).collect()),
        "top-1000" => Ok(parse_top_1000()),
        "ephemeral-iana" => Ok(range_inclusive(EPHEMERAL_IANA.0, EPHEMERAL_IANA.1)),
        "ephemeral-linux" => Ok(range_inclusive(EPHEMERAL_LINUX.0, EPHEMERAL_LINUX.1)),
        "ephemeral-windows" => Ok(range_inclusive(EPHEMERAL_WINDOWS.0, EPHEMERAL_WINDOWS.1)),
        "ephemeral-bsd" => Ok(range_inclusive(EPHEMERAL_BSD.0, EPHEMERAL_BSD.1)),
        other if other.contains('-') => {
            let (lo_s, hi_s) = other
                .split_once('-')
                .ok_or_else(|| PortSpecError::InvalidRange(other.to_owned()))?;
            let lo: u16 = lo_s
                .trim()
                .parse()
                .map_err(|_| PortSpecError::InvalidNumber(lo_s.to_owned()))?;
            let hi: u16 = hi_s
                .trim()
                .parse()
                .map_err(|_| PortSpecError::InvalidNumber(hi_s.to_owned()))?;
            if lo > hi {
                return Err(PortSpecError::RangeOutOfOrder(lo, hi));
            }
            Ok(range_inclusive(lo, hi))
        }
        other => {
            let port: u16 = other
                .parse()
                .map_err(|_| PortSpecError::InvalidNumber(other.to_owned()))?;
            Ok(vec![port])
        }
    }
}

fn range_inclusive(lo: u16, hi: u16) -> Vec<u16> {
    (lo..=hi).collect()
}

fn parse_top_1000() -> Vec<u16> {
    TOP_1000_RAW
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.parse::<u16>().ok())
        .collect()
}

impl FromStr for PortSpec {
    type Err = PortSpecError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PortSpec::from_spec_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_port() {
        let ps = PortSpec::from_spec_str("22").unwrap();
        assert!(ps.contains(22));
        assert_eq!(ps.len(), 1);
    }

    #[test]
    fn parses_range() {
        let ps = PortSpec::from_spec_str("1024-1026").unwrap();
        assert_eq!(ps.len(), 3);
        assert!(ps.contains(1024));
        assert!(ps.contains(1025));
        assert!(ps.contains(1026));
    }

    #[test]
    fn parses_named_iana_ephemeral() {
        let ps = PortSpec::from_spec_str("ephemeral-iana").unwrap();
        assert_eq!(ps.len(), (65535 - 49152 + 1) as usize);
        assert!(ps.contains(49152));
        assert!(ps.contains(65535));
        assert!(!ps.contains(49151));
    }

    #[test]
    fn parses_top_1000_has_well_known_ports() {
        let ps = PortSpec::from_spec_str("top-1000").unwrap();
        assert_eq!(ps.len(), 1000, "expected 1000 ports in nmap top-1000");
        // The top 5 by nmap frequency should all be present.
        for p in [80, 23, 443, 21, 22] {
            assert!(ps.contains(p), "top-1000 must contain port {p}");
        }
    }

    #[test]
    fn rejects_out_of_order_range() {
        assert!(matches!(
            PortSpec::from_spec_str("500-100"),
            Err(PortSpecError::RangeOutOfOrder(500, 100))
        ));
    }

    #[test]
    fn rejects_unknown_input() {
        let err = PortSpec::from_spec_str("ephemeral-moon").unwrap_err();
        assert!(matches!(err, PortSpecError::InvalidNumber(_)));
    }

    #[test]
    fn deserializes_list_of_specs() {
        let raw = r#"["22", "80", "1024-1026", "ephemeral-iana"]"#;
        let ps: PortSpec = serde_json::from_str(raw).unwrap();
        assert!(ps.contains(22));
        assert!(ps.contains(80));
        assert!(ps.contains(1025));
        assert!(ps.contains(49152));
    }

    #[test]
    fn bad_spec_in_list_returns_error_not_panic() {
        let raw = r#"["22", "garbage"]"#;
        let err = serde_json::from_str::<PortSpec>(raw).unwrap_err();
        // Just confirm it errored and didn't panic.
        assert!(err.to_string().contains("invalid port"));
    }
}
