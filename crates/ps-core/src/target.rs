//! Target addressing: hosts, CIDR blocks, ip/port pairs.

use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Target {
    pub ip: IpAddr,
    pub port: u16,
}

impl Target {
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CidrBlock(pub IpNet);

impl CidrBlock {
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.contains(&ip)
    }
}

impl FromStr for CidrBlock {
    type Err = ipnet::AddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<IpNet>().map(CidrBlock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_equality() {
        let a = Target::new("10.0.0.1".parse().unwrap(), 80);
        let b = Target::new("10.0.0.1".parse().unwrap(), 80);
        assert_eq!(a, b);
    }

    #[test]
    fn cidr_contains_host() {
        let block: CidrBlock = "10.0.0.0/24".parse().unwrap();
        assert!(block.contains("10.0.0.17".parse().unwrap()));
        assert!(!block.contains("10.0.1.17".parse().unwrap()));
    }

    #[test]
    fn cidr_round_trips_through_json() {
        let block: CidrBlock = "2001:db8::/32".parse().unwrap();
        let json = serde_json::to_string(&block).unwrap();
        let back: CidrBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(block, back);
    }
}
