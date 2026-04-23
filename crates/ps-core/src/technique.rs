//! Technique tags mirror the agentic-pentest-proxy technique taxonomy.
//!
//! Values: "recon", "web_app", "api_testing", "ssl_tls", "dos",
//! "destructive", "social_engineering". Unknown tags deserialize to
//! `TechniqueTag::Other(String)` so forward-compatibility is preserved.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TechniqueTag {
    Recon,
    WebApp,
    ApiTesting,
    SslTls,
    Dos,
    Destructive,
    SocialEngineering,
    Other(String),
}

impl TechniqueTag {
    pub fn as_wire(&self) -> &str {
        match self {
            Self::Recon => "recon",
            Self::WebApp => "web_app",
            Self::ApiTesting => "api_testing",
            Self::SslTls => "ssl_tls",
            Self::Dos => "dos",
            Self::Destructive => "destructive",
            Self::SocialEngineering => "social_engineering",
            Self::Other(s) => s.as_str(),
        }
    }

    pub fn from_wire(s: &str) -> Self {
        match s {
            "recon" => Self::Recon,
            "web_app" => Self::WebApp,
            "api_testing" => Self::ApiTesting,
            "ssl_tls" => Self::SslTls,
            "dos" => Self::Dos,
            "destructive" => Self::Destructive,
            "social_engineering" => Self::SocialEngineering,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl Serialize for TechniqueTag {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_wire())
    }
}

impl<'de> Deserialize<'de> for TechniqueTag {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(Self::from_wire(&s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_tag_round_trips() {
        let t = TechniqueTag::WebApp;
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"web_app\"");
        let back: TechniqueTag = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn unknown_tag_preserved() {
        let back: TechniqueTag = serde_json::from_str("\"wireless\"").unwrap();
        assert_eq!(back, TechniqueTag::Other("wireless".into()));
        let json = serde_json::to_string(&back).unwrap();
        assert_eq!(json, "\"wireless\"");
    }
}
