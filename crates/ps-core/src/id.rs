//! Identifier newtypes. Backed by ULID so they sort lexicographically by time.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use ulid::Ulid;

macro_rules! id_newtype {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Ulid);

        impl $name {
            pub fn new() -> Self {
                Self(Ulid::new())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl FromStr for $name {
            type Err = ulid::DecodeError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self(Ulid::from_string(s)?))
            }
        }
    };
}

id_newtype!(EngagementId, "Identifier for a single engagement run.");
id_newtype!(CatchId, "Identifier for one port-catch (groups all events per catch).");
id_newtype!(EventId, "Per-event unique identifier.");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_time_sortable() {
        let a = EventId::new();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = EventId::new();
        assert!(a.to_string() < b.to_string(), "ULIDs must sort by generation time");
    }

    #[test]
    fn ids_round_trip_json() {
        let id = CatchId::new();
        let json = serde_json::to_string(&id).unwrap();
        let back: CatchId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn ids_parse_from_string() {
        let id = EngagementId::new();
        let s = id.to_string();
        let parsed: EngagementId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }
}
