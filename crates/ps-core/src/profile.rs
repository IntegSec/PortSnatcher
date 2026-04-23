//! Pentest profile: a coherent bundle of defaults (rate caps, probe ladder, artifact retention).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Internal,
    External,
    Ctf,
}

#[derive(Debug, Clone, Copy)]
pub struct ProfileDefaults {
    pub global_pps: u32,
    pub per_target_pps: u32,
    pub full_probe_ladder: bool,
    pub toast_on_catch: bool,
    pub full_pcap: bool,
    pub scope_file_required: bool,
}

impl Profile {
    pub fn defaults(self) -> ProfileDefaults {
        match self {
            Profile::Internal => ProfileDefaults {
                global_pps: 50_000,
                per_target_pps: 2_000,
                full_probe_ladder: true,
                toast_on_catch: true,
                full_pcap: true,
                scope_file_required: true,
            },
            Profile::External => ProfileDefaults {
                global_pps: 1_000,
                per_target_pps: 200,
                full_probe_ladder: false,
                toast_on_catch: false,
                full_pcap: false,
                scope_file_required: true,
            },
            Profile::Ctf => ProfileDefaults {
                global_pps: 100_000,
                per_target_pps: 10_000,
                full_probe_ladder: true,
                toast_on_catch: true,
                full_pcap: true,
                scope_file_required: false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_has_conservative_caps() {
        let d = Profile::Internal.defaults();
        assert_eq!(d.global_pps, 50_000);
        assert_eq!(d.per_target_pps, 2_000);
        assert!(d.scope_file_required);
    }

    #[test]
    fn external_is_quietest() {
        let d = Profile::External.defaults();
        assert!(d.global_pps < Profile::Internal.defaults().global_pps);
        assert!(!d.toast_on_catch);
        assert!(d.scope_file_required);
    }

    #[test]
    fn ctf_is_loudest_and_skips_scope_requirement() {
        let d = Profile::Ctf.defaults();
        assert!(d.global_pps > Profile::Internal.defaults().global_pps);
        assert!(!d.scope_file_required);
    }

    #[test]
    fn profile_serializes_lowercase() {
        let json = serde_json::to_string(&Profile::Internal).unwrap();
        assert_eq!(json, "\"internal\"");
    }
}
