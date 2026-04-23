//! Engagement: runtime-ready composition of Config + ScopeFile + profile
//! defaults. What the orchestrator reads to decide what to do.

use std::sync::Arc;

use crate::config::Config;
use crate::id::EngagementId;
use crate::profile::Profile;
use crate::scope::file::ScopeFile;
use crate::scope::guard::ScopeGuard;

#[derive(Debug, Clone)]
pub struct Engagement {
    pub id: EngagementId,
    pub profile: Profile,
    pub scope_file: ScopeFile,
    pub config: Config,
    pub scope_guard: Arc<ScopeGuard>,
}

impl Engagement {
    pub fn new(
        id: EngagementId,
        profile: Profile,
        scope_file: ScopeFile,
        config: Config,
        scope_guard: ScopeGuard,
    ) -> Self {
        Self {
            id,
            profile,
            scope_file,
            config,
            scope_guard: Arc::new(scope_guard),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructs() {
        let raw = include_str!("../tests/fixtures/scope-portsnatcher-ext.json");
        let sf: ScopeFile = serde_json::from_str(raw).unwrap();
        let cfg = Config::from_toml_str(r#"scope_file = "./scope.json""#).unwrap();
        let guard = ScopeGuard::builder().build();
        let eng = Engagement::new(EngagementId::new(), Profile::Internal, sf, cfg, guard);
        assert_eq!(eng.profile, Profile::Internal);
    }
}
