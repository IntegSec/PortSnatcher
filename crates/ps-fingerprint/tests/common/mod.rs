//! Shared helpers for ps-fingerprint integration tests.

#![allow(dead_code)]

use ps_core::config::Config;
use ps_core::engagement::Engagement;
use ps_core::id::EngagementId;
use ps_core::profile::Profile;
use ps_core::scope::file::{
    AuthorizedTargets, EngagementWindow, PortPolicy, PortsnatcherExtension, ScopeFile,
};
use ps_core::scope::guard::ScopeGuard;
use ps_core::technique::TechniqueTag;
use time::macros::datetime;

/// Build an Engagement with the given authorized/excluded technique lists.
pub fn engagement_with_techniques(
    authorized: Vec<TechniqueTag>,
    excluded: Vec<TechniqueTag>,
) -> Engagement {
    let scope = ScopeFile {
        engagement_id: "ENG-TEST-0001".into(),
        client: "Test Client".into(),
        operator: "test@example.com".into(),
        authorized_targets: AuthorizedTargets {
            ip_ranges: vec!["127.0.0.0/8".into()],
            domains: vec![],
            urls: vec![],
            cloud_accounts: vec![],
        },
        excluded_targets: vec![],
        authorized_techniques: authorized,
        excluded_techniques: excluded,
        engagement_window: EngagementWindow {
            start: datetime!(2026-01-01 00:00 UTC),
            end: datetime!(2030-01-01 00:00 UTC),
        },
        portsnatcher: Some(PortsnatcherExtension {
            port_policy: PortPolicy {
                include: vec!["ephemeral-iana".into()],
                exclude: vec![],
            },
        }),
    };
    let cfg = Config::from_toml_str(r#"scope_file = "./scope.json""#).unwrap();
    let guard = ScopeGuard::builder()
        .allow_cidr("127.0.0.0/8".parse().unwrap())
        .build();
    Engagement::new(EngagementId::new(), Profile::Internal, scope, cfg, guard)
}

/// Default engagement: allow all techniques, exclude none.
pub fn engagement_permissive() -> Engagement {
    engagement_with_techniques(vec![], vec![])
}
