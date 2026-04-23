//! Scope enforcement chokepoint. Every outbound packet must acquire a
//! [`ScopeToken`] via [`ScopeGuard::allow`]. Packet-sending APIs in
//! `ps-engine` are crate-private and accept only `ScopeToken`, so scope
//! bypass is structurally impossible rather than a matter of discipline.

use std::collections::HashSet;
use std::net::IpAddr;

use ipnet::IpNet;
use time::OffsetDateTime;

use crate::target::Target;
use crate::technique::TechniqueTag;

#[derive(Debug)]
pub struct ScopeGuard {
    allow_cidrs: Vec<IpNet>,
    deny_hosts: HashSet<IpAddr>,
    allow_techniques: Vec<TechniqueTag>,
    deny_techniques: Vec<TechniqueTag>,
    window_start: OffsetDateTime,
    window_end: OffsetDateTime,
}

impl ScopeGuard {
    pub fn builder() -> ScopeGuardBuilder {
        ScopeGuardBuilder::default()
    }

    pub fn allow(
        &self,
        target: &Target,
        now: OffsetDateTime,
    ) -> Result<ScopeToken, ScopeViolation> {
        if now < self.window_start || now > self.window_end {
            return Err(ScopeViolation::OutsideWindow);
        }
        if self.deny_hosts.contains(&target.ip) {
            return Err(ScopeViolation::Excluded);
        }
        if !self.allow_cidrs.iter().any(|c| c.contains(&target.ip)) {
            return Err(ScopeViolation::NotInScope);
        }
        Ok(ScopeToken(()))
    }

    pub fn allow_technique(&self, tag: &TechniqueTag) -> bool {
        if self.deny_techniques.contains(tag) {
            return false;
        }
        if self.allow_techniques.is_empty() {
            return true;
        }
        self.allow_techniques.contains(tag)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScopeViolation {
    #[error("target is not in authorized scope")]
    NotInScope,
    #[error("target is excluded")]
    Excluded,
    #[error("outside engagement window")]
    OutsideWindow,
}

/// Capability token. Opaque, only constructable inside this crate. Every
/// outbound-packet API in `ps-engine` requires one, so accepting a
/// `ScopeToken` is proof that `ScopeGuard::allow` has been called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeToken(());

#[derive(Debug, Default)]
pub struct ScopeGuardBuilder {
    allow_cidrs: Vec<IpNet>,
    deny_hosts: HashSet<IpAddr>,
    allow_techniques: Vec<TechniqueTag>,
    deny_techniques: Vec<TechniqueTag>,
    window_start: Option<OffsetDateTime>,
    window_end: Option<OffsetDateTime>,
}

impl ScopeGuardBuilder {
    pub fn allow_cidr(mut self, net: IpNet) -> Self {
        self.allow_cidrs.push(net);
        self
    }

    pub fn deny_host(mut self, ip: IpAddr) -> Self {
        self.deny_hosts.insert(ip);
        self
    }

    pub fn allow_techniques(mut self, tags: Vec<TechniqueTag>) -> Self {
        self.allow_techniques = tags;
        self
    }

    pub fn deny_techniques(mut self, tags: Vec<TechniqueTag>) -> Self {
        self.deny_techniques = tags;
        self
    }

    pub fn window(mut self, start: OffsetDateTime, end: OffsetDateTime) -> Self {
        self.window_start = Some(start);
        self.window_end = Some(end);
        self
    }

    pub fn build(self) -> ScopeGuard {
        ScopeGuard {
            allow_cidrs: self.allow_cidrs,
            deny_hosts: self.deny_hosts,
            allow_techniques: self.allow_techniques,
            deny_techniques: self.deny_techniques,
            window_start: self
                .window_start
                .unwrap_or_else(|| OffsetDateTime::from_unix_timestamp(0).unwrap()),
            window_end: self
                .window_end
                .unwrap_or_else(|| OffsetDateTime::from_unix_timestamp(253_402_300_799).unwrap()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn allows_target_in_cidr() {
        let g = ScopeGuard::builder()
            .allow_cidr("10.0.0.0/24".parse().unwrap())
            .build();
        let target = Target::new("10.0.0.5".parse().unwrap(), 80);
        assert!(g.allow(&target, datetime!(2026-05-01 00:00 UTC)).is_ok());
    }

    #[test]
    fn denies_target_outside_cidr() {
        let g = ScopeGuard::builder()
            .allow_cidr("10.0.0.0/24".parse().unwrap())
            .build();
        let target = Target::new("10.0.1.5".parse().unwrap(), 80);
        assert_eq!(
            g.allow(&target, datetime!(2026-05-01 00:00 UTC)),
            Err(ScopeViolation::NotInScope)
        );
    }

    #[test]
    fn denies_excluded_host_even_if_in_cidr() {
        let excluded: IpAddr = "10.0.0.99".parse().unwrap();
        let g = ScopeGuard::builder()
            .allow_cidr("10.0.0.0/24".parse().unwrap())
            .deny_host(excluded)
            .build();
        let target = Target::new(excluded, 80);
        assert_eq!(
            g.allow(&target, datetime!(2026-05-01 00:00 UTC)),
            Err(ScopeViolation::Excluded)
        );
    }

    #[test]
    fn denies_outside_window() {
        let g = ScopeGuard::builder()
            .allow_cidr("10.0.0.0/24".parse().unwrap())
            .window(
                datetime!(2026-01-01 00:00 UTC),
                datetime!(2026-02-01 00:00 UTC),
            )
            .build();
        let target = Target::new("10.0.0.5".parse().unwrap(), 80);
        assert_eq!(
            g.allow(&target, datetime!(2026-05-01 00:00 UTC)),
            Err(ScopeViolation::OutsideWindow)
        );
    }

    #[test]
    fn technique_allowlist_filters() {
        let g = ScopeGuard::builder()
            .allow_techniques(vec![TechniqueTag::Recon, TechniqueTag::WebApp])
            .build();
        assert!(g.allow_technique(&TechniqueTag::Recon));
        assert!(g.allow_technique(&TechniqueTag::WebApp));
        assert!(!g.allow_technique(&TechniqueTag::Destructive));
    }
}
