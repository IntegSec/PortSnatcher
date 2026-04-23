//! Property tests for CIDR allowlist correctness. Asserts that every IP
//! inside any allowed CIDR is allowed, and every IP outside every allowed
//! CIDR is denied.

use std::net::{IpAddr, Ipv4Addr};

use ipnet::{IpNet, Ipv4Net};
use proptest::prelude::*;
use ps_core::scope::{ScopeGuard, ScopeViolation};
use ps_core::target::Target;
use time::macros::datetime;

fn any_ipv4_net() -> impl Strategy<Value = IpNet> {
    (any::<u32>(), 8u8..=30u8).prop_map(|(addr, prefix)| {
        let ip = Ipv4Addr::from(addr);
        let net = IpNet::V4(Ipv4Net::new(ip, prefix).unwrap());
        net.trunc()
    })
}

proptest! {
    #[test]
    fn contained_ip_is_allowed(net in any_ipv4_net(), host_offset in any::<u32>()) {
        let guard = ScopeGuard::builder().allow_cidr(net).build();
        let base: u32 = match net.network() {
            IpAddr::V4(v) => u32::from(v),
            _ => unreachable!(),
        };
        let size: u128 = (1u128) << (32 - net.prefix_len() as u32);
        if size == 0 { return Ok(()); }
        let ip_u32 = base.wrapping_add((host_offset as u128 % size) as u32);
        let ip = Ipv4Addr::from(ip_u32);
        let target = Target::new(ip.into(), 80);
        prop_assert!(guard.allow(&target, datetime!(2026-05-01 00:00 UTC)).is_ok());
    }

    #[test]
    fn uncontained_ip_is_denied(net in any_ipv4_net(), outsider in any::<u32>()) {
        let guard = ScopeGuard::builder().allow_cidr(net).build();
        let ip = Ipv4Addr::from(outsider);
        if net.contains(&IpAddr::V4(ip)) { return Ok(()); }
        let target = Target::new(ip.into(), 80);
        prop_assert_eq!(
            guard.allow(&target, datetime!(2026-05-01 00:00 UTC)),
            Err(ScopeViolation::NotInScope)
        );
    }
}
