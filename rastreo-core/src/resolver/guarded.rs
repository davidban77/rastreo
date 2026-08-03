use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;

use crate::error::{RastreoError, ResolverError};
use crate::model::{ResolvedTarget, Target};
use crate::resolver::{ResolvedPlan, Resolver};

pub struct GuardedResolver {
    inner: Arc<dyn Resolver>,
    allowlist: Option<Vec<IpNet>>,
    max_total_hosts: Option<usize>,
}

impl GuardedResolver {
    pub fn new(
        inner: Arc<dyn Resolver>,
        allowlist: Option<Vec<IpNet>>,
        max_total_hosts: Option<usize>,
    ) -> Self {
        Self {
            inner,
            allowlist,
            max_total_hosts,
        }
    }

    fn check_allowed(&self, ip: IpAddr) -> Result<(), RastreoError> {
        if let Some(nets) = &self.allowlist {
            if !nets.iter().any(|net| net.contains(&ip)) {
                return Err(ResolverError::TargetNotAllowed { ip }.into());
            }
        }
        Ok(())
    }

    fn check_cap(&self, hosts: usize) -> Result<(), RastreoError> {
        if let Some(limit) = self.max_total_hosts {
            if hosts > limit {
                return Err(ResolverError::AggregateHostCapExceeded { hosts, limit }.into());
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Resolver for GuardedResolver {
    async fn resolve(&self, target: &Target) -> Result<Vec<ResolvedTarget>, RastreoError> {
        let resolved = self.inner.resolve(target).await?;
        for rt in &resolved {
            self.check_allowed(rt.ip)?;
        }
        self.check_cap(resolved.len())?;
        Ok(resolved)
    }

    async fn plan(&self, targets: &[Target]) -> Result<ResolvedPlan, RastreoError> {
        // Both guards are spec-level and fail closed before any target streams: the allow-list is a
        // whole-spec containment test, the cap an arithmetic sum, so a huge scan is rejected without
        // materializing the address space.
        let plan = self.inner.plan(targets).await?;
        if let Some(nets) = &self.allowlist {
            plan.check_allowed(nets)?;
        }
        self.check_cap(plan.total_hosts())?;
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use crate::resolver::HickoryResolver;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
    }

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn net(s: &str) -> IpNet {
        s.parse().expect("cidr")
    }

    fn bare() -> Arc<dyn Resolver> {
        Arc::new(HickoryResolver::from_system().expect("system resolver"))
    }

    fn bare_with_limit(limit: usize) -> Arc<dyn Resolver> {
        Arc::new(
            HickoryResolver::from_system()
                .expect("system resolver")
                .with_limit(limit),
        )
    }

    #[test]
    fn allowlisted_ip_resolves() {
        let guard = GuardedResolver::new(bare(), Some(vec![net("10.0.0.0/8")]), None);
        let out = rt()
            .block_on(guard.resolve(&Target::Ip(ip(10, 1, 2, 3))))
            .expect("in allow-list resolves");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ip, ip(10, 1, 2, 3));
    }

    #[test]
    fn out_of_allowlist_ip_is_rejected() {
        let guard = GuardedResolver::new(bare(), Some(vec![net("10.0.0.0/8")]), None);
        let err = rt()
            .block_on(guard.resolve(&Target::Ip(ip(192, 168, 1, 1))))
            .expect_err("out of allow-list must reject");
        assert!(matches!(
            err,
            RastreoError::Resolver(ResolverError::TargetNotAllowed { ip: got })
                if got == ip(192, 168, 1, 1)
        ));
    }

    #[test]
    fn one_out_of_allowlist_target_rejects_the_whole_request() {
        let guard = GuardedResolver::new(bare(), Some(vec![net("10.0.0.0/8")]), None);
        let targets = vec![Target::Ip(ip(10, 0, 0, 1)), Target::Ip(ip(192, 168, 1, 1))];
        let err = rt()
            .block_on(guard.resolve_stream(&targets))
            .err()
            .expect("a single out-of-allow-list target rejects the request");
        assert!(matches!(
            err,
            RastreoError::Resolver(ResolverError::TargetNotAllowed { ip: got })
                if got == ip(192, 168, 1, 1)
        ));
    }

    #[test]
    fn allowlist_accepts_cidr_fully_inside_the_union() {
        let guard = GuardedResolver::new(bare(), Some(vec![net("10.0.0.0/8")]), None);
        let out: Vec<ResolvedTarget> = rt()
            .block_on(guard.resolve_stream(&[Target::Cidr(net("10.1.2.0/30"))]))
            .expect("inside the allow-list")
            .collect();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn allowlist_rejects_range_that_leaves_the_union() {
        let guard = GuardedResolver::new(bare(), Some(vec![net("10.0.0.0/24")]), None);
        let err = rt()
            .block_on(guard.resolve_stream(&[Target::Range {
                start: ip(10, 0, 0, 250),
                end: ip(10, 0, 1, 5),
            }]))
            .err()
            .expect("a range that leaves the allow-list must reject");
        assert!(matches!(
            err,
            RastreoError::Resolver(ResolverError::TargetNotAllowed { ip: got })
                if got == ip(10, 0, 1, 0)
        ));
    }

    #[test]
    fn allowlist_accepts_range_spanning_two_adjacent_nets() {
        let guard = GuardedResolver::new(
            bare(),
            Some(vec![net("10.0.0.0/25"), net("10.0.0.128/25")]),
            None,
        );
        let out: Vec<ResolvedTarget> = rt()
            .block_on(guard.resolve_stream(&[Target::Range {
                start: ip(10, 0, 0, 100),
                end: ip(10, 0, 0, 200),
            }]))
            .expect("the union of two adjacent nets covers the range")
            .collect();
        assert_eq!(out.len(), 101);
    }

    #[test]
    fn unset_allowlist_allows_any_ip() {
        let guard = GuardedResolver::new(bare(), None, None);
        let out = rt()
            .block_on(guard.resolve(&Target::Ip(ip(203, 0, 113, 5))))
            .expect("no allow-list means allow all");
        assert_eq!(out[0].ip, ip(203, 0, 113, 5));
    }

    #[test]
    fn ipv6_target_is_rejected_by_an_ipv4_only_allowlist() {
        let guard = GuardedResolver::new(bare(), Some(vec![net("10.0.0.0/8")]), None);
        let v6 = IpAddr::V6("2001:db8::1".parse().expect("v6"));
        let err = rt()
            .block_on(guard.resolve(&Target::Ip(v6)))
            .expect_err("an IPv6 target is not in an IPv4 allow-list");
        assert!(matches!(
            err,
            RastreoError::Resolver(ResolverError::TargetNotAllowed { .. })
        ));
    }

    #[test]
    fn aggregate_cap_rejects_over_cap_cidr_without_expanding() {
        // A raised per-spec limit lets the /17 through as one spec; the aggregate cap must still
        // reject it, computed arithmetically from the CIDR host count — no address-space walk.
        let guard = GuardedResolver::new(bare_with_limit(200_000), None, Some(100));
        let err = rt()
            .block_on(guard.resolve_stream(&[Target::Cidr(net("10.0.0.0/17"))]))
            .err()
            .expect("cap exceeded");
        assert!(matches!(
            err,
            RastreoError::Resolver(ResolverError::AggregateHostCapExceeded { hosts, limit })
                if hosts == 32_766 && limit == 100
        ));
    }

    #[test]
    fn aggregate_cap_sums_host_counts_across_specs() {
        let guard = GuardedResolver::new(bare(), None, Some(100));
        let err = rt()
            .block_on(guard.resolve_stream(&[
                Target::Cidr(net("10.0.0.0/25")),
                Target::Cidr(net("10.0.1.0/25")),
            ]))
            .err()
            .expect("the summed host count exceeds the cap");
        assert!(matches!(
            err,
            RastreoError::Resolver(ResolverError::AggregateHostCapExceeded { hosts, limit })
                if hosts == 252 && limit == 100
        ));
    }

    #[test]
    fn aggregate_cap_allows_exactly_the_limit() {
        let guard = GuardedResolver::new(bare(), None, Some(126));
        let out = rt()
            .block_on(guard.resolve_many(&[Target::Cidr(net("10.0.0.0/25"))]))
            .expect("exactly the limit is allowed");
        assert_eq!(out.len(), 126);
    }

    #[test]
    fn resolve_scenario_refuses_a_cap_no_single_spec_exceeds() {
        let guard = GuardedResolver::new(bare(), None, Some(100));
        let targets = vec![
            Target::Cidr(net("10.0.0.0/25")),
            Target::Cidr(net("10.0.1.0/25")),
        ];
        let resolution = rt().block_on(crate::resolver::resolve_scenario(&guard, &targets));
        assert!(
            matches!(
                resolution.refusal(),
                Some(RastreoError::Resolver(ResolverError::AggregateHostCapExceeded { hosts, limit }))
                    if *hosts == 252 && *limit == 100
            ),
            "a sum over the cap must refuse the rehearsal, not only the scan: {:?}",
            resolution.refusal()
        );
        assert_eq!(resolution.total_hosts(), 0);
    }

    #[test]
    fn resolve_scenario_under_the_cap_counts_what_the_scan_streams() {
        let guard = GuardedResolver::new(bare(), None, Some(252));
        let targets = vec![
            Target::Cidr(net("10.0.0.0/25")),
            Target::Cidr(net("10.0.1.0/25")),
        ];
        let resolution = rt().block_on(crate::resolver::resolve_scenario(&guard, &targets));
        assert!(resolution.refusal().is_none());
        assert_eq!(resolution.total_hosts(), 252);
    }

    #[test]
    fn resolve_scenario_attributes_an_out_of_allowlist_target() {
        let guard = GuardedResolver::new(bare(), Some(vec![net("10.0.0.0/8")]), None);
        let targets = vec![Target::Ip(ip(10, 0, 0, 1)), Target::Ip(ip(192, 168, 1, 1))];
        let resolution = rt().block_on(crate::resolver::resolve_scenario(&guard, &targets));
        assert!(resolution.refusal().is_some());
        assert_eq!(resolution.total_hosts(), 0);
    }

    #[test]
    fn both_none_streams_identically_to_the_inner() {
        let inner = bare();
        let guard = GuardedResolver::new(inner.clone(), None, None);
        let targets = vec![
            Target::Cidr(net("10.0.0.0/30")),
            Target::Ip(ip(203, 0, 113, 9)),
        ];
        let via_guard = rt()
            .block_on(guard.resolve_many(&targets))
            .expect("guard resolve_many");
        let via_inner = rt()
            .block_on(inner.resolve_many(&targets))
            .expect("inner resolve_many");
        let guard_ips: Vec<IpAddr> = via_guard.iter().map(|t| t.ip).collect();
        let inner_ips: Vec<IpAddr> = via_inner.iter().map(|t| t.ip).collect();
        assert_eq!(guard_ips, inner_ips);
    }

    #[test]
    fn guarded_resolver_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<GuardedResolver>();
    }

    struct AddresslessName;

    #[async_trait::async_trait]
    impl Resolver for AddresslessName {
        async fn resolve(&self, target: &Target) -> Result<Vec<ResolvedTarget>, RastreoError> {
            match target {
                Target::Ip(addr) => Ok(vec![ResolvedTarget {
                    ip: *addr,
                    original: target.clone(),
                    resolved_at: std::time::SystemTime::now(),
                }]),
                _ => Ok(Vec::new()),
            }
        }
    }

    fn stale() -> Target {
        Target::DnsName("stale.lab".to_string())
    }

    #[test]
    fn the_guard_hands_back_the_targets_the_inner_plan_found_no_addresses_for() {
        let guard = GuardedResolver::new(Arc::new(AddresslessName), None, None);
        let targets = vec![Target::Ip(ip(10, 0, 0, 1)), stale()];
        let plan = rt().block_on(guard.plan(&targets)).expect("plan");
        assert_eq!(plan.unresolvable_targets(), vec![&targets[1]]);
        assert_eq!(plan.total_hosts(), 1);
    }

    #[test]
    fn a_target_with_no_addresses_has_nothing_for_the_allowlist_to_refuse() {
        let guard = GuardedResolver::new(
            Arc::new(AddresslessName),
            Some(vec![net("10.0.0.0/8")]),
            None,
        );
        let targets = vec![Target::Ip(ip(10, 0, 0, 1)), stale()];
        let plan = rt()
            .block_on(guard.plan(&targets))
            .expect("a target contributing no address cannot leave the allow-list");
        assert_eq!(plan.unresolvable_targets(), vec![&targets[1]]);
    }

    #[test]
    fn a_target_with_no_addresses_adds_nothing_to_the_aggregate_cap() {
        let guard = GuardedResolver::new(Arc::new(AddresslessName), None, Some(1));
        let targets = vec![Target::Ip(ip(10, 0, 0, 1)), stale()];
        let plan = rt()
            .block_on(guard.plan(&targets))
            .expect("the sum only shrinks when a target contributes nothing");
        assert_eq!(plan.total_hosts(), 1);
    }
}
