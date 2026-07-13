use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;

use crate::error::{RastreoError, ResolverError};
use crate::model::{ResolvedTarget, Target};
use crate::resolver::Resolver;

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

    async fn resolve_many(&self, targets: &[Target]) -> Result<Vec<ResolvedTarget>, RastreoError> {
        let mut out = Vec::new();
        let mut seen: HashSet<IpAddr> = HashSet::new();
        for t in targets {
            for rt in self.inner.resolve(t).await? {
                self.check_allowed(rt.ip)?;
                if seen.insert(rt.ip) {
                    out.push(rt);
                }
            }
            // Check between targets, not after the whole list, so a cap violation short-circuits.
            self.check_cap(out.len())?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::SystemTime;

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

    struct CountingResolver {
        calls: AtomicUsize,
    }

    impl CountingResolver {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl Resolver for CountingResolver {
        async fn resolve(&self, _target: &Target) -> Result<Vec<ResolvedTarget>, RastreoError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) as u32;
            let addr = IpAddr::V4(Ipv4Addr::from_bits(0x0a00_0000 + n));
            Ok(vec![ResolvedTarget {
                ip: addr,
                original: Target::Ip(addr),
                resolved_at: SystemTime::now(),
            }])
        }
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
            .block_on(guard.resolve_many(&targets))
            .expect_err("a single out-of-allow-list target rejects the request");
        assert!(matches!(
            err,
            RastreoError::Resolver(ResolverError::TargetNotAllowed { ip: got })
                if got == ip(192, 168, 1, 1)
        ));
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
    fn aggregate_cap_short_circuits_without_resolving_every_target() {
        let inner = Arc::new(CountingResolver::new());
        let inner_dyn: Arc<dyn Resolver> = inner.clone();
        let guard = GuardedResolver::new(inner_dyn, None, Some(100));
        let targets: Vec<Target> = (0..200)
            .map(|i| Target::Ip(IpAddr::V4(Ipv4Addr::from_bits(i))))
            .collect();
        let err = rt()
            .block_on(guard.resolve_many(&targets))
            .expect_err("cap exceeded");
        assert!(matches!(
            err,
            RastreoError::Resolver(ResolverError::AggregateHostCapExceeded { hosts, limit })
                if hosts == 101 && limit == 100
        ));
        assert_eq!(
            inner.calls.load(Ordering::SeqCst),
            101,
            "must stop resolving once the cap is passed, not walk all 200 targets"
        );
    }

    #[test]
    fn aggregate_cap_allows_exactly_the_limit() {
        let inner = Arc::new(CountingResolver::new());
        let inner_dyn: Arc<dyn Resolver> = inner.clone();
        let guard = GuardedResolver::new(inner_dyn, None, Some(100));
        let targets: Vec<Target> = (0..100)
            .map(|i| Target::Ip(IpAddr::V4(Ipv4Addr::from_bits(i))))
            .collect();
        let out = rt()
            .block_on(guard.resolve_many(&targets))
            .expect("exactly the limit is allowed");
        assert_eq!(out.len(), 100);
    }

    #[test]
    fn both_none_preserves_order_and_dedup() {
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
}
