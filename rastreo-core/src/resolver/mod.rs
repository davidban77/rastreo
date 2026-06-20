use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use hickory_resolver::TokioResolver;

use crate::error::{RastreoError, ResolverError};
use crate::model::{ResolvedTarget, Target};

pub const DEFAULT_HOST_LIMIT: usize = 65_536;

#[async_trait::async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, target: &Target) -> Result<Vec<ResolvedTarget>, RastreoError>;

    async fn resolve_many(&self, targets: &[Target]) -> Result<Vec<ResolvedTarget>, RastreoError> {
        let mut out = Vec::new();
        let mut seen: HashSet<IpAddr> = HashSet::new();
        for t in targets {
            for rt in self.resolve(t).await? {
                if seen.insert(rt.ip) {
                    out.push(rt);
                }
            }
        }
        Ok(out)
    }
}

pub struct HickoryResolver {
    inner: TokioResolver,
    host_limit: usize,
}

impl HickoryResolver {
    pub fn from_system() -> Result<Self, RastreoError> {
        let builder =
            TokioResolver::builder_tokio().map_err(|source| ResolverError::DnsLookupFailed {
                name: "<system resolver init>".into(),
                source,
            })?;
        let inner = builder
            .build()
            .map_err(|source| ResolverError::DnsLookupFailed {
                name: "<system resolver init>".into(),
                source,
            })?;
        Ok(Self {
            inner,
            host_limit: DEFAULT_HOST_LIMIT,
        })
    }

    pub fn with_limit(mut self, limit: usize) -> Self {
        self.host_limit = limit;
        self
    }

    pub fn host_limit(&self) -> usize {
        self.host_limit
    }

    fn expand_cidr(
        &self,
        net: &ipnet::IpNet,
        original: &Target,
    ) -> Result<Vec<ResolvedTarget>, RastreoError> {
        let limit = self.host_limit as u128;
        let hosts: u128 = match net {
            ipnet::IpNet::V4(n) => match n.prefix_len() {
                32 => 1,
                // RFC 3021 — /31 point-to-point links use both addresses, no network/broadcast.
                31 => 2,
                _ => (n.broadcast().to_bits() - n.network().to_bits() - 1) as u128,
            },
            ipnet::IpNet::V6(n) => {
                let span = u128::from(n.broadcast()) - u128::from(n.network());
                if span >= limit {
                    return Err(ResolverError::CidrTooLarge {
                        cidr: net.to_string(),
                        hosts: span.saturating_add(1),
                        limit: self.host_limit,
                    }
                    .into());
                }
                span + 1
            }
        };
        if hosts > limit {
            return Err(ResolverError::CidrTooLarge {
                cidr: net.to_string(),
                hosts,
                limit: self.host_limit,
            }
            .into());
        }
        let now = SystemTime::now();
        let mut out = Vec::with_capacity(hosts as usize);
        match net {
            ipnet::IpNet::V4(n) if n.prefix_len() == 32 => {
                out.push(ResolvedTarget {
                    ip: IpAddr::V4(n.network()),
                    original: original.clone(),
                    resolved_at: now,
                });
            }
            ipnet::IpNet::V4(n) if n.prefix_len() == 31 => {
                let base = n.network().to_bits();
                out.push(ResolvedTarget {
                    ip: IpAddr::V4(Ipv4Addr::from_bits(base)),
                    original: original.clone(),
                    resolved_at: now,
                });
                out.push(ResolvedTarget {
                    ip: IpAddr::V4(Ipv4Addr::from_bits(base + 1)),
                    original: original.clone(),
                    resolved_at: now,
                });
            }
            _ => {
                for ip in net.hosts() {
                    out.push(ResolvedTarget {
                        ip,
                        original: original.clone(),
                        resolved_at: now,
                    });
                }
            }
        }
        Ok(out)
    }

    fn expand_range(
        &self,
        start: IpAddr,
        end: IpAddr,
        original: &Target,
    ) -> Result<Vec<ResolvedTarget>, RastreoError> {
        match (start, end) {
            (IpAddr::V4(s), IpAddr::V4(e)) => {
                // Widen to u128 so iteration math can't overflow for a full /0 sweep.
                let (s_bits, e_bits) = (s.to_bits() as u128, e.to_bits() as u128);
                if s_bits > e_bits {
                    return Err(ResolverError::InvalidRange {
                        start: s.to_string(),
                        end: e.to_string(),
                    }
                    .into());
                }
                let hosts = e_bits - s_bits + 1;
                if hosts > self.host_limit as u128 {
                    return Err(ResolverError::RangeTooLarge {
                        start: s.to_string(),
                        end: e.to_string(),
                        hosts,
                        limit: self.host_limit,
                    }
                    .into());
                }
                let now = SystemTime::now();
                let mut out = Vec::with_capacity(hosts as usize);
                for i in s_bits..=e_bits {
                    out.push(ResolvedTarget {
                        ip: IpAddr::V4(Ipv4Addr::from_bits(i as u32)),
                        original: original.clone(),
                        resolved_at: now,
                    });
                }
                Ok(out)
            }
            (IpAddr::V6(s), IpAddr::V6(e)) => {
                let (s_bits, e_bits) = (u128::from(s), u128::from(e));
                if s_bits > e_bits {
                    return Err(ResolverError::InvalidRange {
                        start: s.to_string(),
                        end: e.to_string(),
                    }
                    .into());
                }
                let span = e_bits - s_bits;
                let limit = self.host_limit as u128;
                if span >= limit {
                    return Err(ResolverError::RangeTooLarge {
                        start: s.to_string(),
                        end: e.to_string(),
                        hosts: span.saturating_add(1),
                        limit: self.host_limit,
                    }
                    .into());
                }
                let hosts = span + 1;
                let now = SystemTime::now();
                let mut out = Vec::with_capacity(hosts as usize);
                for i in s_bits..=e_bits {
                    out.push(ResolvedTarget {
                        ip: IpAddr::V6(Ipv6Addr::from(i)),
                        original: original.clone(),
                        resolved_at: now,
                    });
                }
                Ok(out)
            }
            (s, e) => Err(ResolverError::MixedFamilyRange {
                start: s.to_string(),
                end: e.to_string(),
            }
            .into()),
        }
    }
}

#[async_trait::async_trait]
impl Resolver for HickoryResolver {
    async fn resolve(&self, target: &Target) -> Result<Vec<ResolvedTarget>, RastreoError> {
        let now = SystemTime::now();
        match target {
            Target::Ip(ip) => Ok(vec![ResolvedTarget {
                ip: *ip,
                original: target.clone(),
                resolved_at: now,
            }]),
            Target::Cidr(net) => self.expand_cidr(net, target),
            Target::Range { start, end } => self.expand_range(*start, *end, target),
            Target::DnsName(name) => {
                let lookup = self
                    .inner
                    .lookup_ip(name.as_str())
                    .await
                    .map_err(|source| ResolverError::DnsLookupFailed {
                        name: name.clone(),
                        source,
                    })?;
                let ips: Vec<IpAddr> = lookup.iter().collect();
                if ips.is_empty() {
                    return Err(ResolverError::DnsNoRecords { name: name.clone() }.into());
                }
                Ok(ips
                    .into_iter()
                    .map(|ip| ResolvedTarget {
                        ip,
                        original: target.clone(),
                        resolved_at: now,
                    })
                    .collect())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
    }

    fn resolver() -> HickoryResolver {
        HickoryResolver::from_system().expect("system resolver init")
    }

    #[test]
    fn resolve_single_ip_returns_one_target() {
        let r = resolver();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let target = Target::Ip(ip);
        let out = rt().block_on(r.resolve(&target)).expect("resolve");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ip, ip);
        assert_eq!(out[0].original, target);
    }

    #[test]
    fn resolve_cidr_slash_30_returns_two_hosts() {
        let r = resolver();
        let net: ipnet::IpNet = "10.0.0.0/30".parse().expect("cidr");
        let target = Target::Cidr(net);
        let out = rt().block_on(r.resolve(&target)).expect("resolve");
        let ips: Vec<IpAddr> = out.iter().map(|rt| rt.ip).collect();
        assert_eq!(
            ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            ]
        );
    }

    #[test]
    fn resolve_cidr_slash_31_returns_both_addresses() {
        let r = resolver();
        let net: ipnet::IpNet = "10.0.0.0/31".parse().expect("cidr");
        let target = Target::Cidr(net);
        let out = rt().block_on(r.resolve(&target)).expect("resolve");
        let ips: Vec<IpAddr> = out.iter().map(|rt| rt.ip).collect();
        assert_eq!(
            ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ]
        );
    }

    #[test]
    fn resolve_cidr_slash_32_returns_single_host() {
        let r = resolver();
        let net: ipnet::IpNet = "10.0.0.7/32".parse().expect("cidr");
        let target = Target::Cidr(net);
        let out = rt().block_on(r.resolve(&target)).expect("resolve");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)));
    }

    #[test]
    fn resolve_cidr_too_large_returns_error() {
        let r = resolver();
        let net: ipnet::IpNet = "10.0.0.0/8".parse().expect("cidr");
        let target = Target::Cidr(net);
        let err = rt().block_on(r.resolve(&target)).expect_err("too large");
        assert!(matches!(
            err,
            RastreoError::Resolver(ResolverError::CidrTooLarge { .. })
        ));
    }

    #[test]
    fn resolve_range_four_addresses() {
        let r = resolver();
        let target = Target::Range {
            start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
        };
        let out = rt().block_on(r.resolve(&target)).expect("resolve");
        let ips: Vec<IpAddr> = out.iter().map(|rt| rt.ip).collect();
        assert_eq!(
            ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
            ]
        );
    }

    #[test]
    fn resolve_range_inverted_returns_error() {
        let r = resolver();
        let target = Target::Range {
            start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        };
        let err = rt().block_on(r.resolve(&target)).expect_err("inverted");
        assert!(matches!(
            err,
            RastreoError::Resolver(ResolverError::InvalidRange { .. })
        ));
    }

    #[test]
    fn resolve_range_too_large_returns_error() {
        let r = resolver();
        let target = Target::Range {
            start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            end: IpAddr::V4(Ipv4Addr::new(10, 1, 134, 161)),
        };
        let err = rt()
            .block_on(r.resolve(&target))
            .expect_err("range too large");
        assert!(matches!(
            err,
            RastreoError::Resolver(ResolverError::RangeTooLarge { .. })
        ));
    }

    #[test]
    fn resolve_range_mixed_family_returns_error() {
        let r = resolver();
        let target = Target::Range {
            start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            end: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        };
        let err = rt().block_on(r.resolve(&target)).expect_err("mixed");
        assert!(matches!(
            err,
            RastreoError::Resolver(ResolverError::MixedFamilyRange { .. })
        ));
    }

    #[test]
    fn resolved_target_round_trips_original() {
        let r = resolver();
        let target = Target::Range {
            start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
        };
        let out = rt().block_on(r.resolve(&target)).expect("resolve");
        for rt in &out {
            assert_eq!(rt.original, target);
        }
    }

    #[test]
    fn resolve_many_deduplicates_by_ip() {
        let r = resolver();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let targets = vec![Target::Ip(ip), Target::Ip(ip)];
        let out = rt()
            .block_on(r.resolve_many(&targets))
            .expect("resolve_many");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ip, ip);
    }

    #[test]
    fn resolve_many_preserves_distinct_ips() {
        let r = resolver();
        let targets = vec![
            Target::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            Target::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            Target::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        ];
        let out = rt()
            .block_on(r.resolve_many(&targets))
            .expect("resolve_many");
        let ips: Vec<IpAddr> = out.iter().map(|rt| rt.ip).collect();
        assert_eq!(
            ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            ]
        );
    }

    #[test]
    fn with_limit_overrides_default_for_cidr() {
        let r = HickoryResolver::from_system().expect("init").with_limit(2);
        assert_eq!(r.host_limit(), 2);
        let net: ipnet::IpNet = "10.0.0.0/29".parse().expect("cidr");
        let target = Target::Cidr(net);
        let err = rt().block_on(r.resolve(&target)).expect_err("too large");
        assert!(matches!(
            err,
            RastreoError::Resolver(ResolverError::CidrTooLarge { .. })
        ));
    }

    #[test]
    fn resolve_cidr_ipv6_slash_126_returns_four_addresses() {
        let r = resolver();
        let net: ipnet::IpNet = "2001:db8::/126".parse().expect("cidr");
        let target = Target::Cidr(net);
        let out = rt().block_on(r.resolve(&target)).expect("resolve");
        let ips: Vec<IpAddr> = out.iter().map(|rt| rt.ip).collect();
        assert_eq!(
            ips,
            vec![
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3)),
            ]
        );
    }

    #[test]
    fn resolve_cidr_ipv6_slash_zero_rejected_without_panic() {
        let r = resolver();
        let net: ipnet::IpNet = "::/0".parse().expect("cidr");
        let target = Target::Cidr(net);
        let err = rt().block_on(r.resolve(&target)).expect_err("too large");
        assert!(matches!(
            err,
            RastreoError::Resolver(ResolverError::CidrTooLarge { .. })
        ));
    }

    #[test]
    fn resolve_range_ipv6_happy_path() {
        let r = resolver();
        let target = Target::Range {
            start: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            end: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 4)),
        };
        let out = rt().block_on(r.resolve(&target)).expect("resolve");
        let ips: Vec<IpAddr> = out.iter().map(|rt| rt.ip).collect();
        assert_eq!(
            ips,
            vec![
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 4)),
            ]
        );
    }

    #[test]
    fn hickory_resolver_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<HickoryResolver>();
        assert_send_sync::<dyn Resolver>();
        assert_send_sync::<Box<dyn Resolver>>();
    }
}
