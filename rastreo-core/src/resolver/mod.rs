use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use hickory_resolver::TokioResolver;
use ipnet::IpNet;

use crate::error::{RastreoError, ResolverError, ResumeError};
use crate::model::{ResolvedTarget, Target};

mod guarded;
pub use guarded::GuardedResolver;

pub const DEFAULT_HOST_LIMIT: usize = 65_536;

#[async_trait::async_trait]
pub trait Resolver: Send + Sync {
    async fn resolve(&self, target: &Target) -> Result<Vec<ResolvedTarget>, RastreoError>;

    /// Resolve DNS eagerly and validate per-spec host limits, returning a plan whose lazy stream
    /// expands CIDR/range specs one target at a time. The default resolves every target eagerly via
    /// [`Resolver::resolve`]; expansion-aware resolvers override this to stay lazy.
    async fn plan(&self, targets: &[Target]) -> Result<ResolvedPlan, RastreoError> {
        let resolved_at = SystemTime::now();
        let mut specs = Vec::with_capacity(targets.len());
        for target in targets {
            let ips = self
                .resolve(target)
                .await?
                .into_iter()
                .map(|rt| rt.ip)
                .collect();
            specs.push(PlannedSpec::Resolved {
                ips,
                original: target.clone(),
            });
        }
        Ok(ResolvedPlan { specs, resolved_at })
    }

    /// Lazy resolution: DNS resolved up front, then CIDR/range specs expanded one target per `next()`
    /// in input-target order with no cross-target dedup.
    async fn resolve_stream(
        &self,
        targets: &[Target],
    ) -> Result<Box<dyn Iterator<Item = ResolvedTarget> + Send>, RastreoError> {
        Ok(self.plan(targets).await?.into_stream())
    }

    async fn resolve_many(&self, targets: &[Target]) -> Result<Vec<ResolvedTarget>, RastreoError> {
        Ok(self.resolve_stream(targets).await?.collect())
    }
}

/// A resolved scan plan: DNS resolved eagerly, per-spec host counts known, ready to stream targets
/// lazily in input order. Overlapping specs are surfaced by [`ResolvedPlan::find_overlaps`], never
/// deduplicated — the stream yields the concatenation of each spec's expansion.
pub struct ResolvedPlan {
    specs: Vec<PlannedSpec>,
    resolved_at: SystemTime,
}

enum PlannedSpec {
    /// A contiguous address block — a single IP, a CIDR's host range, or an explicit range.
    Block {
        first: IpAddr,
        last: IpAddr,
        original: Target,
    },
    /// A resolved point set — a DNS name's addresses, or any target the default plan resolved eagerly.
    Resolved { ips: Vec<IpAddr>, original: Target },
}

impl ResolvedPlan {
    /// The number of targets the stream will yield: the arithmetic sum of per-spec host counts, with
    /// duplicates under overlapping specs included (resolution does not dedup).
    pub fn total_hosts(&self) -> usize {
        self.specs
            .iter()
            .fold(0usize, |sum, spec| sum.saturating_add(spec.hosts()))
    }

    /// The eager DNS resolutions a resume must replay verbatim: each `DnsName` target paired with the
    /// addresses it resolved to. CIDR/range/single-IP specs re-expand deterministically and carry no pin.
    pub fn dns_pins(&self) -> Vec<(Target, Vec<IpAddr>)> {
        self.specs
            .iter()
            .filter_map(|spec| match spec {
                PlannedSpec::Resolved { ips, original }
                    if matches!(original, Target::DnsName(_)) =>
                {
                    Some((original.clone(), ips.clone()))
                }
                _ => None,
            })
            .collect()
    }

    /// Rebuild a plan for a resume: `DnsName` specs replay the checkpoint's pinned addresses (DNS is
    /// not stable, so it is never re-resolved), while IP/CIDR/Range specs re-expand deterministically —
    /// identical numeric-ascending order to the original run. Mismatched pins refuse as a stale checkpoint.
    pub fn from_pinned(
        targets: &[Target],
        dns_pins: &[(Target, Vec<IpAddr>)],
    ) -> Result<ResolvedPlan, RastreoError> {
        let resolved_at = SystemTime::now();
        let mut specs = Vec::with_capacity(targets.len());
        let mut pins = dns_pins.iter();
        for target in targets {
            let spec = match target {
                Target::Ip(ip) => PlannedSpec::Block {
                    first: *ip,
                    last: *ip,
                    original: target.clone(),
                },
                Target::Cidr(net) => {
                    let (first, last, _) = cidr_bounds(net);
                    PlannedSpec::Block {
                        first,
                        last,
                        original: target.clone(),
                    }
                }
                Target::Range { start, end } => {
                    let (first, last, _) = range_bounds(*start, *end)?;
                    PlannedSpec::Block {
                        first,
                        last,
                        original: target.clone(),
                    }
                }
                Target::DnsName(_) => {
                    let (pinned_target, ips) =
                        pins.next().ok_or(ResumeError::FingerprintMismatch)?;
                    if pinned_target != target {
                        return Err(ResumeError::FingerprintMismatch.into());
                    }
                    PlannedSpec::Resolved {
                        ips: ips.clone(),
                        original: target.clone(),
                    }
                }
            };
            specs.push(spec);
        }
        Ok(ResolvedPlan { specs, resolved_at })
    }

    pub fn into_stream(self) -> Box<dyn Iterator<Item = ResolvedTarget> + Send> {
        let now = self.resolved_at;
        Box::new(
            self.specs
                .into_iter()
                .flat_map(move |spec| spec.into_stream(now)),
        )
    }

    pub(crate) fn check_allowed(&self, allowlist: &[IpNet]) -> Result<(), RastreoError> {
        for spec in &self.specs {
            spec.check_allowed(allowlist)?;
        }
        Ok(())
    }

    // Pairwise over contiguous blocks only — DNS point sets are excluded. No IP expansion; #specs is
    // small, so the quadratic scan is cheaper than sorting.
    pub(crate) fn find_overlaps(&self) -> Vec<(Target, Target)> {
        let blocks: Vec<(bool, u128, u128, &Target)> = self
            .specs
            .iter()
            .filter_map(PlannedSpec::interval)
            .collect();
        let mut out = Vec::new();
        for a in 0..blocks.len() {
            for b in (a + 1)..blocks.len() {
                let (v6_a, lo_a, hi_a, target_a) = blocks[a];
                let (v6_b, lo_b, hi_b, target_b) = blocks[b];
                if v6_a == v6_b && lo_a <= hi_b && lo_b <= hi_a {
                    out.push((target_a.clone(), target_b.clone()));
                }
            }
        }
        out
    }
}

impl PlannedSpec {
    fn hosts(&self) -> usize {
        match self {
            PlannedSpec::Block { first, last, .. } => block_span(*first, *last),
            PlannedSpec::Resolved { ips, .. } => ips.len(),
        }
    }

    fn interval(&self) -> Option<(bool, u128, u128, &Target)> {
        match self {
            PlannedSpec::Block {
                first,
                last,
                original,
            } => {
                let (is_v6, lo) = ip_to_bits(*first);
                let (_, hi) = ip_to_bits(*last);
                Some((is_v6, lo, hi, original))
            }
            PlannedSpec::Resolved { .. } => None,
        }
    }

    fn check_allowed(&self, allowlist: &[IpNet]) -> Result<(), RastreoError> {
        match self {
            PlannedSpec::Block { first, last, .. } => {
                if let Some(ip) = first_uncovered_ip(*first, *last, allowlist) {
                    return Err(ResolverError::TargetNotAllowed { ip }.into());
                }
            }
            PlannedSpec::Resolved { ips, .. } => {
                for ip in ips {
                    if !allowlist.iter().any(|net| net.contains(ip)) {
                        return Err(ResolverError::TargetNotAllowed { ip: *ip }.into());
                    }
                }
            }
        }
        Ok(())
    }

    fn into_stream(self, now: SystemTime) -> Box<dyn Iterator<Item = ResolvedTarget> + Send> {
        match self {
            PlannedSpec::Block {
                first,
                last,
                original,
            } => block_stream(first, last, original, now),
            PlannedSpec::Resolved { ips, original } => {
                Box::new(ips.into_iter().map(move |ip| ResolvedTarget {
                    ip,
                    original: original.clone(),
                    resolved_at: now,
                }))
            }
        }
    }
}

// Contiguous [first, last] block for a CIDR plus its host count. `/32` is a single host, `/31` is
// the RFC 3021 point-to-point pair, wider IPv4 nets exclude network+broadcast, IPv6 spans the whole
// block. The count saturates so a `::/0` sweep can be rejected on size without overflowing.
fn cidr_bounds(net: &IpNet) -> (IpAddr, IpAddr, u128) {
    match net {
        IpNet::V4(n) => match n.prefix_len() {
            32 => (IpAddr::V4(n.network()), IpAddr::V4(n.network()), 1),
            31 => {
                let base = n.network().to_bits();
                (
                    IpAddr::V4(Ipv4Addr::from_bits(base)),
                    IpAddr::V4(Ipv4Addr::from_bits(base + 1)),
                    2,
                )
            }
            _ => {
                let hosts = (n.broadcast().to_bits() - n.network().to_bits() - 1) as u128;
                (
                    IpAddr::V4(Ipv4Addr::from_bits(n.network().to_bits() + 1)),
                    IpAddr::V4(Ipv4Addr::from_bits(n.broadcast().to_bits() - 1)),
                    hosts,
                )
            }
        },
        IpNet::V6(n) => {
            let span = u128::from(n.broadcast()) - u128::from(n.network());
            (
                IpAddr::V6(n.network()),
                IpAddr::V6(n.broadcast()),
                span.saturating_add(1),
            )
        }
    }
}

// Inclusive [start, end] block for an explicit range plus its host count, validating the endpoints
// share a family and are ordered. The count saturates so a full sweep can be size-rejected safely.
fn range_bounds(start: IpAddr, end: IpAddr) -> Result<(IpAddr, IpAddr, u128), RastreoError> {
    match (start, end) {
        (IpAddr::V4(s), IpAddr::V4(e)) => {
            let (s_bits, e_bits) = (s.to_bits() as u128, e.to_bits() as u128);
            if s_bits > e_bits {
                return Err(ResolverError::InvalidRange {
                    start: s.to_string(),
                    end: e.to_string(),
                }
                .into());
            }
            Ok((start, end, e_bits - s_bits + 1))
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
            Ok((start, end, (e_bits - s_bits).saturating_add(1)))
        }
        (s, e) => Err(ResolverError::MixedFamilyRange {
            start: s.to_string(),
            end: e.to_string(),
        }
        .into()),
    }
}

/// The refusals a target earns from its own written form, before any lookup and independent of a resolver's host limit.
pub(crate) fn ensure_target_shape(target: &Target) -> Result<(), RastreoError> {
    match target {
        Target::Ip(_) | Target::Cidr(_) | Target::DnsName(_) => Ok(()),
        Target::Range { start, end } => range_bounds(*start, *end).map(|_| ()),
    }
}

fn ip_to_bits(ip: IpAddr) -> (bool, u128) {
    match ip {
        IpAddr::V4(a) => (false, a.to_bits() as u128),
        IpAddr::V6(a) => (true, u128::from(a)),
    }
}

fn block_span(first: IpAddr, last: IpAddr) -> usize {
    match (first, last) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (b.to_bits() as u128 - a.to_bits() as u128 + 1) as usize,
        (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(b) - u128::from(a) + 1) as usize,
        _ => 0,
    }
}

fn block_stream(
    first: IpAddr,
    last: IpAddr,
    original: Target,
    now: SystemTime,
) -> Box<dyn Iterator<Item = ResolvedTarget> + Send> {
    match (first, last) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            Box::new((a.to_bits()..=b.to_bits()).map(move |bits| ResolvedTarget {
                ip: IpAddr::V4(Ipv4Addr::from_bits(bits)),
                original: original.clone(),
                resolved_at: now,
            }))
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => Box::new((u128::from(a)..=u128::from(b)).map(
            move |bits| ResolvedTarget {
                ip: IpAddr::V6(Ipv6Addr::from(bits)),
                original: original.clone(),
                resolved_at: now,
            },
        )),
        // A mixed-family block is unreachable — planning validates family agreement.
        _ => Box::new(std::iter::empty()),
    }
}

// The first address in `[first, last]` not covered by the allow-list union, or `None` when the whole
// block sits inside the union. Sweeps the same-family allow-list intervals, so it is O(#allowlist).
fn first_uncovered_ip(first: IpAddr, last: IpAddr, allowlist: &[IpNet]) -> Option<IpAddr> {
    match (first, last) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mut ivals: Vec<(u128, u128)> = allowlist
                .iter()
                .filter_map(|net| match net {
                    IpNet::V4(n) => Some((
                        n.network().to_bits() as u128,
                        n.broadcast().to_bits() as u128,
                    )),
                    IpNet::V6(_) => None,
                })
                .collect();
            uncovered_point(a.to_bits() as u128, b.to_bits() as u128, &mut ivals)
                .map(|bits| IpAddr::V4(Ipv4Addr::from_bits(bits as u32)))
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mut ivals: Vec<(u128, u128)> = allowlist
                .iter()
                .filter_map(|net| match net {
                    IpNet::V6(n) => Some((u128::from(n.network()), u128::from(n.broadcast()))),
                    IpNet::V4(_) => None,
                })
                .collect();
            uncovered_point(u128::from(a), u128::from(b), &mut ivals)
                .map(|bits| IpAddr::V6(Ipv6Addr::from(bits)))
        }
        _ => Some(first),
    }
}

fn uncovered_point(lo: u128, hi: u128, ivals: &mut [(u128, u128)]) -> Option<u128> {
    ivals.sort_unstable_by_key(|(start, _)| *start);
    let mut cursor = lo;
    for (start, end) in ivals.iter() {
        if *start > cursor {
            return Some(cursor);
        }
        if *end >= cursor {
            if *end >= hi {
                return None;
            }
            cursor = end + 1;
        }
    }
    Some(cursor).filter(|c| *c <= hi)
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
                source: source.into(),
            })?;
        let inner = builder
            .build()
            .map_err(|source| ResolverError::DnsLookupFailed {
                name: "<system resolver init>".into(),
                source: source.into(),
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

    fn plan_cidr(&self, net: &IpNet, original: &Target) -> Result<PlannedSpec, RastreoError> {
        let (first, last, hosts) = cidr_bounds(net);
        if hosts > self.host_limit as u128 {
            return Err(ResolverError::CidrTooLarge {
                cidr: net.to_string(),
                hosts,
                limit: self.host_limit,
            }
            .into());
        }
        Ok(PlannedSpec::Block {
            first,
            last,
            original: original.clone(),
        })
    }

    fn plan_range(
        &self,
        start: IpAddr,
        end: IpAddr,
        original: &Target,
    ) -> Result<PlannedSpec, RastreoError> {
        let (first, last, hosts) = range_bounds(start, end)?;
        if hosts > self.host_limit as u128 {
            return Err(ResolverError::RangeTooLarge {
                start: start.to_string(),
                end: end.to_string(),
                hosts,
                limit: self.host_limit,
            }
            .into());
        }
        Ok(PlannedSpec::Block {
            first,
            last,
            original: original.clone(),
        })
    }

    async fn lookup_dns(&self, name: &str) -> Result<Vec<IpAddr>, RastreoError> {
        let lookup =
            self.inner
                .lookup_ip(name)
                .await
                .map_err(|source| ResolverError::DnsLookupFailed {
                    name: name.to_string(),
                    source: source.into(),
                })?;
        let ips: Vec<IpAddr> = lookup.iter().collect();
        if ips.is_empty() {
            return Err(ResolverError::DnsNoRecords {
                name: name.to_string(),
            }
            .into());
        }
        Ok(ips)
    }
}

#[async_trait::async_trait]
impl Resolver for HickoryResolver {
    async fn resolve(&self, target: &Target) -> Result<Vec<ResolvedTarget>, RastreoError> {
        Ok(self
            .plan(std::slice::from_ref(target))
            .await?
            .into_stream()
            .collect())
    }

    async fn plan(&self, targets: &[Target]) -> Result<ResolvedPlan, RastreoError> {
        let resolved_at = SystemTime::now();
        let mut specs = Vec::with_capacity(targets.len());
        for target in targets {
            let spec = match target {
                Target::Ip(ip) => PlannedSpec::Block {
                    first: *ip,
                    last: *ip,
                    original: target.clone(),
                },
                Target::Cidr(net) => self.plan_cidr(net, target)?,
                Target::Range { start, end } => self.plan_range(*start, *end, target)?,
                Target::DnsName(name) => PlannedSpec::Resolved {
                    ips: self.lookup_dns(name).await?,
                    original: target.clone(),
                },
            };
            specs.push(spec);
        }
        Ok(ResolvedPlan { specs, resolved_at })
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

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
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
    fn resolve_many_concatenates_duplicate_ips_without_dedup() {
        let r = resolver();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let targets = vec![Target::Ip(ip), Target::Ip(ip)];
        let out = rt()
            .block_on(r.resolve_many(&targets))
            .expect("resolve_many");
        let ips: Vec<IpAddr> = out.iter().map(|rt| rt.ip).collect();
        assert_eq!(
            ips,
            vec![ip, ip],
            "both specs stream — no cross-target dedup"
        );
    }

    #[test]
    fn resolve_many_preserves_input_order_with_repeats() {
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
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ]
        );
    }

    #[test]
    fn resolve_stream_yields_concatenated_per_spec_sequence_in_input_order() {
        let r = resolver();
        let targets = vec![
            Target::Cidr("10.0.0.0/30".parse().expect("cidr")),
            Target::Ip(ipv4(192, 168, 1, 5)),
            Target::Range {
                start: ipv4(10, 0, 1, 1),
                end: ipv4(10, 0, 1, 3),
            },
        ];
        let out: Vec<IpAddr> = rt()
            .block_on(r.resolve_stream(&targets))
            .expect("resolve_stream")
            .map(|rt| rt.ip)
            .collect();
        assert_eq!(
            out,
            vec![
                ipv4(10, 0, 0, 1),
                ipv4(10, 0, 0, 2),
                ipv4(192, 168, 1, 5),
                ipv4(10, 0, 1, 1),
                ipv4(10, 0, 1, 2),
                ipv4(10, 0, 1, 3),
            ]
        );
    }

    #[test]
    fn total_hosts_equals_the_number_of_targets_the_stream_yields() {
        let r = resolver();
        let targets = vec![
            Target::Cidr("10.0.0.0/24".parse().expect("cidr")),
            Target::Ip(ipv4(192, 168, 1, 5)),
            Target::Range {
                start: ipv4(10, 0, 1, 1),
                end: ipv4(10, 0, 1, 200),
            },
            Target::Cidr("2001:db8::/126".parse().expect("cidr")),
        ];
        let plan = rt().block_on(r.plan(&targets)).expect("plan");
        let counted = plan.total_hosts();
        let yielded = plan.into_stream().count();
        assert_eq!(
            counted, yielded,
            "the pre-flight sum must equal what the stream yields"
        );
    }

    #[test]
    fn find_overlaps_reports_specs_that_share_addresses() {
        let r = resolver();
        let a = Target::Cidr("10.0.0.0/24".parse().expect("cidr"));
        let b = Target::Range {
            start: ipv4(10, 0, 0, 100),
            end: ipv4(10, 0, 0, 200),
        };
        let plan = rt()
            .block_on(r.plan(&[a.clone(), b.clone()]))
            .expect("plan");
        let overlaps = plan.find_overlaps();
        assert_eq!(overlaps.len(), 1);
        assert_eq!(overlaps[0], (a, b));
    }

    #[test]
    fn find_overlaps_empty_for_disjoint_specs() {
        let r = resolver();
        let targets = vec![
            Target::Cidr("10.0.0.0/24".parse().expect("cidr")),
            Target::Cidr("10.0.1.0/24".parse().expect("cidr")),
            Target::Ip(ipv4(192, 168, 1, 1)),
        ];
        let plan = rt().block_on(r.plan(&targets)).expect("plan");
        assert!(plan.find_overlaps().is_empty());
    }

    #[test]
    fn dns_pins_returns_only_dns_name_resolutions() {
        let dns = Target::DnsName("router-1.lab".to_string());
        let plan = ResolvedPlan {
            specs: vec![
                PlannedSpec::Resolved {
                    ips: vec![ipv4(10, 0, 0, 5), ipv4(10, 0, 0, 6)],
                    original: dns.clone(),
                },
                // An IP target the default plan() resolved eagerly re-expands deterministically; no pin.
                PlannedSpec::Resolved {
                    ips: vec![ipv4(10, 0, 0, 9)],
                    original: Target::Ip(ipv4(10, 0, 0, 9)),
                },
                PlannedSpec::Block {
                    first: ipv4(10, 0, 1, 1),
                    last: ipv4(10, 0, 1, 3),
                    original: Target::Cidr("10.0.1.0/30".parse().expect("cidr")),
                },
            ],
            resolved_at: std::time::SystemTime::now(),
        };
        let pins = plan.dns_pins();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].0, dns);
        assert_eq!(pins[0].1, vec![ipv4(10, 0, 0, 5), ipv4(10, 0, 0, 6)]);
    }

    #[test]
    fn dns_pins_empty_when_no_dns_targets() {
        let plan = ResolvedPlan {
            specs: vec![PlannedSpec::Block {
                first: ipv4(10, 0, 0, 1),
                last: ipv4(10, 0, 0, 1),
                original: Target::Ip(ipv4(10, 0, 0, 1)),
            }],
            resolved_at: std::time::SystemTime::now(),
        };
        assert!(plan.dns_pins().is_empty());
    }

    #[test]
    fn find_overlaps_ignores_cross_family_specs() {
        let r = resolver();
        let targets = vec![
            Target::Cidr("10.0.0.0/24".parse().expect("cidr")),
            Target::Cidr("::/126".parse().expect("cidr")),
        ];
        let plan = rt().block_on(r.plan(&targets)).expect("plan");
        assert!(
            plan.find_overlaps().is_empty(),
            "an IPv4 block and an IPv6 block never share addresses"
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
    fn from_pinned_replays_pinned_dns_addresses_without_resolving() {
        let dns = Target::DnsName("router-1.lab".to_string());
        let pins = vec![(dns.clone(), vec![ipv4(10, 0, 0, 5), ipv4(10, 0, 0, 6)])];
        let plan = ResolvedPlan::from_pinned(&[dns], &pins).expect("from_pinned");
        let ips: Vec<IpAddr> = plan.into_stream().map(|rt| rt.ip).collect();
        assert_eq!(ips, vec![ipv4(10, 0, 0, 5), ipv4(10, 0, 0, 6)]);
    }

    #[test]
    fn from_pinned_reexpands_ip_cidr_and_range_identically_to_plan() {
        let targets = vec![
            Target::Cidr("10.0.0.0/30".parse().expect("cidr")),
            Target::Ip(ipv4(192, 168, 1, 5)),
            Target::Range {
                start: ipv4(10, 0, 1, 1),
                end: ipv4(10, 0, 1, 3),
            },
        ];
        let via_plan: Vec<IpAddr> = rt()
            .block_on(resolver().plan(&targets))
            .expect("plan")
            .into_stream()
            .map(|rt| rt.ip)
            .collect();
        let via_pinned: Vec<IpAddr> = ResolvedPlan::from_pinned(&targets, &[])
            .expect("from_pinned")
            .into_stream()
            .map(|rt| rt.ip)
            .collect();
        assert_eq!(
            via_pinned, via_plan,
            "a resumed plan re-expands IP/CIDR/Range specs identically to the original resolution"
        );
    }

    #[test]
    fn from_pinned_missing_dns_pin_refuses_as_stale_checkpoint() {
        let dns = Target::DnsName("router-1.lab".to_string());
        assert!(matches!(
            ResolvedPlan::from_pinned(&[dns], &[]),
            Err(RastreoError::Resume(ResumeError::FingerprintMismatch))
        ));
    }

    #[test]
    fn from_pinned_mismatched_dns_pin_refuses() {
        let target = Target::DnsName("router-1.lab".to_string());
        let pins = vec![(
            Target::DnsName("other.lab".to_string()),
            vec![ipv4(10, 0, 0, 5)],
        )];
        assert!(matches!(
            ResolvedPlan::from_pinned(&[target], &pins),
            Err(RastreoError::Resume(ResumeError::FingerprintMismatch))
        ));
    }

    #[test]
    fn from_pinned_total_hosts_counts_the_full_target_set() {
        let dns = Target::DnsName("hosts.lab".to_string());
        let pins = vec![(dns.clone(), vec![ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2)])];
        let targets = vec![dns, Target::Cidr("10.0.1.0/30".parse().expect("cidr"))];
        let plan = ResolvedPlan::from_pinned(&targets, &pins).expect("from_pinned");
        assert_eq!(plan.total_hosts(), 4, "2 pinned DNS ips + 2 CIDR hosts");
    }

    #[test]
    fn hickory_resolver_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<HickoryResolver>();
        assert_send_sync::<dyn Resolver>();
        assert_send_sync::<Box<dyn Resolver>>();
    }

    #[test]
    fn resolve_stream_is_send() {
        fn assert_send<T: Send>(_: &T) {}
        let r = resolver();
        let stream = rt()
            .block_on(r.resolve_stream(&[Target::Ip(ipv4(10, 0, 0, 1))]))
            .expect("resolve_stream");
        assert_send(&stream);
    }
}
