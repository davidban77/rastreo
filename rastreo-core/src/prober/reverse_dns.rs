use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::rr::{Name, RData};
use hickory_resolver::TokioResolver;

use crate::error::{ConfigError, RastreoError};
use crate::model::{ProbeCtx, ProbeKind, ProbeOutcome, ResolvedTarget, Signal};
use crate::prober::Prober;

pub struct ReverseDnsProber {
    resolvers: Vec<IpAddr>,
    resolver: TokioResolver,
}

impl ReverseDnsProber {
    pub fn new(resolvers: Vec<IpAddr>) -> Result<Self, RastreoError> {
        let resolver = if resolvers.is_empty() {
            build_system_resolver()?
        } else {
            build_custom_resolver(&resolvers)?
        };
        Ok(Self {
            resolvers,
            resolver,
        })
    }

    pub fn resolvers(&self) -> &[IpAddr] {
        &self.resolvers
    }
}

/// Serde default for `ProberConfig::ReverseDns.resolvers` — empty, meaning use the system resolver.
pub fn default_resolvers() -> Vec<IpAddr> {
    Vec::new()
}

fn apply_resolver_opts(builder: &mut hickory_resolver::ResolverBuilder<TokioRuntimeProvider>) {
    let opts = builder.options_mut();
    opts.attempts = 1;
    opts.cache_size = 0;
    opts.use_hosts_file = ResolveHosts::Never;
    opts.num_concurrent_reqs = 1;
    opts.try_tcp_on_error = false;
    // Outer tokio::time::timeout owns the deadline; keep the inner timeout wide.
    opts.timeout = Duration::from_secs(3600);
}

fn build_system_resolver() -> Result<TokioResolver, RastreoError> {
    let mut builder = TokioResolver::builder_tokio().map_err(|e| {
        ConfigError::invalid(format!(
            "failed to load system resolver: {e}. \
             On distroless / minimal container images without /etc/resolv.conf, \
             supply explicit DNS servers via the reverse_dns prober's \
             `resolvers: [1.1.1.1, 8.8.8.8]` config field to bypass the system resolver."
        ))
    })?;
    apply_resolver_opts(&mut builder);
    builder
        .build()
        .map_err(|e| ConfigError::invalid(format!("failed to build system resolver: {e}")).into())
}

fn build_custom_resolver(resolvers: &[IpAddr]) -> Result<TokioResolver, RastreoError> {
    let name_servers: Vec<NameServerConfig> = resolvers
        .iter()
        .map(|ip| NameServerConfig::udp(*ip))
        .collect();
    let config = ResolverConfig::from_parts(None, Vec::new(), name_servers);
    let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    apply_resolver_opts(&mut builder);
    builder
        .build()
        .map_err(|e| ConfigError::invalid(format!("failed to build custom resolver: {e}")).into())
}

fn trim_trailing_dot(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_string()
}

#[async_trait::async_trait]
impl Prober for ReverseDnsProber {
    fn kind(&self) -> ProbeKind {
        ProbeKind::ReverseDns
    }

    async fn probe(
        &self,
        target: &ResolvedTarget,
        ctx: &ProbeCtx,
    ) -> Result<ProbeOutcome, RastreoError> {
        let query_name: Name = target.ip.into();
        let mut signals = Vec::new();
        let mut reachable = false;

        match tokio::time::timeout(ctx.timeout, self.resolver.reverse_lookup(query_name)).await {
            Ok(Ok(lookup)) => {
                reachable = true;
                for record in lookup.answers() {
                    if let RData::PTR(ref ptr) = record.data {
                        signals.push(Signal::ReverseDnsName(trim_trailing_dot(&ptr.0.to_utf8())));
                    }
                }
            }
            Ok(Err(err)) => {
                if err.is_no_records_found() {
                    // NXDOMAIN, NoError-with-empty-answers: server responded.
                    reachable = true;
                } else if let NetError::Dns(DnsError::ResponseCode(_)) = &err {
                    // REFUSED / SERVFAIL / etc. — server responded.
                    reachable = true;
                }
                // Else: network-layer error — reachable stays false, no signals.
            }
            Err(_) => {
                // Outer tokio timeout fired — reachable stays false.
            }
        }

        Ok(ProbeOutcome {
            kind: ProbeKind::ReverseDns,
            target_ip: target.ip,
            timestamp: SystemTime::now(),
            reachable,
            signals,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::model::Target;

    fn ctx_with_timeout(ms: u64) -> ProbeCtx {
        ProbeCtx {
            timeout: Duration::from_millis(ms),
            retries: 0,
        }
    }

    #[test]
    fn new_with_empty_resolvers_uses_system_conf() {
        if !std::path::Path::new("/etc/resolv.conf").exists() {
            // Skip on hosts without a system resolver config (distroless).
            return;
        }
        let prober = ReverseDnsProber::new(Vec::new()).expect("system resolver init succeeds");
        assert!(prober.resolvers().is_empty());
        assert_eq!(prober.kind(), ProbeKind::ReverseDns);
    }

    #[test]
    fn new_with_custom_resolvers_accepts_ipv4() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let prober = ReverseDnsProber::new(vec![ip]).expect("build ok");
        assert_eq!(prober.resolvers(), &[ip]);
    }

    #[test]
    fn new_with_custom_resolvers_accepts_ipv6() {
        let ip: IpAddr = "2606:4700:4700::1111".parse().expect("parse ipv6");
        let prober = ReverseDnsProber::new(vec![ip]).expect("build ok");
        assert_eq!(prober.resolvers(), &[ip]);
    }

    #[test]
    fn new_with_explicit_resolvers_bypasses_system_conf_on_distroless() {
        let resolvers = vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        ];
        let prober = ReverseDnsProber::new(resolvers.clone()).expect("bypass system resolver");
        assert_eq!(prober.resolvers(), resolvers.as_slice());
    }

    #[test]
    fn new_with_multiple_custom_resolvers_preserves_order() {
        let ip_a = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let prober = ReverseDnsProber::new(vec![ip_a, ip_b]).expect("build ok");
        assert_eq!(prober.resolvers(), &[ip_a, ip_b]);
    }

    #[test]
    fn default_resolvers_returns_empty_vec() {
        assert!(default_resolvers().is_empty());
    }

    #[test]
    fn probe_kind_returns_reverse_dns() {
        let prober =
            ReverseDnsProber::new(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]).expect("build ok");
        assert_eq!(prober.kind(), ProbeKind::ReverseDns);
    }

    #[test]
    fn trim_trailing_dot_from_ptr_name() {
        assert_eq!(
            trim_trailing_dot("router.example.com."),
            "router.example.com"
        );
        assert_eq!(
            trim_trailing_dot("router.example.com"),
            "router.example.com"
        );
        assert_eq!(trim_trailing_dot(""), "");
    }

    #[test]
    fn reverse_dns_prober_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<ReverseDnsProber>();
        assert_send_sync::<Box<dyn Prober>>();
    }

    #[tokio::test]
    async fn probe_against_unreachable_resolver_returns_no_signals() {
        // Both the resolver and the target sit inside the RFC 5737 documentation
        // range so /etc/hosts cannot short-circuit the lookup. Outcome must be
        // `Ok` with `reachable = false` and empty signals — never a `RastreoError`.
        let resolver = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let target_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let target = ResolvedTarget {
            ip: target_ip,
            original: Target::Ip(target_ip),
            resolved_at: SystemTime::UNIX_EPOCH,
        };
        let prober = ReverseDnsProber::new(vec![resolver]).expect("build ok");
        let outcome = prober
            .probe(&target, &ctx_with_timeout(100))
            .await
            .expect("probe returns outcome");
        assert_eq!(outcome.kind, ProbeKind::ReverseDns);
        assert!(!outcome.reachable);
        assert!(outcome.signals.is_empty());
    }

    #[tokio::test]
    async fn probe_uses_target_ipv6_arpa_name() {
        let ip: IpAddr = "2001:db8::1".parse().expect("parse ipv6");
        let target = ResolvedTarget {
            ip,
            original: Target::Ip(ip),
            resolved_at: SystemTime::UNIX_EPOCH,
        };
        let resolver_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let prober = ReverseDnsProber::new(vec![resolver_ip]).expect("build ok");
        let outcome = prober
            .probe(&target, &ctx_with_timeout(100))
            .await
            .expect("probe returns outcome");
        assert_eq!(outcome.target_ip, ip);
        assert!(!outcome.reachable);
    }

    #[tokio::test]
    async fn probe_reports_reachable_when_ptr_lookup_returns_no_records() {
        use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
        use hickory_resolver::proto::serialize::binary::{BinDecodable, BinEncodable};
        use tokio::net::UdpSocket;

        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let port = socket.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let (n, peer) = match socket.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let request = match Message::from_bytes(&buf[..n]) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let query: Query = match request.queries.first() {
                    Some(q) => q.clone(),
                    None => continue,
                };
                let mut response = Message::new(0, MessageType::Response, OpCode::Query);
                response.metadata.id = request.metadata.id;
                response.metadata.response_code = ResponseCode::NXDomain;
                response.metadata.recursion_available = true;
                response.add_query(query);
                let bytes = match response.to_bytes() {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let _ = socket.send_to(&bytes, peer).await;
            }
        });

        // Point the prober at our loopback stub server. NameServerConfig::udp defaults
        // to port 53, so build a custom config that pins the port to our stub.
        use hickory_resolver::config::{ConnectionConfig, ProtocolConfig, ResolverConfig};
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut connection = ConnectionConfig::new(ProtocolConfig::Udp);
        connection.port = port;
        let name_server = NameServerConfig::new(loopback, true, vec![connection]);
        let config = ResolverConfig::from_parts(None, Vec::new(), vec![name_server]);
        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        apply_resolver_opts(&mut builder);
        let resolver = builder.build().expect("build resolver");

        let target_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        let target = ResolvedTarget {
            ip: target_ip,
            original: Target::Ip(target_ip),
            resolved_at: SystemTime::UNIX_EPOCH,
        };
        let prober = ReverseDnsProber {
            resolvers: vec![loopback],
            resolver,
        };
        let outcome = prober
            .probe(&target, &ctx_with_timeout(2_000))
            .await
            .expect("probe returns outcome");
        assert!(
            outcome.reachable,
            "NXDOMAIN response must mark outcome reachable"
        );
        assert!(outcome.signals.is_empty());
    }

    #[test]
    fn ipv4_addr_converts_to_arpa_name() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let name: Name = ip.into();
        assert_eq!(name.to_utf8(), "4.3.2.1.in-addr.arpa.");
    }

    #[test]
    fn ipv6_addr_converts_to_arpa_name() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let name: Name = ip.into();
        assert!(
            name.to_utf8().ends_with("ip6.arpa."),
            "unexpected name: {}",
            name.to_utf8()
        );
    }
}
