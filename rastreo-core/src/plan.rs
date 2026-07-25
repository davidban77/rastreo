#[cfg(feature = "nats")]
use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;

use schemars::JsonSchema;

use crate::config::DiscoverScenarioConfig;
use crate::model::Target;
use crate::pipeline::ResolvedScenarioTarget;
use crate::prober::ProberConfig;
use crate::sink::SinkConfig;

const IP_LIST_CUTOFF: usize = 6;

/// Structured plan of a single discovery scenario — what a dry-run would probe, without executing it.
#[derive(Debug, Clone, serde::Serialize, JsonSchema)]
#[non_exhaustive]
pub struct DiscoveryPlan {
    /// Name of the scenario this plan describes.
    pub scenario: String,
    /// Each configured target with the IPs it resolved to, or its resolution error.
    pub targets: Vec<PlannedTarget>,
    /// Human-readable summary of each configured prober.
    pub probers: Vec<String>,
    /// Human-readable summary of the configured sink.
    pub sink: String,
    /// Effective in-flight probe cap for this run.
    pub max_concurrent: u32,
    /// Effective probes-per-second cap; `null` when unlimited.
    pub probe_rate: Option<u32>,
    /// Effective retransmit attempts for connectionless probers.
    pub retries: u32,
    /// Effective per-probe timeout in milliseconds.
    pub timeout_ms: u64,
    /// Total probes the scan would run: unique resolved IPs times probers.
    pub total_probes: usize,
}

#[derive(Debug, Clone, serde::Serialize, JsonSchema)]
#[non_exhaustive]
pub struct PlannedTarget {
    /// The target as written in the scenario.
    pub target: String,
    /// IPs the target resolved to, or the resolution error.
    pub resolution: TargetResolution,
}

#[derive(Debug, Clone, serde::Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TargetResolution {
    Resolved(Vec<IpAddr>),
    Error(String),
}

/// Effective scheduler/timeout settings after the caller applies CLI-over-YAML precedence.
#[derive(Debug, Clone, Copy)]
pub struct PlanKnobs {
    pub max_concurrent: u32,
    pub probe_rate: Option<u32>,
    pub retries: u32,
    pub timeout_ms: u64,
}

impl DiscoveryPlan {
    pub fn new(
        scenario: String,
        config: &DiscoverScenarioConfig,
        resolutions: &[ResolvedScenarioTarget],
        knobs: PlanKnobs,
    ) -> Self {
        let mut unique_ips: HashSet<IpAddr> = HashSet::new();
        let mut targets = Vec::with_capacity(resolutions.len());
        for entry in resolutions {
            let target = render_target(&entry.target);
            let resolution = match &entry.result {
                Ok(ips) => {
                    unique_ips.extend(ips.iter().copied());
                    TargetResolution::Resolved(ips.clone())
                }
                Err(err) => TargetResolution::Error(err.to_string()),
            };
            targets.push(PlannedTarget { target, resolution });
        }
        let probers: Vec<String> = config.probers.iter().map(render_prober).collect();
        let total_probes = unique_ips.len().saturating_mul(config.probers.len());
        Self {
            scenario,
            targets,
            probers,
            sink: render_sink(config.base.sink.as_ref()),
            max_concurrent: knobs.max_concurrent,
            probe_rate: knobs.probe_rate,
            retries: knobs.retries,
            timeout_ms: knobs.timeout_ms,
            total_probes,
        }
    }
}

impl fmt::Display for DiscoveryPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  scenario: {}", self.scenario)?;
        writeln!(f, "    targets:")?;
        for planned in &self.targets {
            match &planned.resolution {
                TargetResolution::Resolved(ips) => {
                    writeln!(f, "      {} → {}", planned.target, format_ip_list(ips))?;
                }
                TargetResolution::Error(err) => {
                    writeln!(f, "      {} → <error: {err}>", planned.target)?;
                }
            }
        }
        writeln!(f, "    probers: {}", format_prober_line(&self.probers))?;
        writeln!(f, "    sink: {}", self.sink)?;
        writeln!(f, "    concurrency: {}", self.max_concurrent)?;
        match self.probe_rate {
            Some(rate) => writeln!(f, "    rate: {rate}/sec")?,
            None => writeln!(f, "    rate: unlimited")?,
        }
        writeln!(f, "    retries: {}", self.retries)?;
        writeln!(f, "    timeout_ms: {}", self.timeout_ms)
    }
}

// In core so these #[non_exhaustive] enums match exhaustively — a new variant fails to compile here until rendered, where the CLI could only fall back to a catch-all.
fn render_target(target: &Target) -> String {
    match target {
        Target::Ip(ip) => ip.to_string(),
        Target::Cidr(net) => net.to_string(),
        Target::Range { start, end } => format!("{start}-{end}"),
        Target::DnsName(name) => name.clone(),
    }
}

fn render_prober(config: &ProberConfig) -> String {
    match config {
        ProberConfig::TcpConnect { ports } => {
            format!("tcp_connect (ports {})", format_ports(ports))
        }
        #[cfg(feature = "http")]
        ProberConfig::Http { ports, .. } => format!("http (ports {})", format_ports(ports)),
        ProberConfig::Dns {
            ports, query_names, ..
        } => format!(
            "dns (ports {}, queries {})",
            format_ports(ports),
            query_names.join(", ")
        ),
        ProberConfig::Udp { ports, protocol } => format!(
            "udp (ports {}, protocol {:?})",
            format_ports(ports),
            protocol
        ),
        #[cfg(feature = "snmp")]
        ProberConfig::Snmp { ports, version, .. } => {
            format!("snmp (ports {}, {:?})", format_ports(ports), version)
        }
        #[cfg(feature = "lldp")]
        ProberConfig::Lldp { ports, version, .. } => {
            format!("lldp (ports {}, {:?})", format_ports(ports), version)
        }
        #[cfg(feature = "arp")]
        ProberConfig::Arp { interface } => format!("arp (interface {interface:?})"),
        #[cfg(feature = "ndp")]
        ProberConfig::Ndp { interface } => format!("ndp (interface {interface:?})"),
        #[cfg(feature = "ssh")]
        ProberConfig::Ssh { ports } => format!("ssh (ports {})", format_ports(ports)),
        #[cfg(feature = "icmp")]
        ProberConfig::Icmp { count, interval_ms } => {
            format!("icmp (count {count}, interval_ms {interval_ms})")
        }
        #[cfg(feature = "tls")]
        ProberConfig::Tls { ports } => format!("tls (ports {})", format_ports(ports)),
        #[cfg(feature = "gnmi")]
        ProberConfig::Gnmi {
            ports, plaintext, ..
        } => format!(
            "gnmi (ports {}, {})",
            format_ports(ports),
            if *plaintext { "plaintext" } else { "tls" }
        ),
        ProberConfig::ReverseDns { resolvers } => {
            if resolvers.is_empty() {
                "reverse_dns (system resolvers)".to_string()
            } else {
                let list: Vec<String> = resolvers.iter().map(|r| r.to_string()).collect();
                format!("reverse_dns (resolvers {})", list.join(", "))
            }
        }
    }
}

fn render_sink(sink: Option<&SinkConfig>) -> String {
    match sink {
        None => "stdout (default)".to_string(),
        Some(SinkConfig::Stdout) => "stdout".to_string(),
        Some(SinkConfig::File { path }) => format!("file: {}", path.display()),
        Some(SinkConfig::Memory) => "memory".to_string(),
        #[cfg(feature = "kafka")]
        Some(SinkConfig::Kafka { brokers, topic, .. }) => {
            format!("kafka: brokers={} topic={topic}", brokers.join(","))
        }
        #[cfg(feature = "nats")]
        Some(SinkConfig::Nats {
            servers,
            subject,
            stream,
            ..
        }) => {
            let servers = servers
                .iter()
                .map(|s| strip_userinfo(s))
                .collect::<Vec<_>>()
                .join(",");
            format!("nats: servers={servers} subject={subject} stream={stream}")
        }
    }
}

// Strip inline `user:pass@` credentials so a `nats://user:pass@host` server URL never leaks into the rendered plan.
#[cfg(feature = "nats")]
fn strip_userinfo(server: &str) -> Cow<'_, str> {
    let Some(scheme_end) = server.find("://") else {
        return Cow::Borrowed(server);
    };
    let authority_start = scheme_end + 3;
    let authority_end = server[authority_start..]
        .find('/')
        .map_or(server.len(), |i| authority_start + i);
    let Some(at) = server[authority_start..authority_end].rfind('@') else {
        return Cow::Borrowed(server);
    };
    let host_start = authority_start + at + 1;
    Cow::Owned(format!(
        "{}{}",
        &server[..authority_start],
        &server[host_start..]
    ))
}

fn format_prober_line(probers: &[String]) -> String {
    if probers.is_empty() {
        "<none>".to_string()
    } else {
        probers.join(", ")
    }
}

fn format_ports(ports: &[u16]) -> String {
    let mut buf = String::new();
    for (i, p) in ports.iter().enumerate() {
        if i > 0 {
            buf.push_str(", ");
        }
        buf.push_str(&p.to_string());
    }
    buf
}

fn format_ip_list(ips: &[IpAddr]) -> String {
    if ips.len() <= IP_LIST_CUTOFF {
        let mut buf = String::new();
        for (i, ip) in ips.iter().enumerate() {
            if i > 0 {
                buf.push_str(", ");
            }
            buf.push_str(&ip.to_string());
        }
        return buf;
    }
    let mut buf = String::new();
    for ip in ips.iter().take(3) {
        if !buf.is_empty() {
            buf.push_str(", ");
        }
        buf.push_str(&ip.to_string());
    }
    let plural = if ips.len() == 1 {
        "address"
    } else {
        "addresses"
    };
    let count = ips.len();
    format!("{buf}, ... ({count} {plural})")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BaseProbeConfig;
    use crate::error::{RastreoError, ResolverError};
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn plan_of(
        config: &DiscoverScenarioConfig,
        resolutions: &[ResolvedScenarioTarget],
        knobs: PlanKnobs,
    ) -> DiscoveryPlan {
        DiscoveryPlan::new("discovery".to_string(), config, resolutions, knobs)
    }

    fn default_knobs() -> PlanKnobs {
        PlanKnobs {
            max_concurrent: 64,
            probe_rate: None,
            retries: 0,
            timeout_ms: 1000,
        }
    }

    fn tcp_scenario() -> DiscoverScenarioConfig {
        let mut base = BaseProbeConfig::new();
        base.sink = Some(SinkConfig::Stdout);
        DiscoverScenarioConfig::new(
            base,
            vec![Target::Ip(ip(127, 0, 0, 1))],
            vec![ProberConfig::TcpConnect {
                ports: vec![22, 80],
            }],
        )
    }

    #[test]
    fn render_target_uses_natural_form_per_variant() {
        assert_eq!(render_target(&Target::Ip(ip(10, 0, 0, 1))), "10.0.0.1");
        assert_eq!(
            render_target(&Target::Cidr("10.0.0.0/24".parse().expect("cidr"))),
            "10.0.0.0/24"
        );
        assert_eq!(
            render_target(&Target::DnsName("example.com".into())),
            "example.com"
        );
        assert_eq!(
            render_target(&Target::Range {
                start: ip(10, 0, 0, 1),
                end: ip(10, 0, 0, 5),
            }),
            "10.0.0.1-10.0.0.5"
        );
    }

    #[test]
    fn render_sink_none_prints_default() {
        assert_eq!(render_sink(None), "stdout (default)");
    }

    #[test]
    fn render_sink_stdout_prints_stdout() {
        assert_eq!(render_sink(Some(&SinkConfig::Stdout)), "stdout");
    }

    #[test]
    fn render_sink_memory_prints_memory() {
        assert_eq!(render_sink(Some(&SinkConfig::Memory)), "memory");
    }

    #[test]
    fn render_sink_file_prints_path() {
        let sink = SinkConfig::File {
            path: "/tmp/x.ndjson".into(),
        };
        assert_eq!(render_sink(Some(&sink)), "file: /tmp/x.ndjson");
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn render_sink_kafka_shows_brokers_and_topic() {
        let sink = SinkConfig::Kafka {
            brokers: vec!["127.0.0.1:1".into(), "127.0.0.1:2".into()],
            topic: "rastreo.devices".into(),
            links_topic: None,
            profiles_topic: None,
            flush_mode: crate::sink::KafkaFlushMode::default(),
            dead_letter: None,
            tls: None,
            sasl: None,
            retry: crate::sink::SinkRetry::default(),
        };
        assert_eq!(
            render_sink(Some(&sink)),
            "kafka: brokers=127.0.0.1:1,127.0.0.1:2 topic=rastreo.devices"
        );
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn render_sink_kafka_never_emits_sasl_credentials() {
        let sink = SinkConfig::Kafka {
            brokers: vec!["127.0.0.1:1".into()],
            topic: "rastreo.devices".into(),
            links_topic: None,
            profiles_topic: None,
            flush_mode: crate::sink::KafkaFlushMode::default(),
            dead_letter: None,
            tls: None,
            sasl: Some(crate::sink::KafkaSasl {
                mechanism: crate::sink::SaslMechanism::ScramSha256,
                username: "svc-user".into(),
                password: crate::prober::Password("PLAINTEXT-SENTINEL".into()),
            }),
            retry: crate::sink::SinkRetry::default(),
        };
        let rendered = render_sink(Some(&sink));
        assert!(
            !rendered.contains("PLAINTEXT-SENTINEL"),
            "plan rendered the SASL password: {rendered}"
        );
        assert!(
            !rendered.contains("svc-user"),
            "plan rendered the SASL username: {rendered}"
        );
    }

    #[cfg(feature = "nats")]
    #[test]
    fn render_sink_nats_shows_servers_subject_stream() {
        let sink = SinkConfig::Nats {
            servers: vec!["nats://127.0.0.1:4222".into()],
            subject: "rastreo.devices".into(),
            stream: "RASTREO".into(),
            links_subject: None,
            profiles_subject: None,
            credentials: crate::sink::NatsCredentials::default(),
            flush_mode: crate::sink::NatsFlushMode::default(),
            dead_letter: None,
            retry: crate::sink::SinkRetry::default(),
        };
        assert_eq!(
            render_sink(Some(&sink)),
            "nats: servers=nats://127.0.0.1:4222 subject=rastreo.devices stream=RASTREO"
        );
    }

    #[cfg(feature = "nats")]
    #[test]
    fn render_sink_nats_strips_inline_userinfo_credentials() {
        let sink = SinkConfig::Nats {
            servers: vec!["nats://u:p@h:4222".into()],
            subject: "rastreo.devices".into(),
            stream: "RASTREO".into(),
            links_subject: None,
            profiles_subject: None,
            credentials: crate::sink::NatsCredentials::default(),
            flush_mode: crate::sink::NatsFlushMode::default(),
            dead_letter: None,
            retry: crate::sink::SinkRetry::default(),
        };
        let rendered = render_sink(Some(&sink));
        assert_eq!(
            rendered,
            "nats: servers=nats://h:4222 subject=rastreo.devices stream=RASTREO"
        );
        assert!(
            !rendered.contains("u:p"),
            "userinfo must not leak: {rendered}"
        );
    }

    #[cfg(feature = "nats")]
    #[test]
    fn strip_userinfo_covers_authority_edge_cases() {
        assert_eq!(
            strip_userinfo("nats://user:pass@host:4222"),
            "nats://host:4222"
        );
        assert_eq!(strip_userinfo("nats://host:4222"), "nats://host:4222");
        assert_eq!(
            strip_userinfo("nats://u:p@host:4222/js"),
            "nats://host:4222/js"
        );
        assert_eq!(strip_userinfo("host:4222"), "host:4222");
        assert_eq!(strip_userinfo("nats://a@b@host:4222"), "nats://host:4222");
    }

    #[test]
    fn render_prober_tcp_connect_lists_ports() {
        let p = ProberConfig::TcpConnect {
            ports: vec![22, 80, 443],
        };
        assert_eq!(render_prober(&p), "tcp_connect (ports 22, 80, 443)");
    }

    #[test]
    fn render_prober_dns_lists_ports_and_queries() {
        let p = ProberConfig::Dns {
            ports: vec![53],
            query_names: vec!["a.example.com.".into(), "b.example.com.".into()],
            query_type: crate::prober::DnsQueryType::A,
            transport: crate::prober::DnsTransport::Udp,
            recursion_desired: true,
        };
        assert_eq!(
            render_prober(&p),
            "dns (ports 53, queries a.example.com., b.example.com.)"
        );
    }

    #[test]
    fn render_prober_udp_lists_ports_and_protocol() {
        let p = ProberConfig::Udp {
            ports: vec![123],
            protocol: crate::prober::UdpProtocol::Ntp,
        };
        assert_eq!(render_prober(&p), "udp (ports 123, protocol Ntp)");
    }

    #[test]
    fn render_prober_reverse_dns_uses_system_resolvers_when_empty() {
        let p = ProberConfig::ReverseDns {
            resolvers: Vec::new(),
        };
        assert_eq!(render_prober(&p), "reverse_dns (system resolvers)");
    }

    #[test]
    fn render_prober_reverse_dns_lists_custom_resolvers() {
        let p = ProberConfig::ReverseDns {
            resolvers: vec![ip(1, 1, 1, 1), ip(8, 8, 8, 8)],
        };
        assert_eq!(
            render_prober(&p),
            "reverse_dns (resolvers 1.1.1.1, 8.8.8.8)"
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn render_prober_http_lists_ports() {
        let p = ProberConfig::Http {
            ports: vec![80, 443],
            scheme: crate::prober::HttpScheme::Auto,
            path: crate::prober::http::default_path(),
            tls_verify: crate::prober::http::default_tls_verify(),
            user_agent: crate::prober::http::default_user_agent(),
        };
        assert_eq!(render_prober(&p), "http (ports 80, 443)");
    }

    #[test]
    fn format_prober_line_none_when_empty() {
        assert_eq!(format_prober_line(&[]), "<none>");
    }

    #[test]
    fn format_prober_line_joins_with_comma() {
        let probers = vec![
            "tcp_connect (ports 22)".to_string(),
            "dns (ports 53)".to_string(),
        ];
        assert_eq!(
            format_prober_line(&probers),
            "tcp_connect (ports 22), dns (ports 53)"
        );
    }

    #[test]
    fn format_ip_list_under_cutoff_prints_all_addresses() {
        let ips: Vec<IpAddr> = (1..=IP_LIST_CUTOFF as u8)
            .map(|i| ip(10, 0, 0, i))
            .collect();
        let out = format_ip_list(&ips);
        assert!(!out.contains("..."), "no ellipsis at cutoff: {out}");
        assert!(out.contains("10.0.0.1"));
        assert!(out.contains("10.0.0.6"));
    }

    #[test]
    fn format_ip_list_over_cutoff_uses_ellipsis_and_count() {
        let ips: Vec<IpAddr> = (1..=8).map(|i| ip(10, 0, 0, i)).collect();
        let out = format_ip_list(&ips);
        assert!(
            out.starts_with("10.0.0.1, 10.0.0.2, 10.0.0.3, ..."),
            "got: {out}"
        );
        assert!(out.ends_with("(8 addresses)"), "got: {out}");
    }

    #[test]
    fn format_ip_list_single_entry_prints_bare_address() {
        assert_eq!(format_ip_list(&[ip(10, 0, 0, 1)]), "10.0.0.1");
    }

    #[test]
    fn display_renders_exact_dry_run_block() {
        let config = tcp_scenario();
        let resolutions = vec![ResolvedScenarioTarget::new(
            Target::Ip(ip(127, 0, 0, 1)),
            Ok(vec![ip(127, 0, 0, 1)]),
        )];
        let plan = plan_of(&config, &resolutions, default_knobs());
        let expected = "  scenario: discovery\n    targets:\n      127.0.0.1 → 127.0.0.1\n    probers: tcp_connect (ports 22, 80)\n    sink: stdout\n    concurrency: 64\n    rate: unlimited\n    retries: 0\n    timeout_ms: 1000\n";
        assert_eq!(plan.to_string(), expected);
    }

    #[test]
    fn display_renders_error_resolution_inline() {
        let mut base = BaseProbeConfig::new();
        base.sink = Some(SinkConfig::Stdout);
        let config = DiscoverScenarioConfig::new(
            base,
            vec![Target::DnsName("x.invalid".into())],
            vec![ProberConfig::TcpConnect { ports: vec![22] }],
        );
        let resolutions = vec![ResolvedScenarioTarget::new(
            Target::DnsName("x.invalid".into()),
            Err(RastreoError::Resolver(ResolverError::DnsNoRecords {
                name: "x.invalid".into(),
            })),
        )];
        let plan = plan_of(&config, &resolutions, default_knobs());
        let out = plan.to_string();
        assert!(out.contains("x.invalid → <error:"), "{out}");
    }

    #[test]
    fn display_shows_rate_per_second_when_set() {
        let config = tcp_scenario();
        let resolutions = vec![ResolvedScenarioTarget::new(
            Target::Ip(ip(127, 0, 0, 1)),
            Ok(vec![ip(127, 0, 0, 1)]),
        )];
        let knobs = PlanKnobs {
            probe_rate: Some(25),
            ..default_knobs()
        };
        assert!(plan_of(&config, &resolutions, knobs)
            .to_string()
            .contains("    rate: 25/sec\n"));
    }

    #[test]
    fn display_empty_probers_prints_none() {
        let mut base = BaseProbeConfig::new();
        base.sink = Some(SinkConfig::Stdout);
        let config =
            DiscoverScenarioConfig::new(base, vec![Target::Ip(ip(10, 0, 0, 1))], Vec::new());
        let resolutions = vec![ResolvedScenarioTarget::new(
            Target::Ip(ip(10, 0, 0, 1)),
            Ok(vec![ip(10, 0, 0, 1)]),
        )];
        assert!(plan_of(&config, &resolutions, default_knobs())
            .to_string()
            .contains("    probers: <none>\n"));
    }

    #[test]
    fn total_probes_dedups_unique_ips_times_probers() {
        let mut base = BaseProbeConfig::new();
        base.sink = Some(SinkConfig::Stdout);
        let config = DiscoverScenarioConfig::new(
            base,
            vec![
                Target::Ip(ip(10, 0, 0, 1)),
                Target::Cidr("10.0.0.0/29".parse().expect("cidr")),
            ],
            vec![
                ProberConfig::TcpConnect { ports: vec![22] },
                ProberConfig::ReverseDns {
                    resolvers: Vec::new(),
                },
            ],
        );
        let resolutions = vec![
            ResolvedScenarioTarget::new(Target::Ip(ip(10, 0, 0, 1)), Ok(vec![ip(10, 0, 0, 1)])),
            ResolvedScenarioTarget::new(
                Target::Cidr("10.0.0.0/29".parse().expect("cidr")),
                Ok(vec![ip(10, 0, 0, 1), ip(10, 0, 0, 2)]),
            ),
        ];
        // unique IPs {.1, .2} = 2, probers = 2 → 4.
        assert_eq!(
            plan_of(&config, &resolutions, default_knobs()).total_probes,
            4
        );
    }

    #[test]
    fn total_probes_zero_when_all_targets_error() {
        let config = tcp_scenario();
        let resolutions = vec![ResolvedScenarioTarget::new(
            Target::DnsName("x.invalid".into()),
            Err(RastreoError::Resolver(ResolverError::DnsNoRecords {
                name: "x.invalid".into(),
            })),
        )];
        assert_eq!(
            plan_of(&config, &resolutions, default_knobs()).total_probes,
            0
        );
    }

    #[test]
    fn discovery_plan_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DiscoveryPlan>();
        assert_send_sync::<PlannedTarget>();
        assert_send_sync::<TargetResolution>();
        assert_send_sync::<PlanKnobs>();
    }

    #[test]
    fn discovery_plan_serializes_to_json() {
        let config = tcp_scenario();
        let resolutions = vec![ResolvedScenarioTarget::new(
            Target::Ip(ip(127, 0, 0, 1)),
            Ok(vec![ip(127, 0, 0, 1)]),
        )];
        let plan = plan_of(&config, &resolutions, default_knobs());
        let json = serde_json::to_value(&plan).expect("serialize");
        assert_eq!(json["scenario"], "discovery");
        assert_eq!(json["total_probes"], 1);
        assert_eq!(json["probers"][0], "tcp_connect (ports 22, 80)");
        assert_eq!(json["targets"][0]["resolution"]["resolved"][0], "127.0.0.1");
    }

    #[test]
    fn discovery_plan_json_schema_generates() {
        let schema = schemars::schema_for!(DiscoveryPlan);
        let json = serde_json::to_value(&schema).expect("schema serialize");
        assert!(json["properties"]["total_probes"].is_object());
    }
}
