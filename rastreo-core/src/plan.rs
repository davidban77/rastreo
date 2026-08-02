use std::fmt;
use std::net::IpAddr;

use schemars::JsonSchema;

use crate::classifier::ClassifierConfig;
use crate::config::{BaseProbeConfig, DiscoverScenarioConfig};
use crate::encoder::EncoderConfig;
use crate::error::RastreoError;
use crate::fuser::{DirectFuser, FuserConfig};
use crate::model::Target;
use crate::prober::ProberConfig;
use crate::resolver::ScenarioResolution;
use crate::sink::{SinkConfig, SinkType};

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
    /// Human-readable summary of the resolved fuser chain, outermost layer first.
    pub fuser: String,
    /// Human-readable summary of the resolved classifier.
    pub classifier: String,
    /// Wire format records leave in: `ndjson` or `table`.
    pub encoder: String,
    /// Human-readable summary of where records would go; several destinations, comma-separated, when the run fans out.
    pub sink: String,
    /// Effective in-flight probe cap for this run.
    pub max_concurrent: u32,
    /// Effective probes-per-second cap; `null` when unlimited.
    pub probe_rate: Option<u32>,
    /// Effective retransmit attempts for connectionless probers.
    pub retries: u32,
    /// Effective per-probe timeout in milliseconds.
    pub timeout_ms: u64,
    /// Total probes the scan would run: every address it would probe times probers, `0` when it would abort first.
    pub total_probes: usize,
    /// Error the scan would abort on before its first probe; absent when every target resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
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

enum PlannedSink<'a> {
    Scenario,
    Injected(&'a [SinkType]),
}

impl DiscoveryPlan {
    /// Plan the stages a scenario alone determines, leaving every resolution-derived field unset; a scenario [`DiscoverScenarioConfig::validate`] rejects has no plan.
    pub fn new(
        scenario: String,
        config: &DiscoverScenarioConfig,
        knobs: PlanKnobs,
    ) -> Result<Self, RastreoError> {
        Self::build(scenario, config, None, knobs, PlannedSink::Scenario)
    }

    /// Plan the scan a resolution would run, counting the addresses that resolution streams.
    pub fn resolved(
        scenario: String,
        config: &DiscoverScenarioConfig,
        resolution: &ScenarioResolution,
        knobs: PlanKnobs,
    ) -> Result<Self, RastreoError> {
        Self::build(
            scenario,
            config,
            Some(resolution),
            knobs,
            PlannedSink::Scenario,
        )
    }

    /// Plan the scan a resolution would run for a caller that injects its own sink, rendering `destinations` in write order instead of the scenario's `sink:`.
    pub fn resolved_into(
        scenario: String,
        config: &DiscoverScenarioConfig,
        resolution: &ScenarioResolution,
        knobs: PlanKnobs,
        destinations: &[SinkType],
    ) -> Result<Self, RastreoError> {
        Self::build(
            scenario,
            config,
            Some(resolution),
            knobs,
            PlannedSink::Injected(destinations),
        )
    }

    fn build(
        scenario: String,
        config: &DiscoverScenarioConfig,
        resolution: Option<&ScenarioResolution>,
        knobs: PlanKnobs,
        planned_sink: PlannedSink<'_>,
    ) -> Result<Self, RastreoError> {
        config.validate()?;
        // Exhaustive, so a field added to the config cannot reach a run until the plan states whether it renders.
        let DiscoverScenarioConfig {
            base:
                BaseProbeConfig {
                    fuser,
                    classifier,
                    sink,
                    name: _,
                    encoder: _,
                    max_concurrent: _,
                    probe_rate: _,
                    retries: _,
                    timeout_ms: _,
                    rate_limit: _,
                },
            targets: _,
            probers: prober_configs,
        } = config;
        let targets = resolution.map_or_else(Vec::new, |resolution| {
            resolution
                .entries()
                .iter()
                .map(|(target, result)| PlannedTarget {
                    target: render_target(target),
                    resolution: match result {
                        Ok(ips) => TargetResolution::Resolved(ips.clone()),
                        Err(err) => TargetResolution::Error(err.to_string()),
                    },
                })
                .collect()
        });
        let probers: Vec<String> = prober_configs.iter().map(render_prober).collect();
        let total_probes = resolution
            .map_or(0, ScenarioResolution::total_hosts)
            .saturating_mul(prober_configs.len());
        Ok(Self {
            scenario,
            targets,
            probers,
            fuser: render_fuser(fuser.as_ref()),
            classifier: render_classifier(classifier.as_ref()),
            encoder: render_encoder(&config.effective_encoder_config()),
            sink: match planned_sink {
                PlannedSink::Scenario => render_sink(sink.as_ref()),
                PlannedSink::Injected(destinations) => render_destinations(destinations),
            },
            max_concurrent: knobs.max_concurrent,
            probe_rate: knobs.probe_rate,
            retries: knobs.retries,
            timeout_ms: knobs.timeout_ms,
            total_probes,
            refusal: resolution
                .and_then(ScenarioResolution::refusal)
                .map(ToString::to_string),
        })
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
        writeln!(f, "    fuser: {}", self.fuser)?;
        writeln!(f, "    classifier: {}", self.classifier)?;
        writeln!(f, "    encoder: {}", self.encoder)?;
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

fn render_fuser(fuser: Option<&FuserConfig>) -> String {
    match fuser {
        Some(config) => render_fuser_chain(config),
        None => render_fuser_chain(&crate::fuser::default_fuser_config()),
    }
}

fn render_fuser_chain(config: &FuserConfig) -> String {
    let mut out = String::new();
    let mut layer = config;
    loop {
        if !out.is_empty() {
            out.push_str(" over ");
        }
        out.push_str(&render_fuser_layer(layer));
        match inner_fuser(layer) {
            Some(inner) => layer = inner,
            None => return out,
        }
    }
}

fn inner_fuser(config: &FuserConfig) -> Option<&FuserConfig> {
    match config {
        FuserConfig::Direct { .. } => None,
        #[cfg(feature = "mib_enrichment")]
        FuserConfig::MibEnrichment { inner, .. } => Some(inner),
        FuserConfig::Identity { inner, .. } => Some(inner),
    }
}

fn render_fuser_layer(config: &FuserConfig) -> String {
    match config {
        FuserConfig::Direct {
            include_unreachable,
            confidence_baseline,
            confidence_per_signal,
        } => format!(
            "direct (include_unreachable {}, confidence_baseline {}, confidence_per_signal {})",
            include_unreachable.unwrap_or(DirectFuser::DEFAULT_INCLUDE_UNREACHABLE),
            confidence_baseline.unwrap_or(DirectFuser::DEFAULT_CONFIDENCE_BASELINE),
            confidence_per_signal.unwrap_or(DirectFuser::DEFAULT_CONFIDENCE_PER_SIGNAL),
        ),
        #[cfg(feature = "mib_enrichment")]
        FuserConfig::MibEnrichment { data_path, .. } => match data_path {
            Some(path) if !path.is_empty() => format!("mib_enrichment (table {path})"),
            _ => "mib_enrichment (bundled table)".to_string(),
        },
        FuserConfig::Identity { identity_hints, .. } => {
            if identity_hints.vrrp_groups.is_empty() {
                "identity".to_string()
            } else {
                format!(
                    "identity ({} vrrp groups)",
                    identity_hints.vrrp_groups.len()
                )
            }
        }
    }
}

fn render_classifier(classifier: Option<&ClassifierConfig>) -> String {
    match classifier {
        Some(config) => render_classifier_config(config),
        None => render_classifier_config(&crate::classifier::default_classifier_config()),
    }
}

fn render_classifier_config(config: &ClassifierConfig) -> String {
    match config {
        ClassifierConfig::Noop => "noop".to_string(),
        ClassifierConfig::Rules {
            merge_mode,
            platform_rules,
            role_rules,
        } => format!(
            "rules (merge_mode {}, platform_rules {}, role_rules {})",
            merge_mode.as_label(),
            platform_rules.len(),
            role_rules.len()
        ),
    }
}

// Width is deliberately absent: the CLI measures it off the terminal, so rendering it would make one scenario plan two different texts.
fn render_encoder(encoder: &EncoderConfig) -> String {
    match encoder {
        EncoderConfig::Ndjson => "ndjson".to_string(),
        EncoderConfig::Table { .. } => "table".to_string(),
    }
}

fn render_sink(sink: Option<&SinkConfig>) -> String {
    let Some(sink) = sink else {
        return "stdout (default)".to_string();
    };
    let label = sink.sink_type().as_label();
    match sink {
        SinkConfig::Stdout | SinkConfig::Memory => label.to_string(),
        SinkConfig::File { path } => format!("{label}: {}", path.display()),
        #[cfg(feature = "kafka")]
        SinkConfig::Kafka { brokers, topic, .. } => {
            format!("{label}: brokers={} topic={topic}", brokers.join(","))
        }
        #[cfg(feature = "nats")]
        SinkConfig::Nats {
            servers,
            subject,
            stream,
            ..
        } => {
            let servers = crate::redact::redacted_server_list(servers);
            format!("{label}: servers={servers} subject={subject} stream={stream}")
        }
    }
}

fn render_destinations(destinations: &[SinkType]) -> String {
    if destinations.is_empty() {
        return "<none>".to_string();
    }
    let mut out = String::new();
    for destination in destinations {
        if !out.is_empty() {
            out.push_str(", ");
        }
        out.push_str(destination.as_label());
    }
    out
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
    use crate::error::ConfigError;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn cidr(s: &str) -> Target {
        Target::Cidr(s.parse().expect("cidr"))
    }

    fn plan_of(config: &DiscoverScenarioConfig, knobs: PlanKnobs) -> DiscoveryPlan {
        DiscoveryPlan::new("discovery".to_string(), config, knobs).expect("plan")
    }

    fn resolved_plan_of(
        config: &DiscoverScenarioConfig,
        resolution: &ScenarioResolution,
        knobs: PlanKnobs,
    ) -> DiscoveryPlan {
        DiscoveryPlan::resolved("discovery".to_string(), config, resolution, knobs).expect("plan")
    }

    // Every resolution a plan test reads comes from the resolver a scan would use, on targets that
    // need no network: the plan cannot be counted off anything the scan would not resolve.
    fn resolution_of(targets: &[Target]) -> ScenarioResolution {
        resolution_under_limit(targets, crate::resolver::DEFAULT_HOST_LIMIT)
    }

    fn resolution_under_limit(targets: &[Target], limit: usize) -> ScenarioResolution {
        let resolver = crate::resolver::HickoryResolver::from_system()
            .expect("system resolver")
            .with_limit(limit);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(crate::resolver::resolve_scenario(&resolver, targets))
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
    fn render_destinations_joins_every_fan_out_child_in_write_order() {
        assert_eq!(render_destinations(&[SinkType::Memory]), "memory");
        assert_eq!(
            render_destinations(&[SinkType::Memory, SinkType::Kafka]),
            "memory, kafka"
        );
        assert_eq!(render_destinations(&[]), "<none>");
    }

    #[test]
    fn an_injected_destination_replaces_the_scenario_sink_in_the_plan() {
        let mut config = tcp_scenario();
        config.base.sink = Some(SinkConfig::File {
            path: "/tmp/ignored.ndjson".into(),
        });
        let resolution = resolution_of(&config.targets);
        let plan = DiscoveryPlan::resolved_into(
            "discovery".to_string(),
            &config,
            &resolution,
            default_knobs(),
            &[SinkType::Memory, SinkType::Nats],
        )
        .expect("plan");
        assert_eq!(
            plan.sink, "memory, nats",
            "a caller that injects its own sink must not have the scenario's rendered",
        );
    }

    #[test]
    fn a_scenario_planned_without_an_injected_destination_still_renders_its_own_sink() {
        let mut config = tcp_scenario();
        config.base.sink = Some(SinkConfig::File {
            path: "/tmp/records.ndjson".into(),
        });
        let resolution = resolution_of(&config.targets);
        let plan = resolved_plan_of(&config, &resolution, default_knobs());
        assert_eq!(plan.sink, "file: /tmp/records.ndjson");
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

    fn direct(include_unreachable: Option<bool>) -> FuserConfig {
        FuserConfig::Direct {
            include_unreachable,
            confidence_baseline: None,
            confidence_per_signal: None,
        }
    }

    #[test]
    fn render_fuser_none_prints_the_pipeline_default() {
        assert_eq!(
            render_fuser(None),
            render_fuser_chain(&crate::fuser::default_fuser_config())
        );
        assert_eq!(
            render_fuser(None),
            "direct (include_unreachable false, confidence_baseline 0.1, confidence_per_signal 0.1)"
        );
    }

    #[test]
    fn render_fuser_direct_shows_the_effective_knobs_not_the_absent_ones() {
        assert_eq!(
            render_fuser(Some(&direct(Some(true)))),
            "direct (include_unreachable true, confidence_baseline 0.1, confidence_per_signal 0.1)"
        );
    }

    #[test]
    fn render_fuser_lists_the_chain_outermost_first() {
        let config = FuserConfig::Identity {
            identity_hints: crate::fuser::IdentityHints::default(),
            inner: Box::new(direct(None)),
        };
        assert!(
            render_fuser(Some(&config)).starts_with("identity over direct ("),
            "{}",
            render_fuser(Some(&config))
        );
    }

    #[test]
    fn render_fuser_identity_counts_declared_vrrp_groups() {
        let config = FuserConfig::Identity {
            identity_hints: crate::fuser::IdentityHints::new(vec![crate::fuser::VrrpGroup {
                virtual_ip: ip(10, 0, 0, 99),
                virtual_mac: "00:00:5e:00:01:2a".to_string(),
                members: Vec::new(),
            }]),
            inner: Box::new(direct(None)),
        };
        assert!(
            render_fuser(Some(&config)).starts_with("identity (1 vrrp groups) over direct ("),
            "{}",
            render_fuser(Some(&config))
        );
    }

    #[cfg(feature = "mib_enrichment")]
    #[test]
    fn render_fuser_names_the_enrichment_table_source() {
        let bundled = FuserConfig::MibEnrichment {
            data_path: None,
            inner: Box::new(direct(None)),
        };
        assert!(
            render_fuser(Some(&bundled))
                .starts_with("mib_enrichment (bundled table) over direct ("),
            "{}",
            render_fuser(Some(&bundled))
        );
        let overlaid = FuserConfig::MibEnrichment {
            data_path: Some("/etc/rastreo/mib.tsv".to_string()),
            inner: Box::new(direct(None)),
        };
        assert!(
            render_fuser(Some(&overlaid))
                .starts_with("mib_enrichment (table /etc/rastreo/mib.tsv) over direct ("),
            "{}",
            render_fuser(Some(&overlaid))
        );
    }

    #[test]
    fn the_plan_names_the_encoder_the_run_would_build() {
        for (encoder, expected) in [
            (None, "ndjson"),
            (Some(EncoderConfig::Ndjson), "ndjson"),
            (Some(EncoderConfig::Table { width: 100 }), "table"),
        ] {
            let mut config = tcp_scenario();
            config.base.encoder = encoder;
            assert_eq!(plan_of(&config, default_knobs()).encoder, expected);
        }
    }

    #[test]
    fn the_encoder_reads_the_same_whatever_width_the_terminal_measured() {
        let narrow = render_encoder(&EncoderConfig::Table { width: 55 });
        assert_eq!(narrow, render_encoder(&EncoderConfig::Table { width: 153 }));
        assert_eq!(narrow, "table");
    }

    #[test]
    fn render_classifier_none_prints_the_pipeline_default() {
        assert_eq!(
            render_classifier(None),
            render_classifier_config(&crate::classifier::default_classifier_config())
        );
        assert_eq!(
            render_classifier(None),
            "rules (merge_mode extend, platform_rules 0, role_rules 0)"
        );
    }

    #[test]
    fn render_classifier_noop_prints_noop() {
        assert_eq!(render_classifier(Some(&ClassifierConfig::Noop)), "noop");
    }

    #[test]
    fn render_classifier_rules_counts_user_supplied_rules() {
        let config = ClassifierConfig::Rules {
            merge_mode: crate::classifier::MergeMode::Replace,
            platform_rules: vec![crate::classifier::PlatformRule {
                signal: crate::classifier::SignalKind::SnmpSysDescr,
                pattern: "Cisco".to_string(),
                platform: Some("cisco_ios".to_string()),
                os_version_capture: None,
                ssh_version_capture: None,
                http_server_capture: None,
                http_version_capture: None,
            }],
            role_rules: Vec::new(),
        };
        assert_eq!(
            render_classifier(Some(&config)),
            "rules (merge_mode replace, platform_rules 1, role_rules 0)"
        );
    }

    #[test]
    fn a_selected_fuser_and_classifier_reach_the_plan_fields() {
        let mut base = BaseProbeConfig::new();
        base.sink = Some(SinkConfig::Stdout);
        base.fuser = Some(direct(Some(true)));
        base.classifier = Some(ClassifierConfig::Noop);
        let config = DiscoverScenarioConfig::new(
            base,
            vec![Target::Ip(ip(127, 0, 0, 1))],
            vec![ProberConfig::TcpConnect { ports: vec![22] }],
        );
        let plan = plan_of(&config, default_knobs());
        assert!(plan.fuser.contains("include_unreachable true"), "{plan:?}");
        assert_eq!(plan.classifier, "noop");
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
        let resolution = resolution_of(&[Target::Ip(ip(127, 0, 0, 1))]);
        let plan = resolved_plan_of(&config, &resolution, default_knobs());
        insta::assert_snapshot!(plan.to_string());
    }

    #[test]
    fn display_renders_a_selected_fuser_and_classifier() {
        let mut base = BaseProbeConfig::new();
        base.sink = Some(SinkConfig::Stdout);
        base.fuser = Some(FuserConfig::Identity {
            identity_hints: crate::fuser::IdentityHints::default(),
            inner: Box::new(FuserConfig::Direct {
                include_unreachable: Some(true),
                confidence_baseline: Some(0.25),
                confidence_per_signal: None,
            }),
        });
        base.classifier = Some(ClassifierConfig::Noop);
        let config = DiscoverScenarioConfig::new(
            base,
            vec![Target::Ip(ip(127, 0, 0, 1))],
            vec![ProberConfig::TcpConnect {
                ports: vec![22, 80],
            }],
        );
        let resolution = resolution_of(&[Target::Ip(ip(127, 0, 0, 1))]);
        let plan = resolved_plan_of(&config, &resolution, default_knobs());
        insta::assert_snapshot!(plan.to_string());
    }

    #[test]
    fn display_renders_error_resolution_inline() {
        let mut base = BaseProbeConfig::new();
        base.sink = Some(SinkConfig::Stdout);
        let config = DiscoverScenarioConfig::new(
            base,
            vec![cidr("10.0.0.0/24")],
            vec![ProberConfig::TcpConnect { ports: vec![22] }],
        );
        let resolution = resolution_under_limit(&[cidr("10.0.0.0/24")], 8);
        let out = resolved_plan_of(&config, &resolution, default_knobs()).to_string();
        assert!(out.contains("10.0.0.0/24 → <error:"), "{out}");
    }

    #[test]
    fn display_names_the_encoder_records_would_leave_in() {
        let mut config = tcp_scenario();
        config.base.encoder = Some(EncoderConfig::Table { width: 120 });
        assert!(plan_of(&config, default_knobs())
            .to_string()
            .contains("    encoder: table\n"));
    }

    #[test]
    fn display_shows_rate_per_second_when_set() {
        let config = tcp_scenario();
        let resolution = resolution_of(&[Target::Ip(ip(127, 0, 0, 1))]);
        let knobs = PlanKnobs {
            probe_rate: Some(25),
            ..default_knobs()
        };
        assert!(resolved_plan_of(&config, &resolution, knobs)
            .to_string()
            .contains("    rate: 25/sec\n"));
    }

    #[test]
    fn display_of_a_plan_whose_probers_were_cleared_prints_none() {
        let config = tcp_scenario();
        let resolution = resolution_of(&[Target::Ip(ip(127, 0, 0, 1))]);
        let mut plan = resolved_plan_of(&config, &resolution, default_knobs());
        plan.probers.clear();
        assert!(plan.to_string().contains("    probers: <none>\n"));
    }

    #[test]
    fn a_scenario_with_no_probers_has_no_plan() {
        let mut base = BaseProbeConfig::new();
        base.sink = Some(SinkConfig::Stdout);
        let config =
            DiscoverScenarioConfig::new(base, vec![Target::Ip(ip(10, 0, 0, 1))], Vec::new());
        let err = DiscoveryPlan::new("discovery".into(), &config, default_knobs())
            .expect_err("a scenario the run refuses must have no plan");
        assert!(
            matches!(&err, RastreoError::Config(ConfigError::InvalidValue(msg)) if msg.contains("probers")),
            "got {err:?}"
        );
    }

    #[test]
    fn a_scenario_with_an_unbuildable_prober_has_no_plan() {
        let mut base = BaseProbeConfig::new();
        base.sink = Some(SinkConfig::Stdout);
        let config = DiscoverScenarioConfig::new(
            base,
            vec![Target::Ip(ip(10, 0, 0, 1))],
            vec![ProberConfig::TcpConnect { ports: Vec::new() }],
        );
        let err = DiscoveryPlan::new("discovery".into(), &config, default_knobs())
            .expect_err("a scenario the run refuses must have no plan");
        assert!(
            matches!(&err, RastreoError::Config(ConfigError::InvalidValue(msg)) if msg.contains("at least one port")),
            "got {err:?}"
        );
    }

    #[test]
    fn a_scenario_with_an_out_of_range_fuser_knob_has_no_plan() {
        let mut base = BaseProbeConfig::new();
        base.sink = Some(SinkConfig::Stdout);
        base.fuser = Some(FuserConfig::Direct {
            include_unreachable: None,
            confidence_baseline: Some(2.0),
            confidence_per_signal: None,
        });
        let config = DiscoverScenarioConfig::new(
            base,
            vec![Target::Ip(ip(10, 0, 0, 1))],
            vec![ProberConfig::TcpConnect { ports: vec![22] }],
        );
        let err = DiscoveryPlan::new("discovery".into(), &config, default_knobs())
            .expect_err("a scenario the run refuses must have no plan");
        assert!(
            matches!(&err, RastreoError::Config(ConfigError::InvalidValue(msg)) if msg.contains("confidence_baseline")),
            "got {err:?}"
        );
    }

    fn two_prober_scenario(targets: Vec<Target>) -> DiscoverScenarioConfig {
        let mut base = BaseProbeConfig::new();
        base.sink = Some(SinkConfig::Stdout);
        DiscoverScenarioConfig::new(
            base,
            targets,
            vec![
                ProberConfig::TcpConnect { ports: vec![22] },
                ProberConfig::ReverseDns {
                    resolvers: Vec::new(),
                },
            ],
        )
    }

    #[test]
    fn total_probes_counts_an_address_once_per_spec_that_yields_it() {
        let targets = vec![cidr("10.0.0.0/30"), Target::Ip(ip(10, 0, 0, 1))];
        let config = two_prober_scenario(targets.clone());
        // The scan streams .1, .2, .1 — the overlapping spec is probed, not deduplicated.
        assert_eq!(
            resolved_plan_of(&config, &resolution_of(&targets), default_knobs()).total_probes,
            6
        );
    }

    #[test]
    fn a_scenario_that_would_abort_on_a_target_plans_no_probes() {
        let targets = vec![Target::Ip(ip(10, 0, 0, 1)), cidr("10.0.0.0/24")];
        let config = two_prober_scenario(targets.clone());
        let plan = resolved_plan_of(
            &config,
            &resolution_under_limit(&targets, 8),
            default_knobs(),
        );
        assert_eq!(plan.total_probes, 0);
        assert!(
            matches!(&plan.targets[0].resolution, TargetResolution::Resolved(ips) if ips == &[ip(10, 0, 0, 1)]),
            "the resolvable target is still attributed: {:?}",
            plan.targets
        );
    }

    #[test]
    fn total_probes_zero_when_every_target_fails_to_resolve() {
        let targets = vec![cidr("10.0.0.0/24")];
        let config = two_prober_scenario(targets.clone());
        assert_eq!(
            resolved_plan_of(
                &config,
                &resolution_under_limit(&targets, 8),
                default_knobs()
            )
            .total_probes,
            0
        );
    }

    #[test]
    fn the_plan_names_the_error_the_scan_would_abort_on() {
        let targets = vec![Target::Ip(ip(10, 0, 0, 1)), cidr("10.0.0.0/24")];
        let config = two_prober_scenario(targets.clone());
        let plan = resolved_plan_of(
            &config,
            &resolution_under_limit(&targets, 8),
            default_knobs(),
        );
        let refusal = plan.refusal.expect("a scan that would abort names why");
        assert!(
            refusal.contains("exceeds the configured limit"),
            "{refusal}"
        );
    }

    #[test]
    fn a_plan_every_target_resolved_for_names_no_refusal() {
        let targets = vec![cidr("10.0.0.0/30")];
        let config = two_prober_scenario(targets.clone());
        assert_eq!(
            resolved_plan_of(&config, &resolution_of(&targets), default_knobs()).refusal,
            None
        );
    }

    #[test]
    fn an_unresolved_plan_counts_no_probes_and_lists_no_targets() {
        let plan = plan_of(
            &two_prober_scenario(vec![cidr("10.0.0.0/30")]),
            default_knobs(),
        );
        assert_eq!(plan.total_probes, 0);
        assert!(plan.targets.is_empty());
        assert_eq!(plan.refusal, None);
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
        let resolution = resolution_of(&[Target::Ip(ip(127, 0, 0, 1))]);
        let plan = resolved_plan_of(&config, &resolution, default_knobs());
        let json = serde_json::to_value(&plan).expect("serialize");
        assert_eq!(json["scenario"], "discovery");
        assert_eq!(json["total_probes"], 1);
        assert_eq!(json["probers"][0], "tcp_connect (ports 22, 80)");
        assert_eq!(json["targets"][0]["resolution"]["resolved"][0], "127.0.0.1");
        assert_eq!(json["fuser"], render_fuser(None));
        assert_eq!(json["classifier"], render_classifier(None));
        assert_eq!(json["encoder"], "ndjson");
    }

    #[test]
    fn discovery_plan_json_schema_generates() {
        let schema = schemars::schema_for!(DiscoveryPlan);
        let json = serde_json::to_value(&schema).expect("schema serialize");
        assert!(json["properties"]["total_probes"].is_object());
    }
}
