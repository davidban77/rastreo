use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use ipnet::IpNet;
use rastreo_core::config::{BaseProbeConfig, DiscoverScenarioConfig};
use rastreo_core::{run_discovery, ConfigError, ProberConfig, SinkConfig, Target};

#[derive(Parser, Debug)]
pub struct DiscoverArgs {
    /// Target to probe. CIDR (10.0.0.0/24), single IP (10.0.0.1), range
    /// (10.0.0.1-10.0.0.5), or DNS name. Repeat to add multiple targets.
    #[arg(long, required = true, num_args = 1..)]
    pub target: Vec<String>,

    /// Port to probe. Repeat or comma-separate for multiple.
    #[arg(short, long, value_delimiter = ',', required = true)]
    pub port: Vec<u16>,

    /// Output sink kind.
    #[arg(long, value_enum, default_value_t = SinkKind::Stdout)]
    pub sink: SinkKind,

    /// File path for --sink file.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Kafka brokers (comma-separated) for --sink kafka. Requires --features kafka build.
    #[arg(long, value_delimiter = ',')]
    pub brokers: Vec<String>,

    /// Kafka topic for --sink kafka.
    #[arg(long)]
    pub topic: Option<String>,

    /// Max concurrent probes.
    #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..))]
    pub concurrency: u32,

    /// Per-probe timeout in milliseconds.
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout_ms: u64,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkKind {
    Stdout,
    File,
    #[cfg(feature = "kafka")]
    Kafka,
}

pub async fn run(args: DiscoverArgs) -> Result<()> {
    let scenario = build_scenario(&args)?;
    let summary = run_discovery(&scenario).await?;
    eprintln!(
        "discovery complete: targets_resolved={} probe_attempts={} probe_errors={} records_emitted={} elapsed_ms={}",
        summary.targets_resolved,
        summary.probe_attempts,
        summary.probe_errors,
        summary.records_emitted,
        summary.elapsed.as_millis(),
    );
    if summary.records_emitted == 0 && summary.probe_attempts > 0 {
        eprintln!(
            "hint: 0 records emitted — no probe reached an open port. Check target reachability and port list."
        );
    }
    Ok(())
}

pub(crate) fn build_scenario(args: &DiscoverArgs) -> Result<DiscoverScenarioConfig> {
    let targets: Vec<Target> = args
        .target
        .iter()
        .map(|s| parse_target(s).with_context(|| format!("invalid --target {s:?}")))
        .collect::<Result<Vec<_>>>()?;

    let sink_config = build_sink_config(args)?;

    let probers = vec![ProberConfig::TcpConnect {
        ports: args.port.clone(),
    }];

    let mut base = BaseProbeConfig::new();
    base.rate_limit = Some(args.concurrency);
    base.timeout_ms = Some(args.timeout_ms);
    base.sink = Some(sink_config);

    Ok(DiscoverScenarioConfig::new(base, targets, probers))
}

fn build_sink_config(args: &DiscoverArgs) -> Result<SinkConfig> {
    match args.sink {
        SinkKind::Stdout => Ok(SinkConfig::Stdout),
        SinkKind::File => {
            let path = args
                .output
                .clone()
                .ok_or_else(|| anyhow!("--sink file requires --output <path>"))?;
            Ok(SinkConfig::File { path })
        }
        #[cfg(feature = "kafka")]
        SinkKind::Kafka => {
            if args.brokers.is_empty() {
                return Err(anyhow!(
                    "--sink kafka requires --brokers <broker[,broker...]>"
                ));
            }
            let topic = args
                .topic
                .clone()
                .ok_or_else(|| anyhow!("--sink kafka requires --topic <name>"))?;
            Ok(SinkConfig::Kafka {
                brokers: args.brokers.clone(),
                topic,
                buffer_threshold: None,
            })
        }
    }
}

pub(crate) fn parse_target(input: &str) -> Result<Target, ConfigError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(ConfigError::InvalidValue("target cannot be empty".into()));
    }
    // CIDR before anything else: a `/` is unambiguous (no other supported form contains it).
    if s.contains('/') {
        let net: IpNet = s.parse().map_err(|e: ipnet::AddrParseError| {
            ConfigError::InvalidValue(format!("CIDR {s:?}: {e}"))
        })?;
        return Ok(Target::Cidr(net));
    }
    if let Ok(ip) = IpAddr::from_str(s) {
        return Ok(Target::Ip(ip));
    }
    // Treat as range only when both sides parse as IPs; otherwise fall through to DNS so
    // hostnames like `router-1.lab` are not mistaken for ranges.
    if let Some((lhs, rhs)) = s.split_once('-') {
        if let (Ok(start), Ok(end)) = (IpAddr::from_str(lhs.trim()), IpAddr::from_str(rhs.trim())) {
            return Ok(Target::Range { start, end });
        }
    }
    Ok(Target::DnsName(s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::net::Ipv4Addr;

    fn args(target: &[&str], port: &[u16]) -> DiscoverArgs {
        DiscoverArgs {
            target: target.iter().map(|s| s.to_string()).collect(),
            port: port.to_vec(),
            sink: SinkKind::Stdout,
            output: None,
            brokers: Vec::new(),
            topic: None,
            concurrency: 64,
            timeout_ms: 1000,
        }
    }

    #[test]
    fn parse_target_single_ipv4() {
        let t = parse_target("10.0.0.1").expect("ip");
        assert_eq!(t, Target::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn parse_target_single_ipv6() {
        let t = parse_target("2001:db8::1").expect("ipv6");
        match t {
            Target::Ip(IpAddr::V6(_)) => {}
            other => panic!("expected V6 Ip, got {other:?}"),
        }
    }

    #[test]
    fn parse_target_cidr_v4() {
        let t = parse_target("10.0.0.0/24").expect("cidr");
        match t {
            Target::Cidr(IpNet::V4(_)) => {}
            other => panic!("expected V4 Cidr, got {other:?}"),
        }
    }

    #[test]
    fn parse_target_cidr_v6() {
        let t = parse_target("2001:db8::/120").expect("cidr v6");
        match t {
            Target::Cidr(IpNet::V6(_)) => {}
            other => panic!("expected V6 Cidr, got {other:?}"),
        }
    }

    #[test]
    fn parse_target_range_v4() {
        let t = parse_target("10.0.0.1-10.0.0.5").expect("range");
        assert_eq!(
            t,
            Target::Range {
                start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            }
        );
    }

    #[test]
    fn parse_target_range_v4_with_whitespace() {
        let t = parse_target("10.0.0.1 - 10.0.0.5").expect("range with spaces");
        assert_eq!(
            t,
            Target::Range {
                start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            }
        );
    }

    #[test]
    fn parse_target_dns_name() {
        let t = parse_target("router-1.lab.local").expect("dns");
        assert_eq!(t, Target::DnsName("router-1.lab.local".into()));
    }

    #[test]
    fn parse_target_empty_string_errors() {
        let err = parse_target("").expect_err("empty");
        assert!(matches!(err, ConfigError::InvalidValue(_)));
    }

    #[test]
    fn parse_target_bad_cidr_errors() {
        let err = parse_target("10.0.0.0/99").expect_err("bad cidr");
        let msg = format!("{err}");
        assert!(msg.contains("CIDR"), "msg: {msg}");
    }

    #[test]
    fn parse_target_unparseable_range_falls_back_to_dns() {
        let t = parse_target("not-an-ip-10.0.0.1").expect("dns fallback");
        assert_eq!(t, Target::DnsName("not-an-ip-10.0.0.1".into()));
    }

    #[test]
    fn build_scenario_with_stdout_sink_produces_expected_shape() {
        let a = args(&["10.0.0.1"], &[22, 80]);
        let scenario = build_scenario(&a).expect("scenario");
        assert_eq!(scenario.targets.len(), 1);
        assert_eq!(scenario.probers.len(), 1);
        match &scenario.probers[0] {
            ProberConfig::TcpConnect { ports } => assert_eq!(ports, &vec![22, 80]),
            _ => panic!("expected TcpConnect prober"),
        }
        match scenario.base.sink {
            Some(SinkConfig::Stdout) => {}
            other => panic!("expected Stdout sink, got {other:?}"),
        }
        assert_eq!(scenario.base.rate_limit, Some(64));
        assert_eq!(scenario.base.timeout_ms, Some(1000));
    }

    #[test]
    fn build_scenario_with_file_sink_uses_output_path() {
        let mut a = args(&["10.0.0.1"], &[80]);
        a.sink = SinkKind::File;
        a.output = Some(PathBuf::from("/tmp/foo.ndjson"));
        let scenario = build_scenario(&a).expect("scenario");
        match scenario.base.sink {
            Some(SinkConfig::File { path }) => {
                assert_eq!(path, PathBuf::from("/tmp/foo.ndjson"));
            }
            other => panic!("expected File sink, got {other:?}"),
        }
    }

    #[test]
    fn build_scenario_file_sink_without_output_errors() {
        let mut a = args(&["10.0.0.1"], &[80]);
        a.sink = SinkKind::File;
        a.output = None;
        let err = build_scenario(&a).expect_err("missing output");
        let msg = format!("{err}");
        assert!(msg.contains("--output"), "msg: {msg}");
    }

    #[test]
    fn build_scenario_multiple_targets_round_trip() {
        let a = args(&["10.0.0.1", "10.0.0.0/30", "router-1.lab"], &[80]);
        let scenario = build_scenario(&a).expect("scenario");
        assert_eq!(scenario.targets.len(), 3);
        assert!(matches!(scenario.targets[0], Target::Ip(_)));
        assert!(matches!(scenario.targets[1], Target::Cidr(_)));
        assert!(matches!(scenario.targets[2], Target::DnsName(_)));
    }

    #[test]
    fn default_concurrency_is_sixty_four() {
        let a = args(&["10.0.0.1"], &[80]);
        assert_eq!(a.concurrency, 64);
    }

    #[test]
    fn default_timeout_ms_is_one_thousand() {
        let a = args(&["10.0.0.1"], &[80]);
        assert_eq!(a.timeout_ms, 1000);
    }

    #[test]
    fn discover_rejects_concurrency_zero() {
        let result = DiscoverArgs::try_parse_from([
            "discover",
            "--target",
            "127.0.0.1",
            "--port",
            "80",
            "--concurrency",
            "0",
        ]);
        assert!(result.is_err(), "expected --concurrency 0 to be rejected");
    }

    #[test]
    fn discover_rejects_timeout_ms_zero() {
        let result = DiscoverArgs::try_parse_from([
            "discover",
            "--target",
            "127.0.0.1",
            "--port",
            "80",
            "--timeout-ms",
            "0",
        ]);
        assert!(result.is_err(), "expected --timeout-ms 0 to be rejected");
    }

    #[test]
    fn discover_accepts_concurrency_one() {
        let parsed = DiscoverArgs::try_parse_from([
            "discover",
            "--target",
            "127.0.0.1",
            "--port",
            "80",
            "--concurrency",
            "1",
        ])
        .expect("--concurrency 1 should parse");
        assert_eq!(parsed.concurrency, 1);
    }

    #[test]
    fn discover_accepts_timeout_ms_one() {
        let parsed = DiscoverArgs::try_parse_from([
            "discover",
            "--target",
            "127.0.0.1",
            "--port",
            "80",
            "--timeout-ms",
            "1",
        ])
        .expect("--timeout-ms 1 should parse");
        assert_eq!(parsed.timeout_ms, 1);
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn build_scenario_kafka_requires_brokers() {
        let mut a = args(&["10.0.0.1"], &[80]);
        a.sink = SinkKind::Kafka;
        a.brokers = Vec::new();
        a.topic = Some("rastreo.devices".into());
        let err = build_scenario(&a).expect_err("missing brokers");
        assert!(format!("{err}").contains("--brokers"));
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn build_scenario_kafka_requires_topic() {
        let mut a = args(&["10.0.0.1"], &[80]);
        a.sink = SinkKind::Kafka;
        a.brokers = vec!["localhost:9092".into()];
        a.topic = None;
        let err = build_scenario(&a).expect_err("missing topic");
        assert!(format!("{err}").contains("--topic"));
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn build_scenario_kafka_with_brokers_and_topic_produces_kafka_sink() {
        let mut a = args(&["10.0.0.1"], &[80]);
        a.sink = SinkKind::Kafka;
        a.brokers = vec!["localhost:9092".into()];
        a.topic = Some("rastreo.devices".into());
        let scenario = build_scenario(&a).expect("scenario");
        match scenario.base.sink {
            Some(SinkConfig::Kafka { brokers, topic, .. }) => {
                assert_eq!(brokers, vec!["localhost:9092".to_string()]);
                assert_eq!(topic, "rastreo.devices");
            }
            other => panic!("expected Kafka sink, got {other:?}"),
        }
    }
}
