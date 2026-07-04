use std::net::IpAddr;
#[cfg(feature = "config")]
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use ipnet::IpNet;
use rastreo_core::config::{BaseProbeConfig, DiscoverScenarioConfig};
#[cfg(feature = "config")]
use rastreo_core::config::{ScenarioEntry, ScenarioFile, ScenarioKind};
#[cfg(feature = "kafka")]
use rastreo_core::KafkaFlushMode;
use rastreo_core::{run_discovery_cancellable, ConfigError, ProberConfig, SinkConfig, Target};
use tokio::sync::watch;

const DEFAULT_CONCURRENCY: u32 = 64;
const DEFAULT_TIMEOUT_MS: u64 = 1000;

#[derive(Parser, Debug)]
pub struct DiscoverArgs {
    /// Target to probe. CIDR (10.0.0.0/24), single IP (10.0.0.1), range
    /// (10.0.0.1-10.0.0.5), or DNS name. Repeat to add multiple targets.
    #[cfg(feature = "config")]
    #[arg(long, num_args = 1.., required_unless_present = "file", conflicts_with = "file")]
    pub target: Vec<String>,

    /// Target to probe. CIDR (10.0.0.0/24), single IP (10.0.0.1), range
    /// (10.0.0.1-10.0.0.5), or DNS name. Repeat to add multiple targets.
    #[cfg(not(feature = "config"))]
    #[arg(long, num_args = 1.., required = true)]
    pub target: Vec<String>,

    /// Port to probe. Repeat or comma-separate for multiple.
    #[cfg(feature = "config")]
    #[arg(
        short,
        long,
        value_delimiter = ',',
        required_unless_present = "file",
        conflicts_with = "file"
    )]
    pub port: Vec<u16>,

    /// Port to probe. Repeat or comma-separate for multiple.
    #[cfg(not(feature = "config"))]
    #[arg(short, long, value_delimiter = ',', required = true)]
    pub port: Vec<u16>,

    /// YAML scenario file to load. When present, --target and --port are not permitted; each scenario in the file is executed in order.
    #[cfg(feature = "config")]
    #[arg(short = 'f', long)]
    pub file: Option<PathBuf>,

    /// Output sink kind. When --file is set and this flag is omitted, the sink from the YAML file is used.
    #[arg(long, value_enum)]
    pub sink: Option<SinkKind>,

    /// File path for --sink file.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Kafka brokers (comma-separated) for --sink kafka. Requires --features kafka build.
    #[arg(long, value_delimiter = ',')]
    pub brokers: Vec<String>,

    /// Kafka topic for --sink kafka.
    #[arg(long)]
    pub topic: Option<String>,

    /// Flush every DeviceRecord to Kafka as a separate message. Only meaningful with --sink kafka.
    #[cfg(feature = "kafka")]
    #[arg(long, conflicts_with = "kafka_batch_threshold")]
    pub kafka_flush_per_record: bool,

    /// Kafka batch threshold in bytes; records accumulate until the buffer reaches this size. Defaults to 65536 (64 KiB). Only meaningful with --sink kafka.
    #[cfg(feature = "kafka")]
    #[arg(long, value_parser = parse_positive_usize)]
    pub kafka_batch_threshold: Option<usize>,

    /// Max concurrent probes. Defaults to 64. With --file, overrides the YAML rate_limit.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    pub concurrency: Option<u32>,

    /// Per-probe timeout in milliseconds. Defaults to 1000. With --file, overrides the YAML timeout_ms.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout_ms: Option<u64>,
}

#[cfg(feature = "kafka")]
fn parse_positive_usize(s: &str) -> Result<usize, String> {
    let n: usize = s
        .parse()
        .map_err(|e| format!("not a non-negative integer: {e}"))?;
    if n == 0 {
        return Err("must be >= 1".into());
    }
    Ok(n)
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkKind {
    Stdout,
    File,
    #[cfg(feature = "kafka")]
    Kafka,
}

pub async fn run(args: DiscoverArgs, cancel: watch::Receiver<bool>) -> Result<()> {
    #[cfg(feature = "config")]
    if args.file.is_some() {
        return run_from_file(&args, cancel).await;
    }
    run_legacy(&args, cancel).await
}

async fn run_legacy(args: &DiscoverArgs, cancel: watch::Receiver<bool>) -> Result<()> {
    let scenario = build_scenario(args)?;
    let summary = run_discovery_cancellable(&scenario, cancel).await?;
    print_summary(&scenario, &summary);
    if !summary.cancelled && summary.records_emitted == 0 && summary.probe_attempts > 0 {
        eprintln!(
            "hint: 0 records emitted — no probe reached an open port. Check target reachability and port list."
        );
    }
    Ok(())
}

#[cfg(feature = "config")]
async fn run_from_file(args: &DiscoverArgs, cancel: watch::Receiver<bool>) -> Result<()> {
    let path = args.file.as_deref().expect("file present per dispatch");
    let file = load_scenario_file(path)?;

    if file.version != 1 {
        return Err(anyhow!(
            "unsupported scenario file version {}: only version 1 is supported",
            file.version
        ));
    }
    if file.kind != ScenarioKind::Discovery {
        return Err(anyhow!(
            "unsupported scenario kind: only 'discovery' is supported"
        ));
    }
    if file.scenarios.is_empty() {
        return Err(anyhow!(
            "scenario file '{}' has no scenarios",
            path.display()
        ));
    }

    let cli_sink = build_cli_sink_override(args)?;
    let total = file.scenarios.len();
    let mut errors = 0usize;

    for (idx, entry) in file.scenarios.into_iter().enumerate() {
        if *cancel.borrow() {
            eprintln!("cancelled before scenario {} of {total}", idx + 1);
            break;
        }
        let mut cfg = match entry {
            ScenarioEntry::Discover(cfg) => cfg,
            #[allow(unreachable_patterns)]
            _ => return Err(anyhow!("unsupported scenario entry variant")),
        };
        merge_defaults(&mut cfg.base, &file.defaults);
        apply_cli_overrides(&mut cfg.base, args, cli_sink.as_ref());

        let label = scenario_label(&cfg.base, idx, total);
        if idx > 0 {
            eprintln!();
        }
        eprintln!("running scenario {label}");

        if cfg.probers.is_empty() {
            eprintln!("scenario {label}: no probers configured, skipping");
            continue;
        }

        match run_discovery_cancellable(&cfg, cancel.clone()).await {
            Ok(summary) => {
                print_summary(&cfg, &summary);
            }
            Err(err) => {
                errors += 1;
                eprintln!("scenario {label} failed: {err:#}");
            }
        }
    }

    if errors == total {
        return Err(anyhow!(
            "all {total} scenario(s) failed; see individual errors above"
        ));
    }
    Ok(())
}

#[cfg(feature = "config")]
fn load_scenario_file(path: &Path) -> Result<ScenarioFile> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read scenario file '{}'", path.display()))?;
    serde_yaml_ng::from_str::<ScenarioFile>(&contents)
        .with_context(|| format!("failed to parse scenario file '{}'", path.display()))
}

#[cfg(feature = "config")]
fn merge_defaults(base: &mut BaseProbeConfig, defaults: &BaseProbeConfig) {
    if base.name.is_none() {
        base.name = defaults.name.clone();
    }
    if base.rate_limit.is_none() {
        base.rate_limit = defaults.rate_limit;
    }
    if base.timeout_ms.is_none() {
        base.timeout_ms = defaults.timeout_ms;
    }
    if base.encoder.is_none() {
        base.encoder = defaults.encoder.clone();
    }
    if base.fuser.is_none() {
        base.fuser = defaults.fuser.clone();
    }
    if base.sink.is_none() {
        base.sink = defaults.sink.clone();
    }
}

#[cfg(feature = "config")]
fn apply_cli_overrides(
    base: &mut BaseProbeConfig,
    args: &DiscoverArgs,
    cli_sink: Option<&SinkConfig>,
) {
    if let Some(c) = args.concurrency {
        base.rate_limit = Some(c);
    }
    if let Some(t) = args.timeout_ms {
        base.timeout_ms = Some(t);
    }
    if let Some(sink) = cli_sink {
        base.sink = Some(sink.clone());
    }
}

#[cfg(feature = "config")]
fn build_cli_sink_override(args: &DiscoverArgs) -> Result<Option<SinkConfig>> {
    if args.sink.is_none() {
        return Ok(None);
    }
    Ok(Some(build_sink_config_for_kind(
        args.sink.expect("checked above"),
        args,
    )?))
}

#[cfg(feature = "config")]
fn scenario_label(base: &BaseProbeConfig, idx: usize, total: usize) -> String {
    match &base.name {
        Some(n) => format!("{} ({} of {total})", n, idx + 1),
        None => format!("{} of {total}", idx + 1),
    }
}

fn print_summary(scenario: &DiscoverScenarioConfig, summary: &rastreo_core::DiscoverySummary) {
    let status = if summary.cancelled {
        "cancelled"
    } else {
        "complete"
    };
    let prefix = match &scenario.base.name {
        Some(n) => format!("scenario '{n}' "),
        None => String::new(),
    };
    eprintln!(
        "{prefix}discovery {}: targets_resolved={} probe_attempts={} probe_errors={} records_emitted={} elapsed_ms={}",
        status,
        summary.targets_resolved,
        summary.probe_attempts,
        summary.probe_errors,
        summary.records_emitted,
        summary.elapsed.as_millis(),
    );
}

pub(crate) fn build_scenario(args: &DiscoverArgs) -> Result<DiscoverScenarioConfig> {
    let targets: Vec<Target> = args
        .target
        .iter()
        .map(|s| parse_target(s).with_context(|| format!("invalid --target {s:?}")))
        .collect::<Result<Vec<_>>>()?;

    let sink_kind = args.sink.unwrap_or(SinkKind::Stdout);
    let sink_config = build_sink_config_for_kind(sink_kind, args)?;

    let probers = vec![ProberConfig::TcpConnect {
        ports: args.port.clone(),
    }];

    let mut base = BaseProbeConfig::new();
    base.rate_limit = Some(args.concurrency.unwrap_or(DEFAULT_CONCURRENCY));
    base.timeout_ms = Some(args.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS));
    base.sink = Some(sink_config);

    Ok(DiscoverScenarioConfig::new(base, targets, probers))
}

fn build_sink_config_for_kind(kind: SinkKind, args: &DiscoverArgs) -> Result<SinkConfig> {
    match kind {
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
            let flush_mode = if args.kafka_flush_per_record {
                KafkaFlushMode::PerRecord
            } else if let Some(bytes) = args.kafka_batch_threshold {
                KafkaFlushMode::Batched {
                    threshold_bytes: bytes,
                }
            } else {
                KafkaFlushMode::default()
            };
            Ok(SinkConfig::Kafka {
                brokers: args.brokers.clone(),
                topic,
                flush_mode,
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
            #[cfg(feature = "config")]
            file: None,
            sink: None,
            output: None,
            brokers: Vec::new(),
            topic: None,
            #[cfg(feature = "kafka")]
            kafka_flush_per_record: false,
            #[cfg(feature = "kafka")]
            kafka_batch_threshold: None,
            concurrency: None,
            timeout_ms: None,
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
        a.sink = Some(SinkKind::File);
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
        a.sink = Some(SinkKind::File);
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
    fn build_scenario_uses_defaults_when_flags_unset() {
        let a = args(&["10.0.0.1"], &[80]);
        let scenario = build_scenario(&a).expect("scenario");
        assert_eq!(scenario.base.rate_limit, Some(DEFAULT_CONCURRENCY));
        assert_eq!(scenario.base.timeout_ms, Some(DEFAULT_TIMEOUT_MS));
    }

    #[test]
    fn build_scenario_uses_flag_values_when_set() {
        let mut a = args(&["10.0.0.1"], &[80]);
        a.concurrency = Some(8);
        a.timeout_ms = Some(200);
        let scenario = build_scenario(&a).expect("scenario");
        assert_eq!(scenario.base.rate_limit, Some(8));
        assert_eq!(scenario.base.timeout_ms, Some(200));
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
        assert_eq!(parsed.concurrency, Some(1));
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
        assert_eq!(parsed.timeout_ms, Some(1));
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_accepts_file_flag_without_target_or_port() {
        let parsed =
            DiscoverArgs::try_parse_from(["discover", "--file", "/tmp/x.yml"]).expect("parses");
        assert_eq!(parsed.file, Some(PathBuf::from("/tmp/x.yml")));
        assert!(parsed.target.is_empty());
        assert!(parsed.port.is_empty());
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_accepts_short_f_flag() {
        let parsed =
            DiscoverArgs::try_parse_from(["discover", "-f", "/tmp/x.yml"]).expect("parses");
        assert_eq!(parsed.file, Some(PathBuf::from("/tmp/x.yml")));
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_rejects_file_and_target_together() {
        let result = DiscoverArgs::try_parse_from([
            "discover",
            "--file",
            "/tmp/x.yml",
            "--target",
            "127.0.0.1",
        ]);
        assert!(result.is_err(), "expected --file + --target to be rejected");
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_rejects_file_and_port_together() {
        let result =
            DiscoverArgs::try_parse_from(["discover", "--file", "/tmp/x.yml", "--port", "80"]);
        assert!(result.is_err(), "expected --file + --port to be rejected");
    }

    #[test]
    fn parse_rejects_neither_file_nor_target() {
        let result = DiscoverArgs::try_parse_from(["discover"]);
        assert!(
            result.is_err(),
            "expected discover without --file or --target to be rejected"
        );
    }

    #[cfg(feature = "config")]
    #[test]
    fn merge_defaults_takes_scenario_field_when_present() {
        let mut base = BaseProbeConfig::new();
        base.rate_limit = Some(10);
        base.timeout_ms = Some(500);
        let mut defaults = BaseProbeConfig::new();
        defaults.rate_limit = Some(999);
        defaults.timeout_ms = Some(9999);
        merge_defaults(&mut base, &defaults);
        assert_eq!(base.rate_limit, Some(10));
        assert_eq!(base.timeout_ms, Some(500));
    }

    #[cfg(feature = "config")]
    #[test]
    fn merge_defaults_falls_back_to_file_defaults_when_scenario_field_missing() {
        let mut base = BaseProbeConfig::new();
        let mut defaults = BaseProbeConfig::new();
        defaults.name = Some("lab".into());
        defaults.rate_limit = Some(32);
        defaults.timeout_ms = Some(750);
        defaults.sink = Some(SinkConfig::Stdout);
        merge_defaults(&mut base, &defaults);
        assert_eq!(base.name.as_deref(), Some("lab"));
        assert_eq!(base.rate_limit, Some(32));
        assert_eq!(base.timeout_ms, Some(750));
        assert!(matches!(base.sink, Some(SinkConfig::Stdout)));
    }

    #[cfg(feature = "config")]
    #[test]
    fn apply_cli_overrides_sets_only_provided_fields() {
        let mut base = BaseProbeConfig::new();
        base.rate_limit = Some(1);
        base.timeout_ms = Some(2);
        base.sink = Some(SinkConfig::Stdout);
        let mut a = args(&[], &[]);
        a.concurrency = Some(99);
        apply_cli_overrides(&mut base, &a, None);
        assert_eq!(base.rate_limit, Some(99));
        assert_eq!(base.timeout_ms, Some(2));
        assert!(matches!(base.sink, Some(SinkConfig::Stdout)));
    }

    #[cfg(feature = "config")]
    #[test]
    fn apply_cli_overrides_replaces_sink_when_provided() {
        let mut base = BaseProbeConfig::new();
        base.sink = Some(SinkConfig::Stdout);
        let a = args(&[], &[]);
        let new_sink = SinkConfig::File {
            path: PathBuf::from("/tmp/out.ndjson"),
        };
        apply_cli_overrides(&mut base, &a, Some(&new_sink));
        match &base.sink {
            Some(SinkConfig::File { path }) => assert_eq!(path, &PathBuf::from("/tmp/out.ndjson")),
            other => panic!("expected File sink, got {other:?}"),
        }
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn build_scenario_kafka_requires_brokers() {
        let mut a = args(&["10.0.0.1"], &[80]);
        a.sink = Some(SinkKind::Kafka);
        a.brokers = Vec::new();
        a.topic = Some("rastreo.devices".into());
        let err = build_scenario(&a).expect_err("missing brokers");
        assert!(format!("{err}").contains("--brokers"));
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn build_scenario_kafka_requires_topic() {
        let mut a = args(&["10.0.0.1"], &[80]);
        a.sink = Some(SinkKind::Kafka);
        a.brokers = vec!["localhost:9092".into()];
        a.topic = None;
        let err = build_scenario(&a).expect_err("missing topic");
        assert!(format!("{err}").contains("--topic"));
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn build_scenario_kafka_with_brokers_and_topic_produces_kafka_sink() {
        let mut a = args(&["10.0.0.1"], &[80]);
        a.sink = Some(SinkKind::Kafka);
        a.brokers = vec!["localhost:9092".into()];
        a.topic = Some("rastreo.devices".into());
        let scenario = build_scenario(&a).expect("scenario");
        match scenario.base.sink {
            Some(SinkConfig::Kafka {
                brokers,
                topic,
                flush_mode,
            }) => {
                assert_eq!(brokers, vec!["localhost:9092".to_string()]);
                assert_eq!(topic, "rastreo.devices");
                assert!(matches!(
                    flush_mode,
                    KafkaFlushMode::Batched {
                        threshold_bytes: 65536
                    }
                ));
            }
            other => panic!("expected Kafka sink, got {other:?}"),
        }
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn build_scenario_kafka_flush_per_record_sets_per_record_mode() {
        let mut a = args(&["10.0.0.1"], &[80]);
        a.sink = Some(SinkKind::Kafka);
        a.brokers = vec!["localhost:9092".into()];
        a.topic = Some("t".into());
        a.kafka_flush_per_record = true;
        let scenario = build_scenario(&a).expect("scenario");
        match scenario.base.sink {
            Some(SinkConfig::Kafka { flush_mode, .. }) => {
                assert!(matches!(flush_mode, KafkaFlushMode::PerRecord));
            }
            other => panic!("expected Kafka sink, got {other:?}"),
        }
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn build_scenario_kafka_batch_threshold_sets_batched_mode() {
        let mut a = args(&["10.0.0.1"], &[80]);
        a.sink = Some(SinkKind::Kafka);
        a.brokers = vec!["localhost:9092".into()];
        a.topic = Some("t".into());
        a.kafka_batch_threshold = Some(16384);
        let scenario = build_scenario(&a).expect("scenario");
        match scenario.base.sink {
            Some(SinkConfig::Kafka { flush_mode, .. }) => match flush_mode {
                KafkaFlushMode::Batched { threshold_bytes } => {
                    assert_eq!(threshold_bytes, 16384);
                }
                other => panic!("expected Batched, got {other:?}"),
            },
            other => panic!("expected Kafka sink, got {other:?}"),
        }
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn build_scenario_kafka_default_uses_batched_64_kib() {
        let mut a = args(&["10.0.0.1"], &[80]);
        a.sink = Some(SinkKind::Kafka);
        a.brokers = vec!["localhost:9092".into()];
        a.topic = Some("t".into());
        let scenario = build_scenario(&a).expect("scenario");
        match scenario.base.sink {
            Some(SinkConfig::Kafka { flush_mode, .. }) => match flush_mode {
                KafkaFlushMode::Batched { threshold_bytes } => {
                    assert_eq!(threshold_bytes, 65536);
                }
                other => panic!("expected Batched default, got {other:?}"),
            },
            other => panic!("expected Kafka sink, got {other:?}"),
        }
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn discover_rejects_kafka_flush_per_record_with_batch_threshold() {
        let result = DiscoverArgs::try_parse_from([
            "discover",
            "--target",
            "127.0.0.1",
            "--port",
            "80",
            "--sink",
            "kafka",
            "--brokers",
            "localhost:9092",
            "--topic",
            "t",
            "--kafka-flush-per-record",
            "--kafka-batch-threshold",
            "1024",
        ]);
        assert!(
            result.is_err(),
            "expected --kafka-flush-per-record + --kafka-batch-threshold to be rejected"
        );
    }
}
