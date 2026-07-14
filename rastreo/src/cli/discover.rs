use std::net::IpAddr;
#[cfg(feature = "config")]
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use ipnet::IpNet;
#[cfg(feature = "config")]
use rastreo_core::config::{parse_scenario_file, ScenarioEntry, ScenarioFile, ScenarioKind};
use rastreo_core::config::{BaseProbeConfig, DiscoverScenarioConfig, MAX_RETRIES};
#[cfg(feature = "kafka")]
use rastreo_core::KafkaFlushMode;
#[cfg(feature = "config")]
use rastreo_core::Resolver;
use rastreo_core::{
    hint_for_error_kind, resolve_scenario_targets, run_discovery_cancellable, ConfigError,
    DiscoveryPlan, HickoryResolver, PlanKnobs, ProberConfig, ResolvedScenarioTarget, SinkConfig,
    Target,
};
use tokio::sync::watch;

const DEFAULT_CONCURRENCY: u32 = 64;
const DEFAULT_TIMEOUT_MS: u64 = 1000;

#[derive(Parser, Debug)]
pub struct DiscoverArgs {
    /// Target to probe. CIDR (10.0.0.0/24), single IP (10.0.0.1), range
    /// (10.0.0.1-10.0.0.5), or DNS name. Repeat to add multiple targets.
    #[cfg_attr(
        feature = "config",
        arg(long, num_args = 1.., required_unless_present = "file", conflicts_with = "file")
    )]
    #[cfg_attr(not(feature = "config"), arg(long, num_args = 1.., required = true))]
    pub target: Vec<String>,

    /// Port to probe. Repeat or comma-separate for multiple.
    #[cfg_attr(
        feature = "config",
        arg(
            short,
            long,
            value_delimiter = ',',
            required_unless_present = "file",
            conflicts_with = "file"
        )
    )]
    #[cfg_attr(
        not(feature = "config"),
        arg(short, long, value_delimiter = ',', required = true)
    )]
    pub port: Vec<u16>,

    /// YAML scenario file to load, or `@name` to resolve a scenario from the catalog
    /// directories (see the CLI docs for search order). When present, --target and
    /// --port are not permitted; each scenario in the file is executed in order.
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

    /// Max probes in flight at once. Defaults to 64. With --file, overrides the YAML max_concurrent.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    pub concurrency: Option<u32>,

    /// Max probes started per second. Unset means no rate limit. With --file, overrides the YAML probe_rate.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    pub rate: Option<u32>,

    /// Retransmit attempts for connectionless probers (UDP, SNMP, DNS); 0 = single-shot. With --file, overrides the YAML `retries`.
    #[arg(long, value_parser = clap::value_parser!(u32).range(0..=MAX_RETRIES as i64))]
    pub retries: Option<u32>,

    /// Per-probe timeout in milliseconds. Defaults to 1000. With --file, overrides the YAML timeout_ms.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout_ms: Option<u64>,

    /// Print what would run without executing any probe or opening any sink. Targets are still resolved (DNS lookups execute) so operators see the expanded plan.
    #[arg(long)]
    pub dry_run: bool,
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
    if args.dry_run {
        return run_dry_run(&args).await;
    }
    #[cfg(feature = "config")]
    if args.file.is_some() {
        return run_from_file(&args, cancel).await;
    }
    run_legacy(&args, cancel).await
}

async fn run_dry_run(args: &DiscoverArgs) -> Result<()> {
    let resolver = HickoryResolver::from_system()?;

    #[cfg(feature = "config")]
    if args.file.is_some() {
        return run_dry_run_from_file(args, &resolver).await;
    }

    let scenario = build_scenario(args)?;
    let resolutions = resolve_scenario_targets(&scenario, &resolver).await;
    let mut out = String::new();
    write_dry_run_header(&mut out, 1);
    let total_probes = write_scenario_plan(&mut out, "discovery", &scenario, &resolutions, args);
    write_totals(&mut out, 1, total_probes);
    print!("{out}");
    dry_run_exit_status(&[resolutions])
}

#[cfg(feature = "config")]
async fn run_dry_run_from_file(args: &DiscoverArgs, resolver: &dyn Resolver) -> Result<()> {
    let raw = args.file.as_deref().expect("file present per dispatch");
    let path = resolve_scenario_source(raw)?;
    let file = load_scenario_file(&path)?;

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

    let mut scenarios: Vec<(String, DiscoverScenarioConfig)> = Vec::with_capacity(total);
    for (idx, entry) in file.scenarios.into_iter().enumerate() {
        let mut cfg = match entry {
            ScenarioEntry::Discover(cfg) => cfg,
            #[allow(unreachable_patterns)]
            _ => return Err(anyhow!("unsupported scenario entry variant")),
        };
        merge_defaults(&mut cfg.base, &file.defaults);
        apply_cli_overrides(&mut cfg.base, args, cli_sink.as_ref());
        let label = dry_run_scenario_label(&cfg.base, idx, total);
        scenarios.push((label, cfg));
    }

    let mut out = String::new();
    let mut total_probes: usize = 0;
    let mut all_resolutions: Vec<Vec<ResolvedScenarioTarget>> = Vec::with_capacity(scenarios.len());
    write_dry_run_header(&mut out, scenarios.len());
    for (label, scenario) in &scenarios {
        let resolutions = resolve_scenario_targets(scenario, resolver).await;
        let scenario_probes = write_scenario_plan(&mut out, label, scenario, &resolutions, args);
        total_probes += scenario_probes;
        all_resolutions.push(resolutions);
    }
    write_totals(&mut out, scenarios.len(), total_probes);
    print!("{out}");
    dry_run_exit_status(&all_resolutions)
}

#[cfg(feature = "config")]
fn dry_run_scenario_label(base: &BaseProbeConfig, idx: usize, total: usize) -> String {
    match &base.name {
        Some(n) => format!("'{n}' ({} of {total})", idx + 1),
        None => format!("{} of {total}", idx + 1),
    }
}

fn write_dry_run_header(out: &mut String, scenario_count: usize) {
    use std::fmt::Write as _;
    let noun = if scenario_count == 1 {
        "scenario"
    } else {
        "scenarios"
    };
    writeln!(out, "[dry-run] would run {scenario_count} {noun}").expect("write to String");
}

fn effective_knobs(scenario: &DiscoverScenarioConfig, args: &DiscoverArgs) -> PlanKnobs {
    PlanKnobs {
        max_concurrent: scenario
            .base
            .max_concurrent
            .unwrap_or_else(|| args.concurrency.unwrap_or(DEFAULT_CONCURRENCY)),
        probe_rate: scenario.base.probe_rate.or(args.rate),
        retries: scenario.base.retries.or(args.retries).unwrap_or(0),
        timeout_ms: scenario
            .base
            .timeout_ms
            .unwrap_or_else(|| args.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
    }
}

fn write_scenario_plan(
    out: &mut String,
    label: &str,
    scenario: &DiscoverScenarioConfig,
    resolutions: &[ResolvedScenarioTarget],
    args: &DiscoverArgs,
) -> usize {
    use std::fmt::Write as _;
    let plan = DiscoveryPlan::new(
        label.to_string(),
        scenario,
        resolutions,
        effective_knobs(scenario, args),
    );
    write!(out, "{plan}").expect("write to String");
    plan.total_probes
}

fn write_totals(out: &mut String, _scenario_count: usize, total_probes: usize) {
    use std::fmt::Write as _;
    writeln!(out, "total probes: {total_probes}").expect("write to String");
}

fn dry_run_exit_status(all: &[Vec<ResolvedScenarioTarget>]) -> Result<()> {
    let mut had_any = false;
    let mut had_success = false;
    for scenario in all {
        for entry in scenario {
            had_any = true;
            if entry.result.is_ok() {
                had_success = true;
            }
        }
    }
    if had_any && !had_success {
        return Err(anyhow!(
            "no targets resolved successfully — nothing would probe"
        ));
    }
    Ok(())
}

async fn run_legacy(args: &DiscoverArgs, cancel: watch::Receiver<bool>) -> Result<()> {
    let scenario = build_scenario(args)?;
    match run_discovery_cancellable(&scenario, cancel).await {
        Ok(summary) => {
            print_summary("discovery", &summary);
            print_runtime_hints(&summary);
            Ok(())
        }
        Err(err) => {
            if let Some(hint) = enrich_scan_error_hint(&err.to_string()) {
                eprintln!("hint: {hint}");
            }
            Err(err.into())
        }
    }
}

#[cfg(feature = "config")]
async fn run_from_file(args: &DiscoverArgs, cancel: watch::Receiver<bool>) -> Result<()> {
    let raw = args.file.as_deref().expect("file present per dispatch");
    let path = resolve_scenario_source(raw)?;
    let file = load_scenario_file(&path)?;

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
        eprintln!("running {label}");

        if cfg.probers.is_empty() {
            eprintln!("{label}: no probers configured, skipping");
            continue;
        }

        match run_discovery_cancellable(&cfg, cancel.clone()).await {
            Ok(summary) => {
                print_summary(&label, &summary);
                print_runtime_hints(&summary);
            }
            Err(err) => {
                errors += 1;
                eprintln!("{label} failed: {err:#}");
                if let Some(hint) = enrich_scan_error_hint(&err.to_string()) {
                    eprintln!("hint: {hint}");
                }
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
fn resolve_scenario_source(input: &Path) -> Result<PathBuf> {
    let as_str = input.to_string_lossy();
    if let Some(name) = as_str.strip_prefix('@') {
        return super::catalog::resolve_catalog_name(name);
    }
    Ok(input.to_path_buf())
}

#[cfg(feature = "config")]
fn load_scenario_file(path: &Path) -> Result<ScenarioFile> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read scenario file '{}'", path.display()))?;
    match parse_scenario_file(&contents) {
        Ok(file) => Ok(file),
        Err(err) => {
            if let Some(hint) = enrich_feature_hint(&err.to_string()) {
                eprintln!("hint: {hint}");
            }
            Err(anyhow::Error::new(err).context(format!(
                "failed to parse scenario file '{}'",
                path.display()
            )))
        }
    }
}

#[cfg(feature = "config")]
const FEATURE_GATED_VARIANTS: &[(&str, &str)] = &[
    ("http", "http"),
    ("snmp", "snmp"),
    ("arp", "arp"),
    ("ndp", "ndp"),
    ("ssh", "ssh"),
    ("icmp", "icmp"),
    ("tls", "tls"),
    ("oui_enrichment", "oui"),
];

#[cfg(feature = "config")]
const RELEASE_BUNDLED_FEATURES: &str = "kafka, http, snmp, arp, ndp, oui, nats, ssh, icmp, tls";

// Resolver / sink errors abort the whole scan and are not kinded, so they hint by string match.
const SCAN_ERROR_HINT_PATTERNS: &[(&str, &str)] = &[
    (
        "nxdomain",
        "DNS resolution failed for the target. Check the resolver configuration or the target's hostname.",
    ),
    (
        "dns lookup failed",
        "DNS resolution failed for the target. Check the resolver configuration or the target's hostname.",
    ),
    (
        "no records found",
        "DNS resolution failed for the target. Check the resolver configuration or the target's hostname.",
    ),
];

fn enrich_scan_error_hint(error_msg: &str) -> Option<String> {
    let lower = error_msg.to_lowercase();
    SCAN_ERROR_HINT_PATTERNS
        .iter()
        .find(|(needle, _)| lower.contains(needle))
        .map(|(_, hint)| (*hint).to_string())
}

fn runtime_probe_hint(summary: &rastreo_core::DiscoverySummary) -> Option<&'static str> {
    summary
        .first_probe_error
        .as_ref()
        .and_then(|fault| hint_for_error_kind(fault.kind))
}

const ZERO_RECORDS_HINT: &str =
    "0 records emitted — no probe reached an open port. Check target reachability and port list.";

fn runtime_hint_line(summary: &rastreo_core::DiscoverySummary) -> Option<String> {
    if summary.cancelled {
        return None;
    }
    if summary.first_probe_error.is_some() {
        return runtime_probe_hint(summary).map(str::to_string);
    }
    if summary.records_emitted == 0 && summary.probe_attempts > 0 {
        return Some(ZERO_RECORDS_HINT.to_string());
    }
    None
}

fn print_runtime_hints(summary: &rastreo_core::DiscoverySummary) {
    if let Some(hint) = runtime_hint_line(summary) {
        eprintln!("hint: {hint}");
    }
}

#[cfg(feature = "config")]
fn enrich_feature_hint(error_msg: &str) -> Option<String> {
    const NEEDLE: &str = "unknown variant `";
    let start = error_msg.find(NEEDLE)? + NEEDLE.len();
    let rest = &error_msg[start..];
    let end = rest.find('`')?;
    let variant = &rest[..end];
    let feature = FEATURE_GATED_VARIANTS
        .iter()
        .find(|(name, _)| *name == variant)
        .map(|(_, feat)| *feat)?;
    Some(format!(
        "'{variant}' requires the '{feature}' Cargo feature. Rebuild with --features {feature} or use the release Docker image which bundles {RELEASE_BUNDLED_FEATURES}."
    ))
}

#[cfg(feature = "config")]
fn merge_defaults(base: &mut BaseProbeConfig, defaults: &BaseProbeConfig) {
    if base.name.is_none() {
        base.name = defaults.name.clone();
    }
    if base.max_concurrent.is_none() {
        base.max_concurrent = defaults.max_concurrent;
    }
    if base.probe_rate.is_none() {
        base.probe_rate = defaults.probe_rate;
    }
    if base.retries.is_none() {
        base.retries = defaults.retries;
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
    if base.classifier.is_none() {
        base.classifier = defaults.classifier.clone();
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
        base.max_concurrent = Some(c);
    }
    if let Some(r) = args.rate {
        base.probe_rate = Some(r);
    }
    if let Some(r) = args.retries {
        base.retries = Some(r);
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
        Some(n) => format!("scenario '{n}' ({} of {total})", idx + 1),
        None => format!("scenario {} of {total}", idx + 1),
    }
}

fn print_summary(label: &str, summary: &rastreo_core::DiscoverySummary) {
    let status = if summary.cancelled {
        "cancelled"
    } else {
        "complete"
    };
    let probe_errors: usize = summary.error_counts.values().sum();
    eprintln!(
        "{label} {}: targets_resolved={} probe_attempts={} probe_errors={} records_emitted={} elapsed_ms={}",
        status,
        summary.targets_resolved,
        summary.probe_attempts,
        probe_errors,
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
    base.max_concurrent = Some(args.concurrency.unwrap_or(DEFAULT_CONCURRENCY));
    base.probe_rate = args.rate;
    base.retries = args.retries;
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
                dead_letter: None,
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
            rate: None,
            retries: None,
            timeout_ms: None,
            dry_run: false,
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
        assert_eq!(scenario.base.max_concurrent, Some(64));
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
        assert_eq!(scenario.base.max_concurrent, Some(DEFAULT_CONCURRENCY));
        assert_eq!(scenario.base.probe_rate, None);
        assert_eq!(scenario.base.timeout_ms, Some(DEFAULT_TIMEOUT_MS));
    }

    #[test]
    fn build_scenario_uses_flag_values_when_set() {
        let mut a = args(&["10.0.0.1"], &[80]);
        a.concurrency = Some(8);
        a.rate = Some(20);
        a.timeout_ms = Some(200);
        let scenario = build_scenario(&a).expect("scenario");
        assert_eq!(scenario.base.max_concurrent, Some(8));
        assert_eq!(scenario.base.probe_rate, Some(20));
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
    fn discover_accepts_rate_flag() {
        let parsed = DiscoverArgs::try_parse_from([
            "discover",
            "--target",
            "127.0.0.1",
            "--port",
            "80",
            "--rate",
            "50",
        ])
        .expect("--rate 50 should parse");
        assert_eq!(parsed.rate, Some(50));
    }

    #[test]
    fn discover_accepts_retries_flag() {
        let parsed = DiscoverArgs::try_parse_from([
            "discover",
            "--target",
            "127.0.0.1",
            "--port",
            "80",
            "--retries",
            "2",
        ])
        .expect("--retries 2 should parse");
        assert_eq!(parsed.retries, Some(2));
    }

    #[test]
    fn discover_accepts_retries_at_max() {
        let max = MAX_RETRIES.to_string();
        let parsed = DiscoverArgs::try_parse_from([
            "discover",
            "--target",
            "127.0.0.1",
            "--port",
            "80",
            "--retries",
            max.as_str(),
        ])
        .expect("--retries at the max should parse");
        assert_eq!(parsed.retries, Some(MAX_RETRIES));
    }

    #[test]
    fn discover_rejects_retries_over_max() {
        let result = DiscoverArgs::try_parse_from([
            "discover",
            "--target",
            "127.0.0.1",
            "--port",
            "80",
            "--retries",
            "99999",
        ]);
        assert!(
            result.is_err(),
            "expected --retries over the max to be rejected"
        );
    }

    #[test]
    fn build_scenario_threads_retries_flag() {
        let mut a = args(&["10.0.0.1"], &[80]);
        a.retries = Some(3);
        let scenario = build_scenario(&a).expect("scenario");
        assert_eq!(scenario.base.retries, Some(3));
    }

    #[test]
    fn build_scenario_leaves_retries_unset_by_default() {
        let a = args(&["10.0.0.1"], &[80]);
        let scenario = build_scenario(&a).expect("scenario");
        assert_eq!(scenario.base.retries, None);
    }

    #[test]
    fn discover_rejects_rate_zero() {
        let result = DiscoverArgs::try_parse_from([
            "discover",
            "--target",
            "127.0.0.1",
            "--port",
            "80",
            "--rate",
            "0",
        ]);
        assert!(result.is_err(), "expected --rate 0 to be rejected");
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
        base.max_concurrent = Some(10);
        base.probe_rate = Some(30);
        base.timeout_ms = Some(500);
        let mut defaults = BaseProbeConfig::new();
        defaults.max_concurrent = Some(999);
        defaults.probe_rate = Some(9);
        defaults.timeout_ms = Some(9999);
        merge_defaults(&mut base, &defaults);
        assert_eq!(base.max_concurrent, Some(10));
        assert_eq!(base.probe_rate, Some(30));
        assert_eq!(base.timeout_ms, Some(500));
    }

    #[cfg(feature = "config")]
    #[test]
    fn merge_defaults_falls_back_to_file_defaults_when_scenario_field_missing() {
        let mut base = BaseProbeConfig::new();
        let mut defaults = BaseProbeConfig::new();
        defaults.name = Some("lab".into());
        defaults.max_concurrent = Some(32);
        defaults.probe_rate = Some(100);
        defaults.timeout_ms = Some(750);
        defaults.sink = Some(SinkConfig::Stdout);
        defaults.classifier = Some(rastreo_core::ClassifierConfig::Noop);
        merge_defaults(&mut base, &defaults);
        assert_eq!(base.name.as_deref(), Some("lab"));
        assert_eq!(base.max_concurrent, Some(32));
        assert_eq!(base.probe_rate, Some(100));
        assert_eq!(base.timeout_ms, Some(750));
        assert!(matches!(base.sink, Some(SinkConfig::Stdout)));
        assert!(matches!(
            base.classifier,
            Some(rastreo_core::ClassifierConfig::Noop)
        ));
    }

    #[cfg(feature = "config")]
    #[test]
    fn apply_cli_overrides_sets_only_provided_fields() {
        let mut base = BaseProbeConfig::new();
        base.max_concurrent = Some(1);
        base.timeout_ms = Some(2);
        base.sink = Some(SinkConfig::Stdout);
        let mut a = args(&[], &[]);
        a.concurrency = Some(99);
        apply_cli_overrides(&mut base, &a, None);
        assert_eq!(base.max_concurrent, Some(99));
        assert_eq!(base.probe_rate, None);
        assert_eq!(base.timeout_ms, Some(2));
        assert!(matches!(base.sink, Some(SinkConfig::Stdout)));
    }

    #[cfg(feature = "config")]
    #[test]
    fn apply_cli_overrides_sets_probe_rate_from_rate_flag() {
        let mut base = BaseProbeConfig::new();
        base.probe_rate = Some(5);
        let mut a = args(&[], &[]);
        a.rate = Some(200);
        apply_cli_overrides(&mut base, &a, None);
        assert_eq!(base.probe_rate, Some(200));
    }

    #[cfg(feature = "config")]
    #[test]
    fn apply_cli_overrides_sets_retries_from_retries_flag() {
        let mut base = BaseProbeConfig::new();
        base.retries = Some(1);
        let mut a = args(&[], &[]);
        a.retries = Some(4);
        apply_cli_overrides(&mut base, &a, None);
        assert_eq!(base.retries, Some(4));
    }

    #[cfg(feature = "config")]
    #[test]
    fn merge_defaults_falls_back_to_file_retries_when_scenario_field_missing() {
        let mut base = BaseProbeConfig::new();
        let mut defaults = BaseProbeConfig::new();
        defaults.retries = Some(2);
        merge_defaults(&mut base, &defaults);
        assert_eq!(base.retries, Some(2));
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
                ..
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

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_matches_http_variant() {
        let msg = "scenarios: unknown variant `http`, expected one of `tcp_connect`, `dns` at line 4 column 3";
        let hint = enrich_feature_hint(msg).expect("hint");
        assert!(hint.contains("--features http"), "hint: {hint}");
        assert!(hint.contains("'http'"), "hint: {hint}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_matches_snmp_variant() {
        let msg = "unknown variant `snmp`, expected one of `tcp_connect`";
        let hint = enrich_feature_hint(msg).expect("hint");
        assert!(hint.contains("--features snmp"), "hint: {hint}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_matches_arp_variant() {
        let hint = enrich_feature_hint("unknown variant `arp`, expected one of ...").expect("hint");
        assert!(hint.contains("--features arp"), "hint: {hint}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_matches_ndp_variant() {
        let hint = enrich_feature_hint("unknown variant `ndp`, expected one of ...").expect("hint");
        assert!(hint.contains("--features ndp"), "hint: {hint}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_matches_ssh_variant() {
        let hint = enrich_feature_hint("unknown variant `ssh`, expected one of ...").expect("hint");
        assert!(hint.contains("--features ssh"), "hint: {hint}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_matches_icmp_variant() {
        let hint =
            enrich_feature_hint("unknown variant `icmp`, expected one of ...").expect("hint");
        assert!(hint.contains("--features icmp"), "hint: {hint}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_matches_tls_variant() {
        let hint = enrich_feature_hint("unknown variant `tls`, expected one of ...").expect("hint");
        assert!(hint.contains("--features tls"), "hint: {hint}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_names_current_bundled_release_features() {
        let hint = enrich_feature_hint("unknown variant `ssh`, expected one of ...").expect("hint");
        for feat in [
            "kafka", "http", "snmp", "arp", "ndp", "oui", "nats", "ssh", "icmp", "tls",
        ] {
            assert!(hint.contains(feat), "hint missing '{feat}': {hint}");
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_maps_oui_enrichment_variant_to_oui_feature() {
        let hint =
            enrich_feature_hint("unknown variant `oui_enrichment`, expected one of `direct`")
                .expect("hint");
        assert!(hint.contains("--features oui"), "hint: {hint}");
        assert!(hint.contains("'oui_enrichment'"), "hint: {hint}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_does_not_fire_for_typo_variant() {
        let msg = "unknown variant `htttp`, expected one of `tcp_connect`";
        assert!(enrich_feature_hint(msg).is_none());
    }

    #[cfg(feature = "config")]
    #[test]
    fn enrich_feature_hint_does_not_fire_when_no_unknown_variant_marker() {
        assert!(enrich_feature_hint("missing field `targets`").is_none());
    }

    #[cfg(feature = "config")]
    #[test]
    fn scenario_label_named_scenario_uses_quoted_name_and_index() {
        let mut base = BaseProbeConfig::new();
        base.name = Some("first".into());
        assert_eq!(scenario_label(&base, 0, 2), "scenario 'first' (1 of 2)");
    }

    #[cfg(feature = "config")]
    #[test]
    fn scenario_label_unnamed_scenario_uses_bare_index() {
        let base = BaseProbeConfig::new();
        assert_eq!(scenario_label(&base, 1, 3), "scenario 2 of 3");
    }

    #[test]
    fn parse_accepts_dry_run_flag() {
        let parsed = DiscoverArgs::try_parse_from([
            "discover",
            "--target",
            "127.0.0.1",
            "--port",
            "22",
            "--dry-run",
        ])
        .expect("parses");
        assert!(parsed.dry_run);
    }

    #[test]
    fn parse_dry_run_defaults_to_false() {
        let parsed =
            DiscoverArgs::try_parse_from(["discover", "--target", "127.0.0.1", "--port", "22"])
                .expect("parses");
        assert!(!parsed.dry_run);
    }

    #[tokio::test]
    async fn dry_run_flag_driven_prints_plan_and_exits_ok() {
        let mut a = args(&["127.0.0.1"], &[22, 80]);
        a.dry_run = true;
        let scenario = build_scenario(&a).expect("scenario");
        let resolver = HickoryResolver::from_system().expect("resolver");
        let resolutions = resolve_scenario_targets(&scenario, &resolver).await;
        let mut out = String::new();
        write_dry_run_header(&mut out, 1);
        let probes = write_scenario_plan(&mut out, "discovery", &scenario, &resolutions, &a);
        write_totals(&mut out, 1, probes);
        assert_eq!(probes, 1, "1 IP × 1 prober = 1 probe");
        assert!(out.contains("[dry-run] would run 1 scenario"), "{out}");
        assert!(!out.contains("0 probes will execute"), "{out}");
        assert!(out.contains("targets:"), "{out}");
        assert!(out.contains("127.0.0.1 → 127.0.0.1"), "{out}");
        assert!(out.contains("tcp_connect (ports 22, 80)"), "{out}");
        assert!(out.contains("sink: stdout"), "{out}");
        assert!(out.contains("concurrency: 64"), "{out}");
        assert!(out.contains("rate: unlimited"), "{out}");
        assert!(out.contains("timeout_ms: 1000"), "{out}");
        assert!(
            out.contains("total probes: 1"),
            "single-scenario prints total: {out}"
        );
        dry_run_exit_status(&[resolutions]).expect("exit ok");
    }

    #[tokio::test]
    async fn dry_run_shows_rate_per_second_when_rate_flag_set() {
        let mut a = args(&["127.0.0.1"], &[22]);
        a.dry_run = true;
        a.rate = Some(25);
        let scenario = build_scenario(&a).expect("scenario");
        let resolver = HickoryResolver::from_system().expect("resolver");
        let resolutions = resolve_scenario_targets(&scenario, &resolver).await;
        let mut out = String::new();
        write_scenario_plan(&mut out, "s", &scenario, &resolutions, &a);
        assert!(out.contains("rate: 25/sec"), "{out}");
    }

    #[tokio::test]
    async fn dry_run_cidr_expansion_below_cutoff_lists_all_addresses() {
        let mut a = args(&["10.0.0.0/29"], &[22]);
        a.dry_run = true;
        let scenario = build_scenario(&a).expect("scenario");
        let resolver = HickoryResolver::from_system().expect("resolver");
        let resolutions = resolve_scenario_targets(&scenario, &resolver).await;
        let mut out = String::new();
        write_scenario_plan(&mut out, "s", &scenario, &resolutions, &a);
        assert!(out.contains("10.0.0.1"), "{out}");
        assert!(out.contains("10.0.0.6"), "{out}");
        assert!(!out.contains("..."), "no ellipsis under cutoff: {out}");
    }

    #[tokio::test]
    async fn dry_run_cidr_expansion_above_cutoff_uses_ellipsis_with_count() {
        let mut a = args(&["10.0.0.0/24"], &[22]);
        a.dry_run = true;
        let scenario = build_scenario(&a).expect("scenario");
        let resolver = HickoryResolver::from_system().expect("resolver");
        let resolutions = resolve_scenario_targets(&scenario, &resolver).await;
        let mut out = String::new();
        let probes = write_scenario_plan(&mut out, "s", &scenario, &resolutions, &a);
        assert_eq!(probes, 254, "1 prober × 254 hosts in /24");
        assert!(out.contains("..."), "ellipsis expected: {out}");
        assert!(out.contains("(254 addresses)"), "count expected: {out}");
    }

    #[tokio::test]
    async fn dry_run_dns_failure_prints_inline_error_and_continues() {
        let mut a = args(&["invalid.nx.does-not-exist.example", "127.0.0.1"], &[22]);
        a.dry_run = true;
        let scenario = build_scenario(&a).expect("scenario");
        let resolver = HickoryResolver::from_system().expect("resolver");
        let resolutions = resolve_scenario_targets(&scenario, &resolver).await;
        let mut out = String::new();
        write_scenario_plan(&mut out, "s", &scenario, &resolutions, &a);
        assert!(
            out.contains("<error:"),
            "expected inline error for failing DNS target: {out}"
        );
        assert!(out.contains("127.0.0.1 → 127.0.0.1"), "{out}");
        dry_run_exit_status(&[resolutions]).expect("at least one resolved => exit 0");
    }

    #[tokio::test]
    async fn dry_run_all_targets_failing_returns_error() {
        let resolutions = vec![
            ResolvedScenarioTarget::new(
                Target::DnsName("x.invalid".into()),
                Err(rastreo_core::RastreoError::Resolver(
                    rastreo_core::ResolverError::DnsNoRecords {
                        name: "x.invalid".into(),
                    },
                )),
            ),
            ResolvedScenarioTarget::new(
                Target::DnsName("y.invalid".into()),
                Err(rastreo_core::RastreoError::Resolver(
                    rastreo_core::ResolverError::DnsNoRecords {
                        name: "y.invalid".into(),
                    },
                )),
            ),
        ];
        let err = dry_run_exit_status(&[resolutions]).expect_err("all-failed => Err");
        let msg = format!("{err}");
        assert!(msg.contains("no targets resolved"), "msg: {msg}");
    }

    #[cfg(feature = "kafka")]
    #[tokio::test]
    async fn dry_run_kafka_sink_never_instantiates_client() {
        // Build a scenario with kafka sink pointing at a bogus broker.
        // The dry-run path must NOT try to connect — completes instantly.
        let mut a = args(&["127.0.0.1"], &[22]);
        a.dry_run = true;
        a.sink = Some(SinkKind::Kafka);
        a.brokers = vec!["127.0.0.1:1".into()];
        a.topic = Some("t".into());

        let scenario = build_scenario(&a).expect("scenario");
        let resolver = HickoryResolver::from_system().expect("resolver");
        let start = std::time::Instant::now();
        let resolutions = resolve_scenario_targets(&scenario, &resolver).await;
        let mut out = String::new();
        write_scenario_plan(&mut out, "s", &scenario, &resolutions, &a);
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() < 2,
            "dry-run must not attempt kafka connect; took {elapsed:?}"
        );
        assert!(out.contains("kafka:"), "{out}");
        assert!(out.contains("brokers=127.0.0.1:1"), "{out}");
        assert!(out.contains("topic=t"), "{out}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn dry_run_scenario_label_uses_quoted_name_when_present() {
        let mut base = BaseProbeConfig::new();
        base.name = Some("routers".into());
        assert_eq!(dry_run_scenario_label(&base, 0, 3), "'routers' (1 of 3)");
    }

    #[cfg(feature = "config")]
    #[test]
    fn dry_run_scenario_label_uses_bare_index_when_unnamed() {
        let base = BaseProbeConfig::new();
        assert_eq!(dry_run_scenario_label(&base, 2, 4), "3 of 4");
    }

    #[test]
    fn write_totals_multi_scenario_prints_total_probe_count() {
        let mut out = String::new();
        write_totals(&mut out, 3, 42);
        assert!(out.contains("total probes: 42"), "{out}");
    }

    #[test]
    fn write_totals_single_scenario_also_prints_total_line() {
        let mut out = String::new();
        write_totals(&mut out, 1, 5);
        assert!(out.contains("total probes: 5"), "{out}");
    }

    #[tokio::test]
    async fn dry_run_single_scenario_now_prints_total_probes_footer() {
        let mut a = args(&["127.0.0.1"], &[22]);
        a.dry_run = true;
        let scenario = build_scenario(&a).expect("scenario");
        let resolver = HickoryResolver::from_system().expect("resolver");
        let resolutions = resolve_scenario_targets(&scenario, &resolver).await;
        let mut out = String::new();
        write_dry_run_header(&mut out, 1);
        let probes = write_scenario_plan(&mut out, "discovery", &scenario, &resolutions, &a);
        write_totals(&mut out, 1, probes);
        assert!(
            out.contains("total probes: 1"),
            "single-scenario dry-run must print total probes footer: {out}"
        );
    }

    #[tokio::test]
    async fn dry_run_probe_count_deduplicates_overlapping_ips() {
        let mut a = args(&["10.0.0.1", "10.0.0.0/29"], &[22]);
        a.dry_run = true;
        let scenario = build_scenario(&a).expect("scenario");
        let resolver = HickoryResolver::from_system().expect("resolver");
        let resolutions = resolve_scenario_targets(&scenario, &resolver).await;
        let mut out = String::new();
        let probes = write_scenario_plan(&mut out, "s", &scenario, &resolutions, &a);
        // /29 usable hosts: 10.0.0.1..10.0.0.6 (6). Explicit 10.0.0.1 overlaps → still 6 unique.
        assert_eq!(probes, 6, "expected deduped unique-IP count, got {probes}");
        // Per-target lines still show duplicates verbatim — dedup is only for the total.
        assert!(out.contains("10.0.0.1 → 10.0.0.1"), "{out}");
    }

    #[test]
    fn enrich_scan_error_hint_matches_nxdomain() {
        let hint =
            enrich_scan_error_hint("resolver error: NXDOMAIN for example.com").expect("hint");
        assert!(hint.contains("DNS resolution failed"), "hint: {hint}");
    }

    #[test]
    fn enrich_scan_error_hint_matches_dns_lookup_failed() {
        let hint = enrich_scan_error_hint("resolver error: DNS lookup failed for x.invalid")
            .expect("hint");
        assert!(hint.contains("DNS resolution failed"), "hint: {hint}");
    }

    #[test]
    fn enrich_scan_error_hint_matches_no_records_found() {
        let hint = enrich_scan_error_hint("resolver error: no records found").expect("hint");
        assert!(hint.contains("DNS resolution failed"), "hint: {hint}");
    }

    #[test]
    fn enrich_scan_error_hint_is_case_insensitive() {
        let hint =
            enrich_scan_error_hint("RESOLVER ERROR: NXDOMAIN for example.com").expect("hint");
        assert!(hint.contains("DNS resolution failed"), "hint: {hint}");
    }

    #[test]
    fn enrich_scan_error_hint_returns_none_for_unknown_message() {
        assert!(enrich_scan_error_hint("some totally novel failure mode").is_none());
    }

    #[test]
    fn enrich_scan_error_hint_returns_none_for_empty_message() {
        assert!(enrich_scan_error_hint("").is_none());
    }

    #[test]
    fn enrich_scan_error_hint_ignores_probe_fault_strings() {
        assert!(enrich_scan_error_hint("probe error: raw socket: Permission denied").is_none());
    }

    fn summary_with_fault(
        kind: rastreo_core::ProbeErrorKind,
        detail: &str,
    ) -> rastreo_core::DiscoverySummary {
        let mut summary = rastreo_core::DiscoverySummary::default();
        summary.first_probe_error = Some(rastreo_core::ProbeFault::new(kind, detail));
        summary
    }

    #[test]
    fn runtime_probe_hint_derives_permission_denied_from_kind() {
        // detail omits any "permission denied" substring: the hint must come from the kind.
        let summary = summary_with_fault(
            rastreo_core::ProbeErrorKind::PermissionDenied,
            "snmp egress blocked",
        );
        let hint = runtime_probe_hint(&summary).expect("hint");
        assert!(hint.contains("CAP_NET_RAW"), "hint: {hint}");
    }

    #[test]
    fn runtime_probe_hint_derives_decode_failed_from_kind() {
        let summary = summary_with_fault(rastreo_core::ProbeErrorKind::DecodeFailed, "gibberish");
        let hint = runtime_probe_hint(&summary).expect("hint");
        assert!(hint.contains("could not parse"), "hint: {hint}");
    }

    #[test]
    fn runtime_probe_hint_agrees_with_core_hint_for_the_same_kind() {
        for kind in [
            rastreo_core::ProbeErrorKind::PermissionDenied,
            rastreo_core::ProbeErrorKind::DnsFailed,
            rastreo_core::ProbeErrorKind::DecodeFailed,
            rastreo_core::ProbeErrorKind::AuthFailed,
        ] {
            let summary = summary_with_fault(kind, "x");
            assert_eq!(
                runtime_probe_hint(&summary),
                rastreo_core::hint_for_error_kind(kind),
                "CLI runtime hint must match the shared core hint for {kind:?}"
            );
        }
    }

    #[test]
    fn runtime_probe_hint_is_none_for_other_kind() {
        let summary = summary_with_fault(rastreo_core::ProbeErrorKind::Other, "unclassified");
        assert!(runtime_probe_hint(&summary).is_none());
    }

    #[test]
    fn runtime_probe_hint_is_none_without_a_fault() {
        let summary = rastreo_core::DiscoverySummary::default();
        assert!(runtime_probe_hint(&summary).is_none());
    }

    #[test]
    fn print_runtime_hints_no_op_when_records_emitted() {
        let mut summary = rastreo_core::DiscoverySummary::default();
        summary.targets_resolved = 1;
        summary.probe_attempts = 1;
        summary.records_emitted = 1;
        assert!(
            runtime_hint_line(&summary).is_none(),
            "records emitted with no fault must produce no hint"
        );
        print_runtime_hints(&summary);
    }

    #[test]
    fn runtime_hint_line_returns_fault_hint_even_when_a_record_was_kept() {
        // SNMP decode-failure keeps the device (records_emitted == 1) yet latches a fault.
        let mut summary =
            summary_with_fault(rastreo_core::ProbeErrorKind::DecodeFailed, "gibberish");
        summary.probe_attempts = 1;
        summary.records_emitted = 1;
        let line = runtime_hint_line(&summary).expect("fault hint must fire despite a kept record");
        assert_eq!(
            line.as_str(),
            rastreo_core::hint_for_error_kind(rastreo_core::ProbeErrorKind::DecodeFailed)
                .expect("decode hint")
        );
    }

    #[test]
    fn runtime_hint_line_falls_back_to_zero_records_hint_without_a_fault() {
        let mut summary = rastreo_core::DiscoverySummary::default();
        summary.probe_attempts = 1;
        summary.records_emitted = 0;
        let line = runtime_hint_line(&summary).expect("fallback hint");
        assert_eq!(line, ZERO_RECORDS_HINT);
        assert!(
            !line.starts_with("hint:"),
            "content must be prefix-free; the label is added at the print layer: {line}"
        );
    }

    #[test]
    fn runtime_hint_line_no_op_when_cancelled() {
        let mut summary = rastreo_core::DiscoverySummary::default();
        summary.targets_resolved = 1;
        summary.probe_attempts = 1;
        summary
            .error_counts
            .insert(rastreo_core::ProbeErrorKind::PermissionDenied, 1);
        summary.cancelled = true;
        summary.first_probe_error = Some(rastreo_core::ProbeFault::new(
            rastreo_core::ProbeErrorKind::PermissionDenied,
            "permission denied",
        ));
        assert!(runtime_hint_line(&summary).is_none());
        print_runtime_hints(&summary);
    }
}
