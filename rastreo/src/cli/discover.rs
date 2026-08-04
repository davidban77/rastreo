use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use ipnet::IpNet;
#[cfg(feature = "config")]
use rastreo_core::config::{parse_scenario_file, ScenarioEntry, ScenarioFile, ScenarioKind};
use rastreo_core::config::{BaseProbeConfig, DiscoverScenarioConfig, MAX_RETRIES};
#[cfg(feature = "snmp")]
use rastreo_core::prober::Community;
use rastreo_core::prober::{
    apply_runnability_filter, expand_probe_selection, parse_probe_selection, ProbeSelectionOptions,
};
#[cfg(feature = "kafka")]
use rastreo_core::KafkaFlushMode;
use rastreo_core::Resolver;
#[cfg(feature = "config")]
use rastreo_core::ScenarioTally;
use rastreo_core::{
    preflight_checkpoint_request, resolve_pinned_scenario, resolve_scenario, run_discovery,
    Checkpoint, CheckpointConfig, ConfigError, DiscoveryPlan, DiscoveryProgress, DiscoverySummary,
    EncoderConfig, Env, HickoryResolver, PlanKnobs, ProbeKind, RastreoError, ResumeError,
    RunOptions, RunReport, ScenarioOutcome, ScenarioReport, ScenarioResolution, SinkConfig,
    SystemEnv, Target,
};
use tokio::sync::watch;

use super::output::{
    accumulate, enrich_scan_error_hint, print_complete, print_note, print_refusal_hint,
    print_runtime_hints, print_start, progress_display_loop, progress_style, rebuild_hint,
    record_destination, stdout_table_width, OutputMode, Verbosity,
};
#[cfg(feature = "config")]
use super::output::{
    enrich_feature_hint, print_aggregate, print_blank, print_failed, print_notice,
};
#[cfg(feature = "snmp")]
use super::probe_args::SnmpVersionArg;
use super::probe_args::{parse_probe_ports, DnsQueryTypeArg, UdpProtocolArg, PROBE_LONG_HELP};

const FLAG_DRIVEN_LABEL: &str = "discover";
const NOTHING_TO_PROBE_HINT: &str =
    "Either the network answered that these names have no addresses, or they are not names a DNS query can carry: a port, brackets, or a zone suffix in a hostname. Check the target list for typos, then the resolver configuration.";
const DEFAULT_CONCURRENCY: u32 = 64;
const DEFAULT_TIMEOUT_MS: u64 = 1000;
const DEFAULT_CHECKPOINT_INTERVAL: usize = 5000;

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

    /// Ports for probers with no well-known port (tcp_connect, http, udp). Probers with a
    /// standard port (dns 53, snmp 161, ssh 22, tls 443, gnmi 57400) are unaffected — override
    /// those with --probe-ports. Omit for the built-in defaults; use --dry-run to confirm.
    #[cfg_attr(
        feature = "config",
        arg(short, long, value_delimiter = ',', conflicts_with = "file")
    )]
    #[cfg_attr(not(feature = "config"), arg(short, long, value_delimiter = ','))]
    pub port: Vec<u16>,

    /// Probe kinds to run, comma-separated. Omit to run the default set.
    #[cfg_attr(
        feature = "config",
        arg(long, value_delimiter = ',', conflicts_with = "file")
    )]
    #[cfg_attr(not(feature = "config"), arg(long, value_delimiter = ','))]
    #[arg(long_help = PROBE_LONG_HELP)]
    pub probe: Vec<String>,

    /// Per-prober port override: --probe-ports snmp=1161 --probe-ports http=8080,8443
    #[cfg_attr(
        feature = "config",
        arg(long, value_parser = parse_probe_ports, conflicts_with = "file")
    )]
    #[cfg_attr(not(feature = "config"), arg(long, value_parser = parse_probe_ports))]
    pub probe_ports: Vec<(ProbeKind, Vec<u16>)>,

    /// UDP service to fingerprint. Required when --probe udp is selected.
    #[cfg_attr(feature = "config", arg(long, value_enum, conflicts_with = "file"))]
    #[cfg_attr(not(feature = "config"), arg(long, value_enum))]
    pub udp_protocol: Option<UdpProtocolArg>,

    /// Name to look up against each target. Required when --probe dns is selected. Repeat or comma-separate for multiple.
    #[cfg_attr(
        feature = "config",
        arg(long, value_delimiter = ',', conflicts_with = "file")
    )]
    #[cfg_attr(not(feature = "config"), arg(long, value_delimiter = ','))]
    pub dns_query: Vec<String>,

    /// Record type for --dns-query. Defaults to A.
    #[cfg_attr(feature = "config", arg(long, value_enum, conflicts_with = "file"))]
    #[cfg_attr(not(feature = "config"), arg(long, value_enum))]
    pub dns_query_type: Option<DnsQueryTypeArg>,

    /// SNMP read community, also read from RASTREO_SNMP_COMMUNITY. Prefer the environment
    /// variable — a flag value is visible in `ps`.
    #[cfg(feature = "snmp")]
    #[cfg_attr(
        feature = "config",
        arg(long, value_parser = parse_community, conflicts_with = "file")
    )]
    #[cfg_attr(not(feature = "config"), arg(long, value_parser = parse_community))]
    pub snmp_community: Option<Community>,

    /// SNMP protocol version. Defaults to v2c.
    #[cfg(feature = "snmp")]
    #[cfg_attr(feature = "config", arg(long, value_enum, conflicts_with = "file"))]
    #[cfg_attr(not(feature = "config"), arg(long, value_enum))]
    pub snmp_version: Option<SnmpVersionArg>,

    /// Request path for the HTTP prober. Defaults to /.
    #[cfg(feature = "http")]
    #[cfg_attr(feature = "config", arg(long, conflicts_with = "file"))]
    #[cfg_attr(not(feature = "config"), arg(long))]
    pub http_path: Option<String>,

    /// Echo requests per target for the ICMP prober. Defaults to 3.
    #[cfg(feature = "icmp")]
    #[cfg_attr(
        feature = "config",
        arg(long, value_parser = clap::value_parser!(u32).range(1..), conflicts_with = "file")
    )]
    #[cfg_attr(
        not(feature = "config"),
        arg(long, value_parser = clap::value_parser!(u32).range(1..))
    )]
    pub icmp_count: Option<u32>,

    /// Network interface the ARP and NDP probers send from.
    #[cfg(any(feature = "arp", feature = "ndp"))]
    #[cfg_attr(feature = "config", arg(long, conflicts_with = "file"))]
    #[cfg_attr(not(feature = "config"), arg(long))]
    pub interface: Option<String>,

    /// YAML scenario file to load, or `@name` to resolve a scenario from the catalog
    /// directories (see the CLI docs for search order). When present, none of the
    /// flag-driven scan arguments are permitted; each scenario in the file is executed in order.
    #[cfg(feature = "config")]
    #[arg(short = 'f', long)]
    pub file: Option<PathBuf>,

    /// Record format: `table` (default on stdout) or `json` for one NDJSON object per line.
    /// With --file, overrides the scenario's `encoder`.
    #[arg(long, value_enum, env = "RASTREO_FORMAT")]
    pub format: Option<OutputFormat>,

    /// Output sink kind. When --file is set and this flag is omitted, the sink from the YAML file is used.
    #[arg(long, value_enum)]
    pub sink: Option<SinkKind>,

    /// File path for --sink file.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Kafka brokers (comma-separated) for --sink kafka.
    #[cfg(feature = "kafka")]
    #[arg(long, value_delimiter = ',')]
    pub brokers: Vec<String>,

    /// Kafka topic for --sink kafka.
    #[cfg(feature = "kafka")]
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

    // Retired: parsed so a run can name the replacement instead of clap reporting an unknown flag.
    #[arg(long, hide = true, value_name = "FORMAT")]
    pub dry_run_format: Option<String>,

    /// Write a resume checkpoint to this path during the scan. The scenario must be resume-safe (durable sink, no identity fuser, no LLDP/gNMI prober) or the scan is refused before probing. The file is removed on successful completion and kept on cancellation.
    #[arg(long)]
    pub checkpoint: Option<PathBuf>,

    /// Targets between checkpoint writes. Defaults to 5000. Requires --checkpoint.
    #[arg(long, value_parser = parse_checkpoint_interval, requires = "checkpoint")]
    pub checkpoint_interval: Option<usize>,

    /// Resume a scan from the checkpoint at --checkpoint <path>: skip the already-done targets, restore
    /// the original scan identity, and continue. The checkpoint must exist and still match the scenario.
    #[arg(long, requires = "checkpoint")]
    pub resume: bool,

    /// Write a JSON report of the run to this path: how every scenario the run reached ended, its summary
    /// when it produced one, and the run's totals. Written whenever the run reached a scenario, whatever
    /// the exit code; a run that refuses before reaching one writes none.
    #[arg(long, conflicts_with = "dry_run")]
    pub run_report: Option<PathBuf>,
}

// Typed at the clap boundary so the plaintext never reaches a `{args:?}` render.
#[cfg(feature = "snmp")]
fn parse_community(raw: &str) -> Result<Community, String> {
    Ok(Community(raw.to_string()))
}

fn parse_checkpoint_interval(s: &str) -> Result<usize, String> {
    match s.parse::<usize>() {
        Ok(n) if n >= 1 => Ok(n),
        Ok(_) => Err("must be at least 1".to_string()),
        Err(e) => Err(format!("not a positive integer: {e}")),
    }
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    #[value(alias = "text")]
    Table,
    #[value(alias = "ndjson")]
    Json,
}

fn encoder_for_format(format: OutputFormat, table_width: u16) -> EncoderConfig {
    match format {
        OutputFormat::Table => EncoderConfig::Table { width: table_width },
        OutputFormat::Json => EncoderConfig::Ndjson,
    }
}

// Only stdout is read by a person; every other destination holds machine data.
fn record_encoder(
    format: Option<OutputFormat>,
    writes_to_stdout: bool,
    table_width: u16,
) -> EncoderConfig {
    match format {
        Some(format) => encoder_for_format(format, table_width),
        None if writes_to_stdout => encoder_for_format(OutputFormat::Table, table_width),
        None => EncoderConfig::Ndjson,
    }
}

fn writes_to_stdout(sink: Option<&SinkConfig>) -> bool {
    matches!(sink, None | Some(SinkConfig::Stdout))
}

// A dry run puts the plan on stdout in place of the records. A `--file` run has no sink to read
// until its scenario loads, so it counts as stdout: the cheaper of the two wrong answers.
fn stdout_carries_the_payload(args: &DiscoverArgs) -> bool {
    args.dry_run || matches!(effective_sink_kind(args), None | Some(SinkKind::Stdout))
}

// The scenario's own sink is the final answer, and the only one a scenario that runs is judged by.
fn mode_for_sink(mode: OutputMode, sink: Option<&SinkConfig>) -> OutputMode {
    mode.with_record_destination(record_destination(writes_to_stdout(sink)))
}

// The plan itself always goes to stdout, so it reads as text unless the caller asked for machine output.
fn dry_run_plan_format(args: &DiscoverArgs) -> OutputFormat {
    args.format.unwrap_or(OutputFormat::Table)
}

/// The sink a run will write to, or `None` when only the scenario file knows.
fn effective_sink_kind(args: &DiscoverArgs) -> Option<SinkKind> {
    if let Some(kind) = args.sink {
        return Some(kind);
    }
    #[cfg(feature = "config")]
    if args.file.is_some() {
        return None;
    }
    Some(SinkKind::Stdout)
}

const RETIRED_DRY_RUN_FORMAT: &str =
    "--dry-run-format was retired: use --format, which now sets the dry-run plan and the record \
     stream alike. Pass --format table where you passed text, or --format json where you passed \
     json.";

fn ensure_no_retired_flags(args: &DiscoverArgs) -> Result<()> {
    match args.dry_run_format {
        Some(_) => Err(anyhow!(RETIRED_DRY_RUN_FORMAT)),
        None => Ok(()),
    }
}

/// A flag naming where records go, or how to reach that destination; inert unless its sink is selected.
struct SinkFlag {
    flag: &'static str,
    sink: SinkKind,
    supplied: bool,
}

fn sink_flags(args: &DiscoverArgs) -> Vec<SinkFlag> {
    #[cfg_attr(not(feature = "kafka"), allow(unused_mut))]
    let mut flags = vec![SinkFlag {
        flag: "--output",
        sink: SinkKind::File,
        supplied: args.output.is_some(),
    }];
    #[cfg(feature = "kafka")]
    flags.extend([
        SinkFlag {
            flag: "--brokers",
            sink: SinkKind::Kafka,
            supplied: !args.brokers.is_empty(),
        },
        SinkFlag {
            flag: "--topic",
            sink: SinkKind::Kafka,
            supplied: args.topic.is_some(),
        },
        SinkFlag {
            flag: "--kafka-flush-per-record",
            sink: SinkKind::Kafka,
            supplied: args.kafka_flush_per_record,
        },
        SinkFlag {
            flag: "--kafka-batch-threshold",
            sink: SinkKind::Kafka,
            supplied: args.kafka_batch_threshold.is_some(),
        },
    ]);
    flags
}

// A discarded destination flag leaves the operator believing records went somewhere they did not.
fn ensure_sink_flags_reach_their_sink(args: &DiscoverArgs) -> Result<()> {
    match sink_flags(args)
        .iter()
        .find(|flag| flag.supplied && args.sink != Some(flag.sink))
    {
        Some(flag) => Err(anyhow!(sink_flag_mismatch(flag, &destination_label(args)))),
        None => Ok(()),
    }
}

fn sink_flag_mismatch(flag: &SinkFlag, destination: &str) -> String {
    let sink = sink_kind_value(flag.sink);
    format!(
        "{name} only applies to --sink {sink}, and this run writes to {destination}. \
         Add --sink {sink}, or drop {name}.",
        name = flag.flag
    )
}

fn destination_label(args: &DiscoverArgs) -> String {
    match effective_sink_kind(args) {
        Some(kind) => sink_kind_label(kind).to_string(),
        None => "the destination named in the scenario file".to_string(),
    }
}

fn sink_kind_value(kind: SinkKind) -> &'static str {
    match kind {
        SinkKind::Stdout => "stdout",
        SinkKind::File => "file",
        #[cfg(feature = "kafka")]
        SinkKind::Kafka => "kafka",
    }
}

fn sink_kind_label(kind: SinkKind) -> &'static str {
    match kind {
        SinkKind::Stdout => "stdout",
        SinkKind::File => "a file",
        #[cfg(feature = "kafka")]
        SinkKind::Kafka => "kafka",
    }
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

pub async fn run(
    args: DiscoverArgs,
    cancel: watch::Receiver<bool>,
    verbosity: Verbosity,
) -> Result<()> {
    let mode = OutputMode::new(verbosity, args.format == Some(OutputFormat::Json))
        .with_record_destination(record_destination(stdout_carries_the_payload(&args)));
    ensure_no_retired_flags(&args)?;
    ensure_sink_flags_reach_their_sink(&args)?;
    if args.dry_run {
        return run_dry_run(&args, mode).await;
    }
    #[cfg(feature = "config")]
    if args.file.is_some() {
        run_from_file(&args, cancel, mode).await?;
        return Ok(());
    }
    run_legacy(&args, cancel, mode).await
}

async fn run_dry_run(args: &DiscoverArgs, mode: OutputMode) -> Result<()> {
    let resolver = HickoryResolver::from_system()?;

    #[cfg(feature = "config")]
    if args.file.is_some() {
        return run_dry_run_from_file(args, &resolver, mode).await;
    }

    let scenario = scenario_from_flags(args, mode)?;
    let resolution = rehearsed_resolution(&scenario, args, &resolver)
        .await
        .map_err(|err| refuse(err, mode))?;
    let plan = build_resolved_plan("discovery", &scenario, &resolution, args).await?;
    render_dry_run(&[plan], dry_run_plan_format(args))?;
    refuse_on_resolution_error(&resolution, mode)?;
    ensure_a_target_resolved(&resolution, scenario.targets.len(), mode)
}

// A resume replays the checkpoint's pins rather than re-resolving names the run will never ask about again.
async fn rehearsed_resolution(
    scenario: &DiscoverScenarioConfig,
    args: &DiscoverArgs,
    resolver: &dyn Resolver,
) -> Result<ScenarioResolution, RastreoError> {
    match dry_run_checkpoint_preflight(scenario, args)? {
        Some(checkpoint) => resolve_pinned_scenario(
            &scenario.targets,
            &checkpoint.dns_pins,
            checkpoint.highest_flushed_index,
        ),
        None => Ok(resolve_scenario(resolver, &scenario.targets).await),
    }
}

fn dry_run_checkpoint_preflight(
    scenario: &DiscoverScenarioConfig,
    args: &DiscoverArgs,
) -> Result<Option<Checkpoint>, RastreoError> {
    let Some(config) = checkpoint_config(args) else {
        return Ok(None);
    };
    Ok(preflight_checkpoint_request(scenario, &config)?)
}

fn ensure_a_target_resolved(
    resolution: &ScenarioResolution,
    targets: usize,
    mode: OutputMode,
) -> Result<()> {
    if resolution.refusal().is_some() {
        return Ok(());
    }
    let unresolvable: Vec<String> = resolution
        .unresolvable_targets()
        .iter()
        .map(ToString::to_string)
        .collect();
    refuse_nothing_to_probe(targets, &unresolvable, mode)
}

// Over the target set, not a host count: a resume leaves zero hosts to probe on targets that resolved.
fn refuse_nothing_to_probe(
    targets: usize,
    unresolvable: &[String],
    mode: OutputMode,
) -> Result<()> {
    if unresolvable.is_empty() || unresolvable.len() < targets {
        return Ok(());
    }
    print_refusal_hint(NOTHING_TO_PROBE_HINT, mode);
    Err(anyhow!(
        "every target is unresolvable ({}); there is nothing to probe",
        unresolvable.join(", ")
    ))
}

#[cfg(feature = "config")]
async fn run_dry_run_from_file(
    args: &DiscoverArgs,
    resolver: &dyn Resolver,
    mode: OutputMode,
) -> Result<()> {
    let raw = args.file.as_deref().expect("file present per dispatch");
    let path = resolve_scenario_source(raw)?;
    let file = load_scenario_file(&path).map_err(|e| e.report(mode))?;

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
    ensure_checkpoint_is_single_scenario(args, &file, &path)?;

    let cli_sink = build_cli_sink_override(args)?;
    let cli_encoder = build_cli_encoder_override(args);
    let plan_format = dry_run_plan_format(args);
    let total = file.scenarios.len();

    let mut plans: Vec<DiscoveryPlan> = Vec::with_capacity(total);
    let mut failed = 0usize;
    let mut skipped = 0usize;

    for (idx, entry) in file.scenarios.into_iter().enumerate() {
        let mut cfg = match entry {
            ScenarioEntry::Discover(cfg) => cfg,
            #[allow(unreachable_patterns)]
            _ => return Err(anyhow!("unsupported scenario entry variant")),
        };
        merge_defaults(&mut cfg.base, &file.defaults);
        apply_cli_overrides(&mut cfg.base, args, cli_sink.as_ref(), cli_encoder.as_ref());
        let label = scenario_plan_label(&cfg.base, idx, total, plan_format);
        if skip_prober_less_scenario(&cfg, &label, mode) {
            skipped += 1;
            continue;
        }
        // Ahead of resolution, so a scenario the run would refuse costs no DNS lookup.
        if let Err(err) = cfg.validate() {
            failed += 1;
            report_scenario_failure(&label, &err, mode);
            continue;
        }
        let resolution = match rehearsed_resolution(&cfg, args, resolver).await {
            Ok(resolution) => resolution,
            Err(err) => {
                failed += 1;
                report_scenario_failure(&label, &err, mode);
                continue;
            }
        };
        match build_resolved_plan(&label, &cfg, &resolution, args).await {
            Ok(plan) => {
                plans.push(plan);
                // Planned so the render names which target refused, then counted as the run counts it.
                if let Some(err) = resolution.refusal() {
                    failed += 1;
                    report_scenario_failure(&label, err, mode);
                } else if let Err(err) =
                    ensure_a_target_resolved(&resolution, cfg.targets.len(), mode)
                {
                    failed += 1;
                    print_failed(&label, &err.to_string());
                }
            }
            Err(err) => {
                failed += 1;
                report_scenario_failure(&label, &err, mode);
            }
        }
    }

    render_dry_run(&plans, plan_format)?;
    if failed > 0 {
        return Err(anyhow!(
            "{failed} of {total} scenario(s) failed; see individual errors above"
        ));
    }
    ensure_not_every_scenario_was_skipped(skipped, total, &path)
}

// One checkpoint path cannot represent several scenarios' progress, so the write is refused where the resume would be: before the scan, not after it.
#[cfg(feature = "config")]
fn ensure_checkpoint_is_single_scenario(
    args: &DiscoverArgs,
    file: &ScenarioFile,
    path: &Path,
) -> Result<()> {
    if args.checkpoint.is_none() || file.scenarios.len() < 2 {
        return Ok(());
    }
    Err(anyhow!(
        "--checkpoint supports a single-scenario run; '{}' has {} scenarios. \
         One checkpoint path cannot record several scenarios' progress, so a checkpoint written here could not be resumed.",
        path.display(),
        file.scenarios.len()
    ))
}

// A file whose every scenario was skipped probed nothing, and a run that probed nothing did not succeed.
#[cfg(feature = "config")]
fn ensure_not_every_scenario_was_skipped(skipped: usize, total: usize, path: &Path) -> Result<()> {
    if skipped == 0 || skipped < total {
        return Ok(());
    }
    Err(anyhow!(
        "every scenario in '{}' was skipped for having no probers; there is nothing to probe",
        path.display()
    ))
}

// One predicate and one message, so the run and the rehearsal cannot drift apart on which scenarios they skip.
#[cfg(feature = "config")]
fn skip_prober_less_scenario(
    scenario: &DiscoverScenarioConfig,
    label: &str,
    mode: OutputMode,
) -> bool {
    if !scenario.probers.is_empty() {
        return false;
    }
    print_notice(&format!("{label}: no probers configured, skipping"), mode);
    true
}

// Machine output carries the plain scenario name (matching rastreo-server's scenario_label so both surfaces name a scenario the same way); text keeps the multi-scenario `'name' (N of M)` header decoration.
#[cfg(feature = "config")]
fn scenario_plan_label(
    base: &BaseProbeConfig,
    idx: usize,
    total: usize,
    format: OutputFormat,
) -> String {
    match format {
        OutputFormat::Table => dry_run_scenario_label(base, idx, total),
        OutputFormat::Json => machine_scenario_label(base),
    }
}

#[cfg(feature = "config")]
fn machine_scenario_label(base: &BaseProbeConfig) -> String {
    base.name.clone().unwrap_or_else(|| "unnamed".to_string())
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
            .unwrap_or_else(|| args.concurrency.unwrap_or(DEFAULT_CONCURRENCY))
            .max(1),
        probe_rate: scenario.base.probe_rate.or(args.rate),
        retries: scenario.base.retries.or(args.retries).unwrap_or(0),
        timeout_ms: scenario
            .base
            .timeout_ms
            .unwrap_or_else(|| args.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
    }
}

// One place decides what a run is given, so a rehearsal and the run it rehearses read one set of options.
fn run_options<'a>(scenario: &'a DiscoverScenarioConfig, args: &DiscoverArgs) -> RunOptions<'a> {
    let opts = RunOptions::new(scenario);
    match checkpoint_config(args) {
        Some(checkpoint) => opts.checkpoint(checkpoint),
        None => opts,
    }
}

async fn build_resolved_plan(
    label: &str,
    scenario: &DiscoverScenarioConfig,
    resolution: &ScenarioResolution,
    args: &DiscoverArgs,
) -> Result<DiscoveryPlan, RastreoError> {
    Ok(run_options(scenario, args)
        .plan(label.to_string(), effective_knobs(scenario, args))
        .await?
        .resolve(resolution))
}

// No verbosity reaches the plan: it is the only channel carrying what the run would do.
fn render_dry_run(plans: &[DiscoveryPlan], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Table => print!("{}", render_dry_run_text(plans)),
        OutputFormat::Json => println!("{}", render_dry_run_json(plans)?),
    }
    Ok(())
}

fn render_dry_run_text(plans: &[DiscoveryPlan]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    write_dry_run_header(&mut out, plans.len());
    let mut total_probes = 0usize;
    for plan in plans {
        write!(out, "{plan}").expect("write to String");
        total_probes += plan.total_probes;
    }
    write_totals(&mut out, plans.len(), total_probes);
    out
}

fn render_dry_run_json(plans: &[DiscoveryPlan]) -> Result<String> {
    serde_json::to_string_pretty(plans)
        .map_err(|e| anyhow!("failed to serialize dry-run plans to JSON: {e}"))
}

#[cfg(test)]
async fn write_scenario_plan(
    out: &mut String,
    label: &str,
    scenario: &DiscoverScenarioConfig,
    resolution: &ScenarioResolution,
    args: &DiscoverArgs,
) -> usize {
    use std::fmt::Write as _;
    let plan = build_resolved_plan(label, scenario, resolution, args)
        .await
        .expect("plan");
    write!(out, "{plan}").expect("write to String");
    plan.total_probes
}

fn write_totals(out: &mut String, _scenario_count: usize, total_probes: usize) {
    use std::fmt::Write as _;
    writeln!(out, "total probes: {total_probes}").expect("write to String");
}

fn refuse_on_resolution_error(resolution: &ScenarioResolution, mode: OutputMode) -> Result<()> {
    let Some(err) = resolution.refusal() else {
        return Ok(());
    };
    let rendered = render_error_chain(err);
    if let Some(hint) = scan_error_hint(err) {
        print_refusal_hint(&hint, mode);
    }
    Err(anyhow!("{rendered}"))
}

async fn run_discovery_reporting_progress(
    opts: RunOptions<'_>,
    cancel: watch::Receiver<bool>,
    mode: OutputMode,
) -> std::result::Result<DiscoverySummary, RastreoError> {
    let (progress_tx, progress_rx) = watch::channel(DiscoveryProgress::default());
    let style = progress_style(mode.record_destination());
    let display = tokio::spawn(progress_display_loop(progress_rx, style, mode));
    let result = run_discovery(opts.cancel(cancel).progress(progress_tx)).await;
    let _ = display.await;
    result
}

#[cfg(feature = "config")]
fn report_scenario_failure(label: &str, err: &RastreoError, mode: OutputMode) {
    print_failed(label, &render_error_chain(err));
    if let Some(hint) = scan_error_hint(err) {
        print_refusal_hint(&hint, mode);
    }
}

// A failure line and a hint needle are both single-line, so flatten every level onto one line.
fn render_error_chain(err: &dyn std::error::Error) -> String {
    let mut rendered = err.to_string();
    let mut next = err.source();
    while let Some(source) = next {
        rendered.push_str(": ");
        rendered.push_str(&source.to_string());
        next = source.source();
    }
    rendered
}

// A report says how the scenarios the run reached ended, so a run that reached none writes no file.
fn write_run_report(path: Option<&Path>, report: &RunReport) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    if report.scenarios.is_empty() {
        return Ok(());
    }
    report.write(path)?;
    Ok(())
}

// A failed report write fails the run, but never replaces the diagnosis of the scan it was reporting on.
fn run_outcome(scan: Result<()>, report_write: Result<()>) -> Result<()> {
    scan.and(report_write)
}

fn outcome_of(scan: &Result<()>) -> ScenarioOutcome {
    match scan {
        Ok(()) => ScenarioOutcome::Completed,
        Err(_) => ScenarioOutcome::Failed,
    }
}

fn checkpoint_config(args: &DiscoverArgs) -> Option<CheckpointConfig> {
    args.checkpoint.as_ref().map(|path| CheckpointConfig {
        path: path.clone(),
        interval: args
            .checkpoint_interval
            .unwrap_or(DEFAULT_CHECKPOINT_INTERVAL),
        resume: args.resume,
    })
}

async fn run_legacy(
    args: &DiscoverArgs,
    cancel: watch::Receiver<bool>,
    mode: OutputMode,
) -> Result<()> {
    let scenario = scenario_from_flags(args, mode)?;
    let mode = mode_for_sink(mode, scenario.base.sink.as_ref());
    let (scan, summary) = scan_from_flags(&scenario, args, cancel, mode).await;

    let mut aggregate = DiscoverySummary::default();
    if let Some(summary) = &summary {
        accumulate(&mut aggregate, summary);
    }
    let entry = ScenarioReport::new(FLAG_DRIVEN_LABEL.to_string(), outcome_of(&scan), summary);
    let report = RunReport::new(vec![entry], 1, aggregate);

    run_outcome(scan, write_run_report(args.run_report.as_deref(), &report))
}

// The scenario exists by now, so every way this ends is an outcome the report names.
async fn scan_from_flags(
    scenario: &DiscoverScenarioConfig,
    args: &DiscoverArgs,
    cancel: watch::Receiver<bool>,
    mode: OutputMode,
) -> (Result<()>, Option<DiscoverySummary>) {
    let opts = run_options(scenario, args);
    let plan = match opts
        .plan(
            FLAG_DRIVEN_LABEL.to_string(),
            effective_knobs(scenario, args),
        )
        .await
    {
        Ok(plan) => plan,
        Err(err) => return (Err(refuse(err, mode)), None),
    };
    print_start(&plan, scenario.targets.len(), mode);
    match run_discovery_reporting_progress(opts, cancel, mode).await {
        Ok(summary) => {
            print_complete(FLAG_DRIVEN_LABEL, &summary, mode);
            print_runtime_hints(&summary, mode);
            let scan = refuse_nothing_to_probe(
                scenario.targets.len(),
                &summary.unresolvable_targets,
                mode,
            );
            (scan, Some(summary))
        }
        Err(err) => (Err(refuse(err, mode)), None),
    }
}

#[cfg(feature = "config")]
async fn run_from_file(
    args: &DiscoverArgs,
    cancel: watch::Receiver<bool>,
    mode: OutputMode,
) -> Result<RunReport> {
    let raw = args.file.as_deref().expect("file present per dispatch");
    let path = resolve_scenario_source(raw)?;
    let file = load_scenario_file(&path).map_err(|e| e.report(mode))?;

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

    ensure_checkpoint_is_single_scenario(args, &file, &path)?;

    let cli_sink = build_cli_sink_override(args)?;
    let cli_encoder = build_cli_encoder_override(args);
    let total = file.scenarios.len();
    let mut aggregate = DiscoverySummary::default();
    let mut scenarios: Vec<ScenarioReport> = Vec::with_capacity(total);
    // The aggregate is written after every scenario, so one of them claiming the destination claims it.
    let mut any_scenario_wrote_to_stdout = false;

    for (idx, entry) in file.scenarios.into_iter().enumerate() {
        if *cancel.borrow() {
            print_notice(
                &format!("cancelled before scenario {} of {total}", idx + 1),
                mode,
            );
            aggregate.cancelled = true;
            break;
        }
        let mut cfg = match entry {
            ScenarioEntry::Discover(cfg) => cfg,
            #[allow(unreachable_patterns)]
            _ => return Err(anyhow!("unsupported scenario entry variant")),
        };
        merge_defaults(&mut cfg.base, &file.defaults);
        apply_cli_overrides(&mut cfg.base, args, cli_sink.as_ref(), cli_encoder.as_ref());
        let mode = mode_for_sink(mode, cfg.base.sink.as_ref());

        let label = scenario_label(&cfg.base, idx, total);
        if idx > 0 {
            print_blank(mode);
        }

        let name = machine_scenario_label(&cfg.base);
        if skip_prober_less_scenario(&cfg, &label, mode) {
            scenarios.push(ScenarioReport::new(name, ScenarioOutcome::Skipped, None));
            continue;
        }

        let opts = run_options(&cfg, args);
        let plan = match opts.plan(label.clone(), effective_knobs(&cfg, args)).await {
            Ok(plan) => plan,
            Err(err) => {
                report_scenario_failure(&label, &err, mode);
                scenarios.push(ScenarioReport::new(name, ScenarioOutcome::Failed, None));
                continue;
            }
        };
        print_start(&plan, cfg.targets.len(), mode);
        any_scenario_wrote_to_stdout |= writes_to_stdout(cfg.base.sink.as_ref());

        match run_discovery_reporting_progress(opts, cancel.clone(), mode).await {
            Ok(summary) => {
                print_complete(&label, &summary, mode);
                print_runtime_hints(&summary, mode);
                accumulate(&mut aggregate, &summary);
                let scan =
                    refuse_nothing_to_probe(cfg.targets.len(), &summary.unresolvable_targets, mode);
                if let Err(err) = &scan {
                    print_failed(&label, &err.to_string());
                }
                scenarios.push(ScenarioReport::new(name, outcome_of(&scan), Some(summary)));
            }
            Err(err) => {
                report_scenario_failure(&label, &err, mode);
                scenarios.push(ScenarioReport::new(name, ScenarioOutcome::Failed, None));
            }
        }
    }

    let report = RunReport::new(scenarios, total, aggregate);
    let tally = report.aggregate.scenario_counts;

    if total > 1 {
        let mode = mode.with_record_destination(record_destination(any_scenario_wrote_to_stdout));
        print_blank(mode);
        print_aggregate(tally, &report.aggregate.summary, mode);
    }

    let report_write = write_run_report(args.run_report.as_deref(), &report);
    run_outcome(scenario_loop_outcome(tally, total, &path), report_write)?;
    Ok(report)
}

#[cfg(feature = "config")]
fn scenario_loop_outcome(tally: ScenarioTally, total: usize, path: &Path) -> Result<()> {
    if tally.failed > 0 {
        return Err(anyhow!(
            "{} of {total} scenario(s) failed; see individual errors above",
            tally.failed
        ));
    }
    ensure_not_every_scenario_was_skipped(tally.skipped, total, path)
}

#[cfg(feature = "config")]
pub(crate) fn resolve_scenario_source(input: &Path) -> Result<PathBuf> {
    let as_str = input.to_string_lossy();
    if let Some(name) = as_str.strip_prefix('@') {
        return super::catalog::resolve_catalog_name(name);
    }
    Ok(input.to_path_buf())
}

#[cfg(feature = "config")]
pub(crate) struct ScenarioLoadError {
    source: anyhow::Error,
    hint: Option<String>,
}

#[cfg(feature = "config")]
impl ScenarioLoadError {
    pub(crate) fn report(self, mode: OutputMode) -> anyhow::Error {
        if let Some(hint) = &self.hint {
            print_refusal_hint(hint, mode);
        }
        self.source
    }
}

#[cfg(feature = "config")]
pub(crate) fn load_scenario_file(
    path: &Path,
) -> std::result::Result<ScenarioFile, ScenarioLoadError> {
    let contents = std::fs::read_to_string(path).map_err(|err| ScenarioLoadError {
        source: anyhow::Error::new(err)
            .context(format!("failed to read scenario file '{}'", path.display())),
        hint: None,
    })?;
    parse_scenario_file(&contents, &SystemEnv).map_err(|err| ScenarioLoadError {
        hint: enrich_feature_hint(&err.to_string()),
        source: anyhow::Error::new(err).context(format!(
            "failed to parse scenario file '{}'",
            path.display()
        )),
    })
}

#[cfg(feature = "config")]
pub(crate) fn merge_defaults(base: &mut BaseProbeConfig, defaults: &BaseProbeConfig) {
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
    cli_encoder: Option<&EncoderConfig>,
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
    match cli_encoder {
        Some(encoder) => base.encoder = Some(encoder.clone()),
        None if base.encoder.is_none() => {
            base.encoder = Some(record_encoder(
                None,
                writes_to_stdout(base.sink.as_ref()),
                stdout_table_width(),
            ));
        }
        None => {}
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
fn build_cli_encoder_override(args: &DiscoverArgs) -> Option<EncoderConfig> {
    args.format
        .map(|format| encoder_for_format(format, stdout_table_width()))
}

#[cfg(feature = "config")]
pub(crate) fn scenario_label(base: &BaseProbeConfig, idx: usize, total: usize) -> String {
    match &base.name {
        Some(n) => format!("scenario '{n}' ({} of {total})", idx + 1),
        None => format!("scenario {} of {total}", idx + 1),
    }
}

#[cfg(test)]
fn build_scenario(args: &DiscoverArgs) -> Result<DiscoverScenarioConfig> {
    build_scenario_with_notes(args).map(|(scenario, _)| scenario)
}

fn build_scenario_with_notes(args: &DiscoverArgs) -> Result<(DiscoverScenarioConfig, Vec<String>)> {
    let targets: Vec<Target> = args
        .target
        .iter()
        .map(|s| parse_target(s).with_context(|| format!("invalid --target {s:?}")))
        .collect::<Result<Vec<_>>>()?;

    let sink_kind = args.sink.unwrap_or(SinkKind::Stdout);
    let sink_config = build_sink_config_for_kind(sink_kind, args)?;

    let selected = select_probe_kinds(args)?;
    reject_uncompiled_probe_ports(args)?;
    let probers = expand_probe_selection(&selected.kinds, &probe_options(args, &SystemEnv))?;
    let notes = selection_notes(args, &selected);

    let mut base = BaseProbeConfig::new();
    base.max_concurrent = Some(args.concurrency.unwrap_or(DEFAULT_CONCURRENCY));
    base.probe_rate = args.rate;
    base.retries = args.retries;
    base.timeout_ms = Some(args.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS));
    base.encoder = Some(record_encoder(
        args.format,
        writes_to_stdout(Some(&sink_config)),
        stdout_table_width(),
    ));
    base.sink = Some(sink_config);

    Ok((DiscoverScenarioConfig::new(base, targets, probers), notes))
}

fn scenario_from_flags(args: &DiscoverArgs, mode: OutputMode) -> Result<DiscoverScenarioConfig> {
    match build_scenario_with_notes(args) {
        Ok((scenario, notes)) => {
            for note in &notes {
                print_note(note, mode);
            }
            Ok(scenario)
        }
        Err(err) => {
            if let Some(hint) = probe_selection_hint(&err) {
                print_refusal_hint(&hint, mode);
            }
            Err(err)
        }
    }
}

const DEFAULT_PROBE_TOKEN: &str = "default";

struct SelectedProbes {
    kinds: Vec<ProbeKind>,
    dropped: Vec<ProbeKind>,
}

fn select_probe_kinds(args: &DiscoverArgs) -> Result<SelectedProbes, RastreoError> {
    select_probe_kinds_with(args, probe_is_runnable)
}

// An absent --probe is spelled `default` so the two paths cannot diverge.
fn select_probe_kinds_with(
    args: &DiscoverArgs,
    runnable: impl Fn(ProbeKind) -> bool,
) -> Result<SelectedProbes, RastreoError> {
    let implied = [DEFAULT_PROBE_TOKEN.to_string()];
    let values: &[String] = if args.probe.is_empty() {
        &implied
    } else {
        &args.probe
    };

    let selection = parse_probe_selection(values)?;
    let defaulted = selection.defaulted.clone();
    let kinds = apply_runnability_filter(selection, runnable);
    let dropped = defaulted
        .into_iter()
        .filter(|kind| !kinds.contains(kind))
        .collect();
    Ok(SelectedProbes { kinds, dropped })
}

fn probe_is_runnable(kind: ProbeKind) -> bool {
    runnability_check(kind).is_none_or(|check| check())
}

// `_ => None`: a kind core later gives a precondition reads as runnable until an arm lands here.
fn runnability_check(kind: ProbeKind) -> Option<fn() -> bool> {
    match kind {
        #[cfg(feature = "icmp")]
        ProbeKind::Icmp => Some(rastreo_core::IcmpProber::is_runnable),
        _ => None,
    }
}

fn reject_uncompiled_probe_ports(args: &DiscoverArgs) -> Result<(), RastreoError> {
    match args
        .probe_ports
        .iter()
        .find(|(kind, _)| !kind.is_compiled_in())
    {
        Some((kind, _)) => Err(ConfigError::ProbeKindNotCompiled {
            kind: kind.label(),
            feature: kind.required_feature().unwrap_or(kind.label()),
        }
        .into()),
        None => Ok(()),
    }
}

fn probe_options(args: &DiscoverArgs, env: &dyn Env) -> ProbeSelectionOptions {
    #[cfg(not(feature = "snmp"))]
    let _ = env;
    let mut options = ProbeSelectionOptions::default();
    options.ports.clone_from(&args.port);
    options.ports_by_kind = args.probe_ports.iter().cloned().collect();
    options.dns_query_names.clone_from(&args.dns_query);
    options.udp_protocol = args.udp_protocol.map(Into::into);
    if let Some(query_type) = args.dns_query_type {
        options.dns_query_type = query_type.into();
    }
    #[cfg(feature = "snmp")]
    {
        if let Some(community) = snmp_community(args, env) {
            options.snmp_community = community;
        }
        if let Some(version) = args.snmp_version {
            options.snmp_version = version.into();
        }
    }
    #[cfg(feature = "http")]
    if let Some(path) = &args.http_path {
        options.http_path = path.clone();
    }
    #[cfg(feature = "icmp")]
    if let Some(count) = args.icmp_count {
        options.icmp_count = count;
    }
    #[cfg(any(feature = "arp", feature = "ndp"))]
    if let Some(interface) = &args.interface {
        options.interface = interface.clone();
    }
    options
}

#[cfg(feature = "snmp")]
const SNMP_COMMUNITY_ENV: &str = "RASTREO_SNMP_COMMUNITY";

// Read here rather than through clap's `env`, because clap counts an env-sourced value as
// present and would reject every --file run made from a shell that exports the variable.
#[cfg(feature = "snmp")]
fn snmp_community(args: &DiscoverArgs, env: &dyn Env) -> Option<Community> {
    args.snmp_community
        .clone()
        .or_else(|| env.var(SNMP_COMMUNITY_ENV).ok().map(Community))
        .filter(|community| !community.is_empty())
}

fn probe_selection_hint(err: &anyhow::Error) -> Option<String> {
    match err.downcast_ref::<RastreoError>()? {
        RastreoError::Config(ConfigError::ProbeKindNotCompiled { kind, feature }) => {
            Some(rebuild_hint(kind, feature))
        }
        RastreoError::Config(ConfigError::ProbeKindMissingParam { kind, .. }) => {
            missing_param_flag(kind)
                .map(|flag| format!("pass {flag} to give '{kind}' the parameter it needs."))
        }
        _ => None,
    }
}

fn missing_param_flag(kind: &str) -> Option<&'static str> {
    match kind {
        "udp" => Some("--udp-protocol <PROTOCOL>"),
        "dns" => Some("--dns-query <NAME>"),
        _ => None,
    }
}

fn scan_error_hint(err: &RastreoError) -> Option<String> {
    resume_hint(err)
        .map(str::to_string)
        .or_else(|| enrich_scan_error_hint(&render_error_chain(err)))
}

// Core names the concept it is missing; the flag that expresses it is the CLI's to name.
fn resume_hint(err: &RastreoError) -> Option<&'static str> {
    match err {
        RastreoError::Resume(ResumeError::NoCheckpointToResume { .. }) => Some(
            "--resume continues a checkpoint an earlier --checkpoint run wrote. Drop --resume to scan from zero.",
        ),
        _ => None,
    }
}

fn refuse(err: RastreoError, mode: OutputMode) -> anyhow::Error {
    if let Some(hint) = scan_error_hint(&err) {
        print_refusal_hint(&hint, mode);
    }
    err.into()
}

/// A flag whose only job is to parameterise specific probe kinds; inert when none of them run.
struct ParameterFlag {
    flag: String,
    consumers: Vec<ProbeKind>,
    supplied: bool,
}

impl ParameterFlag {
    fn new(flag: String, consumers: &[ProbeKind], supplied: bool) -> Self {
        Self {
            flag,
            consumers: consumers
                .iter()
                .copied()
                .filter(|kind| kind.is_compiled_in())
                .collect(),
            supplied,
        }
    }
}

#[cfg(feature = "snmp")]
const SNMP_PARAMETER_READERS: &[ProbeKind] = &[ProbeKind::Snmp, ProbeKind::Lldp];

fn parameter_flags(args: &DiscoverArgs) -> Vec<ParameterFlag> {
    let mut flags = vec![
        ParameterFlag::new(
            "--udp-protocol".to_string(),
            &[ProbeKind::Udp],
            args.udp_protocol.is_some(),
        ),
        ParameterFlag::new(
            "--dns-query".to_string(),
            &[ProbeKind::Dns],
            !args.dns_query.is_empty(),
        ),
        ParameterFlag::new(
            "--dns-query-type".to_string(),
            &[ProbeKind::Dns],
            args.dns_query_type.is_some(),
        ),
    ];
    #[cfg(feature = "snmp")]
    {
        flags.push(ParameterFlag::new(
            "--snmp-community".to_string(),
            SNMP_PARAMETER_READERS,
            args.snmp_community.is_some(),
        ));
        flags.push(ParameterFlag::new(
            "--snmp-version".to_string(),
            SNMP_PARAMETER_READERS,
            args.snmp_version.is_some(),
        ));
    }
    #[cfg(feature = "http")]
    flags.push(ParameterFlag::new(
        "--http-path".to_string(),
        &[ProbeKind::Http],
        args.http_path.is_some(),
    ));
    #[cfg(feature = "icmp")]
    flags.push(ParameterFlag::new(
        "--icmp-count".to_string(),
        &[ProbeKind::Icmp],
        args.icmp_count.is_some(),
    ));
    #[cfg(any(feature = "arp", feature = "ndp"))]
    flags.push(ParameterFlag::new(
        "--interface".to_string(),
        &[ProbeKind::Arp, ProbeKind::Ndp],
        args.interface.is_some(),
    ));
    for (kind, ports) in &args.probe_ports {
        flags.push(ParameterFlag::new(
            format!("--probe-ports {}={}", kind.label(), join_ports(ports)),
            &[*kind],
            true,
        ));
    }
    flags
}

fn unused_parameter_notes(args: &DiscoverArgs, selected: &[ProbeKind]) -> Vec<String> {
    parameter_flags(args)
        .iter()
        .filter(|flag| {
            flag.supplied
                && !flag
                    .consumers
                    .iter()
                    .any(|consumer| selected.contains(consumer))
        })
        .map(unused_flag_note)
        .collect()
}

fn unused_flag_note(flag: &ParameterFlag) -> String {
    format!(
        "{} had no effect — no {} probe in this run. Add {}.",
        flag.flag,
        join_or(flag.consumers.iter().map(|kind| kind.label().to_string())),
        join_or(
            flag.consumers
                .iter()
                .map(|kind| format!("--probe {}", kind.label()))
        ),
    )
}

fn join_or(parts: impl Iterator<Item = String>) -> String {
    parts.collect::<Vec<_>>().join(" or ")
}

fn join_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn selection_notes(args: &DiscoverArgs, selected: &SelectedProbes) -> Vec<String> {
    let mut notes: Vec<String> = selected
        .dropped
        .iter()
        .map(|kind| dropped_kind_note(*kind))
        .collect();
    notes.extend(unused_parameter_notes(args, &selected.kinds));

    if args.port.is_empty() {
        return notes;
    }

    let (port_takers, others): (Vec<ProbeKind>, Vec<ProbeKind>) = selected
        .kinds
        .iter()
        .partition(|kind| kind.consumes_shared_ports());

    if port_takers.is_empty() {
        notes.push(unused_port_note(&others));
    } else if args.probe.is_empty() && !others.is_empty() {
        notes.push(port_scope_note(&port_takers, &others));
    }
    notes
}

fn dropped_kind_note(kind: ProbeKind) -> String {
    format!(
        "{label} dropped from the default set — {reason}. Run with --probe {label} to attempt it anyway.",
        label = kind.label(),
        reason = unrunnable_reason(kind)
    )
}

fn unrunnable_reason(kind: ProbeKind) -> &'static str {
    match kind {
        ProbeKind::Icmp => "cannot open an ICMP socket here",
        _ => "its runtime precondition is not met here",
    }
}

fn port_scope_note(port_takers: &[ProbeKind], others: &[ProbeKind]) -> String {
    format!(
        "--port applies to {}; the default probe set also runs {}. Use --probe tcp_connect for a port-only scan.",
        labels(port_takers),
        labels(others)
    )
}

fn unused_port_note(kinds: &[ProbeKind]) -> String {
    format!(
        "--port had no effect — none of the selected probes ({}) read a shared port list. Use --probe-ports <kind>=<port> to retarget one.",
        labels(kinds)
    )
}

fn labels(kinds: &[ProbeKind]) -> String {
    kinds
        .iter()
        .map(|kind| kind.label())
        .collect::<Vec<_>>()
        .join(", ")
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
                links_topic: None,
                profiles_topic: None,
                flush_mode,
                dead_letter: None,
                tls: None,
                sasl: None,
                retry: rastreo_core::SinkRetry::default(),
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
    use super::super::output::RecordDestination;
    use super::*;
    use rastreo_core::{MapEnv, ProberConfig};
    use std::net::Ipv4Addr;

    fn parse_args<I, S>(argv: I) -> std::result::Result<DiscoverArgs, clap::Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<std::ffi::OsString> + Clone,
    {
        crate::cli::parse_without_env(argv)
    }

    #[test]
    fn render_error_chain_flattens_every_level_onto_one_line() {
        use rastreo_core::{SinkError, SinkErrorClass};
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "No such file or directory");
        let err = RastreoError::Sink(SinkError::new(SinkErrorClass::Other, io));
        assert_eq!(
            render_error_chain(&err),
            "output sink failed: No such file or directory"
        );
    }

    #[test]
    fn render_error_chain_of_a_sourceless_error_is_its_display() {
        let err = RastreoError::Config(rastreo_core::ConfigError::EmptyProbeSelection);
        assert_eq!(render_error_chain(&err), "no probe kinds selected");
    }

    fn args(target: &[&str], port: &[u16]) -> DiscoverArgs {
        DiscoverArgs {
            target: target.iter().map(|s| s.to_string()).collect(),
            port: port.to_vec(),
            probe: Vec::new(),
            probe_ports: Vec::new(),
            udp_protocol: None,
            dns_query: Vec::new(),
            dns_query_type: None,
            #[cfg(feature = "snmp")]
            snmp_community: None,
            #[cfg(feature = "snmp")]
            snmp_version: None,
            #[cfg(feature = "http")]
            http_path: None,
            #[cfg(feature = "icmp")]
            icmp_count: None,
            #[cfg(any(feature = "arp", feature = "ndp"))]
            interface: None,
            #[cfg(feature = "config")]
            file: None,
            sink: None,
            output: None,
            #[cfg(feature = "kafka")]
            brokers: Vec::new(),
            #[cfg(feature = "kafka")]
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
            dry_run_format: None,
            format: None,
            checkpoint: None,
            checkpoint_interval: None,
            resume: false,
            run_report: None,
        }
    }

    fn tcp_args(target: &[&str], port: &[u16]) -> DiscoverArgs {
        let mut a = args(target, port);
        a.probe = vec!["tcp_connect".to_string()];
        a
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
        let a = tcp_args(&["10.0.0.1"], &[22, 80]);
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
        let result = parse_args([
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
        let result = parse_args([
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
        let parsed = parse_args([
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
    fn discover_rejects_checkpoint_interval_zero() {
        let result = parse_args([
            "discover",
            "--target",
            "127.0.0.1",
            "--port",
            "80",
            "--checkpoint",
            "/tmp/ck.json",
            "--checkpoint-interval",
            "0",
        ]);
        assert!(
            result.is_err(),
            "expected --checkpoint-interval 0 to be rejected"
        );
    }

    #[test]
    fn discover_rejects_checkpoint_interval_without_checkpoint() {
        let result = parse_args([
            "discover",
            "--target",
            "127.0.0.1",
            "--port",
            "80",
            "--checkpoint-interval",
            "100",
        ]);
        let err =
            result.expect_err("--checkpoint-interval without --checkpoint should be rejected");
        assert!(
            err.to_string().contains("--checkpoint"),
            "clap error should name the missing --checkpoint: {err}"
        );
    }

    #[test]
    fn checkpoint_config_is_none_without_the_flag() {
        assert!(checkpoint_config(&args(&["127.0.0.1"], &[80])).is_none());
    }

    #[test]
    fn checkpoint_config_defaults_interval_when_only_path_set() {
        let mut a = args(&["127.0.0.1"], &[80]);
        a.checkpoint = Some(PathBuf::from("/tmp/ck.json"));
        let config = checkpoint_config(&a).expect("checkpoint set");
        assert_eq!(config.path, PathBuf::from("/tmp/ck.json"));
        assert_eq!(config.interval, DEFAULT_CHECKPOINT_INTERVAL);
    }

    #[test]
    fn checkpoint_config_uses_explicit_interval() {
        let mut a = args(&["127.0.0.1"], &[80]);
        a.checkpoint = Some(PathBuf::from("/tmp/ck.json"));
        a.checkpoint_interval = Some(250);
        assert_eq!(checkpoint_config(&a).expect("set").interval, 250);
    }

    #[test]
    fn checkpoint_config_carries_resume_flag() {
        let mut a = args(&["127.0.0.1"], &[80]);
        a.checkpoint = Some(PathBuf::from("/tmp/ck.json"));
        a.resume = true;
        assert!(checkpoint_config(&a).expect("set").resume);
    }

    #[test]
    fn checkpoint_config_defaults_resume_to_false() {
        let mut a = args(&["127.0.0.1"], &[80]);
        a.checkpoint = Some(PathBuf::from("/tmp/ck.json"));
        assert!(!checkpoint_config(&a).expect("set").resume);
    }

    fn report_of(entries: usize) -> RunReport {
        let scenarios = (0..entries)
            .map(|i| {
                ScenarioReport::new(
                    format!("s{i}"),
                    ScenarioOutcome::Completed,
                    Some(DiscoverySummary::default()),
                )
            })
            .collect();
        RunReport::new(scenarios, entries, DiscoverySummary::default())
    }

    #[test]
    fn a_run_that_reached_no_scenario_writes_no_report() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("run.json");
        write_run_report(Some(&path), &report_of(0)).expect("a scenario-less run reports nothing");
        assert!(!path.exists());
    }

    #[test]
    fn a_run_that_reached_a_scenario_writes_the_report() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("run.json");
        write_run_report(Some(&path), &report_of(1)).expect("write");
        assert!(path.exists());
    }

    #[test]
    fn no_report_path_writes_nothing_anywhere() {
        write_run_report(None, &report_of(1)).expect("an absent flag is not a failure");
    }

    #[test]
    fn an_unwritable_report_path_fails_the_run() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing").join("run.json");
        let err = write_run_report(Some(&path), &report_of(1)).expect_err("no such directory");
        assert!(
            err.to_string().contains("run report"),
            "the failure names what could not be written: {err}"
        );
    }

    #[test]
    fn a_scan_that_failed_keeps_its_diagnosis_when_the_report_could_not_be_written() {
        let err = run_outcome(
            Err(anyhow!("every target is unresolvable")),
            Err(anyhow!("run report could not be written to /nope/run.json")),
        )
        .expect_err("the run failed");
        assert!(
            err.to_string().contains("every target is unresolvable"),
            "the scan's own failure is what the operator reads: {err}"
        );
    }

    #[test]
    fn a_clean_scan_fails_on_a_report_it_could_not_write() {
        let err = run_outcome(
            Ok(()),
            Err(anyhow!("run report could not be written to /nope/run.json")),
        )
        .expect_err("a report the operator asked for and did not get is a failure");
        assert!(err.to_string().contains("run report"), "{err}");
    }

    #[test]
    fn a_clean_scan_that_wrote_its_report_succeeds() {
        assert!(run_outcome(Ok(()), Ok(())).is_ok());
    }

    #[test]
    fn an_entry_is_named_completed_only_when_its_scan_returned_ok() {
        assert_eq!(outcome_of(&Ok(())), ScenarioOutcome::Completed);
        assert_eq!(
            outcome_of(&Err(anyhow!("nothing to probe"))),
            ScenarioOutcome::Failed
        );
    }

    #[cfg(feature = "config")]
    #[test]
    fn a_report_path_is_legal_beside_a_scenario_file() {
        let argv = [
            "discover",
            "--file",
            "/tmp/x.yml",
            "--run-report",
            "/tmp/r.json",
        ];
        assert!(parse_args(argv).is_ok());
    }

    #[test]
    fn a_dry_run_refuses_a_report_path() {
        let argv = [
            "discover",
            "--target",
            "127.0.0.1",
            "--dry-run",
            "--run-report",
            "/tmp/r.json",
        ];
        let err = parse_args(argv).expect_err("a rehearsal produces no summary to report");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[cfg(feature = "config")]
    fn scenario_file_of(scenarios: usize) -> ScenarioFile {
        let mut yaml = String::from("version: 1\nkind: discovery\nscenarios:\n");
        for i in 0..scenarios {
            yaml.push_str(&format!("  - signal_type: discover\n    name: s{i}\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n"));
        }
        parse_scenario_file(&yaml, &MapEnv::new()).expect("parse scenario file")
    }

    #[cfg(feature = "config")]
    fn checkpoint_args(resume: bool) -> DiscoverArgs {
        let mut a = args(&["127.0.0.1"], &[80]);
        a.checkpoint = Some(PathBuf::from("/tmp/ck.json"));
        a.resume = resume;
        a
    }

    #[cfg(feature = "config")]
    #[test]
    fn a_multi_scenario_checkpoint_is_refused_whether_or_not_resume_was_asked_for() {
        for resume in [false, true] {
            let err = ensure_checkpoint_is_single_scenario(
                &checkpoint_args(resume),
                &scenario_file_of(2),
                Path::new("scan.yml"),
            )
            .expect_err("one checkpoint path cannot record two scenarios' progress");
            assert!(
                err.to_string()
                    .contains("--checkpoint supports a single-scenario run"),
                "{err}"
            );
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn a_single_scenario_file_accepts_a_checkpoint_request() {
        for resume in [false, true] {
            assert!(ensure_checkpoint_is_single_scenario(
                &checkpoint_args(resume),
                &scenario_file_of(1),
                Path::new("scan.yml"),
            )
            .is_ok());
        }
    }

    #[cfg(feature = "config")]
    #[test]
    fn a_multi_scenario_file_asking_for_no_checkpoint_is_accepted() {
        assert!(ensure_checkpoint_is_single_scenario(
            &args(&["127.0.0.1"], &[80]),
            &scenario_file_of(2),
            Path::new("scan.yml"),
        )
        .is_ok());
    }

    #[cfg(feature = "config")]
    #[test]
    fn a_file_refuses_only_once_every_one_of_its_scenarios_was_skipped() {
        let path = Path::new("scan.yml");
        assert!(ensure_not_every_scenario_was_skipped(0, 1, path).is_ok());
        assert!(ensure_not_every_scenario_was_skipped(1, 2, path).is_ok());
        let err = ensure_not_every_scenario_was_skipped(2, 2, path)
            .expect_err("a run that probed nothing did not succeed");
        assert!(err.to_string().contains("nothing to probe"), "{err}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn a_file_that_skipped_nothing_is_never_reported_as_all_skipped() {
        assert!(ensure_not_every_scenario_was_skipped(0, 0, Path::new("scan.yml")).is_ok());
    }

    #[test]
    fn discover_accepts_resume_with_checkpoint() {
        let parsed = parse_args([
            "discover",
            "--target",
            "127.0.0.1",
            "--port",
            "80",
            "--checkpoint",
            "/tmp/ck.json",
            "--resume",
        ])
        .expect("--resume with --checkpoint should parse");
        assert!(parsed.resume);
    }

    #[test]
    fn discover_rejects_resume_without_checkpoint() {
        let result = parse_args([
            "discover",
            "--target",
            "127.0.0.1",
            "--port",
            "80",
            "--resume",
        ]);
        let err = result.expect_err("--resume without --checkpoint should be rejected");
        assert!(
            err.to_string().contains("--checkpoint"),
            "clap error should name the missing --checkpoint: {err}"
        );
    }

    #[test]
    fn discover_accepts_rate_flag() {
        let parsed = parse_args([
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
        let parsed = parse_args([
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
        let parsed = parse_args([
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
        let result = parse_args([
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
        let result = parse_args([
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
        let parsed = parse_args([
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
        let parsed = parse_args(["discover", "--file", "/tmp/x.yml"]).expect("parses");
        assert_eq!(parsed.file, Some(PathBuf::from("/tmp/x.yml")));
        assert!(parsed.target.is_empty());
        assert!(parsed.port.is_empty());
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_accepts_short_f_flag() {
        let parsed = parse_args(["discover", "-f", "/tmp/x.yml"]).expect("parses");
        assert_eq!(parsed.file, Some(PathBuf::from("/tmp/x.yml")));
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_rejects_file_and_target_together() {
        let result = parse_args(["discover", "--file", "/tmp/x.yml", "--target", "127.0.0.1"]);
        assert!(result.is_err(), "expected --file + --target to be rejected");
    }

    #[cfg(feature = "config")]
    #[test]
    fn parse_rejects_file_and_port_together() {
        let result = parse_args(["discover", "--file", "/tmp/x.yml", "--port", "80"]);
        assert!(result.is_err(), "expected --file + --port to be rejected");
    }

    #[test]
    fn parse_rejects_neither_file_nor_target() {
        let result = parse_args(["discover"]);
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
        apply_cli_overrides(&mut base, &a, None, None);
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
        apply_cli_overrides(&mut base, &a, None, None);
        assert_eq!(base.probe_rate, Some(200));
    }

    #[cfg(feature = "config")]
    #[test]
    fn apply_cli_overrides_sets_retries_from_retries_flag() {
        let mut base = BaseProbeConfig::new();
        base.retries = Some(1);
        let mut a = args(&[], &[]);
        a.retries = Some(4);
        apply_cli_overrides(&mut base, &a, None, None);
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
        apply_cli_overrides(&mut base, &a, Some(&new_sink), None);
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
        let result = parse_args([
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
        let parsed = parse_args([
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
            parse_args(["discover", "--target", "127.0.0.1", "--port", "22"]).expect("parses");
        assert!(!parsed.dry_run);
    }

    #[test]
    fn the_dry_run_plan_is_text_unless_json_is_asked_for() {
        let parsed = parse_args([
            "discover",
            "--target",
            "127.0.0.1",
            "--port",
            "22",
            "--dry-run",
        ])
        .expect("parses");
        assert_eq!(dry_run_plan_format(&parsed), OutputFormat::Table);
    }

    fn parse_with_dry_run_format(value: &str) -> DiscoverArgs {
        parse_args([
            "discover",
            "--target",
            "127.0.0.1",
            "--port",
            "22",
            "--dry-run",
            "--dry-run-format",
            value,
        ])
        .expect("the retired flag still parses so the run can name its replacement")
    }

    #[test]
    fn the_retired_dry_run_format_flag_points_at_the_format_it_became() {
        for (retired, replacement) in [("text", "--format table"), ("json", "--format json")] {
            let err = ensure_no_retired_flags(&parse_with_dry_run_format(retired))
                .expect_err("--dry-run-format no longer drives anything");
            let msg = format!("{err}");
            assert!(msg.contains("--dry-run-format"), "msg: {msg}");
            assert!(msg.contains(replacement), "msg: {msg}");
        }
    }

    #[test]
    fn a_run_without_the_retired_flag_is_accepted() {
        ensure_no_retired_flags(&args(&["127.0.0.1"], &[])).expect("nothing to reject");
    }

    #[test]
    fn the_retired_dry_run_format_flag_is_hidden_from_help() {
        use clap::CommandFactory as _;

        let command = DiscoverArgs::command();
        let arg = command
            .get_arguments()
            .find(|arg| arg.get_id() == "dry_run_format")
            .expect("the retired flag is still declared");
        assert!(arg.is_hide_set(), "a retired flag is not a documented one");
    }

    #[tokio::test]
    async fn render_dry_run_text_matches_legacy_primitive_output() {
        let mut a = args(&["127.0.0.1"], &[22, 80]);
        a.dry_run = true;
        let scenario = build_scenario(&a).expect("scenario");
        let resolver = HickoryResolver::from_system().expect("resolver");
        let resolution = resolve_scenario(&resolver, &scenario.targets).await;

        let mut legacy = String::new();
        write_dry_run_header(&mut legacy, 1);
        let probes =
            write_scenario_plan(&mut legacy, "discovery", &scenario, &resolution, &a).await;
        write_totals(&mut legacy, 1, probes);

        let plan = build_resolved_plan("discovery", &scenario, &resolution, &a)
            .await
            .expect("plan");
        assert_eq!(render_dry_run_text(&[plan]), legacy);
    }

    #[tokio::test]
    async fn render_dry_run_json_emits_array_of_one_plan() {
        let mut a = tcp_args(&["127.0.0.1"], &[22]);
        a.dry_run = true;
        let scenario = build_scenario(&a).expect("scenario");
        let resolver = HickoryResolver::from_system().expect("resolver");
        let resolution = resolve_scenario(&resolver, &scenario.targets).await;
        let plan = build_resolved_plan("discovery", &scenario, &resolution, &a)
            .await
            .expect("plan");

        let json = render_dry_run_json(&[plan]).expect("json");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        let arr = value.as_array().expect("array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["scenario"], "discovery");
        assert_eq!(arr[0]["total_probes"], 1);
        assert_eq!(arr[0]["sink"], "stdout");
        assert_eq!(arr[0]["probers"][0], "tcp_connect (ports 22)");
    }

    #[tokio::test]
    async fn render_dry_run_json_multi_plan_is_array_in_order() {
        let a = args(&["127.0.0.1"], &[22]);
        let scenario = build_scenario(&a).expect("scenario");
        let resolution = resolution_of(&scenario).await;
        let first = build_resolved_plan("one", &scenario, &resolution, &a)
            .await
            .expect("plan");
        let second = build_resolved_plan("two", &scenario, &resolution, &a)
            .await
            .expect("plan");

        let json = render_dry_run_json(&[first, second]).expect("json");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        let arr = value.as_array().expect("array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["scenario"], "one");
        assert_eq!(arr[1]["scenario"], "two");
    }

    #[tokio::test]
    async fn render_dry_run_json_contains_no_text_prose() {
        let a = args(&["127.0.0.1"], &[22]);
        let scenario = build_scenario(&a).expect("scenario");
        let resolution = resolution_of(&scenario).await;
        let plan = build_resolved_plan("discovery", &scenario, &resolution, &a)
            .await
            .expect("plan");
        let json = render_dry_run_json(&[plan]).expect("json");
        assert!(!json.contains("[dry-run]"), "{json}");
        assert!(!json.contains("total probes:"), "{json}");
    }

    #[tokio::test]
    async fn dry_run_flag_driven_prints_plan_and_exits_ok() {
        let mut a = tcp_args(&["127.0.0.1"], &[22, 80]);
        a.dry_run = true;
        let scenario = build_scenario(&a).expect("scenario");
        let resolver = HickoryResolver::from_system().expect("resolver");
        let resolution = resolve_scenario(&resolver, &scenario.targets).await;
        let mut out = String::new();
        write_dry_run_header(&mut out, 1);
        let probes = write_scenario_plan(&mut out, "discovery", &scenario, &resolution, &a).await;
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
        assert!(resolution.refusal().is_none());
    }

    #[tokio::test]
    async fn dry_run_shows_rate_per_second_when_rate_flag_set() {
        let mut a = args(&["127.0.0.1"], &[22]);
        a.dry_run = true;
        a.rate = Some(25);
        let scenario = build_scenario(&a).expect("scenario");
        let resolver = HickoryResolver::from_system().expect("resolver");
        let resolution = resolve_scenario(&resolver, &scenario.targets).await;
        let mut out = String::new();
        write_scenario_plan(&mut out, "s", &scenario, &resolution, &a).await;
        assert!(out.contains("rate: 25/sec"), "{out}");
    }

    #[tokio::test]
    async fn dry_run_cidr_expansion_below_cutoff_lists_all_addresses() {
        let mut a = args(&["10.0.0.0/29"], &[22]);
        a.dry_run = true;
        let scenario = build_scenario(&a).expect("scenario");
        let resolver = HickoryResolver::from_system().expect("resolver");
        let resolution = resolve_scenario(&resolver, &scenario.targets).await;
        let mut out = String::new();
        write_scenario_plan(&mut out, "s", &scenario, &resolution, &a).await;
        assert!(out.contains("10.0.0.1"), "{out}");
        assert!(out.contains("10.0.0.6"), "{out}");
        assert!(!out.contains("..."), "no ellipsis under cutoff: {out}");
    }

    #[tokio::test]
    async fn dry_run_cidr_expansion_above_cutoff_uses_ellipsis_with_count() {
        let mut a = tcp_args(&["10.0.0.0/24"], &[22]);
        a.dry_run = true;
        let scenario = build_scenario(&a).expect("scenario");
        let resolver = HickoryResolver::from_system().expect("resolver");
        let resolution = resolve_scenario(&resolver, &scenario.targets).await;
        let mut out = String::new();
        let probes = write_scenario_plan(&mut out, "s", &scenario, &resolution, &a).await;
        assert_eq!(probes, 254, "1 prober × 254 hosts in /24");
        assert!(out.contains("..."), "ellipsis expected: {out}");
        assert!(out.contains("(254 addresses)"), "count expected: {out}");
    }

    #[tokio::test]
    async fn dry_run_renders_every_target_though_one_did_not_resolve() {
        let mut a = args(&["invalid.nx.does-not-exist.example", "127.0.0.1"], &[22]);
        a.dry_run = true;
        let scenario = build_scenario(&a).expect("scenario");
        let resolver = HickoryResolver::from_system().expect("resolver");
        let resolution = resolve_scenario(&resolver, &scenario.targets).await;
        let mut out = String::new();
        write_scenario_plan(&mut out, "s", &scenario, &resolution, &a).await;
        assert!(
            out.contains("invalid.nx.does-not-exist.example → <"),
            "the target that did not resolve is still listed: {out}"
        );
        assert!(out.contains("127.0.0.1 → 127.0.0.1"), "{out}");
        assert_eq!(
            resolution.refusal().is_some(),
            out.contains("<error:"),
            "a per-target error and a whole-set refusal travel together: {out}"
        );
    }

    async fn resolution_of(scenario: &DiscoverScenarioConfig) -> ScenarioResolution {
        let resolver = HickoryResolver::from_system().expect("resolver");
        resolve_scenario(&resolver, &scenario.targets).await
    }

    // Each arm is a resolver refusing for its own reason: the rehearsal reads the refusal off the
    // resolution and never matches on which one.
    #[tokio::test]
    async fn a_resolution_error_refuses_the_dry_run_whatever_variant_raised_it() {
        let bare: std::sync::Arc<dyn rastreo_core::Resolver> = std::sync::Arc::new(
            HickoryResolver::from_system()
                .expect("resolver")
                .with_limit(8),
        );
        let over_limit: Box<dyn rastreo_core::Resolver> = Box::new(
            HickoryResolver::from_system()
                .expect("resolver")
                .with_limit(8),
        );
        let capped: Box<dyn rastreo_core::Resolver> = Box::new(rastreo_core::GuardedResolver::new(
            bare.clone(),
            None,
            Some(4),
        ));
        let allowlisted: Box<dyn rastreo_core::Resolver> =
            Box::new(rastreo_core::GuardedResolver::new(
                bare,
                Some(vec!["10.0.0.0/8".parse().expect("cidr")]),
                None,
            ));
        let cases: Vec<(Box<dyn rastreo_core::Resolver>, Vec<Target>)> = vec![
            (
                over_limit,
                vec![Target::Cidr("10.0.0.0/24".parse().expect("cidr"))],
            ),
            (
                capped,
                vec![
                    Target::Cidr("10.0.0.0/30".parse().expect("cidr")),
                    Target::Cidr("10.0.1.0/30".parse().expect("cidr")),
                    Target::Cidr("10.0.2.0/30".parse().expect("cidr")),
                ],
            ),
            (
                allowlisted,
                vec![Target::Ip("203.0.113.1".parse().expect("ip"))],
            ),
        ];
        for (resolver, targets) in cases {
            let resolution = resolve_scenario(resolver.as_ref(), &targets).await;
            let expected = resolution
                .refusal()
                .expect("the resolver refused")
                .to_string();
            let refusal =
                refuse_on_resolution_error(&resolution, OutputMode::from(Verbosity::Quiet))
                    .expect_err("a resolution error the scan aborts on must refuse the rehearsal");
            assert!(
                refusal.to_string().contains(&expected),
                "the refusal must carry the resolver's own reason: {refusal}"
            );
        }
    }

    #[tokio::test]
    async fn a_fully_resolved_scenario_has_nothing_to_refuse() {
        let a = args(&["127.0.0.1"], &[22]);
        let scenario = build_scenario(&a).expect("scenario");
        let resolution = resolution_of(&scenario).await;
        refuse_on_resolution_error(&resolution, OutputMode::from(Verbosity::Quiet))
            .expect("every target resolved");
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
        let resolution = resolve_scenario(&resolver, &scenario.targets).await;
        let mut out = String::new();
        write_scenario_plan(&mut out, "s", &scenario, &resolution, &a).await;
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

    #[cfg(feature = "config")]
    #[test]
    fn scenario_plan_label_text_keeps_the_multi_scenario_decoration() {
        let mut base = BaseProbeConfig::new();
        base.name = Some("routers".into());
        assert_eq!(
            scenario_plan_label(&base, 0, 3, OutputFormat::Table),
            "'routers' (1 of 3)"
        );
    }

    #[cfg(feature = "config")]
    #[test]
    fn scenario_plan_label_json_uses_plain_name_like_the_server() {
        let mut base = BaseProbeConfig::new();
        base.name = Some("routers".into());
        assert_eq!(
            scenario_plan_label(&base, 0, 3, OutputFormat::Json),
            "routers"
        );
    }

    #[cfg(feature = "config")]
    #[test]
    fn scenario_plan_label_json_falls_back_to_unnamed_when_no_name() {
        let base = BaseProbeConfig::new();
        assert_eq!(
            scenario_plan_label(&base, 1, 2, OutputFormat::Json),
            "unnamed"
        );
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
        let mut a = tcp_args(&["127.0.0.1"], &[22]);
        a.dry_run = true;
        let scenario = build_scenario(&a).expect("scenario");
        let resolver = HickoryResolver::from_system().expect("resolver");
        let resolution = resolve_scenario(&resolver, &scenario.targets).await;
        let mut out = String::new();
        write_dry_run_header(&mut out, 1);
        let probes = write_scenario_plan(&mut out, "discovery", &scenario, &resolution, &a).await;
        write_totals(&mut out, 1, probes);
        assert!(
            out.contains("total probes: 1"),
            "single-scenario dry-run must print total probes footer: {out}"
        );
    }

    #[cfg(feature = "config")]
    fn write_scenario_file(contents: &str) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(contents.as_bytes()).expect("write scenario");
        f.flush().expect("flush scenario");
        f
    }

    #[cfg(feature = "config")]
    const TWO_SCENARIOS: &str = "version: 1
kind: discovery
scenarios:
  - signal_type: discover
    name: first
    targets:
      - Ip: \"127.0.0.1\"
    probers:
      - type: tcp_connect
        ports: [22]
  - signal_type: discover
    name: second
    targets:
      - Ip: \"127.0.0.1\"
    probers:
      - type: tcp_connect
        ports: [22]
";

    #[cfg(feature = "config")]
    #[tokio::test]
    async fn a_cancel_before_the_first_scenario_marks_the_aggregate_cancelled() {
        let file = write_scenario_file(TWO_SCENARIOS);
        let mut a = args(&[], &[]);
        a.file = Some(file.path().to_path_buf());
        let (_tx, cancel) = watch::channel(true);

        let report = run_from_file(&a, cancel, OutputMode::from(Verbosity::Normal))
            .await
            .expect("a cancelled run with no failed scenario exits ok");

        assert!(
            report.scenarios.is_empty(),
            "no scenario was reached, so no entry carries the cancellation"
        );
        assert!(
            report.aggregate.summary.cancelled,
            "a run interrupted before any scenario must not report a clean aggregate"
        );
        assert_eq!(report.aggregate.scenario_counts.total, 2);
        assert_eq!(report.aggregate.scenario_counts.completed, 0);
        assert_eq!(report.aggregate.scenario_counts.failed, 0);
    }

    #[cfg(feature = "config")]
    #[tokio::test]
    async fn an_uncancelled_run_leaves_the_aggregate_uncancelled() {
        let file = write_scenario_file(TWO_SCENARIOS);
        let records = tempfile::NamedTempFile::new().expect("tempfile");
        let mut a = args(&[], &[]);
        a.file = Some(file.path().to_path_buf());
        a.sink = Some(SinkKind::File);
        a.output = Some(records.path().to_path_buf());
        a.timeout_ms = Some(50);
        let (_tx, cancel) = watch::channel(false);

        let report = run_from_file(&a, cancel, OutputMode::from(Verbosity::Quiet))
            .await
            .expect("both scenarios run to completion against loopback");

        assert!(!report.aggregate.summary.cancelled);
        assert_eq!(report.aggregate.scenario_counts.completed, 2);
        assert_eq!(report.scenarios.len(), 2);
    }

    #[tokio::test]
    async fn dry_run_probe_count_counts_an_overlapping_address_once_per_spec() {
        let mut a = tcp_args(&["10.0.0.1", "10.0.0.0/29"], &[22]);
        a.dry_run = true;
        let scenario = build_scenario(&a).expect("scenario");
        let resolver = HickoryResolver::from_system().expect("resolver");
        let resolution = resolve_scenario(&resolver, &scenario.targets).await;
        let mut out = String::new();
        let probes = write_scenario_plan(&mut out, "s", &scenario, &resolution, &a).await;
        // /29 usable hosts: 10.0.0.1..10.0.0.6 (6), plus the explicit 10.0.0.1 the scan probes again.
        assert_eq!(
            probes, 7,
            "expected the count the scan performs, got {probes}"
        );
        assert!(out.contains("10.0.0.1 → 10.0.0.1"), "{out}");
    }

    fn prober_kinds(scenario: &DiscoverScenarioConfig) -> Vec<ProbeKind> {
        scenario
            .probers
            .iter()
            .map(|config| {
                rastreo_core::prober::create_prober(config)
                    .expect("the factory accepts every expanded config")
                    .kind()
            })
            .collect()
    }

    fn kinds_for(a: &DiscoverArgs) -> Vec<ProbeKind> {
        prober_kinds(&build_scenario(a).expect("scenario"))
    }

    fn ports_of(scenario: &DiscoverScenarioConfig, wanted: ProbeKind) -> Vec<u16> {
        let plan = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(RunOptions::new(scenario).plan(
                "s".to_string(),
                PlanKnobs {
                    max_concurrent: 1,
                    probe_rate: None,
                    retries: 0,
                    timeout_ms: 1,
                },
            ))
            .expect("plan");
        let rendered = plan
            .probers
            .iter()
            .find(|line| line.starts_with(&format!("{} (", wanted.label())))
            .unwrap_or_else(|| panic!("no {} prober in {:?}", wanted.label(), plan.probers))
            .clone();
        let inner = rendered
            .split_once("ports ")
            .unwrap_or_else(|| panic!("no port list in {rendered}"))
            .1;
        inner
            .trim_end_matches(')')
            .split(&[',', ' '][..])
            .filter(|token| !token.is_empty())
            .map_while(|token| token.parse::<u16>().ok())
            .collect()
    }

    #[test]
    fn port_is_no_longer_required_without_a_file() {
        let parsed =
            parse_args(["discover", "--target", "127.0.0.1"]).expect("--target alone must parse");
        assert!(parsed.port.is_empty());
        assert!(parsed.probe.is_empty());
    }

    #[test]
    fn omitting_probe_runs_the_zero_config_default_set() {
        let kinds = kinds_for(&args(&["10.0.0.1"], &[]));
        assert!(kinds.contains(&ProbeKind::TcpConnect), "{kinds:?}");
        assert!(kinds.contains(&ProbeKind::ReverseDns), "{kinds:?}");
        for excluded in [
            ProbeKind::Udp,
            ProbeKind::Dns,
            ProbeKind::Arp,
            ProbeKind::Ndp,
            ProbeKind::Lldp,
            ProbeKind::Gnmi,
        ] {
            assert!(
                !kinds.contains(&excluded),
                "{} must not default on: {kinds:?}",
                excluded.label()
            );
        }
    }

    #[test]
    fn probe_default_selects_exactly_what_omitting_the_flag_selects() {
        let mut explicit = args(&["10.0.0.1"], &[]);
        explicit.probe = vec!["default".to_string()];
        assert_eq!(kinds_for(&explicit), kinds_for(&args(&["10.0.0.1"], &[])));
    }

    #[test]
    fn naming_a_default_kind_before_or_after_default_yields_the_same_run() {
        let mut before = args(&["10.0.0.1"], &[]);
        before.probe = vec!["default".to_string(), "tcp_connect".to_string()];
        let mut after = args(&["10.0.0.1"], &[]);
        after.probe = vec!["tcp_connect".to_string(), "default".to_string()];
        assert_eq!(kinds_for(&before), kinds_for(&after));
        assert!(kinds_for(&before).contains(&ProbeKind::TcpConnect));
    }

    #[test]
    fn a_named_kind_outside_the_default_set_is_added_to_it() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.probe = vec!["default".to_string(), "udp".to_string()];
        a.udp_protocol = Some(UdpProtocolArg::Ntp);
        let kinds = kinds_for(&a);
        assert_eq!(kinds.first(), Some(&ProbeKind::Udp), "{kinds:?}");
        assert!(kinds.contains(&ProbeKind::TcpConnect), "{kinds:?}");
    }

    #[test]
    fn shared_ports_retarget_tcp_connect() {
        let mut a = args(&["10.0.0.1"], &[9100]);
        a.probe = vec!["tcp_connect".to_string()];
        let scenario = build_scenario(&a).expect("scenario");
        assert_eq!(ports_of(&scenario, ProbeKind::TcpConnect), vec![9100]);
    }

    #[test]
    fn shared_ports_leave_a_protocol_pinned_prober_on_its_own_port() {
        let mut a = args(&["10.0.0.1"], &[1161]);
        a.probe = vec!["dns".to_string()];
        a.dns_query = vec!["example.com.".to_string()];
        let scenario = build_scenario(&a).expect("scenario");
        assert_eq!(ports_of(&scenario, ProbeKind::Dns), vec![53]);
    }

    #[test]
    fn a_per_kind_override_retargets_a_protocol_pinned_prober() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.probe = vec!["dns".to_string()];
        a.dns_query = vec!["example.com.".to_string()];
        a.probe_ports = vec![(ProbeKind::Dns, vec![5353])];
        let scenario = build_scenario(&a).expect("scenario");
        assert_eq!(ports_of(&scenario, ProbeKind::Dns), vec![5353]);
    }

    #[test]
    fn a_per_kind_override_beats_the_shared_port_list() {
        let mut a = args(&["10.0.0.1"], &[9100]);
        a.probe = vec!["tcp_connect".to_string()];
        a.probe_ports = vec![(ProbeKind::TcpConnect, vec![2222])];
        let scenario = build_scenario(&a).expect("scenario");
        assert_eq!(ports_of(&scenario, ProbeKind::TcpConnect), vec![2222]);
    }

    #[test]
    fn an_unknown_probe_kind_is_rejected_and_lists_what_this_build_offers() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.probe = vec!["nonsense".to_string()];
        let err = build_scenario(&a).expect_err("unknown kind");
        assert!(matches!(
            err.downcast_ref::<RastreoError>(),
            Some(RastreoError::Config(ConfigError::UnknownProbeKind { .. }))
        ));
        assert!(format!("{err}").contains("tcp_connect"), "err: {err}");
    }

    #[test]
    fn udp_without_a_protocol_is_rejected_before_any_probe() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.probe = vec!["udp".to_string()];
        let err = build_scenario(&a).expect_err("udp needs a protocol");
        assert!(matches!(
            err.downcast_ref::<RastreoError>(),
            Some(RastreoError::Config(ConfigError::ProbeKindMissingParam {
                kind: "udp",
                ..
            }))
        ));
    }

    #[test]
    fn dns_without_a_query_name_is_rejected_before_any_probe() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.probe = vec!["dns".to_string()];
        let err = build_scenario(&a).expect_err("dns needs a query name");
        assert!(matches!(
            err.downcast_ref::<RastreoError>(),
            Some(RastreoError::Config(ConfigError::ProbeKindMissingParam {
                kind: "dns",
                ..
            }))
        ));
    }

    #[test]
    fn the_missing_param_hint_names_the_flag_core_deliberately_does_not() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.probe = vec!["udp".to_string()];
        let err = build_scenario(&a).expect_err("udp needs a protocol");
        assert!(
            !format!("{err}").contains("--udp-protocol"),
            "core must stay flag-agnostic: {err}"
        );
        let hint = probe_selection_hint(&err).expect("hint");
        assert!(hint.contains("--udp-protocol"), "hint: {hint}");
    }

    #[test]
    fn the_dns_missing_param_hint_names_the_query_flag() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.probe = vec!["dns".to_string()];
        let hint =
            probe_selection_hint(&build_scenario(&a).expect_err("dns needs a name")).expect("hint");
        assert!(hint.contains("--dns-query"), "hint: {hint}");
    }

    #[test]
    fn the_not_compiled_hint_names_the_feature_and_the_rebuild_route() {
        let err = anyhow::Error::new(RastreoError::Config(ConfigError::ProbeKindNotCompiled {
            kind: "gnmi",
            feature: "gnmi",
        }));
        let hint = probe_selection_hint(&err).expect("hint");
        assert!(hint.contains("--features gnmi"), "hint: {hint}");
        assert!(hint.contains("Docker image"), "hint: {hint}");
    }

    #[test]
    fn an_unknown_kind_gets_no_hint_because_the_error_already_lists_the_options() {
        let err = anyhow::Error::new(RastreoError::Config(ConfigError::UnknownProbeKind {
            name: "nonsense".into(),
            available: "tcp_connect".into(),
        }));
        assert!(probe_selection_hint(&err).is_none());
    }

    #[test]
    fn a_non_selection_error_gets_no_selection_hint() {
        assert!(probe_selection_hint(&anyhow!("--sink file requires --output <path>")).is_none());
    }

    fn missing_checkpoint() -> RastreoError {
        RastreoError::Resume(ResumeError::NoCheckpointToResume {
            path: PathBuf::from("/var/lib/rastreo/scan.checkpoint"),
        })
    }

    #[test]
    fn the_missing_checkpoint_hint_names_the_flag_core_deliberately_does_not() {
        let err = missing_checkpoint();
        assert!(
            !render_error_chain(&err).contains("--resume"),
            "core must stay flag-agnostic: {err}"
        );
        let hint = scan_error_hint(&err).expect("hint");
        assert!(hint.contains("--resume"), "hint: {hint}");
    }

    #[test]
    fn the_missing_checkpoint_error_still_names_the_path_it_looked_at() {
        assert!(
            render_error_chain(&missing_checkpoint()).contains("/var/lib/rastreo/scan.checkpoint")
        );
    }

    #[test]
    fn a_resume_refusal_the_cli_cannot_improve_on_gets_no_hint() {
        assert!(scan_error_hint(&RastreoError::Resume(ResumeError::FingerprintMismatch)).is_none());
    }

    #[test]
    fn scan_error_hint_still_reaches_the_string_matched_resolver_hints() {
        let err = RastreoError::Resolver(rastreo_core::ResolverError::DnsNoRecords {
            name: "missing.lab".into(),
        });
        let hint = scan_error_hint(&err).expect("hint");
        assert!(hint.contains("DNS resolution failed"), "hint: {hint}");
    }

    #[test]
    fn a_dry_run_puts_its_plan_on_stdout_whatever_the_sink() {
        let mut a = args(&["10.0.0.1"], &[80]);
        a.dry_run = true;
        a.sink = Some(SinkKind::File);
        a.output = Some(PathBuf::from("/tmp/records.ndjson"));
        assert!(stdout_carries_the_payload(&a));
    }

    #[test]
    fn a_file_sink_run_leaves_stdout_empty() {
        let mut a = args(&["10.0.0.1"], &[80]);
        a.sink = Some(SinkKind::File);
        a.output = Some(PathBuf::from("/tmp/records.ndjson"));
        assert!(!stdout_carries_the_payload(&a));
    }

    #[test]
    fn a_flag_driven_run_defaults_its_records_onto_stdout() {
        assert!(stdout_carries_the_payload(&args(&["10.0.0.1"], &[80])));
    }

    #[cfg(feature = "config")]
    #[test]
    fn a_file_run_counts_as_stdout_until_the_scenario_names_its_sink() {
        let mut a = args(&[], &[]);
        a.file = Some(PathBuf::from("scan.yml"));
        assert!(stdout_carries_the_payload(&a));
    }

    #[test]
    fn a_scenario_naming_a_file_sink_takes_its_advisories_off_the_record_stream() {
        let merged = OutputMode::new(Verbosity::Normal, true)
            .with_record_destination(RecordDestination::SharedCapture);
        let refined = mode_for_sink(
            merged,
            Some(&SinkConfig::File {
                path: PathBuf::from("/tmp/records.ndjson"),
            }),
        );
        assert!(!merged.prints_advisories());
        assert!(refined.prints_advisories());
    }

    #[test]
    fn a_scenario_naming_no_sink_is_judged_as_the_stdout_sink_core_defaults_to() {
        let mode = OutputMode::from(Verbosity::Normal);
        assert_eq!(
            mode_for_sink(mode, None),
            mode_for_sink(mode, Some(&SinkConfig::Stdout))
        );
    }

    fn quiet() -> OutputMode {
        OutputMode::from(Verbosity::Quiet)
    }

    #[test]
    fn a_target_set_with_one_address_between_them_is_not_refused() {
        assert!(refuse_nothing_to_probe(2, &["stale.lab".to_string()], quiet()).is_ok());
    }

    #[test]
    fn a_target_set_whose_every_member_has_no_addresses_is_refused_by_name() {
        let err = refuse_nothing_to_probe(
            2,
            &["stale.lab".to_string(), "gone.lab".to_string()],
            quiet(),
        )
        .expect_err("a scan that probed nothing did not succeed");
        assert!(err.to_string().contains("stale.lab, gone.lab"), "{err}");
    }

    #[test]
    fn a_target_set_that_wholly_resolved_is_never_refused() {
        assert!(refuse_nothing_to_probe(2, &[], quiet()).is_ok());
    }

    #[test]
    fn the_refusal_and_its_hint_hold_for_a_target_no_lookup_was_performed_on() {
        let err = refuse_nothing_to_probe(1, &["192.168.1.1:80".to_string()], quiet())
            .expect_err("a scan that probed nothing did not succeed");
        let refusal = err.to_string().to_lowercase();
        assert!(refusal.contains("192.168.1.1:80"), "{refusal}");
        assert!(
            !refusal.contains("resolved to") && !refusal.contains("answered"),
            "a target that was never looked up neither resolved nor answered: {refusal}"
        );
        let hint = NOTHING_TO_PROBE_HINT.to_lowercase();
        assert!(
            hint.contains("dns query can carry"),
            "the hint must name the kind of target no lookup was performed for: {hint}"
        );
    }

    #[test]
    fn the_refusal_reads_the_target_set_rather_than_a_host_count() {
        let unresolvable = ["stale.lab".to_string()];
        assert!(refuse_nothing_to_probe(1, &unresolvable, quiet()).is_err());
        assert!(refuse_nothing_to_probe(2, &unresolvable, quiet()).is_ok());
    }

    #[test]
    fn a_kind_with_no_runtime_precondition_is_always_runnable() {
        assert!(runnability_check(ProbeKind::TcpConnect).is_none());
        assert!(probe_is_runnable(ProbeKind::TcpConnect));
        assert!(runnability_check(ProbeKind::ReverseDns).is_none());
        assert!(probe_is_runnable(ProbeKind::ReverseDns));
    }

    #[cfg(feature = "icmp")]
    #[test]
    fn icmp_declares_a_runnability_check() {
        assert!(
            runnability_check(ProbeKind::Icmp).is_some(),
            "icmp must be checked against the prober's own capability probe"
        );
    }

    #[cfg(feature = "icmp")]
    #[test]
    fn icmp_runnability_is_the_probers_own_capability_check() {
        assert_eq!(
            probe_is_runnable(ProbeKind::Icmp),
            rastreo_core::IcmpProber::is_runnable()
        );
    }

    #[test]
    fn the_selection_honours_the_runnability_predicate() {
        let expected = apply_runnability_filter(
            parse_probe_selection(&[DEFAULT_PROBE_TOKEN.to_string()]).expect("parses"),
            |_| false,
        );
        let selected =
            select_probe_kinds_with(&args(&["10.0.0.1"], &[]), |_| false).expect("selects");
        assert_eq!(selected.kinds, expected);
    }

    #[test]
    fn dropped_holds_every_default_kind_the_predicate_rejected() {
        let expected: Vec<ProbeKind> = rastreo_core::prober::default_probe_kinds()
            .into_iter()
            .filter(|kind| {
                !apply_runnability_filter(
                    parse_probe_selection(&[DEFAULT_PROBE_TOKEN.to_string()]).expect("parses"),
                    |_| false,
                )
                .contains(kind)
            })
            .collect();
        let selected =
            select_probe_kinds_with(&args(&["10.0.0.1"], &[]), |_| false).expect("selects");
        assert_eq!(selected.dropped, expected);
    }

    #[test]
    fn an_explicitly_named_kind_survives_a_predicate_that_rejects_it() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.probe = vec!["default".to_string(), "icmp".to_string()];
        let selected = select_probe_kinds_with(&a, |_| false).expect("selects");
        assert_eq!(selected.kinds.first(), Some(&ProbeKind::Icmp));
        assert!(!selected.dropped.contains(&ProbeKind::Icmp));
    }

    fn selected(kinds: &[ProbeKind], dropped: &[ProbeKind]) -> SelectedProbes {
        SelectedProbes {
            kinds: kinds.to_vec(),
            dropped: dropped.to_vec(),
        }
    }

    #[test]
    fn a_dropped_default_kind_is_reported_with_the_flag_that_forces_it() {
        let notes = selection_notes(
            &args(&["10.0.0.1"], &[]),
            &selected(&[ProbeKind::TcpConnect], &[ProbeKind::Icmp]),
        );
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].starts_with("icmp dropped from the default set"),
            "{notes:?}"
        );
        assert!(notes[0].contains("ICMP socket"), "{notes:?}");
        assert!(notes[0].contains("--probe icmp"), "{notes:?}");
    }

    #[test]
    fn nothing_dropped_and_no_port_produces_no_notes() {
        let notes = selection_notes(
            &args(&["10.0.0.1"], &[]),
            &selected(&[ProbeKind::TcpConnect, ProbeKind::ReverseDns], &[]),
        );
        assert!(notes.is_empty(), "{notes:?}");
    }

    #[test]
    fn port_without_probe_reports_which_probers_it_reaches() {
        let notes = selection_notes(
            &args(&["10.0.0.1"], &[8080]),
            &selected(&[ProbeKind::TcpConnect, ProbeKind::ReverseDns], &[]),
        );
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].contains("--port applies to tcp_connect;"),
            "{notes:?}"
        );
        assert!(notes[0].contains("also runs reverse_dns"), "{notes:?}");
        assert!(notes[0].contains("--probe tcp_connect"), "{notes:?}");
    }

    #[test]
    fn port_with_an_explicit_probe_skips_the_scope_note() {
        let mut a = args(&["10.0.0.1"], &[8080]);
        a.probe = vec!["tcp_connect".to_string(), "reverse_dns".to_string()];
        let notes = selection_notes(
            &a,
            &selected(&[ProbeKind::TcpConnect, ProbeKind::ReverseDns], &[]),
        );
        assert!(notes.is_empty(), "{notes:?}");
    }

    #[test]
    fn port_that_reaches_no_selected_prober_is_reported_as_a_no_op() {
        let mut a = args(&["10.0.0.1"], &[1161]);
        a.probe = vec!["reverse_dns".to_string()];
        let notes = selection_notes(&a, &selected(&[ProbeKind::ReverseDns], &[]));
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("--port had no effect"), "{notes:?}");
        assert!(notes[0].contains("(reverse_dns)"), "{notes:?}");
        assert!(notes[0].contains("--probe-ports"), "{notes:?}");
    }

    #[test]
    fn a_dropped_kind_is_reported_alongside_a_port_note() {
        let notes = selection_notes(
            &args(&["10.0.0.1"], &[8080]),
            &selected(
                &[ProbeKind::TcpConnect, ProbeKind::ReverseDns],
                &[ProbeKind::Icmp],
            ),
        );
        assert_eq!(notes.len(), 2, "{notes:?}");
        assert!(notes[0].starts_with("icmp"), "{notes:?}");
        assert!(notes[1].starts_with("--port applies"), "{notes:?}");
    }

    fn args_with_every_parameter_flag() -> DiscoverArgs {
        let mut a = args(&["10.0.0.1"], &[]);
        a.udp_protocol = Some(UdpProtocolArg::Ntp);
        a.dns_query = vec!["example.com".to_string()];
        a.dns_query_type = Some(DnsQueryTypeArg::Mx);
        #[cfg(feature = "snmp")]
        {
            a.snmp_community = Some(Community("lab-ro".to_string()));
            a.snmp_version = Some(SnmpVersionArg::V1);
        }
        #[cfg(feature = "http")]
        {
            a.http_path = Some("/health".to_string());
        }
        #[cfg(feature = "icmp")]
        {
            a.icmp_count = Some(5);
        }
        #[cfg(any(feature = "arp", feature = "ndp"))]
        {
            a.interface = Some("eth0".to_string());
        }
        a.probe_ports = vec![(ProbeKind::Dns, vec![5353])];
        a
    }

    #[test]
    fn every_parameter_flag_reads_as_supplied_when_it_is_set() {
        for flag in parameter_flags(&args_with_every_parameter_flag()) {
            assert!(flag.supplied, "{} was set but reads as absent", flag.flag);
        }
    }

    #[test]
    fn no_parameter_flag_reads_as_supplied_on_bare_arguments() {
        for flag in parameter_flags(&args(&["10.0.0.1"], &[])) {
            assert!(
                !flag.supplied,
                "{} reads as supplied without being set",
                flag.flag
            );
        }
    }

    #[test]
    fn every_parameter_flag_names_a_kind_this_build_carries() {
        for flag in parameter_flags(&args_with_every_parameter_flag()) {
            assert!(
                !flag.consumers.is_empty(),
                "{} names no compiled-in consumer, so its note would name no kind",
                flag.flag
            );
        }
    }

    #[test]
    fn every_supplied_parameter_flag_whose_kinds_are_all_absent_is_reported() {
        let mut a = args_with_every_parameter_flag();
        a.probe = vec!["reverse_dns".to_string()];
        let notes = selection_notes(&a, &selected(&[ProbeKind::ReverseDns], &[]));
        for flag in parameter_flags(&a) {
            let opener = format!("{} had no effect", flag.flag);
            let note = notes
                .iter()
                .find(|note| note.starts_with(&opener))
                .unwrap_or_else(|| panic!("{} is silently ignored: {notes:?}", flag.flag));
            for consumer in &flag.consumers {
                assert!(note.contains(consumer.label()), "{note}");
                assert!(
                    note.contains(&format!("--probe {}", consumer.label())),
                    "{note}"
                );
            }
        }
    }

    #[test]
    fn a_parameter_flag_whose_kind_runs_produces_no_note() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.probe = vec!["dns".to_string()];
        a.dns_query = vec!["example.com".to_string()];
        a.dns_query_type = Some(DnsQueryTypeArg::Mx);
        let notes = selection_notes(&a, &selected(&[ProbeKind::Dns], &[]));
        assert!(notes.is_empty(), "{notes:?}");
    }

    #[test]
    fn a_per_kind_port_override_for_an_unselected_kind_is_reported_with_its_value() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.probe = vec!["tcp_connect".to_string()];
        a.probe_ports = vec![(ProbeKind::Dns, vec![5353, 15353])];
        let notes = selection_notes(&a, &selected(&[ProbeKind::TcpConnect], &[]));
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].starts_with("--probe-ports dns=5353,15353 had no effect"),
            "{notes:?}"
        );
        assert!(notes[0].contains("--probe dns"), "{notes:?}");
    }

    #[test]
    fn a_per_kind_port_override_for_a_selected_kind_produces_no_note() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.probe = vec!["tcp_connect".to_string()];
        a.probe_ports = vec![(ProbeKind::TcpConnect, vec![2222])];
        let notes = selection_notes(&a, &selected(&[ProbeKind::TcpConnect], &[]));
        assert!(notes.is_empty(), "{notes:?}");
    }

    #[cfg(all(feature = "arp", feature = "ndp"))]
    #[test]
    fn a_parameter_flag_with_two_consumers_names_both() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.probe = vec!["tcp_connect".to_string()];
        a.interface = Some("eth0".to_string());
        let notes = selection_notes(&a, &selected(&[ProbeKind::TcpConnect], &[]));
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("no arp or ndp probe"), "{notes:?}");
        assert!(notes[0].contains("--probe arp or --probe ndp"), "{notes:?}");
    }

    #[test]
    fn every_per_prober_parameter_argument_is_covered_by_the_unused_flag_table() {
        use clap::CommandFactory as _;

        // --port is excluded because its remedy is --probe-ports, so it keeps bespoke notes.
        const NOT_A_PER_PROBER_PARAMETER: &[&str] = &[
            "help",
            "target",
            "probe",
            "port",
            "file",
            "format",
            "sink",
            "output",
            "brokers",
            "topic",
            "kafka_flush_per_record",
            "kafka_batch_threshold",
            "concurrency",
            "rate",
            "retries",
            "timeout_ms",
            "dry_run",
            "dry_run_format",
            "checkpoint",
            "checkpoint_interval",
            "resume",
            "run_report",
        ];

        let covered: Vec<String> = parameter_flags(&args_with_every_parameter_flag())
            .into_iter()
            .map(|flag| flag.flag)
            .collect();
        for arg in DiscoverArgs::command().get_arguments() {
            let id = arg.get_id().as_str();
            if NOT_A_PER_PROBER_PARAMETER.contains(&id) {
                continue;
            }
            let long = format!(
                "--{}",
                arg.get_long()
                    .unwrap_or_else(|| panic!("{id} has no long form"))
            );
            let with_value = format!("{long} ");
            assert!(
                covered
                    .iter()
                    .any(|flag| *flag == long || flag.starts_with(&with_value)),
                "{long} parameterises a prober but is missing from the unused-flag table, so it \
                 would be discarded in silence when its kind does not run"
            );
        }
    }

    #[test]
    fn a_per_kind_port_override_is_accepted_exactly_when_the_kind_is_compiled_in() {
        for kind in ProbeKind::all() {
            let mut a = args(&["10.0.0.1"], &[]);
            a.probe_ports = vec![(*kind, vec![1234])];
            match reject_uncompiled_probe_ports(&a) {
                Ok(()) => assert!(
                    kind.is_compiled_in(),
                    "{} is not in this build",
                    kind.label()
                ),
                Err(err) => {
                    assert!(!kind.is_compiled_in(), "{} is in this build", kind.label());
                    let msg = err.to_string();
                    assert!(msg.contains(kind.label()), "{msg}");
                    if let Some(feature) = kind.required_feature() {
                        assert!(msg.contains(feature), "{msg}");
                    }
                }
            }
        }
    }

    #[test]
    fn probe_options_carry_the_shared_and_per_kind_ports() {
        let mut a = args(&["10.0.0.1"], &[9100, 9200]);
        a.probe_ports = vec![(ProbeKind::Dns, vec![5353])];
        let options = probe_options(&a, &MapEnv::new());
        assert_eq!(options.ports, vec![9100, 9200]);
        assert_eq!(
            options.ports_by_kind.get(&ProbeKind::Dns),
            Some(&vec![5353])
        );
    }

    #[test]
    fn probe_options_carry_the_dns_query_names_and_type() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.dns_query = vec!["example.com.".to_string()];
        a.dns_query_type = Some(DnsQueryTypeArg::Mx);
        let options = probe_options(&a, &MapEnv::new());
        assert_eq!(options.dns_query_names, vec!["example.com.".to_string()]);
        assert_eq!(
            options.dns_query_type,
            rastreo_core::prober::DnsQueryType::Mx
        );
    }

    #[test]
    fn probe_options_leave_unset_flags_on_the_core_defaults() {
        let options = probe_options(&args(&["10.0.0.1"], &[]), &MapEnv::new());
        let defaults = ProbeSelectionOptions::default();
        assert!(options.ports.is_empty());
        assert!(options.ports_by_kind.is_empty());
        assert!(options.udp_protocol.is_none());
        assert_eq!(options.http_path, defaults.http_path);
        assert_eq!(options.icmp_count, defaults.icmp_count);
        assert_eq!(options.interface, defaults.interface);
    }

    #[test]
    fn probe_options_carry_the_udp_protocol() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.udp_protocol = Some(UdpProtocolArg::MemcachedStats);
        assert_eq!(
            probe_options(&a, &MapEnv::new()).udp_protocol,
            Some(rastreo_core::prober::UdpProtocol::MemcachedStats)
        );
    }

    #[cfg(feature = "snmp")]
    fn snmp_community_env(value: Option<&str>) -> MapEnv {
        match value {
            Some(value) => MapEnv::new().set(SNMP_COMMUNITY_ENV, value),
            None => MapEnv::new(),
        }
    }

    #[cfg(feature = "snmp")]
    #[test]
    fn probe_options_carry_the_snmp_community_and_version() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.snmp_community = Some(Community("lab-ro".to_string()));
        a.snmp_version = Some(SnmpVersionArg::V1);
        let options = probe_options(&a, &snmp_community_env(None));
        assert_eq!(&*options.snmp_community, "lab-ro");
        assert_eq!(options.snmp_version, rastreo_core::prober::SnmpVersion::V1);
    }

    #[cfg(feature = "snmp")]
    #[test]
    fn the_snmp_community_falls_back_to_the_environment() {
        let a = args(&["10.0.0.1"], &[]);
        let options = probe_options(&a, &snmp_community_env(Some("from-env")));
        assert_eq!(&*options.snmp_community, "from-env");
    }

    #[cfg(feature = "snmp")]
    #[test]
    fn the_snmp_community_flag_beats_the_environment() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.snmp_community = Some(Community("from-flag".to_string()));
        let options = probe_options(&a, &snmp_community_env(Some("from-env")));
        assert_eq!(&*options.snmp_community, "from-flag");
    }

    #[cfg(feature = "snmp")]
    #[test]
    fn an_empty_snmp_community_environment_variable_leaves_the_default() {
        let a = args(&["10.0.0.1"], &[]);
        let options = probe_options(&a, &snmp_community_env(Some("")));
        assert_eq!(
            &*options.snmp_community,
            &*ProbeSelectionOptions::default().snmp_community
        );
    }

    #[cfg(feature = "snmp")]
    #[test]
    fn an_empty_snmp_community_flag_leaves_the_default_like_an_empty_environment_variable() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.snmp_community = Some(Community(String::new()));
        let options = probe_options(&a, &snmp_community_env(None));
        assert_eq!(
            &*options.snmp_community,
            &*ProbeSelectionOptions::default().snmp_community
        );
    }

    #[cfg(feature = "snmp")]
    #[test]
    fn the_snmp_community_is_redacted_in_the_parsed_arguments() {
        let parsed = parse_args([
            "discover",
            "--target",
            "127.0.0.1",
            "--snmp-community",
            "super-secret",
        ])
        .expect("parses");
        let rendered = format!("{parsed:?}");
        assert!(!rendered.contains("super-secret"), "{rendered}");
    }

    #[cfg(feature = "http")]
    #[test]
    fn probe_options_carry_the_http_path() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.http_path = Some("/health".to_string());
        assert_eq!(probe_options(&a, &MapEnv::new()).http_path, "/health");
    }

    #[cfg(feature = "icmp")]
    #[test]
    fn probe_options_carry_the_icmp_count() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.icmp_count = Some(7);
        assert_eq!(probe_options(&a, &MapEnv::new()).icmp_count, 7);
    }

    #[cfg(any(feature = "arp", feature = "ndp"))]
    #[test]
    fn probe_options_carry_the_interface() {
        let mut a = args(&["10.0.0.1"], &[]);
        a.interface = Some("eth0".to_string());
        assert_eq!(probe_options(&a, &MapEnv::new()).interface, "eth0");
    }

    #[test]
    fn discover_parses_a_comma_separated_probe_list() {
        let parsed = parse_args([
            "discover",
            "--target",
            "127.0.0.1",
            "--probe",
            "tcp_connect,reverse_dns",
        ])
        .expect("parses");
        assert_eq!(parsed.probe, vec!["tcp_connect", "reverse_dns"]);
    }

    #[test]
    fn discover_parses_repeated_probe_ports_flags() {
        let parsed = parse_args([
            "discover",
            "--target",
            "127.0.0.1",
            "--probe-ports",
            "dns=5353",
            "--probe-ports",
            "tcp=2222,2223",
        ])
        .expect("parses");
        assert_eq!(
            parsed.probe_ports,
            vec![
                (ProbeKind::Dns, vec![5353]),
                (ProbeKind::TcpConnect, vec![2222, 2223]),
            ]
        );
    }

    #[test]
    fn discover_rejects_a_malformed_probe_ports_value() {
        assert!(
            parse_args(["discover", "--target", "127.0.0.1", "--probe-ports", "dns",]).is_err()
        );
    }

    #[cfg(feature = "icmp")]
    #[test]
    fn discover_rejects_icmp_count_zero() {
        assert!(parse_args(["discover", "--target", "127.0.0.1", "--icmp-count", "0",]).is_err());
    }

    #[cfg(feature = "config")]
    fn rejects_alongside_file(extra: &[&str]) -> bool {
        let mut argv = vec!["discover", "--file", "/tmp/x.yml"];
        argv.extend_from_slice(extra);
        parse_args(argv)
            .err()
            .is_some_and(|err| err.kind() == clap::error::ErrorKind::ArgumentConflict)
    }

    #[cfg(feature = "config")]
    #[test]
    fn every_scan_shaping_argument_conflicts_with_file() {
        use clap::CommandFactory as _;

        // Sink and knob overrides, run-mode switches, and the resume machinery stay legal.
        const LEGAL_WITH_FILE: &[&str] = &[
            "help",
            "file",
            "format",
            "sink",
            "output",
            "brokers",
            "topic",
            "kafka_flush_per_record",
            "kafka_batch_threshold",
            "concurrency",
            "rate",
            "retries",
            "timeout_ms",
            "dry_run",
            "dry_run_format",
            "checkpoint",
            "checkpoint_interval",
            "resume",
            "run_report",
        ];
        // Tried in order until one parses; a value-parse failure would mask the conflict.
        const SAMPLE_VALUES: &[&str] = &["1", "tcp=1"];

        let command = DiscoverArgs::command();
        for arg in command.get_arguments() {
            let id = arg.get_id().as_str();
            if LEGAL_WITH_FILE.contains(&id) {
                continue;
            }
            let long = format!(
                "--{}",
                arg.get_long()
                    .unwrap_or_else(|| panic!("{id} has no long form"))
            );
            let rejected = if arg.get_action().takes_values() {
                let possible: Vec<String> = arg
                    .get_possible_values()
                    .iter()
                    .map(|value| value.get_name().to_string())
                    .collect();
                let values: Vec<&str> = if possible.is_empty() {
                    SAMPLE_VALUES.to_vec()
                } else {
                    possible.iter().map(String::as_str).collect()
                };
                values
                    .iter()
                    .any(|value| rejects_alongside_file(&[&long, value]))
            } else {
                rejects_alongside_file(&[&long])
            };
            assert!(
                rejected,
                "{long} describes a scan --file already describes; it must declare \
                 conflicts_with = \"file\""
            );
        }
    }

    #[test]
    fn format_defaults_to_absent_so_yaml_keeps_its_encoder() {
        let parsed = parse_args(["discover", "--target", "127.0.0.1"]).expect("parses");
        assert_eq!(parsed.format, None);
    }

    #[test]
    fn format_accepts_table_and_its_text_alias() {
        for value in ["table", "text"] {
            let parsed = parse_args(["discover", "--target", "127.0.0.1", "--format", value])
                .expect("parses");
            assert_eq!(parsed.format, Some(OutputFormat::Table), "value: {value}");
        }
    }

    #[test]
    fn format_accepts_json_and_its_ndjson_alias() {
        for value in ["json", "ndjson"] {
            let parsed = parse_args(["discover", "--target", "127.0.0.1", "--format", value])
                .expect("parses");
            assert_eq!(parsed.format, Some(OutputFormat::Json), "value: {value}");
        }
    }

    #[test]
    fn format_rejects_an_unknown_value() {
        let result = parse_args(["discover", "--target", "127.0.0.1", "--format", "yaml"]);
        assert!(result.is_err(), "unknown record format must be rejected");
    }

    #[test]
    fn table_format_carries_the_measured_width() {
        assert!(matches!(
            encoder_for_format(OutputFormat::Table, 137),
            EncoderConfig::Table { width: 137 }
        ));
    }

    #[test]
    fn json_format_is_the_ndjson_encoder() {
        assert!(matches!(
            encoder_for_format(OutputFormat::Json, 137),
            EncoderConfig::Ndjson
        ));
    }

    #[test]
    fn stdout_defaults_to_the_table_encoder() {
        assert!(matches!(
            record_encoder(None, true, 100),
            EncoderConfig::Table { width: 100 }
        ));
    }

    #[test]
    fn every_other_destination_defaults_to_ndjson() {
        assert!(matches!(
            record_encoder(None, false, 100),
            EncoderConfig::Ndjson
        ));
    }

    #[test]
    fn an_explicit_format_beats_the_per_destination_default() {
        assert!(matches!(
            record_encoder(Some(OutputFormat::Json), true, 100),
            EncoderConfig::Ndjson
        ));
        assert!(matches!(
            record_encoder(Some(OutputFormat::Table), false, 100),
            EncoderConfig::Table { width: 100 }
        ));
    }

    #[test]
    fn an_unset_sink_is_the_stdout_destination_core_defaults_to() {
        assert!(writes_to_stdout(None));
        assert!(writes_to_stdout(Some(&SinkConfig::Stdout)));
        assert!(!writes_to_stdout(Some(&SinkConfig::File {
            path: PathBuf::from("/tmp/x")
        })));
    }

    #[test]
    fn build_scenario_puts_a_table_on_stdout() {
        let scenario = build_scenario(&tcp_args(&["10.0.0.1"], &[80])).expect("scenario");
        assert!(
            matches!(scenario.base.encoder, Some(EncoderConfig::Table { .. })),
            "got {:?}",
            scenario.base.encoder
        );
    }

    #[test]
    fn build_scenario_puts_ndjson_in_a_file() {
        let mut a = tcp_args(&["10.0.0.1"], &[80]);
        a.sink = Some(SinkKind::File);
        a.output = Some(PathBuf::from("/tmp/out.ndjson"));
        let scenario = build_scenario(&a).expect("scenario");
        assert!(
            matches!(scenario.base.encoder, Some(EncoderConfig::Ndjson)),
            "got {:?}",
            scenario.base.encoder
        );
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn build_scenario_puts_ndjson_on_a_broker() {
        let mut a = tcp_args(&["10.0.0.1"], &[80]);
        a.sink = Some(SinkKind::Kafka);
        a.brokers = vec!["localhost:9092".into()];
        a.topic = Some("rastreo.devices".into());
        let scenario = build_scenario(&a).expect("scenario");
        assert!(
            matches!(scenario.base.encoder, Some(EncoderConfig::Ndjson)),
            "got {:?}",
            scenario.base.encoder
        );
    }

    #[test]
    fn build_scenario_honours_an_explicit_json_format_on_stdout() {
        let mut a = tcp_args(&["10.0.0.1"], &[80]);
        a.format = Some(OutputFormat::Json);
        let scenario = build_scenario(&a).expect("scenario");
        assert!(
            matches!(scenario.base.encoder, Some(EncoderConfig::Ndjson)),
            "got {:?}",
            scenario.base.encoder
        );
    }

    #[cfg(feature = "config")]
    #[test]
    fn apply_cli_overrides_replaces_the_scenario_encoder_when_format_is_given() {
        let mut base = BaseProbeConfig::new();
        base.encoder = Some(EncoderConfig::Ndjson);
        let mut a = args(&[], &[]);
        a.format = Some(OutputFormat::Table);
        let cli_encoder = build_cli_encoder_override(&a);
        apply_cli_overrides(&mut base, &a, None, cli_encoder.as_ref());
        assert!(
            matches!(base.encoder, Some(EncoderConfig::Table { .. })),
            "got {:?}",
            base.encoder
        );
    }

    #[cfg(feature = "config")]
    #[test]
    fn apply_cli_overrides_leaves_the_scenario_encoder_alone_without_format() {
        let mut base = BaseProbeConfig::new();
        base.encoder = Some(EncoderConfig::Table { width: 61 });
        let a = args(&[], &[]);
        assert!(build_cli_encoder_override(&a).is_none());
        apply_cli_overrides(&mut base, &a, None, None);
        assert!(
            matches!(base.encoder, Some(EncoderConfig::Table { width: 61 })),
            "got {:?}",
            base.encoder
        );
    }

    #[cfg(feature = "config")]
    #[test]
    fn a_scenario_without_an_encoder_gets_the_table_on_stdout() {
        let mut base = BaseProbeConfig::new();
        base.sink = Some(SinkConfig::Stdout);
        apply_cli_overrides(&mut base, &args(&[], &[]), None, None);
        assert!(
            matches!(base.encoder, Some(EncoderConfig::Table { .. })),
            "got {:?}",
            base.encoder
        );
    }

    #[cfg(feature = "config")]
    #[test]
    fn a_scenario_without_a_sink_still_gets_the_table_because_core_defaults_to_stdout() {
        let mut base = BaseProbeConfig::new();
        apply_cli_overrides(&mut base, &args(&[], &[]), None, None);
        assert!(
            matches!(base.encoder, Some(EncoderConfig::Table { .. })),
            "got {:?}",
            base.encoder
        );
    }

    #[cfg(feature = "config")]
    #[test]
    fn a_scenario_without_an_encoder_keeps_ndjson_off_stdout() {
        let mut base = BaseProbeConfig::new();
        base.sink = Some(SinkConfig::File {
            path: PathBuf::from("/tmp/out.ndjson"),
        });
        apply_cli_overrides(&mut base, &args(&[], &[]), None, None);
        assert!(
            matches!(base.encoder, Some(EncoderConfig::Ndjson)),
            "got {:?}",
            base.encoder
        );
    }

    #[cfg(feature = "config")]
    #[test]
    fn the_destination_default_reads_the_sink_the_cli_overrode_it_with() {
        let mut base = BaseProbeConfig::new();
        base.sink = Some(SinkConfig::Stdout);
        apply_cli_overrides(
            &mut base,
            &args(&[], &[]),
            Some(&SinkConfig::File {
                path: PathBuf::from("/tmp/out.ndjson"),
            }),
            None,
        );
        assert!(
            matches!(base.encoder, Some(EncoderConfig::Ndjson)),
            "got {:?}",
            base.encoder
        );
    }

    #[test]
    fn the_dry_run_plan_follows_format_json() {
        let mut a = args(&["127.0.0.1"], &[]);
        a.format = Some(OutputFormat::Json);
        assert_eq!(dry_run_plan_format(&a), OutputFormat::Json);
    }

    #[test]
    fn the_dry_run_plan_follows_format_table() {
        let mut a = args(&["127.0.0.1"], &[]);
        a.format = Some(OutputFormat::Table);
        assert_eq!(dry_run_plan_format(&a), OutputFormat::Table);
    }

    #[test]
    fn a_flag_driven_run_knows_it_writes_to_stdout() {
        assert_eq!(
            effective_sink_kind(&args(&["127.0.0.1"], &[])),
            Some(SinkKind::Stdout)
        );
    }

    #[cfg(feature = "config")]
    #[test]
    fn a_file_run_without_sink_leaves_the_destination_to_the_scenario() {
        let mut a = args(&[], &[]);
        a.file = Some(PathBuf::from("/tmp/x.yml"));
        assert_eq!(effective_sink_kind(&a), None);
    }

    fn args_with_every_sink_flag() -> DiscoverArgs {
        let mut a = args(&["127.0.0.1"], &[]);
        a.output = Some(PathBuf::from("/tmp/x.txt"));
        #[cfg(feature = "kafka")]
        {
            a.brokers = vec!["localhost:9092".into()];
            a.topic = Some("t".into());
            a.kafka_flush_per_record = true;
            a.kafka_batch_threshold = Some(1024);
        }
        a
    }

    #[test]
    fn every_sink_scoped_argument_is_covered_by_the_sink_flag_table() {
        use clap::CommandFactory as _;

        const NOT_SINK_SCOPED: &[&str] = &[
            "help",
            "target",
            "probe",
            "port",
            "probe_ports",
            "udp_protocol",
            "dns_query",
            "dns_query_type",
            "snmp_community",
            "snmp_version",
            "http_path",
            "icmp_count",
            "interface",
            "file",
            "format",
            "sink",
            "concurrency",
            "rate",
            "retries",
            "timeout_ms",
            "dry_run",
            "dry_run_format",
            "checkpoint",
            "checkpoint_interval",
            "resume",
            "run_report",
        ];

        let covered: Vec<&str> = sink_flags(&args_with_every_sink_flag())
            .into_iter()
            .map(|flag| flag.flag)
            .collect();
        for arg in DiscoverArgs::command().get_arguments() {
            let id = arg.get_id().as_str();
            if NOT_SINK_SCOPED.contains(&id) {
                continue;
            }
            let long = format!(
                "--{}",
                arg.get_long()
                    .unwrap_or_else(|| panic!("{id} has no long form"))
            );
            assert!(
                covered.contains(&long.as_str()),
                "{long} names a destination but is missing from the sink-flag table, so it \
                 would be discarded in silence under a sink that cannot consume it"
            );
        }
    }

    #[test]
    fn every_sink_flag_reports_the_sink_that_would_have_consumed_it() {
        for flag in sink_flags(&args_with_every_sink_flag()) {
            assert!(flag.supplied, "{} was not read back", flag.flag);
            let msg = sink_flag_mismatch(&flag, "stdout");
            assert!(msg.contains(flag.flag), "{msg}");
            assert!(
                msg.contains(&format!("--sink {}", sink_kind_value(flag.sink))),
                "{msg}"
            );
            assert!(msg.contains("this run writes to stdout"), "{msg}");
        }
    }

    #[test]
    fn a_sink_flag_is_accepted_by_its_own_sink() {
        let mut a = args(&["127.0.0.1"], &[]);
        a.sink = Some(SinkKind::File);
        a.output = Some(PathBuf::from("/tmp/x.txt"));
        ensure_sink_flags_reach_their_sink(&a).expect("a file sink takes --output");
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn the_kafka_flags_are_accepted_by_a_broker_sink() {
        let mut a = args(&["127.0.0.1"], &[]);
        a.sink = Some(SinkKind::Kafka);
        a.brokers = vec!["localhost:9092".into()];
        a.topic = Some("t".into());
        a.kafka_flush_per_record = true;
        ensure_sink_flags_reach_their_sink(&a).expect("a broker sink takes its own flags");
    }

    #[test]
    fn a_run_with_no_sink_flags_is_always_accepted() {
        ensure_sink_flags_reach_their_sink(&args(&["127.0.0.1"], &[])).expect("nothing to check");
    }

    #[test]
    fn output_without_a_file_sink_names_the_destination_it_would_have_missed() {
        let mut a = args(&["127.0.0.1"], &[]);
        a.output = Some(PathBuf::from("/tmp/x.txt"));
        let err = ensure_sink_flags_reach_their_sink(&a).expect_err("stdout cannot take --output");
        let msg = format!("{err}");
        assert!(msg.contains("--sink file"), "msg: {msg}");
        assert!(msg.contains("stdout"), "msg: {msg}");
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn output_alongside_a_broker_sink_is_refused() {
        let mut a = args(&["127.0.0.1"], &[]);
        a.sink = Some(SinkKind::Kafka);
        a.brokers = vec!["localhost:9092".into()];
        a.topic = Some("t".into());
        a.output = Some(PathBuf::from("/tmp/x.txt"));
        let err = ensure_sink_flags_reach_their_sink(&a).expect_err("kafka cannot take --output");
        assert!(format!("{err}").contains("kafka"), "{err}");
    }

    #[cfg(feature = "kafka")]
    #[test]
    fn broker_flags_without_a_broker_sink_are_refused() {
        let mut a = args(&["127.0.0.1"], &[]);
        a.brokers = vec!["localhost:9092".into()];
        a.topic = Some("t".into());
        let err = ensure_sink_flags_reach_their_sink(&a).expect_err("stdout cannot reach a broker");
        let msg = format!("{err}");
        assert!(msg.contains("--brokers"), "msg: {msg}");
        assert!(msg.contains("--sink kafka"), "msg: {msg}");
    }

    #[cfg(feature = "config")]
    #[test]
    fn output_alongside_a_scenario_file_is_refused_because_it_reaches_no_sink() {
        let mut a = args(&[], &[]);
        a.file = Some(PathBuf::from("/tmp/x.yml"));
        a.output = Some(PathBuf::from("/tmp/x.ndjson"));
        let err = ensure_sink_flags_reach_their_sink(&a)
            .expect_err("--output is only ever read through --sink file");
        let msg = format!("{err}");
        assert!(msg.contains("--sink file"), "msg: {msg}");
        assert!(msg.contains("scenario file"), "msg: {msg}");
    }
}
