use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::classifier::{create_classifier, Classifier, ClassifierConfig};
use crate::config::DiscoverScenarioConfig;
use crate::encoder::{create_encoder, Encoder, EncoderConfig};
use crate::error::{ConfigError, ProbeErrorKind, RastreoError};
use crate::fuser::{create_fuser, drive_fuser, Fuser, FuserConfig};
use crate::model::{
    DeviceRecord, ProbeCtx, ProbeFault, ProbeKind, ProbeOutcome, ResolvedTarget, ScanMetadata,
    Target, PROBE_KIND_COUNT,
};
use crate::prober::{create_prober, Prober};
use crate::resolver::{HickoryResolver, Resolver};
use crate::scheduler::{BoundedScheduler, Scheduler};
use crate::sink::{create_sink, Sink, SinkConfig, SinkErrorClass, SinkType};

const DEFAULT_TIMEOUT_MS: u64 = 1000;
const DEFAULT_CONCURRENCY: u32 = 64;

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct DiscoverySummary {
    pub targets_resolved: usize,
    pub probe_attempts: usize,
    pub records_emitted: usize,
    /// Faulted probes tallied by [`ProbeErrorKind`]; empty when no probe faulted.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub error_counts: BTreeMap<ProbeErrorKind, usize>,
    /// Per-`ProbeKind` attempted / errored breakdown; empty when no probes ran.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub probes_by_kind: Vec<ProbeKindSummary>,
    /// Records delivered to a DLQ destination during this scan.
    #[serde(default)]
    pub dlq_records: usize,
    /// DLQ deliveries keyed by `(destination sink type, failure class)`; empty when nothing was quarantined.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dlq_records_by_type_and_class: Vec<(SinkType, SinkErrorClass, u64)>,
    /// Concrete sink kind the scan wrote against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sink_type: Option<SinkType>,
    /// True when the run terminated early via the cancellation token; counters reflect partial progress.
    #[serde(default)]
    pub cancelled: bool,
    /// Kind and sample detail of the first probe that faulted; latched once per scan, `None` when no probe faulted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_probe_error: Option<ProbeFault>,
    #[serde(rename = "elapsed_ms", serialize_with = "serialize_duration_as_millis")]
    pub elapsed: Duration,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub struct ProbeKindSummary {
    pub kind: ProbeKind,
    pub attempted: usize,
    pub errored: usize,
}

fn serialize_duration_as_millis<S: serde::Serializer>(
    d: &Duration,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_u128(d.as_millis())
}

pub async fn run_discovery(
    scenario: &DiscoverScenarioConfig,
) -> Result<DiscoverySummary, RastreoError> {
    let (_tx, rx) = watch::channel(false);
    run_discovery_cancellable(scenario, rx).await
}

/// Per-target resolution outcome, preserving which input `Target` produced which IPs (or which error). Used by the `--dry-run` planner to attribute expansions back to the original YAML / CLI entry.
#[derive(Debug)]
#[non_exhaustive]
pub struct ResolvedScenarioTarget {
    pub target: Target,
    pub result: Result<Vec<IpAddr>, RastreoError>,
}

impl ResolvedScenarioTarget {
    pub fn new(target: Target, result: Result<Vec<IpAddr>, RastreoError>) -> Self {
        Self { target, result }
    }
}

/// Resolve every target in a scenario without probing, preserving per-target attribution. Unlike [`Resolver::resolve_many`], failures on one target do not abort the run — each `Target` gets its own `Result`.
pub async fn resolve_scenario_targets(
    scenario: &DiscoverScenarioConfig,
    resolver: &dyn Resolver,
) -> Vec<ResolvedScenarioTarget> {
    let mut out = Vec::with_capacity(scenario.targets.len());
    for target in &scenario.targets {
        let result = resolver
            .resolve(target)
            .await
            .map(|rts| rts.into_iter().map(|rt| rt.ip).collect());
        out.push(ResolvedScenarioTarget::new(target.clone(), result));
    }
    out
}

pub async fn run_discovery_with_components(
    scenario: &DiscoverScenarioConfig,
    resolver: Arc<dyn Resolver>,
    sink: Box<dyn Sink>,
) -> Result<DiscoverySummary, RastreoError> {
    let (_tx, rx) = watch::channel(false);
    run_discovery_with_components_cancellable(scenario, resolver, sink, rx).await
}

/// Same as [`run_discovery`], but stops scanning new targets when `cancel` flips to true; each already-started target's probers complete atomically, so finished targets still emit complete records. The sink is closed on every exit path.
pub async fn run_discovery_cancellable(
    scenario: &DiscoverScenarioConfig,
    cancel: watch::Receiver<bool>,
) -> Result<DiscoverySummary, RastreoError> {
    let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system()?);
    let sink_config = scenario.base.sink.clone().unwrap_or(SinkConfig::Stdout);
    let sink = create_sink(&sink_config).await?;
    run_discovery_with_components_cancellable(scenario, resolver, sink, cancel).await
}

/// Same as [`run_discovery_with_components`], but stops scanning new targets when `cancel` flips to true; each already-started target's probers complete atomically, so finished targets still emit complete records. The sink is closed on every exit path.
pub async fn run_discovery_with_components_cancellable(
    scenario: &DiscoverScenarioConfig,
    resolver: Arc<dyn Resolver>,
    mut sink: Box<dyn Sink>,
    cancel: watch::Receiver<bool>,
) -> Result<DiscoverySummary, RastreoError> {
    scenario.base.ensure_no_retired_fields()?;
    scenario.base.ensure_retries_within_bound()?;
    if scenario.probers.is_empty() {
        return Err(ConfigError::invalid("scenario.probers must not be empty").into());
    }

    let start = Instant::now();
    let scan_metadata = Arc::new(ScanMetadata::new(scenario));

    let resolved = resolver.resolve_many(&scenario.targets).await?;
    let targets_resolved = resolved.len();

    let max_concurrent = scenario
        .base
        .max_concurrent
        .unwrap_or(DEFAULT_CONCURRENCY)
        .max(1) as usize;
    let scheduler = BoundedScheduler::new(max_concurrent).with_probe_rate(scenario.base.probe_rate);

    let timeout_ms = scenario.base.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    let ctx = ProbeCtx {
        timeout: Duration::from_millis(timeout_ms),
        retries: scenario.base.retries.unwrap_or(0),
    };

    let encoder_config = scenario
        .base
        .encoder
        .clone()
        .unwrap_or(EncoderConfig::Ndjson);
    let encoder = create_encoder(&encoder_config)?;

    let fuser_config = scenario.base.fuser.clone().unwrap_or(FuserConfig::Direct {
        include_unreachable: None,
        confidence_baseline: None,
        confidence_per_signal: None,
    });
    let mut fuser = create_fuser(&fuser_config)?;

    let classifier_config = scenario
        .base
        .classifier
        .clone()
        .unwrap_or(ClassifierConfig::Noop);
    let classifier = create_classifier(&classifier_config)?;

    let mut probers: Vec<Arc<dyn Prober>> = Vec::with_capacity(scenario.probers.len());
    for prober_config in &scenario.probers {
        probers.push(Arc::from(create_prober(prober_config)?));
    }

    let acc = scan_and_accumulate(&scheduler, probers, resolved, ctx, cancel).await;

    finish_discovery(
        acc,
        fuser.as_mut(),
        classifier.as_ref(),
        encoder.as_ref(),
        sink.as_mut(),
        &scan_metadata,
        targets_resolved,
        start,
    )
    .await
}

#[derive(Default)]
struct ScanAccumulation {
    all_outcomes: Vec<ProbeOutcome>,
    probe_attempts: usize,
    error_counts: BTreeMap<ProbeErrorKind, usize>,
    first_probe_error: Option<ProbeFault>,
    attempts_by_kind: [usize; PROBE_KIND_COUNT],
    errors_by_kind: [usize; PROBE_KIND_COUNT],
    cancelled: bool,
}

async fn scan_and_accumulate(
    scheduler: &BoundedScheduler,
    probers: Vec<Arc<dyn Prober>>,
    resolved: Vec<ResolvedTarget>,
    ctx: ProbeCtx,
    cancel: watch::Receiver<bool>,
) -> ScanAccumulation {
    let prober_kinds: Vec<ProbeKind> = probers.iter().map(|p| p.kind()).collect();
    let scans = scheduler
        .run_scan(probers, resolved, ctx, cancel.clone())
        .await;
    let cancelled = *cancel.borrow();

    let mut acc = ScanAccumulation {
        cancelled,
        ..Default::default()
    };
    // Target-outer iteration sees faults in a different order than the batch prober-outer loop, so
    // `first_probe_error` tracks the smallest `(prober_pass_index, target_index)` key to keep the
    // batch's choice — the first fault a prober-outer scan would have latched.
    let mut best_key: Option<(usize, usize)> = None;

    for scan in scans {
        let target_index = scan.target_index;
        for (pass_index, result) in scan.outcomes {
            acc.probe_attempts += 1;
            let kind = prober_kinds[pass_index];
            acc.attempts_by_kind[kind.index()] += 1;
            match result {
                Ok(outcome) => {
                    if let Some(fault) = &outcome.fault {
                        acc.errors_by_kind[kind.index()] += 1;
                        *acc.error_counts.entry(fault.kind).or_insert(0) += 1;
                        let key = (pass_index, target_index);
                        if best_key.is_none_or(|bk| key < bk) {
                            best_key = Some(key);
                            acc.first_probe_error = Some(fault.clone());
                        }
                    }
                    acc.all_outcomes.push(outcome);
                }
                // A prober carries every fault as data on the outcome; a stray `Err` means it could
                // not attempt at all. Keep the contract total by counting it as `Other`.
                Err(err) => {
                    acc.errors_by_kind[kind.index()] += 1;
                    *acc.error_counts.entry(ProbeErrorKind::Other).or_insert(0) += 1;
                    tracing::debug!(error = %err, "probe failed");
                    let msg = err.to_string();
                    if !msg.is_empty() {
                        let key = (pass_index, target_index);
                        if best_key.is_none_or(|bk| key < bk) {
                            best_key = Some(key);
                            acc.first_probe_error =
                                Some(ProbeFault::new(ProbeErrorKind::Other, msg));
                        }
                    }
                }
            }
        }
    }

    acc
}

#[allow(clippy::too_many_arguments)]
async fn finish_discovery(
    acc: ScanAccumulation,
    fuser: &mut dyn Fuser,
    classifier: &dyn Classifier,
    encoder: &dyn Encoder,
    sink: &mut dyn Sink,
    scan_metadata: &Arc<ScanMetadata>,
    targets_resolved: usize,
    start: Instant,
) -> Result<DiscoverySummary, RastreoError> {
    let sink_type = sink.kind();

    let mut records = drive_fuser(fuser, acc.all_outcomes)?;
    for record in &mut records {
        classifier.classify(record)?;
        stamp_scan_metadata(record, scan_metadata);
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut records_emitted: usize = 0;
    let mut emit_err: Option<RastreoError> = None;

    for record in &records {
        buf.clear();
        if let Err(e) = encoder.encode_record(record, &mut buf) {
            emit_err = Some(e);
            break;
        }
        if let Err(e) = sink.write(&buf).await {
            emit_err = Some(e);
            break;
        }
        records_emitted += 1;
    }

    let close_err = sink.close().await.err();

    if acc.cancelled {
        tracing::info!(records_emitted, "discovery cancelled; sink closed");
    }

    let dlq_records_by_type_and_class = sink.dlq_records_by_type_and_class();
    let dlq_records = dlq_records_by_type_and_class
        .iter()
        .fold(0u64, |sum, (_, _, c)| sum.saturating_add(*c)) as usize;
    let probes_by_kind = build_probes_by_kind(&acc.attempts_by_kind, &acc.errors_by_kind);

    if let Some(e) = emit_err {
        return Err(e);
    }
    if let Some(e) = close_err {
        return Err(e);
    }

    Ok(DiscoverySummary {
        targets_resolved,
        probe_attempts: acc.probe_attempts,
        records_emitted,
        error_counts: acc.error_counts,
        probes_by_kind,
        dlq_records,
        dlq_records_by_type_and_class,
        sink_type: Some(sink_type),
        cancelled: acc.cancelled,
        first_probe_error: acc.first_probe_error,
        elapsed: start.elapsed(),
    })
}

fn stamp_scan_metadata(record: &mut DeviceRecord, scan_metadata: &Arc<ScanMetadata>) {
    record.scan_metadata = Arc::clone(scan_metadata);
}

fn build_probes_by_kind(
    attempts: &[usize; PROBE_KIND_COUNT],
    errors: &[usize; PROBE_KIND_COUNT],
) -> Vec<ProbeKindSummary> {
    let mut out = Vec::new();
    for kind in ProbeKind::all() {
        let idx = kind.index();
        if attempts[idx] == 0 && errors[idx] == 0 {
            continue;
        }
        out.push(ProbeKindSummary {
            kind: *kind,
            attempted: attempts[idx],
            errored: errors[idx],
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::classifier::ClassifierConfig;
    use crate::config::BaseProbeConfig;
    use crate::error::ConfigError;
    use crate::model::Target;
    use crate::prober::ProberConfig;

    fn scenario_with_probers(probers: Vec<ProberConfig>) -> DiscoverScenarioConfig {
        DiscoverScenarioConfig {
            base: BaseProbeConfig::default(),
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers,
        }
    }

    #[tokio::test]
    async fn run_discovery_rejects_retired_rate_limit_field() {
        use crate::config::{ScenarioEntry, ScenarioFile};

        // The server POST /scans path bypasses parse_scenario_file, so the pipeline must reject.
        let json = r#"{
            "version": 1,
            "kind": "discovery",
            "scenarios": [
                {
                    "signal_type": "discover",
                    "rate_limit": 50,
                    "targets": [{"Ip": "127.0.0.1"}],
                    "probers": [{"type": "tcp_connect", "ports": [22]}]
                }
            ]
        }"#;
        let file: ScenarioFile = serde_json::from_str(json).expect("deserialize");
        let ScenarioEntry::Discover(scenario) = &file.scenarios[0];

        let mem = crate::sink::MemorySink::new();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let err = run_discovery_with_components(scenario, resolver, Box::new(mem))
            .await
            .expect_err("retired rate_limit must error");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("max_concurrent"), "msg: {msg}");
                assert!(msg.contains("probe_rate"), "msg: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_discovery_empty_probers_returns_config_error() {
        let scenario = scenario_with_probers(Vec::new());
        let err = run_discovery(&scenario).await.expect_err("empty probers");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("probers"), "unexpected message: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_discovery_emits_record_for_open_loopback_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("records.ndjson");

        let base = BaseProbeConfig {
            sink: Some(SinkConfig::File { path: path.clone() }),
            timeout_ms: Some(500),
            ..Default::default()
        };

        let scenario = DiscoverScenarioConfig {
            base,
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let summary = run_discovery(&scenario).await.expect("run_discovery");
        assert_eq!(summary.targets_resolved, 1);
        assert_eq!(summary.probe_attempts, 1);
        assert!(summary.error_counts.is_empty());
        assert_eq!(summary.records_emitted, 1);

        let bytes = std::fs::read(&path).expect("read");
        let lines: Vec<&[u8]> = bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(lines.len(), 1);
        let record: crate::model::DeviceRecord =
            serde_json::from_slice(lines[0]).expect("parse json");
        assert_eq!(record.mgmt_ip, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(record
            .signals
            .iter()
            .any(|s| matches!(s, crate::model::Signal::OpenPort(p) if *p == port)));
    }

    #[tokio::test]
    async fn run_discovery_unreachable_target_emits_no_records() {
        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let closed_port = closed_listener.local_addr().expect("local_addr").port();
        drop(closed_listener);

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("none.ndjson");

        let base = BaseProbeConfig {
            sink: Some(SinkConfig::File { path: path.clone() }),
            timeout_ms: Some(200),
            ..Default::default()
        };

        let scenario = DiscoverScenarioConfig {
            base,
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect {
                ports: vec![closed_port],
            }],
        };

        let summary = run_discovery(&scenario).await.expect("run_discovery");
        assert_eq!(summary.targets_resolved, 1);
        assert_eq!(summary.probe_attempts, 1);
        assert_eq!(summary.records_emitted, 0);

        let bytes = std::fs::read(&path).expect("read");
        assert!(bytes.is_empty(), "no records expected, got {bytes:?}");
    }

    #[tokio::test]
    async fn run_discovery_with_components_uses_provided_resolver() {
        use crate::model::ResolvedTarget;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingResolver {
            inner: HickoryResolver,
            calls: AtomicUsize,
        }

        #[async_trait::async_trait]
        impl Resolver for CountingResolver {
            async fn resolve(
                &self,
                target: &crate::model::Target,
            ) -> Result<Vec<ResolvedTarget>, RastreoError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.inner.resolve(target).await
            }
        }

        let resolver = Arc::new(CountingResolver {
            inner: HickoryResolver::from_system().expect("init"),
            calls: AtomicUsize::new(0),
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let resolver_dyn: Arc<dyn Resolver> = resolver.clone();
        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();
        let sink: Box<dyn Sink> = Box::new(mem);
        let _summary = run_discovery_with_components(&scenario, resolver_dyn, sink)
            .await
            .expect("run_discovery_with_components");

        assert!(resolver.calls.load(Ordering::SeqCst) >= 1);
        assert!(!handle.bytes().is_empty());
    }

    #[tokio::test]
    async fn run_discovery_with_components_uses_provided_sink() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();

        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let summary = run_discovery_with_components(&scenario, resolver, Box::new(mem))
            .await
            .expect("run_discovery_with_components");
        assert_eq!(summary.records_emitted, 1);
        let lines = handle.ndjson_lines();
        assert_eq!(lines.len(), 1);
        let record: crate::model::DeviceRecord =
            serde_json::from_str(&lines[0]).expect("parse json");
        assert_eq!(record.mgmt_ip, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn discovery_summary_serializes_elapsed_as_millis_field() {
        let summary = DiscoverySummary {
            targets_resolved: 1,
            probe_attempts: 2,
            records_emitted: 1,
            elapsed: Duration::from_millis(142),
            ..Default::default()
        };
        let json: serde_json::Value = serde_json::to_value(&summary).expect("serialize");
        assert_eq!(json["elapsed_ms"], 142);
        assert_eq!(json["records_emitted"], 1);
        assert!(json.get("elapsed").is_none());
    }

    #[test]
    fn discovery_summary_serializes_cancelled_field() {
        let summary = DiscoverySummary {
            targets_resolved: 1,
            probe_attempts: 2,
            records_emitted: 1,
            cancelled: true,
            elapsed: Duration::from_millis(7),
            ..Default::default()
        };
        let json: serde_json::Value = serde_json::to_value(&summary).expect("serialize");
        assert_eq!(json["cancelled"], true);
    }

    #[tokio::test]
    async fn run_discovery_populates_probes_by_kind_and_sink_type() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        Box::leak(Box::new(listener));

        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let mem = crate::sink::MemorySink::new();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery_with_components(&scenario, resolver, Box::new(mem))
            .await
            .expect("run_discovery_with_components");
        assert_eq!(summary.sink_type, Some(crate::sink::SinkType::Memory));
        assert_eq!(summary.dlq_records, 0);
        assert_eq!(summary.probes_by_kind.len(), 1);
        assert_eq!(summary.probes_by_kind[0].kind, ProbeKind::TcpConnect);
        assert_eq!(summary.probes_by_kind[0].attempted, 1);
        assert_eq!(summary.probes_by_kind[0].errored, 0);
    }

    #[test]
    fn discovery_summary_default_has_none_sink_type_and_empty_kind_breakdown() {
        let summary = DiscoverySummary::default();
        assert_eq!(summary.probes_by_kind.len(), 0);
        assert_eq!(summary.dlq_records, 0);
        assert!(summary.dlq_records_by_type_and_class.is_empty());
        assert!(summary.sink_type.is_none());
        assert!(summary.first_probe_error.is_none());
        assert!(summary.error_counts.is_empty());
    }

    #[test]
    fn discovery_summary_omits_first_probe_error_and_error_counts_from_wire_when_empty() {
        let summary = DiscoverySummary::default();
        let json: serde_json::Value = serde_json::to_value(&summary).expect("serialize");
        assert!(
            json.get("first_probe_error").is_none(),
            "first_probe_error must be skipped when None: {json}"
        );
        assert!(
            json.get("error_counts").is_none(),
            "error_counts must be skipped when empty: {json}"
        );
    }

    #[test]
    fn discovery_summary_serializes_first_probe_error_and_error_counts_when_present() {
        let mut error_counts = BTreeMap::new();
        error_counts.insert(ProbeErrorKind::DecodeFailed, 3);
        let summary = DiscoverySummary {
            first_probe_error: Some(ProbeFault::new(
                ProbeErrorKind::PermissionDenied,
                "permission denied",
            )),
            error_counts,
            ..Default::default()
        };
        let json: serde_json::Value = serde_json::to_value(&summary).expect("serialize");
        assert_eq!(json["first_probe_error"]["kind"], "permission_denied");
        assert_eq!(json["first_probe_error"]["detail"], "permission denied");
        assert_eq!(json["error_counts"]["decode_failed"], 3);
    }

    #[tokio::test]
    async fn run_discovery_reports_no_probe_errors_for_dark_targets() {
        use crate::prober::UdpProtocol;

        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(100),
                ..Default::default()
            },
            targets: vec![
                Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Target::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            ],
            probers: vec![ProberConfig::Udp {
                ports: vec![1],
                protocol: UdpProtocol::Ntp,
            }],
        };

        let mem = crate::sink::MemorySink::new();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery_with_components(&scenario, resolver, Box::new(mem))
            .await
            .expect("returns summary");

        assert_eq!(summary.probe_attempts, 2);
        assert!(
            summary.error_counts.is_empty(),
            "a target that does not answer is a discovery result, not a probe error"
        );
        assert!(summary.first_probe_error.is_none());
        assert_eq!(summary.records_emitted, 0);
        let udp = summary
            .probes_by_kind
            .iter()
            .find(|k| k.kind == ProbeKind::Udp)
            .expect("udp kind summary");
        assert_eq!(udp.attempted, 2);
        assert_eq!(udp.errored, 0);
    }

    #[cfg(feature = "snmp")]
    async fn spawn_undecodable_snmp_agent() -> u16 {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind agent");
        let port = socket.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                if let Ok((_, peer)) = socket.recv_from(&mut buf).await {
                    let _ = socket.send_to(&[0xff, 0xfe, 0xfd, 0xfc], peer).await;
                }
            }
        });
        port
    }

    #[cfg(feature = "snmp")]
    #[tokio::test]
    async fn run_discovery_snmp_decode_failure_keeps_the_device_and_counts_the_fault() {
        use crate::prober::snmp::{SnmpVersion, UsmCredentials};

        let port = spawn_undecodable_snmp_agent().await;
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::Snmp {
                ports: vec![port],
                version: SnmpVersion::V2c,
                community: crate::prober::Community("public".into()),
                credentials: UsmCredentials::default(),
            }],
        };

        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery_with_components(&scenario, resolver, Box::new(mem))
            .await
            .expect("returns summary");

        assert_eq!(
            summary.records_emitted, 1,
            "the agent answered on the port; the decode-failed device is kept, not dropped"
        );
        assert_eq!(
            summary
                .error_counts
                .get(&ProbeErrorKind::DecodeFailed)
                .copied(),
            Some(1),
            "the decode failure is tallied as a fault: {:?}",
            summary.error_counts
        );
        let record: crate::model::DeviceRecord =
            serde_json::from_str(&handle.ndjson_lines()[0]).expect("parse record");
        assert!(
            record.probe_kinds.contains(&ProbeKind::Snmp),
            "the probe got a response, so Snmp is provenance: {:?}",
            record.probe_kinds
        );
    }

    #[cfg(feature = "snmp")]
    #[tokio::test]
    async fn run_discovery_latches_the_first_fault_and_ignores_subsequent() {
        use crate::prober::snmp::{SnmpVersion, UsmCredentials};

        let snmp_prober_on = |port: u16| ProberConfig::Snmp {
            ports: vec![port],
            version: SnmpVersion::V2c,
            community: crate::prober::Community("public".into()),
            credentials: UsmCredentials::default(),
        };
        let first_port = spawn_undecodable_snmp_agent().await;
        let second_port = spawn_undecodable_snmp_agent().await;

        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![snmp_prober_on(first_port), snmp_prober_on(second_port)],
        };

        let mem = crate::sink::MemorySink::new();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery_with_components(&scenario, resolver, Box::new(mem))
            .await
            .expect("returns summary");

        assert_eq!(
            summary
                .error_counts
                .get(&ProbeErrorKind::DecodeFailed)
                .copied(),
            Some(2),
            "an undecodable agent reply is a probe fault, not an absent host"
        );
        let fault = summary
            .first_probe_error
            .as_ref()
            .expect("first probe error must be latched");
        assert_eq!(fault.kind, ProbeErrorKind::DecodeFailed);
        assert!(
            fault.detail.contains("decode"),
            "must carry the fault, got: {}",
            fault.detail
        );
        assert!(
            fault.detail.contains(&first_port.to_string()),
            "the first fault must win the latch, got: {}",
            fault.detail
        );
        assert!(
            !fault.detail.contains(&second_port.to_string()),
            "a later fault must not overwrite the latched first one, got: {}",
            fault.detail
        );
    }

    #[tokio::test]
    async fn include_unreachable_emits_a_record_per_dark_target() {
        use crate::prober::UdpProtocol;

        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(100),
                fuser: Some(FuserConfig::Direct {
                    include_unreachable: Some(true),
                    confidence_baseline: None,
                    confidence_per_signal: None,
                }),
                ..Default::default()
            },
            targets: vec![
                Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Target::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            ],
            probers: vec![ProberConfig::Udp {
                ports: vec![1],
                protocol: UdpProtocol::Ntp,
            }],
        };

        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery_with_components(&scenario, resolver, Box::new(mem))
            .await
            .expect("returns summary");

        assert!(summary.error_counts.is_empty());
        assert_eq!(
            summary.records_emitted, 2,
            "a dark host is an outcome, so include_unreachable emits one record per dark IP"
        );
        let records: Vec<crate::model::DeviceRecord> = handle
            .ndjson_lines()
            .iter()
            .map(|l| serde_json::from_str(l).expect("parse record"))
            .collect();
        for record in &records {
            assert!(
                record.probe_kinds.is_empty(),
                "nothing responded, so nothing is provenance: {:?}",
                record.probe_kinds
            );
            assert!(record.signals.is_empty());
        }
    }

    #[tokio::test]
    async fn probe_kinds_on_a_reachable_record_exclude_silent_probers() {
        use crate::prober::UdpProtocol;

        let open_port = open_loopback_port().await;
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(100),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![
                ProberConfig::TcpConnect {
                    ports: vec![open_port],
                },
                ProberConfig::Udp {
                    ports: vec![1],
                    protocol: UdpProtocol::Ntp,
                },
            ],
        };

        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery_with_components(&scenario, resolver, Box::new(mem))
            .await
            .expect("returns summary");

        assert_eq!(summary.records_emitted, 1);
        let lines = handle.ndjson_lines();
        let record: crate::model::DeviceRecord =
            serde_json::from_str(&lines[0]).expect("parse record");
        assert_eq!(
            record.probe_kinds,
            vec![ProbeKind::TcpConnect],
            "the silent udp prober answered nothing and must not claim provenance"
        );
    }

    #[tokio::test]
    async fn run_discovery_first_probe_error_is_none_when_no_errors() {
        let port = open_loopback_port().await;
        let scenario = scenario_for_port(port);
        let mem = crate::sink::MemorySink::new();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery_with_components(&scenario, resolver, Box::new(mem))
            .await
            .expect("run_discovery_with_components");
        assert_eq!(summary.records_emitted, 1);
        assert!(
            summary.first_probe_error.is_none(),
            "first_probe_error must stay None when no probe errors: {:?}",
            summary.first_probe_error
        );
    }

    #[tokio::test]
    async fn discovery_summary_populates_dlq_records_by_type_and_class_on_tee_wrapped_kafka() {
        use crate::sink::{TeeChild, TeeSink, SINK_ERROR_CLASS_COUNT};

        struct KafkaLikeSink {
            dlq: u64,
        }

        #[async_trait::async_trait]
        impl crate::sink::Sink for KafkaLikeSink {
            async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
                self.dlq += 1;
                Ok(())
            }
            async fn flush(&mut self) -> Result<(), RastreoError> {
                Ok(())
            }
            fn kind(&self) -> SinkType {
                SinkType::Kafka
            }
            fn dlq_records_by_class(&self) -> [u64; SINK_ERROR_CLASS_COUNT] {
                let mut out = [0; SINK_ERROR_CLASS_COUNT];
                out[SinkErrorClass::ProduceFailure.index()] = self.dlq;
                out
            }
        }

        let port = open_loopback_port().await;
        let scenario = scenario_for_port(port);

        let mem = crate::sink::MemorySink::new();
        let kafka = KafkaLikeSink { dlq: 0 };
        let tee = TeeSink::new(vec![
            TeeChild::Owned(Box::new(mem)),
            TeeChild::Owned(Box::new(kafka)),
        ]);
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery_with_components(&scenario, resolver, Box::new(tee))
            .await
            .expect("run_discovery_with_components");

        assert_eq!(summary.sink_type, Some(SinkType::Tee));
        assert_eq!(summary.records_emitted, 1);
        assert_eq!(summary.dlq_records, 1);
        assert_eq!(
            summary.dlq_records_by_type_and_class,
            vec![(SinkType::Kafka, SinkErrorClass::ProduceFailure, 1)]
        );
    }

    #[tokio::test]
    async fn run_discovery_applies_default_concurrency_and_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("defaults.ndjson");

        let base = BaseProbeConfig {
            sink: Some(SinkConfig::File { path }),
            ..Default::default()
        };

        let scenario = DiscoverScenarioConfig {
            base,
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let summary = run_discovery(&scenario).await.expect("run_discovery");
        assert_eq!(summary.records_emitted, 1);
    }

    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct FailingSinkInner {
        writes: AtomicUsize,
        flushes: AtomicUsize,
    }

    struct FailingSink {
        inner: Arc<FailingSinkInner>,
        fail_after_writes: usize,
    }

    impl FailingSink {
        fn new(fail_after_writes: usize) -> Self {
            Self {
                inner: Arc::new(FailingSinkInner::default()),
                fail_after_writes,
            }
        }

        fn handle(&self) -> FailingSinkHandle {
            FailingSinkHandle {
                inner: Arc::clone(&self.inner),
            }
        }
    }

    #[derive(Clone)]
    struct FailingSinkHandle {
        inner: Arc<FailingSinkInner>,
    }

    impl FailingSinkHandle {
        fn writes(&self) -> usize {
            self.inner.writes.load(Ordering::SeqCst)
        }
        fn flushes(&self) -> usize {
            self.inner.flushes.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl crate::sink::Sink for FailingSink {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            let n = self.inner.writes.fetch_add(1, Ordering::SeqCst) + 1;
            if n > self.fail_after_writes {
                return Err(RastreoError::Sink(crate::sink::SinkError::new(
                    SinkErrorClass::WriteFailure,
                    std::io::Error::other("simulated write failure"),
                )));
            }
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            self.inner.flushes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    async fn open_loopback_port() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        Box::leak(Box::new(listener));
        port
    }

    fn scenario_for_port(port: u16) -> DiscoverScenarioConfig {
        DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        }
    }

    #[tokio::test]
    async fn run_discovery_flushes_sink_even_after_emit_error() {
        let port = open_loopback_port().await;
        let scenario = scenario_for_port(port);

        let sink = Box::new(FailingSink::new(0));
        let handle = sink.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let (_tx, rx) = watch::channel(false);

        let err = run_discovery_with_components_cancellable(&scenario, resolver, sink, rx)
            .await
            .expect_err("write must error");
        match &err {
            RastreoError::Sink(e) => {
                assert!(format!("{e}").contains("simulated"), "unexpected msg: {e}");
                assert_eq!(e.class, SinkErrorClass::WriteFailure);
            }
            other => panic!("expected Sink error, got {other:?}"),
        }
        assert_eq!(
            err.sink_error_class(),
            Some(SinkErrorClass::WriteFailure),
            "the pipeline surfaces the failing sink's carried class"
        );
        assert!(handle.writes() >= 1, "write must have been attempted");
        assert_eq!(handle.flushes(), 1, "flush must be called after error");
    }

    #[tokio::test]
    async fn run_discovery_flushes_sink_on_cancellation_before_any_emit() {
        let port = open_loopback_port().await;
        let scenario = scenario_for_port(port);

        let (tx, rx) = watch::channel(false);
        tx.send(true).expect("send cancel");

        let mem = crate::sink::MemorySink::new();
        let mem_handle = mem.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));

        let summary =
            run_discovery_with_components_cancellable(&scenario, resolver, Box::new(mem), rx)
                .await
                .expect("cancellation path returns Ok summary");
        assert!(summary.cancelled, "cancelled flag must be set");
        assert_eq!(summary.records_emitted, 0);
        assert_eq!(summary.probe_attempts, 0);
        assert!(
            mem_handle.bytes().is_empty(),
            "no records emitted, sink empty"
        );
    }

    #[tokio::test]
    async fn run_discovery_cancellation_returns_partial_summary_with_cancelled_true() {
        let port = open_loopback_port().await;
        let mut scenario = scenario_for_port(port);
        scenario.probers = vec![
            ProberConfig::TcpConnect { ports: vec![port] },
            ProberConfig::TcpConnect { ports: vec![port] },
        ];

        let (tx, rx) = watch::channel(false);
        tx.send(true).expect("send cancel");

        let mem = crate::sink::MemorySink::new();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary =
            run_discovery_with_components_cancellable(&scenario, resolver, Box::new(mem), rx)
                .await
                .expect("cancellation returns summary");
        assert!(summary.cancelled);
        assert_eq!(summary.probe_attempts, 0);
        assert!(summary.error_counts.is_empty());
        assert_eq!(summary.records_emitted, 0);
    }

    #[tokio::test]
    async fn run_discovery_cancel_emits_completed_targets_atomically() {
        let port = open_loopback_port().await;

        // 198.51.100.x is TEST-NET-2: connects there time out, so the scan is still priming new
        // targets when the 50ms cancel lands. Loopback target 0 finishes fast and reaches the sink.
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(400),
                max_concurrent: Some(4),
                ..Default::default()
            },
            targets: vec![
                Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Target::Ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
                Target::Ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))),
                Target::Ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3))),
            ],
            probers: vec![
                ProberConfig::TcpConnect { ports: vec![port] },
                ProberConfig::TcpConnect { ports: vec![port] },
            ],
        };

        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = tx.send(true);
        });

        let mem = crate::sink::MemorySink::new();
        let mem_handle = mem.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary =
            run_discovery_with_components_cancellable(&scenario, resolver, Box::new(mem), rx)
                .await
                .expect("returns summary");

        assert!(summary.cancelled, "cancelled flag must be true");
        assert_eq!(
            summary.probe_attempts % 2,
            0,
            "target-outer cancellation is atomic per target: a returned target carries every prober's outcome, so attempts is a multiple of the prober count"
        );
        assert!(
            summary.records_emitted >= 1,
            "the completed loopback target's record must reach the sink even though the run was cancelled"
        );
        assert!(
            !mem_handle.ndjson_lines().is_empty(),
            "sink received at least one NDJSON line from a completed target"
        );
    }

    struct CancelAfterFirstWriteSink {
        cancel_tx: watch::Sender<bool>,
        delegate: crate::sink::MemorySink,
        first: bool,
        flushes: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl crate::sink::Sink for CancelAfterFirstWriteSink {
        async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
            self.delegate.write(data).await?;
            if self.first {
                self.first = false;
                let _ = self.cancel_tx.send(true);
            }
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            self.flushes.fetch_add(1, Ordering::SeqCst);
            self.delegate.flush().await
        }
    }

    #[tokio::test]
    async fn run_discovery_cancel_signaled_mid_emit_drains_all_records() {
        let port = open_loopback_port().await;

        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let (tx, rx) = watch::channel(false);
        let mem = crate::sink::MemorySink::new();
        let mem_handle = mem.handle();
        let flushes = Arc::new(AtomicUsize::new(0));
        let sink = Box::new(CancelAfterFirstWriteSink {
            cancel_tx: tx,
            delegate: mem,
            first: true,
            flushes: Arc::clone(&flushes),
        });
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery_with_components_cancellable(&scenario, resolver, sink, rx)
            .await
            .expect("cancel mid-emit returns summary");

        assert_eq!(
            summary.records_emitted, 1,
            "the sole record must reach the sink; emit loop must not short-circuit on cancel"
        );
        assert!(
            !summary.cancelled,
            "cancel arrived after the prober loop and post-loop re-check; cancelled stays false"
        );
        assert_eq!(mem_handle.ndjson_lines().len(), 1);
        assert!(
            flushes.load(Ordering::SeqCst) >= 1,
            "flush must be called on every exit path"
        );
    }

    #[tokio::test]
    async fn run_discovery_cancel_during_single_prober_run_sets_cancelled_flag() {
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(200),
                max_concurrent: Some(4),
                // pace starts so scheduler.run outlasts the 50ms cancel — deterministic, not connect-timing dependent
                probe_rate: Some(10),
                ..Default::default()
            },
            targets: vec![
                Target::Ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
                Target::Ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))),
                Target::Ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3))),
                Target::Ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4))),
            ],
            probers: vec![ProberConfig::TcpConnect { ports: vec![1] }],
        };

        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = tx.send(true);
        });

        let sink = Box::new(FailingSink::new(usize::MAX));
        let handle = sink.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery_with_components_cancellable(&scenario, resolver, sink, rx)
            .await
            .expect("returns summary");

        assert!(
            summary.cancelled,
            "post-loop re-check must observe cancel signaled during the single in-flight scheduler.run"
        );
        assert_eq!(
            summary.probe_attempts, 4,
            "scheduler.run completes naturally; all targets attempted"
        );
        assert_eq!(
            summary.records_emitted, 0,
            "all targets unreachable; no records to emit"
        );
        assert_eq!(handle.flushes(), 1, "flush must run on the cancel path");
    }

    #[tokio::test]
    async fn run_discovery_non_cancelled_path_sets_cancelled_false() {
        let port = open_loopback_port().await;
        let scenario = scenario_for_port(port);

        let mem = crate::sink::MemorySink::new();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery_with_components(&scenario, resolver, Box::new(mem))
            .await
            .expect("run_discovery_with_components");
        assert!(!summary.cancelled);
        assert_eq!(summary.records_emitted, 1);
    }

    #[derive(Default)]
    struct BatchingSinkInner {
        committed: std::sync::Mutex<Vec<Vec<u8>>>,
        closes: AtomicUsize,
        flushes: AtomicUsize,
    }

    struct BatchingSink {
        inner: Arc<BatchingSinkInner>,
        buffer: Vec<Vec<u8>>,
    }

    impl BatchingSink {
        fn new() -> Self {
            Self {
                inner: Arc::new(BatchingSinkInner::default()),
                buffer: Vec::new(),
            }
        }
        fn handle(&self) -> Arc<BatchingSinkInner> {
            Arc::clone(&self.inner)
        }
        fn commit(&mut self) {
            let mut committed = self
                .inner
                .committed
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            committed.extend(self.buffer.drain(..));
        }
    }

    #[async_trait::async_trait]
    impl crate::sink::Sink for BatchingSink {
        async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
            self.buffer.push(data.to_vec());
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            self.inner.flushes.fetch_add(1, Ordering::SeqCst);
            self.commit();
            Ok(())
        }
        async fn close(&mut self) -> Result<(), RastreoError> {
            self.inner.closes.fetch_add(1, Ordering::SeqCst);
            self.commit();
            Ok(())
        }
    }

    #[tokio::test]
    async fn run_discovery_closes_the_sink_once_at_end_of_stream() {
        let port = open_loopback_port().await;
        let scenario = scenario_for_port(port);

        let sink = Box::new(BatchingSink::new());
        let handle = sink.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery_with_components(&scenario, resolver, sink)
            .await
            .expect("run_discovery_with_components");
        assert_eq!(summary.records_emitted, 1);
        assert_eq!(
            handle.closes.load(Ordering::SeqCst),
            1,
            "the pipeline must close the sink exactly once at end-of-stream"
        );
        assert_eq!(
            handle.flushes.load(Ordering::SeqCst),
            0,
            "the terminal drain is close(), not flush()"
        );
    }

    #[tokio::test]
    async fn run_discovery_close_drains_a_batched_sink() {
        let port = open_loopback_port().await;
        let scenario = scenario_for_port(port);

        let sink = Box::new(BatchingSink::new());
        let handle = sink.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery_with_components(&scenario, resolver, sink)
            .await
            .expect("run_discovery_with_components");
        assert_eq!(summary.records_emitted, 1);
        let committed = handle.committed.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            committed.len(),
            1,
            "a record buffered during write must be delivered by close(), not lost"
        );
    }

    #[tokio::test]
    async fn pipeline_correlates_multi_ip_device_via_shared_sysname_and_mac() {
        use crate::fuser::IdentityHints;
        use crate::model::outcome::{ProbeKind, Signal};
        use std::time::SystemTime;

        // Stand up an IdentityFuser directly and drive it with hand-built outcomes.
        // The full run_discovery path is exercised elsewhere; here we assert the fuser
        // composes correctly at the pipeline boundary.
        let sysname = Signal::SnmpSysName("core-sw01".into());
        let mac = "aa:bb:cc:11:22:33";
        let outcomes = vec![
            ProbeOutcome {
                kind: ProbeKind::Snmp,
                target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                timestamp: SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: vec![Signal::Mac(mac.into()), sysname.clone()],
                fault: None,
            },
            ProbeOutcome {
                kind: ProbeKind::Snmp,
                target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                timestamp: SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: vec![Signal::Mac(mac.into()), sysname.clone()],
                fault: None,
            },
            ProbeOutcome {
                kind: ProbeKind::Snmp,
                target_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                timestamp: SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: vec![Signal::Mac(mac.into()), sysname.clone()],
                fault: None,
            },
        ];
        let fuser_cfg = FuserConfig::Identity {
            identity_hints: IdentityHints::default(),
            inner: Box::new(FuserConfig::Direct {
                include_unreachable: None,
                confidence_baseline: None,
                confidence_per_signal: None,
            }),
        };
        let mut f = create_fuser(&fuser_cfg).expect("create");
        let records = drive_fuser(f.as_mut(), outcomes).expect("drive");
        assert_eq!(records.len(), 1, "three IPs share sysName+MAC, one record");
        let r = &records[0];
        assert_eq!(r.mgmt_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        let alt_addresses: Vec<IpAddr> = r.alt_ips.iter().map(|a| a.address).collect();
        assert_eq!(
            alt_addresses,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            ]
        );
        assert!(r.possible_alias_of.is_none());
    }

    #[tokio::test]
    async fn pipeline_runs_classifier_after_fuser() {
        let port = open_loopback_port().await;
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                classifier: Some(ClassifierConfig::Noop),
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery_with_components(&scenario, resolver, Box::new(mem))
            .await
            .expect("run_discovery_with_components");
        assert_eq!(summary.records_emitted, 1);
        let lines = handle.ndjson_lines();
        assert_eq!(lines.len(), 1);
        let record: crate::model::DeviceRecord =
            serde_json::from_str(&lines[0]).expect("parse json");
        assert!(record.platform.is_none(), "noop must leave platform unset");
        assert!(record.role.is_none(), "noop must leave role unset");
    }

    #[tokio::test]
    async fn run_discovery_stamps_scan_metadata_on_every_record() {
        let port_a = open_loopback_port().await;
        let port_b = open_loopback_port().await;

        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                name: Some("integration-lab".into()),
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![
                ProberConfig::TcpConnect {
                    ports: vec![port_a],
                },
                ProberConfig::TcpConnect {
                    ports: vec![port_b],
                },
            ],
        };

        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();
        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let summary = run_discovery_with_components(&scenario, resolver, Box::new(mem))
            .await
            .expect("run_discovery_with_components");
        assert!(summary.records_emitted >= 1);

        let lines = handle.ndjson_lines();
        assert!(!lines.is_empty());
        let records: Vec<crate::model::DeviceRecord> = lines
            .iter()
            .map(|l| serde_json::from_str(l).expect("parse record"))
            .collect();
        let first = &records[0];
        assert_eq!(first.scan_metadata.scan_id.len(), 26);
        assert_eq!(
            first.scan_metadata.scenario_name.as_deref(),
            Some("integration-lab")
        );
        for r in &records {
            assert_eq!(
                r.scan_metadata.scan_id, first.scan_metadata.scan_id,
                "all records must share the same scan_id"
            );
            assert_eq!(
                r.scan_metadata.initiated_at, first.scan_metadata.initiated_at,
                "all records must share the same initiated_at"
            );
            assert_eq!(r.schema_version, crate::model::CURRENT_SCHEMA_VERSION);
            assert_eq!(r.schema_id, crate::model::CURRENT_SCHEMA_ID);
        }
    }

    #[test]
    fn stamp_scan_metadata_shares_one_arc_across_records() {
        fn stub() -> DeviceRecord {
            DeviceRecord {
                identity_key: crate::model::IdentityKey::new("id").expect("identity"),
                mgmt_ip: None,
                mac: None,
                manufacturer: None,
                platform: None,
                os_version: None,
                ssh_version: None,
                http_server: None,
                http_version: None,
                role: None,
                confidence: crate::model::Confidence::new(0.0).expect("confidence"),
                last_seen: std::time::SystemTime::UNIX_EPOCH,
                signals: Vec::new(),
                probe_kinds: Vec::new(),
                schema_version: crate::model::CURRENT_SCHEMA_VERSION.to_string(),
                schema_id: crate::model::CURRENT_SCHEMA_ID.to_string(),
                alt_ips: Vec::new(),
                possible_alias_of: None,
                scan_metadata: Arc::new(ScanMetadata::default()),
            }
        }

        let scan_metadata = Arc::new(ScanMetadata::new(&scenario_with_probers(vec![
            ProberConfig::TcpConnect { ports: vec![22] },
        ])));
        let mut first = stub();
        let mut second = stub();
        stamp_scan_metadata(&mut first, &scan_metadata);
        stamp_scan_metadata(&mut second, &scan_metadata);

        assert!(
            Arc::ptr_eq(&first.scan_metadata, &second.scan_metadata),
            "every record from one scan must share ONE Arc<ScanMetadata>, not a per-record clone"
        );
    }

    #[tokio::test]
    async fn resolve_scenario_targets_returns_one_entry_per_input_target() {
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig::default(),
            targets: vec![
                Target::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                Target::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
                Target::Cidr("10.0.0.0/30".parse().expect("cidr")),
            ],
            probers: vec![ProberConfig::TcpConnect { ports: vec![22] }],
        };

        let resolver = HickoryResolver::from_system().expect("resolver init");
        let out = resolve_scenario_targets(&scenario, &resolver).await;
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].target, scenario.targets[0]);
        assert_eq!(out[1].target, scenario.targets[1]);
        assert_eq!(out[2].target, scenario.targets[2]);
    }

    #[tokio::test]
    async fn resolve_scenario_targets_expands_single_ip_to_one_address() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42));
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig::default(),
            targets: vec![Target::Ip(ip)],
            probers: vec![ProberConfig::TcpConnect { ports: vec![22] }],
        };

        let resolver = HickoryResolver::from_system().expect("resolver init");
        let out = resolve_scenario_targets(&scenario, &resolver).await;
        assert_eq!(out.len(), 1);
        let ips = out[0].result.as_ref().expect("resolves");
        assert_eq!(ips, &vec![ip]);
    }

    #[tokio::test]
    async fn resolve_scenario_targets_expands_cidr_to_all_host_addresses() {
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig::default(),
            targets: vec![Target::Cidr("10.0.0.0/30".parse().expect("cidr"))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![22] }],
        };

        let resolver = HickoryResolver::from_system().expect("resolver init");
        let out = resolve_scenario_targets(&scenario, &resolver).await;
        let ips = out[0].result.as_ref().expect("resolves");
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(ips[1], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[tokio::test]
    async fn resolve_scenario_targets_isolates_failure_to_offending_target() {
        let good = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig::default(),
            targets: vec![
                Target::Ip(good),
                Target::Range {
                    start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
                    end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                },
                Target::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            ],
            probers: vec![ProberConfig::TcpConnect { ports: vec![22] }],
        };

        let resolver = HickoryResolver::from_system().expect("resolver init");
        let out = resolve_scenario_targets(&scenario, &resolver).await;
        assert_eq!(out.len(), 3);
        assert!(out[0].result.is_ok());
        assert!(matches!(
            &out[1].result,
            Err(RastreoError::Resolver(
                crate::error::ResolverError::InvalidRange { .. }
            ))
        ));
        assert!(out[2].result.is_ok());
    }

    #[tokio::test]
    async fn resolve_scenario_targets_preserves_input_order_and_duplicates() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig::default(),
            targets: vec![Target::Ip(ip), Target::Ip(ip), Target::Ip(ip)],
            probers: vec![ProberConfig::TcpConnect { ports: vec![22] }],
        };

        let resolver = HickoryResolver::from_system().expect("resolver init");
        let out = resolve_scenario_targets(&scenario, &resolver).await;
        assert_eq!(out.len(), 3, "no de-dup — one entry per input target");
        for entry in &out {
            let ips = entry.result.as_ref().expect("resolves");
            assert_eq!(ips, &vec![ip]);
        }
    }

    mod inversion_differential {
        use super::*;

        use std::time::SystemTime;

        use crate::model::Signal;

        const FAULT_P1_T2: &str = "fault-pass1-target2";
        const FAULT_P2_T0: &str = "fault-pass2-target0";

        type ProbeSetup = (Vec<Arc<dyn Prober>>, Vec<ResolvedTarget>);
        type MatrixSetup = (&'static str, Vec<Arc<dyn Prober>>, Vec<ResolvedTarget>);

        #[derive(Clone)]
        enum Resp {
            Reachable(Vec<Signal>),
            Dark,
            Fault(ProbeErrorKind, &'static str),
            Err(&'static str),
        }

        struct ScriptedProber {
            kind: ProbeKind,
            responses: Vec<Resp>,
        }

        #[async_trait::async_trait]
        impl Prober for ScriptedProber {
            fn kind(&self) -> ProbeKind {
                self.kind
            }

            async fn probe(
                &self,
                target: &ResolvedTarget,
                _ctx: &ProbeCtx,
            ) -> Result<ProbeOutcome, RastreoError> {
                let idx = match target.ip {
                    IpAddr::V4(v4) => v4.octets()[3] as usize,
                    IpAddr::V6(_) => 0,
                };
                match &self.responses[idx] {
                    Resp::Reachable(signals) => Ok(ProbeOutcome {
                        kind: self.kind,
                        target_ip: target.ip,
                        timestamp: SystemTime::UNIX_EPOCH,
                        reachable: true,
                        signals: signals.clone(),
                        fault: None,
                    }),
                    Resp::Dark => Ok(ProbeOutcome {
                        kind: self.kind,
                        target_ip: target.ip,
                        timestamp: SystemTime::UNIX_EPOCH,
                        reachable: false,
                        signals: Vec::new(),
                        fault: None,
                    }),
                    Resp::Fault(kind, detail) => Ok(ProbeOutcome {
                        kind: self.kind,
                        target_ip: target.ip,
                        timestamp: SystemTime::UNIX_EPOCH,
                        reachable: true,
                        signals: Vec::new(),
                        fault: Some(ProbeFault::new(*kind, *detail)),
                    }),
                    Resp::Err(msg) => Err(RastreoError::Probe(crate::error::ProbeError::Other(
                        (*msg).to_string(),
                    ))),
                }
            }
        }

        fn scripted(kind: ProbeKind, responses: Vec<Resp>) -> Arc<dyn Prober> {
            Arc::new(ScriptedProber { kind, responses })
        }

        fn resolved_n(n: u8) -> Vec<ResolvedTarget> {
            (0..n)
                .map(|i| {
                    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
                    ResolvedTarget {
                        ip,
                        original: Target::Ip(ip),
                        resolved_at: SystemTime::UNIX_EPOCH,
                    }
                })
                .collect()
        }

        fn direct_cfg() -> FuserConfig {
            FuserConfig::Direct {
                include_unreachable: None,
                confidence_baseline: None,
                confidence_per_signal: None,
            }
        }

        fn identity_cfg() -> FuserConfig {
            FuserConfig::Identity {
                identity_hints: crate::fuser::IdentityHints::default(),
                inner: Box::new(direct_cfg()),
            }
        }

        // Prober-outer reference: the pre-inversion pipeline body, frozen. A deterministic mock
        // makes serial probing equivalent to the concurrent scheduler, so this pins the exact
        // outcome order and first-seen fault the batch loop produced.
        async fn scan_and_accumulate_batch(
            probers: Vec<Arc<dyn Prober>>,
            resolved: Vec<ResolvedTarget>,
            ctx: ProbeCtx,
        ) -> ScanAccumulation {
            let mut acc = ScanAccumulation::default();
            for prober in &probers {
                let kind = prober.kind();
                for target in &resolved {
                    let result = prober.probe(target, &ctx).await;
                    acc.probe_attempts += 1;
                    acc.attempts_by_kind[kind.index()] += 1;
                    match result {
                        Ok(outcome) => {
                            if let Some(fault) = &outcome.fault {
                                acc.errors_by_kind[kind.index()] += 1;
                                *acc.error_counts.entry(fault.kind).or_insert(0) += 1;
                                if acc.first_probe_error.is_none() {
                                    acc.first_probe_error = Some(fault.clone());
                                }
                            }
                            acc.all_outcomes.push(outcome);
                        }
                        Err(err) => {
                            acc.errors_by_kind[kind.index()] += 1;
                            *acc.error_counts.entry(ProbeErrorKind::Other).or_insert(0) += 1;
                            if acc.first_probe_error.is_none() {
                                let msg = err.to_string();
                                if !msg.is_empty() {
                                    acc.first_probe_error =
                                        Some(ProbeFault::new(ProbeErrorKind::Other, msg));
                                }
                            }
                        }
                    }
                }
            }
            acc
        }

        async fn run_case(
            probers: Vec<Arc<dyn Prober>>,
            resolved: Vec<ResolvedTarget>,
            fuser_cfg: &FuserConfig,
            scan_metadata: &Arc<ScanMetadata>,
            inverted: bool,
        ) -> (DiscoverySummary, Vec<String>) {
            let ctx = ProbeCtx {
                timeout: Duration::from_millis(100),
                retries: 0,
            };
            let mut fuser = create_fuser(fuser_cfg).expect("fuser");
            let classifier = create_classifier(&ClassifierConfig::Noop).expect("classifier");
            let encoder = create_encoder(&EncoderConfig::Ndjson).expect("encoder");
            let mem = crate::sink::MemorySink::new();
            let handle = mem.handle();
            let mut sink: Box<dyn Sink> = Box::new(mem);
            let targets_resolved = resolved.len();
            let start = Instant::now();

            let acc = if inverted {
                let scheduler = BoundedScheduler::new(8);
                scan_and_accumulate(&scheduler, probers, resolved, ctx, watch::channel(false).1)
                    .await
            } else {
                scan_and_accumulate_batch(probers, resolved, ctx).await
            };

            let summary = finish_discovery(
                acc,
                fuser.as_mut(),
                classifier.as_ref(),
                encoder.as_ref(),
                sink.as_mut(),
                scan_metadata,
                targets_resolved,
                start,
            )
            .await
            .expect("finish_discovery");

            (summary, handle.ndjson_lines())
        }

        fn assert_summaries_match(new: &DiscoverySummary, batch: &DiscoverySummary, label: &str) {
            assert_eq!(
                new.targets_resolved, batch.targets_resolved,
                "{label}: targets_resolved"
            );
            assert_eq!(
                new.probe_attempts, batch.probe_attempts,
                "{label}: probe_attempts"
            );
            assert_eq!(
                new.records_emitted, batch.records_emitted,
                "{label}: records_emitted"
            );
            assert_eq!(
                new.error_counts, batch.error_counts,
                "{label}: error_counts"
            );
            assert_eq!(
                new.probes_by_kind, batch.probes_by_kind,
                "{label}: probes_by_kind"
            );
            assert_eq!(new.dlq_records, batch.dlq_records, "{label}: dlq_records");
            assert_eq!(
                new.dlq_records_by_type_and_class, batch.dlq_records_by_type_and_class,
                "{label}: dlq_records_by_type_and_class"
            );
            assert_eq!(new.sink_type, batch.sink_type, "{label}: sink_type");
            assert_eq!(new.cancelled, batch.cancelled, "{label}: cancelled");
            assert_eq!(
                new.first_probe_error, batch.first_probe_error,
                "{label}: first_probe_error"
            );
            // elapsed intentionally excluded — wall-clock differs between the two runs.
        }

        fn first_probe_error_stress_setup() -> ProbeSetup {
            let probers = vec![
                scripted(
                    ProbeKind::TcpConnect,
                    vec![
                        Resp::Reachable(vec![Signal::OpenPort(22)]),
                        Resp::Reachable(vec![Signal::OpenPort(22)]),
                        Resp::Reachable(vec![Signal::OpenPort(22)]),
                    ],
                ),
                scripted(
                    ProbeKind::Http,
                    vec![
                        Resp::Reachable(vec![Signal::HttpBanner("nginx".into())]),
                        Resp::Reachable(vec![Signal::HttpBanner("nginx".into())]),
                        Resp::Fault(ProbeErrorKind::PermissionDenied, FAULT_P1_T2),
                    ],
                ),
                scripted(
                    ProbeKind::Snmp,
                    vec![
                        Resp::Fault(ProbeErrorKind::DecodeFailed, FAULT_P2_T0),
                        Resp::Reachable(vec![Signal::SnmpSysName("sw".into())]),
                        Resp::Reachable(vec![Signal::SnmpSysName("sw".into())]),
                    ],
                ),
            ];
            (probers, resolved_n(3))
        }

        fn matrix_setups() -> Vec<MatrixSetup> {
            let (stress_probers, stress_targets) = first_probe_error_stress_setup();
            vec![
                (
                    "empty",
                    vec![scripted(ProbeKind::TcpConnect, vec![Resp::Dark])],
                    resolved_n(0),
                ),
                (
                    "single_reachable",
                    vec![scripted(
                        ProbeKind::TcpConnect,
                        vec![Resp::Reachable(vec![Signal::OpenPort(22)])],
                    )],
                    resolved_n(1),
                ),
                (
                    "single_dark",
                    vec![scripted(ProbeKind::TcpConnect, vec![Resp::Dark])],
                    resolved_n(1),
                ),
                (
                    "multi_mixed_three_probers",
                    vec![
                        scripted(
                            ProbeKind::TcpConnect,
                            vec![
                                Resp::Reachable(vec![Signal::OpenPort(22)]),
                                Resp::Dark,
                                Resp::Reachable(vec![Signal::OpenPort(22)]),
                            ],
                        ),
                        scripted(
                            ProbeKind::Http,
                            vec![
                                Resp::Reachable(vec![Signal::HttpBanner("nginx".into())]),
                                Resp::Reachable(vec![Signal::HttpBanner("nginx".into())]),
                                Resp::Dark,
                            ],
                        ),
                        scripted(
                            ProbeKind::Snmp,
                            vec![
                                Resp::Dark,
                                Resp::Reachable(vec![Signal::SnmpSysName("sw".into())]),
                                Resp::Reachable(vec![Signal::SnmpSysName("sw".into())]),
                            ],
                        ),
                    ],
                    resolved_n(3),
                ),
                (
                    "faulted",
                    vec![scripted(
                        ProbeKind::TcpConnect,
                        vec![
                            Resp::Fault(ProbeErrorKind::DecodeFailed, "decode-t0"),
                            Resp::Reachable(vec![Signal::OpenPort(22)]),
                        ],
                    )],
                    resolved_n(2),
                ),
                (
                    "stray_err",
                    vec![scripted(
                        ProbeKind::TcpConnect,
                        vec![
                            Resp::Err("could not attempt"),
                            Resp::Reachable(vec![Signal::OpenPort(22)]),
                        ],
                    )],
                    resolved_n(2),
                ),
                (
                    "all_dark",
                    vec![scripted(
                        ProbeKind::TcpConnect,
                        vec![Resp::Dark, Resp::Dark, Resp::Dark],
                    )],
                    resolved_n(3),
                ),
                ("first_probe_error_stress", stress_probers, stress_targets),
            ]
        }

        #[tokio::test]
        async fn inverted_pipeline_matches_batch_reference_across_matrix() {
            #[allow(unused_mut)]
            let mut fusers = vec![direct_cfg(), identity_cfg()];
            #[cfg(feature = "oui")]
            fusers.push(FuserConfig::OuiEnrichment {
                data_path: String::new(),
                inner: Box::new(direct_cfg()),
            });

            for (label, probers, resolved) in matrix_setups() {
                for fuser_cfg in &fusers {
                    let scan_metadata = Arc::new(ScanMetadata::default());
                    let (summary_new, records_new) = run_case(
                        probers.clone(),
                        resolved.clone(),
                        fuser_cfg,
                        &scan_metadata,
                        true,
                    )
                    .await;
                    let (summary_batch, records_batch) = run_case(
                        probers.clone(),
                        resolved.clone(),
                        fuser_cfg,
                        &scan_metadata,
                        false,
                    )
                    .await;
                    assert_summaries_match(&summary_new, &summary_batch, label);
                    assert_eq!(
                        records_new, records_batch,
                        "{label}: inverted and batch pipelines must emit byte-identical records"
                    );
                }
            }
        }

        #[tokio::test]
        async fn inverted_first_probe_error_uses_batch_prober_outer_choice() {
            let (probers, resolved) = first_probe_error_stress_setup();
            let scan_metadata = Arc::new(ScanMetadata::default());
            let (summary, _) =
                run_case(probers, resolved, &direct_cfg(), &scan_metadata, true).await;
            let fault = summary.first_probe_error.expect("a fault must be latched");
            assert_eq!(
                fault.detail, FAULT_P1_T2,
                "first_probe_error must be the batch's prober-outer first fault (pass 1, target 2), \
                 not the target-outer first-seen fault (pass 2, target 0)"
            );
        }
    }
}
