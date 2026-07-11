use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::classifier::{create_classifier, ClassifierConfig};
use crate::config::DiscoverScenarioConfig;
use crate::encoder::{create_encoder, EncoderConfig};
use crate::error::{ConfigError, RastreoError};
use crate::fuser::{create_fuser, FuserConfig};
use crate::model::{ProbeCtx, ProbeKind, ProbeOutcome, ScanMetadata, Target, PROBE_KIND_COUNT};
use crate::prober::create_prober;
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
    pub probe_errors: usize,
    pub records_emitted: usize,
    /// Per-`ProbeKind` attempted / errored breakdown; empty when no probes ran.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub probes_by_kind: Vec<ProbeKindSummary>,
    /// Records delivered to a DLQ destination during this scan.
    #[serde(default)]
    pub dlq_records: usize,
    /// DLQ deliveries per underlying sink type; populated when the pipeline sink is a fan-out that wraps multiple protocol destinations. Empty for single-protocol sinks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dlq_records_by_type: Vec<(SinkType, u64)>,
    /// Concrete sink kind the scan wrote against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sink_type: Option<SinkType>,
    /// Sink error class when the scan terminated with a sink error; `None` when the scan completed or errored on a non-sink path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sink_error_class: Option<SinkErrorClass>,
    /// True when the run terminated early via the cancellation token; counters reflect partial progress.
    #[serde(default)]
    pub cancelled: bool,
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

/// Same as [`run_discovery`], but aborts between probers and between record emissions when `cancel` flips to true. The sink is flushed on every exit path.
pub async fn run_discovery_cancellable(
    scenario: &DiscoverScenarioConfig,
    cancel: watch::Receiver<bool>,
) -> Result<DiscoverySummary, RastreoError> {
    let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system()?);
    let sink_config = scenario.base.sink.clone().unwrap_or(SinkConfig::Stdout);
    let sink = create_sink(&sink_config).await?;
    run_discovery_with_components_cancellable(scenario, resolver, sink, cancel).await
}

/// Same as [`run_discovery_with_components`], but aborts between probers and between record emissions when `cancel` flips to true. The sink is flushed on every exit path.
pub async fn run_discovery_with_components_cancellable(
    scenario: &DiscoverScenarioConfig,
    resolver: Arc<dyn Resolver>,
    mut sink: Box<dyn Sink>,
    mut cancel: watch::Receiver<bool>,
) -> Result<DiscoverySummary, RastreoError> {
    if scenario.probers.is_empty() {
        return Err(ConfigError::invalid("scenario.probers must not be empty").into());
    }

    let start = Instant::now();
    let scan_metadata = ScanMetadata::new(scenario);

    let resolved = resolver.resolve_many(&scenario.targets).await?;
    let targets_resolved = resolved.len();

    let concurrency = scenario
        .base
        .rate_limit
        .unwrap_or(DEFAULT_CONCURRENCY)
        .max(1) as usize;
    let scheduler = BoundedScheduler::new(concurrency);

    let timeout_ms = scenario.base.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    let ctx = ProbeCtx {
        timeout: Duration::from_millis(timeout_ms),
        retries: 0,
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
    let fuser = create_fuser(&fuser_config)?;

    let classifier_config = scenario
        .base
        .classifier
        .clone()
        .unwrap_or(ClassifierConfig::Noop);
    let classifier = create_classifier(&classifier_config)?;

    let mut all_outcomes: Vec<ProbeOutcome> = Vec::new();
    let mut probe_attempts: usize = 0;
    let mut probe_errors: usize = 0;
    let mut cancelled = false;
    let mut attempts_by_kind: [usize; PROBE_KIND_COUNT] = [0; PROBE_KIND_COUNT];
    let mut errors_by_kind: [usize; PROBE_KIND_COUNT] = [0; PROBE_KIND_COUNT];

    let sink_type = sink.kind();

    for prober_config in &scenario.probers {
        if *cancel.borrow_and_update() {
            cancelled = true;
            break;
        }
        let prober: Arc<dyn crate::prober::Prober> = Arc::from(create_prober(prober_config)?);
        let prober_kind = prober.kind();
        let results = scheduler.run(prober, resolved.clone(), ctx.clone()).await;
        probe_attempts += results.len();
        attempts_by_kind[prober_kind.index()] += results.len();
        for result in results {
            match result {
                Ok(outcome) => all_outcomes.push(outcome),
                Err(err) => {
                    probe_errors += 1;
                    errors_by_kind[prober_kind.index()] += 1;
                    tracing::debug!(error = %err, "probe failed");
                }
            }
        }
    }

    if !cancelled && *cancel.borrow_and_update() {
        cancelled = true;
    }

    let mut records = fuser.fuse_many(all_outcomes)?;
    for record in &mut records {
        classifier.classify(record)?;
        record.scan_metadata = scan_metadata.clone();
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

    let flush_err = sink.flush().await.err();

    if cancelled {
        tracing::info!(records_emitted, "discovery cancelled; sink flushed");
    }

    let dlq_records_by_type = sink.dlq_records_by_type();
    let dlq_records = dlq_records_by_type
        .iter()
        .fold(0u64, |acc, (_, c)| acc.saturating_add(*c)) as usize;
    let probes_by_kind = build_probes_by_kind(&attempts_by_kind, &errors_by_kind);

    if let Some(e) = emit_err {
        return Err(e);
    }
    if let Some(e) = flush_err {
        return Err(e);
    }

    Ok(DiscoverySummary {
        targets_resolved,
        probe_attempts,
        probe_errors,
        records_emitted,
        probes_by_kind,
        dlq_records,
        dlq_records_by_type,
        sink_type: Some(sink_type),
        sink_error_class: None,
        cancelled,
        elapsed: start.elapsed(),
    })
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
        assert_eq!(summary.probe_errors, 0);
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
            probe_errors: 0,
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
            probe_errors: 0,
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
        assert!(summary.sink_error_class.is_none());
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
        assert!(summary.dlq_records_by_type.is_empty());
        assert!(summary.sink_type.is_none());
        assert!(summary.sink_error_class.is_none());
    }

    #[tokio::test]
    async fn discovery_summary_populates_dlq_records_by_type_on_tee_wrapped_kafka() {
        use crate::sink::{TeeChild, TeeSink};

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
            fn dlq_records_delivered(&self) -> u64 {
                self.dlq
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
        assert_eq!(summary.dlq_records_by_type, vec![(SinkType::Kafka, 1)]);
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
                return Err(RastreoError::Sink(std::io::Error::other(
                    "simulated write failure",
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
        match err {
            RastreoError::Sink(e) => {
                assert!(format!("{e}").contains("simulated"), "unexpected msg: {e}");
            }
            other => panic!("expected Sink error, got {other:?}"),
        }
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
        assert_eq!(summary.probe_errors, 0);
        assert_eq!(summary.records_emitted, 0);
    }

    #[tokio::test]
    async fn run_discovery_cancel_between_probers_emits_records_from_completed_probers() {
        let port = open_loopback_port().await;

        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(400),
                rate_limit: Some(4),
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
            summary.probe_attempts, 4,
            "first prober ran against all four targets; second prober was skipped"
        );
        assert!(
            summary.records_emitted >= 1,
            "records from prober 1 outcomes must reach the sink even though the run was cancelled"
        );
        assert!(
            !mem_handle.ndjson_lines().is_empty(),
            "sink received at least one NDJSON line from the completed prober"
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
                rate_limit: Some(4),
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
            },
            ProbeOutcome {
                kind: ProbeKind::Snmp,
                target_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                timestamp: SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: vec![Signal::Mac(mac.into()), sysname.clone()],
            },
            ProbeOutcome {
                kind: ProbeKind::Snmp,
                target_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                timestamp: SystemTime::UNIX_EPOCH,
                reachable: true,
                signals: vec![Signal::Mac(mac.into()), sysname.clone()],
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
        let f = create_fuser(&fuser_cfg).expect("create");
        let records = f.fuse_many(outcomes).expect("fuse_many");
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
}
