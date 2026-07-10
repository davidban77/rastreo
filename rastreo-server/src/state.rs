use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rastreo_core::observability::otlp_config::parse_env_u64;
use rastreo_core::{
    DiscoverySummary, Resolver, SinkErrorClass, SinkType, PROBE_KIND_COUNT, SINK_ERROR_CLASS_COUNT,
};

#[cfg(feature = "otlp")]
pub use rastreo_core::observability::otlp_config::OtlpProtocol;
#[cfg(feature = "otlp")]
use rastreo_core::observability::otlp_config::{parse_env_bool, parse_env_protocol};
#[cfg(feature = "otlp")]
use std::sync::OnceLock;

pub(crate) struct HistogramShard {
    pub buckets: [AtomicU64; 11],
    pub plus_inf: AtomicU64,
    pub sum_bits: AtomicU64,
    pub count: AtomicU64,
}

impl HistogramShard {
    pub const BUCKET_BOUNDS: [f64; 11] = [
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ];

    pub fn new() -> Self {
        Self {
            buckets: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            plus_inf: AtomicU64::new(0),
            sum_bits: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    pub fn observe(&self, seconds: f64) {
        for (i, bound) in Self::BUCKET_BOUNDS.iter().enumerate() {
            if seconds <= *bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.plus_inf.fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        let mut current = self.sum_bits.load(Ordering::Relaxed);
        loop {
            let updated = f64::from_bits(current) + seconds;
            match self.sum_bits.compare_exchange_weak(
                current,
                updated.to_bits(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    pub fn snapshot(&self) -> HistogramSnapshot {
        HistogramSnapshot {
            buckets: self.buckets.each_ref().map(|a| a.load(Ordering::Relaxed)),
            plus_inf: self.plus_inf.load(Ordering::Relaxed),
            sum: f64::from_bits(self.sum_bits.load(Ordering::Relaxed)),
            count: self.count.load(Ordering::Relaxed),
        }
    }
}

impl Default for HistogramShard {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) struct HistogramSnapshot {
    pub buckets: [u64; 11],
    pub plus_inf: u64,
    pub sum: f64,
    pub count: u64,
}

/// Per-`ProbeKind` success / error counters — fixed-size arrays indexed by `ProbeKind::index()`.
pub(crate) struct ProbeKindCounters {
    pub succeeded: [AtomicU64; PROBE_KIND_COUNT],
    pub errored: [AtomicU64; PROBE_KIND_COUNT],
}

impl ProbeKindCounters {
    fn new() -> Self {
        Self {
            succeeded: std::array::from_fn(|_| AtomicU64::new(0)),
            errored: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

/// Per-`SinkType` × per-`SinkErrorClass` DLQ delivery counters — v1 uses a sink-type-hint
/// mapping: Kafka DLQ deliveries record under `produce_failure`, NATS under `publish_failure`.
pub(crate) struct DlqRecordsCounter {
    pub kafka: [AtomicU64; SINK_ERROR_CLASS_COUNT],
    pub nats: [AtomicU64; SINK_ERROR_CLASS_COUNT],
}

impl DlqRecordsCounter {
    fn new() -> Self {
        Self {
            kafka: std::array::from_fn(|_| AtomicU64::new(0)),
            nats: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

/// Per-scenario scan-duration histogram bank. Every observation lands on `all`; if
/// the scenario name (truncated to `max_length`) is in `allowlist` it also lands on
/// `per_scenario[name]`, otherwise on the shared `other` shard.
pub(crate) struct ScenarioHistograms {
    pub all: HistogramShard,
    pub per_scenario: RwLock<HashMap<String, HistogramShard>>,
    pub allowlist: HashSet<String>,
    pub other: HistogramShard,
    pub max_length: usize,
}

impl ScenarioHistograms {
    fn new(allowlist: HashSet<String>, max_length: usize) -> Self {
        let mut seeded = HashMap::with_capacity(allowlist.len());
        for name in &allowlist {
            seeded.insert(name.clone(), HistogramShard::new());
        }
        Self {
            all: HistogramShard::new(),
            per_scenario: RwLock::new(seeded),
            allowlist,
            other: HistogramShard::new(),
            max_length,
        }
    }

    fn resolve_label<'a>(&self, scenario: &'a str) -> Option<&'a str> {
        let trimmed = if scenario.len() > self.max_length {
            // Snap down to a char boundary so multi-byte codepoints are never split.
            &scenario[..scenario.floor_char_boundary(self.max_length)]
        } else {
            scenario
        };
        if self.allowlist.contains(trimmed) {
            Some(trimmed)
        } else {
            None
        }
    }

    pub fn observe(&self, seconds: f64, scenario: &str) {
        self.all.observe(seconds);
        match self.resolve_label(scenario) {
            Some(label) => {
                {
                    let guard = self.per_scenario.read().unwrap_or_else(|e| e.into_inner());
                    if let Some(shard) = guard.get(label) {
                        shard.observe(seconds);
                        return;
                    }
                }
                let mut guard = self.per_scenario.write().unwrap_or_else(|e| e.into_inner());
                let shard = guard.entry(label.to_string()).or_default();
                shard.observe(seconds);
            }
            None => self.other.observe(seconds),
        }
    }
}

/// Server-side metric-cardinality guard: only scenario names in the allow-list
/// become distinct `scenario` label values; everything else buckets to `other`.
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    pub scenario_allowlist: HashSet<String>,
    pub scenario_max_length: usize,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            scenario_allowlist: HashSet::new(),
            scenario_max_length: 64,
        }
    }
}

impl MetricsConfig {
    /// Read `RASTREO_SCENARIO_LABEL_ALLOWLIST` (comma-separated) and `RASTREO_SCENARIO_LABEL_MAX_LENGTH`, falling back to defaults when unset.
    pub fn from_env() -> anyhow::Result<Self> {
        let allowlist: HashSet<String> = match std::env::var("RASTREO_SCENARIO_LABEL_ALLOWLIST") {
            Ok(raw) => raw
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect(),
            Err(std::env::VarError::NotPresent) => HashSet::new(),
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(anyhow::anyhow!(
                    "invalid value for RASTREO_SCENARIO_LABEL_ALLOWLIST: not valid UTF-8"
                ));
            }
        };
        for reserved in RESERVED_SCENARIO_LABELS {
            if allowlist.contains(*reserved) {
                return Err(anyhow::anyhow!(
                    "invalid value for RASTREO_SCENARIO_LABEL_ALLOWLIST: {reserved:?} is reserved \
                     for the aggregate / catch-all bucket and cannot be an allow-list entry"
                ));
            }
        }
        let max_length = parse_env_u64("RASTREO_SCENARIO_LABEL_MAX_LENGTH", 64)? as usize;
        Ok(Self {
            scenario_allowlist: allowlist,
            scenario_max_length: max_length.max(1),
        })
    }
}

const RESERVED_SCENARIO_LABELS: &[&str] = &["_all", "other"];

pub struct Metrics {
    pub started_at: Instant,
    pub scans_total_success: AtomicU64,
    pub scans_total_error: AtomicU64,
    pub scans_total_cancelled: AtomicU64,
    pub records_emitted_total: AtomicU64,
    pub(crate) probes: ProbeKindCounters,
    pub(crate) sink_errors: [AtomicU64; SINK_ERROR_CLASS_COUNT],
    pub(crate) dlq: DlqRecordsCounter,
    pub(crate) scan_duration: ScenarioHistograms,
    #[cfg(feature = "otlp")]
    otlp_scan_duration: OnceLock<opentelemetry::metrics::Histogram<f64>>,
}

impl Metrics {
    pub fn new() -> Self {
        Self::with_config(MetricsConfig::default())
    }

    pub fn with_config(config: MetricsConfig) -> Self {
        Self {
            started_at: Instant::now(),
            scans_total_success: AtomicU64::new(0),
            scans_total_error: AtomicU64::new(0),
            scans_total_cancelled: AtomicU64::new(0),
            records_emitted_total: AtomicU64::new(0),
            probes: ProbeKindCounters::new(),
            sink_errors: std::array::from_fn(|_| AtomicU64::new(0)),
            dlq: DlqRecordsCounter::new(),
            scan_duration: ScenarioHistograms::new(
                config.scenario_allowlist,
                config.scenario_max_length,
            ),
            #[cfg(feature = "otlp")]
            otlp_scan_duration: OnceLock::new(),
        }
    }

    #[cfg(feature = "otlp")]
    pub fn attach_otlp_scan_duration(
        &self,
        histogram: opentelemetry::metrics::Histogram<f64>,
    ) -> Result<(), opentelemetry::metrics::Histogram<f64>> {
        self.otlp_scan_duration.set(histogram)
    }

    pub fn record_scan_completion(&self, summary: &DiscoverySummary, scenario: &str) {
        if summary.cancelled {
            self.scans_total_cancelled.fetch_add(1, Ordering::Relaxed);
        } else {
            self.scans_total_success.fetch_add(1, Ordering::Relaxed);
        }
        self.records_emitted_total
            .fetch_add(summary.records_emitted as u64, Ordering::Relaxed);
        for pk in &summary.probes_by_kind {
            let succeeded = pk.attempted.saturating_sub(pk.errored) as u64;
            let idx = pk.kind.index();
            self.probes.succeeded[idx].fetch_add(succeeded, Ordering::Relaxed);
            self.probes.errored[idx].fetch_add(pk.errored as u64, Ordering::Relaxed);
        }
        if summary.dlq_records > 0 {
            self.record_dlq(summary.sink_type, summary.dlq_records as u64);
        }
        let seconds = summary.elapsed.as_secs_f64();
        self.scan_duration.observe(seconds, scenario);
        self.record_otlp_scan_duration(seconds, scenario);
    }

    pub fn record_scan_error(
        &self,
        elapsed: Duration,
        sink_class: Option<SinkErrorClass>,
        scenario: &str,
    ) {
        self.scans_total_error.fetch_add(1, Ordering::Relaxed);
        if let Some(class) = sink_class {
            self.sink_errors[class.index()].fetch_add(1, Ordering::Relaxed);
        }
        let seconds = elapsed.as_secs_f64();
        self.scan_duration.observe(seconds, scenario);
        self.record_otlp_scan_duration(seconds, scenario);
    }

    fn record_dlq(&self, sink_type: Option<SinkType>, count: u64) {
        let (bucket, class) = match sink_type {
            Some(SinkType::Kafka) => (&self.dlq.kafka, SinkErrorClass::ProduceFailure),
            Some(SinkType::Nats) => (&self.dlq.nats, SinkErrorClass::PublishFailure),
            _ => return,
        };
        bucket[class.index()].fetch_add(count, Ordering::Relaxed);
    }

    #[cfg(feature = "otlp")]
    fn record_otlp_scan_duration(&self, seconds: f64, scenario: &str) {
        if let Some(h) = self.otlp_scan_duration.get() {
            h.record(seconds, &[opentelemetry::KeyValue::new("scenario", "_all")]);
            let label = self
                .scan_duration
                .resolve_label(scenario)
                .unwrap_or("other");
            h.record(
                seconds,
                &[opentelemetry::KeyValue::new("scenario", label.to_string())],
            );
        }
    }

    #[cfg(not(feature = "otlp"))]
    fn record_otlp_scan_duration(&self, _seconds: f64, _scenario: &str) {}
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Tunables for the `/readyz` gate — each check disables when its knob is zero.
#[derive(Debug, Clone)]
pub struct ReadinessConfig {
    pub max_inflight_scans: u64,
    pub sink_error_quarantine: Duration,
    pub scan_error_quarantine: Duration,
}

impl Default for ReadinessConfig {
    fn default() -> Self {
        Self {
            max_inflight_scans: 100,
            sink_error_quarantine: Duration::from_secs(30),
            scan_error_quarantine: Duration::from_secs(30),
        }
    }
}

impl ReadinessConfig {
    /// Read `RASTREO_MAX_INFLIGHT_SCANS`, `RASTREO_SINK_ERROR_QUARANTINE_SECS`, and `RASTREO_SCAN_ERROR_QUARANTINE_SECS`, falling back to defaults when unset.
    pub fn from_env() -> anyhow::Result<Self> {
        let default = Self::default();
        Ok(Self {
            max_inflight_scans: parse_env_u64(
                "RASTREO_MAX_INFLIGHT_SCANS",
                default.max_inflight_scans,
            )?,
            sink_error_quarantine: Duration::from_secs(parse_env_u64(
                "RASTREO_SINK_ERROR_QUARANTINE_SECS",
                default.sink_error_quarantine.as_secs(),
            )?),
            scan_error_quarantine: Duration::from_secs(parse_env_u64(
                "RASTREO_SCAN_ERROR_QUARANTINE_SECS",
                default.scan_error_quarantine.as_secs(),
            )?),
        })
    }
}

/// OpenTelemetry OTLP exporter configuration read from `RASTREO_OTLP_*` environment variables.
#[cfg(feature = "otlp")]
#[derive(Debug, Clone)]
pub struct OtlpConfig {
    pub endpoint: String,
    pub protocol: OtlpProtocol,
    pub metrics_enabled: bool,
    pub logs_enabled: bool,
    pub metrics_interval: Duration,
    pub service_name: String,
}

#[cfg(feature = "otlp")]
impl OtlpConfig {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let metrics_enabled = parse_env_bool("RASTREO_OTLP_METRICS_ENABLED", false)?;
        let logs_enabled = parse_env_bool("RASTREO_OTLP_LOGS_ENABLED", false)?;
        if !metrics_enabled && !logs_enabled {
            return Ok(None);
        }
        let endpoint = match std::env::var("RASTREO_OTLP_ENDPOINT") {
            Ok(raw) if !raw.trim().is_empty() => raw,
            Ok(_) | Err(std::env::VarError::NotPresent) => {
                return Err(anyhow::anyhow!(
                    "RASTREO_OTLP_ENDPOINT is required when RASTREO_OTLP_METRICS_ENABLED or \
                     RASTREO_OTLP_LOGS_ENABLED is true; set it to your OTLP collector URL \
                     (for example http://otel-collector:4317 for gRPC or \
                     http://otel-collector:4318 for HTTP+protobuf)"
                ));
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(anyhow::anyhow!(
                    "invalid value for RASTREO_OTLP_ENDPOINT: not valid UTF-8"
                ));
            }
        };
        let protocol = parse_env_protocol("RASTREO_OTLP_PROTOCOL", OtlpProtocol::Grpc)?;
        let metrics_interval =
            Duration::from_secs(parse_env_u64("RASTREO_OTLP_METRICS_INTERVAL_SECS", 30)?);
        let service_name = std::env::var("RASTREO_OTLP_SERVICE_NAME")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "rastreo-server".to_string());
        Ok(Some(Self {
            endpoint,
            protocol,
            metrics_enabled,
            logs_enabled,
            metrics_interval,
            service_name,
        }))
    }
}

#[cfg(not(feature = "otlp"))]
#[derive(Debug, Clone)]
pub struct OtlpConfig;

#[cfg(not(feature = "otlp"))]
impl OtlpConfig {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        Ok(None)
    }
}

pub struct ReadinessState {
    pub inflight_scans: AtomicU64,
    pub last_sink_error_epoch_ms: AtomicU64,
    pub last_scan_error_epoch_ms: AtomicU64,
    pub config: ReadinessConfig,
}

impl ReadinessState {
    pub fn new(config: ReadinessConfig) -> Self {
        Self {
            inflight_scans: AtomicU64::new(0),
            last_sink_error_epoch_ms: AtomicU64::new(0),
            last_scan_error_epoch_ms: AtomicU64::new(0),
            config,
        }
    }

    pub fn record_scan_error(&self, is_sink_error: bool) {
        let now = current_epoch_ms();
        self.last_scan_error_epoch_ms.store(now, Ordering::Relaxed);
        if is_sink_error {
            self.last_sink_error_epoch_ms.store(now, Ordering::Relaxed);
        }
    }
}

impl Default for ReadinessState {
    fn default() -> Self {
        Self::new(ReadinessConfig::default())
    }
}

pub(crate) fn current_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone)]
pub struct AppState {
    pub resolver: Arc<dyn Resolver>,
    pub metrics: Arc<Metrics>,
    pub readiness: Arc<ReadinessState>,
}

impl AppState {
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        Self::with_readiness(resolver, ReadinessConfig::default())
    }

    pub fn with_readiness(resolver: Arc<dyn Resolver>, config: ReadinessConfig) -> Self {
        Self::with_config(resolver, config, MetricsConfig::default())
    }

    pub fn with_config(
        resolver: Arc<dyn Resolver>,
        readiness: ReadinessConfig,
        metrics: MetricsConfig,
    ) -> Self {
        Self {
            resolver,
            metrics: Arc::new(Metrics::with_config(metrics)),
            readiness: Arc::new(ReadinessState::new(readiness)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rastreo_core::HickoryResolver;

    fn build_state() -> AppState {
        let resolver: Arc<dyn Resolver> =
            Arc::new(HickoryResolver::from_system().expect("system resolver"));
        AppState::new(resolver)
    }

    #[test]
    fn app_state_is_send_sync_and_clone() {
        fn assert_send_sync_clone<T: Send + Sync + Clone>() {}
        assert_send_sync_clone::<AppState>();
    }

    #[test]
    fn clone_shares_resolver_arc() {
        let state = build_state();
        let clone = state.clone();
        assert!(Arc::ptr_eq(&state.resolver, &clone.resolver));
    }

    #[test]
    fn clone_shares_metrics_arc() {
        let state = build_state();
        let clone = state.clone();
        assert!(Arc::ptr_eq(&state.metrics, &clone.metrics));
    }

    #[test]
    fn histogram_shard_observe_increments_correct_bucket() {
        let shard = HistogramShard::new();
        shard.observe(0.004);
        let snap = shard.snapshot();
        assert_eq!(snap.buckets[0], 1, "0.004 is <= 0.005");
        // Cumulative — every higher bucket also incremented.
        assert_eq!(snap.buckets[10], 1, "0.004 is <= 10.0");
    }

    #[test]
    fn histogram_shard_observe_above_all_increments_plus_inf_only() {
        let shard = HistogramShard::new();
        shard.observe(100.0);
        let snap = shard.snapshot();
        for (i, b) in snap.buckets.iter().enumerate() {
            assert_eq!(*b, 0, "bucket {i} must stay zero for an out-of-range value");
        }
        assert_eq!(snap.plus_inf, 1);
        assert_eq!(snap.count, 1);
    }

    #[test]
    fn histogram_shard_sum_and_count_are_tracked() {
        let shard = HistogramShard::new();
        shard.observe(0.1);
        shard.observe(0.4);
        let snap = shard.snapshot();
        assert_eq!(snap.count, 2);
        assert!((snap.sum - 0.5).abs() < 1e-9);
    }

    use rastreo_core::{ProbeKind, ProbeKindSummary, SinkType};

    fn kind_summary(kind: ProbeKind, attempted: usize, errored: usize) -> ProbeKindSummary {
        let mut s = ProbeKindSummary::default();
        s.kind = kind;
        s.attempted = attempted;
        s.errored = errored;
        s
    }

    fn summary_completed(
        probe_attempts: usize,
        probe_errors: usize,
        records_emitted: usize,
        by_kind: Vec<ProbeKindSummary>,
        elapsed_ms: u64,
    ) -> DiscoverySummary {
        let mut s = DiscoverySummary::default();
        s.targets_resolved = 1;
        s.probe_attempts = probe_attempts;
        s.probe_errors = probe_errors;
        s.records_emitted = records_emitted;
        s.probes_by_kind = by_kind;
        s.elapsed = Duration::from_millis(elapsed_ms);
        s
    }

    #[test]
    fn metrics_record_scan_completion_increments_per_kind_counters() {
        let metrics = Metrics::new();
        let summary = summary_completed(
            10,
            2,
            5,
            vec![kind_summary(ProbeKind::TcpConnect, 10, 2)],
            123,
        );
        metrics.record_scan_completion(&summary, "unnamed");
        let idx = ProbeKind::TcpConnect.index();
        assert_eq!(metrics.scans_total_success.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.scans_total_cancelled.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.probes.succeeded[idx].load(Ordering::Relaxed), 8);
        assert_eq!(metrics.probes.errored[idx].load(Ordering::Relaxed), 2);
        assert_eq!(metrics.records_emitted_total.load(Ordering::Relaxed), 5);
        assert_eq!(metrics.scan_duration.all.snapshot().count, 1);
    }

    #[test]
    fn probes_succeeded_total_is_monotonic_across_multiple_scans() {
        let metrics = Metrics::new();
        let idx = ProbeKind::TcpConnect.index();
        metrics.record_scan_completion(
            &summary_completed(
                10,
                8,
                2,
                vec![kind_summary(ProbeKind::TcpConnect, 10, 8)],
                50,
            ),
            "unnamed",
        );
        let first = metrics.probes.succeeded[idx].load(Ordering::Relaxed);
        metrics.record_scan_completion(
            &summary_completed(
                100,
                90,
                10,
                vec![kind_summary(ProbeKind::TcpConnect, 100, 90)],
                50,
            ),
            "unnamed",
        );
        let second = metrics.probes.succeeded[idx].load(Ordering::Relaxed);
        assert_eq!(first, 2);
        assert_eq!(second, 12);
        assert!(second >= first);
    }

    #[test]
    fn metrics_record_scan_completion_with_cancelled_increments_cancelled_counter() {
        let metrics = Metrics::new();
        let mut summary = summary_completed(3, 0, 1, Vec::new(), 50);
        summary.cancelled = true;
        metrics.record_scan_completion(&summary, "unnamed");
        assert_eq!(metrics.scans_total_cancelled.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.scans_total_success.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn metrics_record_scan_error_without_sink_class_records_scan_error_only() {
        let metrics = Metrics::new();
        metrics.record_scan_error(Duration::from_millis(50), None, "unnamed");
        assert_eq!(metrics.scans_total_error.load(Ordering::Relaxed), 1);
        for class in SinkErrorClass::all() {
            assert_eq!(
                metrics.sink_errors[class.index()].load(Ordering::Relaxed),
                0
            );
        }
        assert_eq!(metrics.scan_duration.all.snapshot().count, 1);
    }

    #[test]
    fn metrics_record_scan_error_with_sink_class_increments_class_counter() {
        let metrics = Metrics::new();
        metrics.record_scan_error(
            Duration::from_millis(50),
            Some(SinkErrorClass::PublishFailure),
            "unnamed",
        );
        assert_eq!(metrics.scans_total_error.load(Ordering::Relaxed), 1);
        assert_eq!(
            metrics.sink_errors[SinkErrorClass::PublishFailure.index()].load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics.sink_errors[SinkErrorClass::AckRejection.index()].load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn metrics_record_dlq_delivery_credits_kafka_bucket_with_produce_failure() {
        let metrics = Metrics::new();
        let mut summary = summary_completed(1, 0, 1, Vec::new(), 10);
        summary.dlq_records = 3;
        summary.sink_type = Some(SinkType::Kafka);
        metrics.record_scan_completion(&summary, "unnamed");
        assert_eq!(
            metrics.dlq.kafka[SinkErrorClass::ProduceFailure.index()].load(Ordering::Relaxed),
            3
        );
        assert_eq!(
            metrics.dlq.nats[SinkErrorClass::PublishFailure.index()].load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn metrics_record_dlq_delivery_credits_nats_bucket_with_publish_failure() {
        let metrics = Metrics::new();
        let mut summary = summary_completed(1, 0, 1, Vec::new(), 10);
        summary.dlq_records = 5;
        summary.sink_type = Some(SinkType::Nats);
        metrics.record_scan_completion(&summary, "unnamed");
        assert_eq!(
            metrics.dlq.nats[SinkErrorClass::PublishFailure.index()].load(Ordering::Relaxed),
            5
        );
    }

    #[test]
    fn metrics_config_default_uses_empty_allowlist_and_max_length_64() {
        let cfg = MetricsConfig::default();
        assert!(cfg.scenario_allowlist.is_empty());
        assert_eq!(cfg.scenario_max_length, 64);
    }

    #[test]
    fn metrics_scan_duration_routes_non_allowlisted_scenario_to_other() {
        let metrics = Metrics::with_config(MetricsConfig {
            scenario_allowlist: {
                let mut s = HashSet::new();
                s.insert("allowed".to_string());
                s
            },
            scenario_max_length: 64,
        });
        metrics.record_scan_error(Duration::from_millis(50), None, "unlisted");
        assert_eq!(metrics.scan_duration.other.snapshot().count, 1);
        let guard = metrics.scan_duration.per_scenario.read().expect("lock");
        assert_eq!(
            guard.get("allowed").map(|s| s.snapshot().count),
            Some(0),
            "unlisted observation must not touch the allowlisted bucket"
        );
    }

    #[test]
    fn metrics_scan_duration_routes_allowlisted_scenario_to_named_bucket() {
        let metrics = Metrics::with_config(MetricsConfig {
            scenario_allowlist: {
                let mut s = HashSet::new();
                s.insert("prod".to_string());
                s
            },
            scenario_max_length: 64,
        });
        metrics.record_scan_error(Duration::from_millis(50), None, "prod");
        assert_eq!(metrics.scan_duration.all.snapshot().count, 1);
        assert_eq!(metrics.scan_duration.other.snapshot().count, 0);
        let guard = metrics.scan_duration.per_scenario.read().expect("lock");
        assert_eq!(guard.get("prod").map(|s| s.snapshot().count), Some(1));
    }

    #[test]
    fn metrics_scan_duration_truncates_scenario_name_to_max_length() {
        let long_name = "a".repeat(200);
        let truncated = &long_name[..5];
        let metrics = Metrics::with_config(MetricsConfig {
            scenario_allowlist: {
                let mut s = HashSet::new();
                s.insert(truncated.to_string());
                s
            },
            scenario_max_length: 5,
        });
        metrics.record_scan_error(Duration::from_millis(50), None, &long_name);
        let guard = metrics.scan_duration.per_scenario.read().expect("lock");
        assert!(guard.contains_key(truncated));
    }

    #[test]
    fn scenario_truncation_does_not_panic_on_multibyte_codepoint() {
        let metrics = Metrics::with_config(MetricsConfig {
            scenario_allowlist: HashSet::new(),
            scenario_max_length: 5,
        });
        // Each CJK character is 3 bytes in UTF-8; `max_length=5` lands mid-codepoint.
        metrics.record_scan_error(Duration::from_millis(50), None, "日本語日本語abcdef");
        assert_eq!(metrics.scan_duration.other.snapshot().count, 1);
    }

    #[test]
    fn observe_recovers_from_poisoned_per_scenario_lock() {
        let metrics = Arc::new(Metrics::with_config(MetricsConfig {
            scenario_allowlist: {
                let mut s = HashSet::new();
                s.insert("prod".to_string());
                s
            },
            scenario_max_length: 64,
        }));
        let poisoner = Arc::clone(&metrics);
        let handle = std::thread::spawn(move || {
            let _guard = poisoner
                .scan_duration
                .per_scenario
                .write()
                .expect("initial write lock");
            panic!("intentional poison");
        });
        let _ = handle.join();
        assert!(metrics.scan_duration.per_scenario.is_poisoned());
        metrics.record_scan_error(Duration::from_millis(50), None, "prod");
        assert_eq!(metrics.scan_duration.all.snapshot().count, 1);
        let guard = metrics
            .scan_duration
            .per_scenario
            .read()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(guard.get("prod").map(|s| s.snapshot().count), Some(1));
    }

    #[test]
    fn scenario_truncation_snaps_to_char_boundary_for_allowlist_match() {
        let metrics = Metrics::with_config(MetricsConfig {
            scenario_allowlist: {
                let mut s = HashSet::new();
                // 3 bytes: one CJK codepoint. `max_length=5` snaps down to 3.
                s.insert("日".to_string());
                s
            },
            scenario_max_length: 5,
        });
        metrics.record_scan_error(Duration::from_millis(50), None, "日本語");
        let guard = metrics.scan_duration.per_scenario.read().expect("lock");
        assert_eq!(guard.get("日").map(|s| s.snapshot().count), Some(1));
    }

    #[test]
    fn metrics_config_from_env_default_when_unset() {
        let _guard = env_guard();
        clear_env();
        // SAFETY: env_guard serialises env-var mutation across tests in this binary.
        unsafe {
            std::env::remove_var("RASTREO_SCENARIO_LABEL_ALLOWLIST");
            std::env::remove_var("RASTREO_SCENARIO_LABEL_MAX_LENGTH");
        }
        let cfg = MetricsConfig::from_env().expect("from_env");
        assert!(cfg.scenario_allowlist.is_empty());
        assert_eq!(cfg.scenario_max_length, 64);
    }

    #[test]
    fn metrics_config_from_env_parses_comma_separated_allowlist() {
        let _guard = env_guard();
        clear_env();
        // SAFETY: env_guard serialises env-var mutation across tests in this binary.
        unsafe {
            std::env::set_var("RASTREO_SCENARIO_LABEL_ALLOWLIST", "prod, staging ,lab , ,");
            std::env::set_var("RASTREO_SCENARIO_LABEL_MAX_LENGTH", "32");
        }
        let cfg = MetricsConfig::from_env().expect("from_env");
        // SAFETY: same guard covers cleanup.
        unsafe {
            std::env::remove_var("RASTREO_SCENARIO_LABEL_ALLOWLIST");
            std::env::remove_var("RASTREO_SCENARIO_LABEL_MAX_LENGTH");
        }
        assert!(cfg.scenario_allowlist.contains("prod"));
        assert!(cfg.scenario_allowlist.contains("staging"));
        assert!(cfg.scenario_allowlist.contains("lab"));
        assert_eq!(cfg.scenario_allowlist.len(), 3);
        assert_eq!(cfg.scenario_max_length, 32);
    }

    #[test]
    fn metrics_config_from_env_rejects_reserved_all_label() {
        let _guard = env_guard();
        clear_env();
        // SAFETY: env_guard serialises env-var mutation across tests in this binary.
        unsafe {
            std::env::set_var("RASTREO_SCENARIO_LABEL_ALLOWLIST", "prod,_all,lab");
        }
        let err = MetricsConfig::from_env().expect_err("must reject");
        // SAFETY: same guard covers cleanup.
        unsafe { std::env::remove_var("RASTREO_SCENARIO_LABEL_ALLOWLIST") };
        let msg = err.to_string();
        assert!(msg.contains("_all"), "msg was {msg}");
        assert!(msg.contains("reserved"), "msg was {msg}");
    }

    #[test]
    fn metrics_config_from_env_rejects_reserved_other_label() {
        let _guard = env_guard();
        clear_env();
        // SAFETY: env_guard serialises env-var mutation across tests in this binary.
        unsafe {
            std::env::set_var("RASTREO_SCENARIO_LABEL_ALLOWLIST", "other");
        }
        let err = MetricsConfig::from_env().expect_err("must reject");
        // SAFETY: same guard covers cleanup.
        unsafe { std::env::remove_var("RASTREO_SCENARIO_LABEL_ALLOWLIST") };
        let msg = err.to_string();
        assert!(msg.contains("other"), "msg was {msg}");
        assert!(msg.contains("reserved"), "msg was {msg}");
    }

    #[test]
    fn metrics_config_from_env_rejects_non_numeric_max_length() {
        let _guard = env_guard();
        clear_env();
        // SAFETY: env_guard serialises env-var mutation across tests in this binary.
        unsafe {
            std::env::set_var("RASTREO_SCENARIO_LABEL_MAX_LENGTH", "not-a-number");
        }
        let err = MetricsConfig::from_env().expect_err("must reject");
        // SAFETY: same guard covers cleanup.
        unsafe { std::env::remove_var("RASTREO_SCENARIO_LABEL_MAX_LENGTH") };
        let msg = err.to_string();
        assert!(
            msg.contains("RASTREO_SCENARIO_LABEL_MAX_LENGTH"),
            "msg: {msg}"
        );
    }

    // Serialise env-var reads so parallel tests do not race each other.
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    const ENV_KEYS: [&str; 9] = [
        "RASTREO_MAX_INFLIGHT_SCANS",
        "RASTREO_SINK_ERROR_QUARANTINE_SECS",
        "RASTREO_SCAN_ERROR_QUARANTINE_SECS",
        "RASTREO_OTLP_ENDPOINT",
        "RASTREO_OTLP_METRICS_ENABLED",
        "RASTREO_OTLP_LOGS_ENABLED",
        "RASTREO_OTLP_METRICS_INTERVAL_SECS",
        "RASTREO_OTLP_SERVICE_NAME",
        "RASTREO_OTLP_PROTOCOL",
    ];

    fn clear_env() {
        for k in ENV_KEYS {
            // SAFETY: env_guard() serialises env-var mutation across tests in this binary; no concurrent readers.
            unsafe { std::env::remove_var(k) };
        }
    }

    #[test]
    fn readiness_config_default_matches_documented_values() {
        let cfg = ReadinessConfig::default();
        assert_eq!(cfg.max_inflight_scans, 100);
        assert_eq!(cfg.sink_error_quarantine, Duration::from_secs(30));
        assert_eq!(cfg.scan_error_quarantine, Duration::from_secs(30));
    }

    #[test]
    fn readiness_config_from_env_uses_defaults_when_unset() {
        let _guard = env_guard();
        clear_env();
        let cfg = ReadinessConfig::from_env().expect("from_env");
        assert_eq!(cfg.max_inflight_scans, 100);
        assert_eq!(cfg.sink_error_quarantine, Duration::from_secs(30));
        assert_eq!(cfg.scan_error_quarantine, Duration::from_secs(30));
    }

    #[test]
    fn readiness_config_from_env_reads_custom_values() {
        let _guard = env_guard();
        clear_env();
        // SAFETY: env_guard() serialises env-var mutation across tests in this binary; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_MAX_INFLIGHT_SCANS", "7");
            std::env::set_var("RASTREO_SINK_ERROR_QUARANTINE_SECS", "12");
            std::env::set_var("RASTREO_SCAN_ERROR_QUARANTINE_SECS", "45");
        }
        let cfg = ReadinessConfig::from_env().expect("from_env");
        clear_env();
        assert_eq!(cfg.max_inflight_scans, 7);
        assert_eq!(cfg.sink_error_quarantine, Duration::from_secs(12));
        assert_eq!(cfg.scan_error_quarantine, Duration::from_secs(45));
    }

    #[test]
    fn readiness_config_from_env_rejects_non_numeric_value() {
        let _guard = env_guard();
        clear_env();
        // SAFETY: env_guard() serialises env-var mutation across tests in this binary; no concurrent readers.
        unsafe { std::env::set_var("RASTREO_MAX_INFLIGHT_SCANS", "not-a-number") };
        let err = ReadinessConfig::from_env().expect_err("must reject non-numeric");
        clear_env();
        let msg = err.to_string();
        assert!(msg.contains("RASTREO_MAX_INFLIGHT_SCANS"), "msg was {msg}");
        assert!(msg.contains("not-a-number"), "msg was {msg}");
    }

    #[test]
    fn readiness_config_zero_disables_checks() {
        let _guard = env_guard();
        clear_env();
        // SAFETY: env_guard() serialises env-var mutation across tests in this binary; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_MAX_INFLIGHT_SCANS", "0");
            std::env::set_var("RASTREO_SINK_ERROR_QUARANTINE_SECS", "0");
            std::env::set_var("RASTREO_SCAN_ERROR_QUARANTINE_SECS", "0");
        }
        let cfg = ReadinessConfig::from_env().expect("from_env");
        clear_env();
        assert_eq!(cfg.max_inflight_scans, 0);
        assert_eq!(cfg.sink_error_quarantine, Duration::ZERO);
        assert_eq!(cfg.scan_error_quarantine, Duration::ZERO);
    }

    #[test]
    fn readiness_state_record_scan_error_non_sink_only_updates_scan_ts() {
        let state = ReadinessState::default();
        state.record_scan_error(false);
        assert!(state.last_scan_error_epoch_ms.load(Ordering::Relaxed) > 0);
        assert_eq!(state.last_sink_error_epoch_ms.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn readiness_state_record_scan_error_sink_updates_both_timestamps() {
        let state = ReadinessState::default();
        state.record_scan_error(true);
        assert!(state.last_scan_error_epoch_ms.load(Ordering::Relaxed) > 0);
        assert!(state.last_sink_error_epoch_ms.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn app_state_with_readiness_stores_config() {
        let resolver: Arc<dyn Resolver> =
            Arc::new(HickoryResolver::from_system().expect("system resolver"));
        let cfg = ReadinessConfig {
            max_inflight_scans: 5,
            sink_error_quarantine: Duration::from_secs(3),
            scan_error_quarantine: Duration::from_secs(9),
        };
        let state = AppState::with_readiness(resolver, cfg);
        assert_eq!(state.readiness.config.max_inflight_scans, 5);
        assert_eq!(
            state.readiness.config.sink_error_quarantine,
            Duration::from_secs(3)
        );
        assert_eq!(
            state.readiness.config.scan_error_quarantine,
            Duration::from_secs(9)
        );
    }

    #[test]
    fn app_state_clone_shares_readiness_arc() {
        let state = build_state();
        let clone = state.clone();
        assert!(Arc::ptr_eq(&state.readiness, &clone.readiness));
    }

    #[cfg(feature = "otlp")]
    mod otlp_tests {
        use super::{clear_env, env_guard};
        use crate::state::{OtlpConfig, OtlpProtocol};
        use std::time::Duration;

        #[test]
        fn otlp_config_from_env_returns_none_when_both_disabled() {
            let _guard = env_guard();
            clear_env();
            let cfg = OtlpConfig::from_env().expect("from_env");
            assert!(cfg.is_none());
        }

        #[test]
        fn otlp_config_from_env_returns_some_when_metrics_enabled() {
            let _guard = env_guard();
            clear_env();
            // SAFETY: env_guard() serialises env-var mutation across tests in this binary; no concurrent readers.
            unsafe {
                std::env::set_var("RASTREO_OTLP_METRICS_ENABLED", "true");
                std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
            }
            let cfg = OtlpConfig::from_env().expect("from_env").expect("some");
            clear_env();
            assert!(cfg.metrics_enabled);
            assert!(!cfg.logs_enabled);
            assert_eq!(cfg.endpoint, "http://collector:4317");
            assert_eq!(cfg.metrics_interval, Duration::from_secs(30));
            assert_eq!(cfg.service_name, "rastreo-server");
        }

        #[test]
        fn otlp_config_from_env_returns_some_when_logs_enabled() {
            let _guard = env_guard();
            clear_env();
            // SAFETY: env_guard() serialises env-var mutation across tests in this binary; no concurrent readers.
            unsafe {
                std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "1");
                std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
                std::env::set_var("RASTREO_OTLP_SERVICE_NAME", "custom-name");
                std::env::set_var("RASTREO_OTLP_METRICS_INTERVAL_SECS", "10");
            }
            let cfg = OtlpConfig::from_env().expect("from_env").expect("some");
            clear_env();
            assert!(!cfg.metrics_enabled);
            assert!(cfg.logs_enabled);
            assert_eq!(cfg.metrics_interval, Duration::from_secs(10));
            assert_eq!(cfg.service_name, "custom-name");
        }

        #[test]
        fn otlp_config_from_env_rejects_metrics_enabled_without_endpoint() {
            let _guard = env_guard();
            clear_env();
            // SAFETY: env_guard() serialises env-var mutation across tests in this binary; no concurrent readers.
            unsafe { std::env::set_var("RASTREO_OTLP_METRICS_ENABLED", "true") };
            let err = OtlpConfig::from_env().expect_err("must reject");
            clear_env();
            let msg = err.to_string();
            assert!(msg.contains("RASTREO_OTLP_ENDPOINT"), "msg was {msg}");
        }

        #[test]
        fn otlp_config_from_env_rejects_logs_enabled_with_blank_endpoint() {
            let _guard = env_guard();
            clear_env();
            // SAFETY: env_guard() serialises env-var mutation across tests in this binary; no concurrent readers.
            unsafe {
                std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
                std::env::set_var("RASTREO_OTLP_ENDPOINT", "   ");
            }
            let err = OtlpConfig::from_env().expect_err("blank endpoint rejected");
            clear_env();
            assert!(err.to_string().contains("RASTREO_OTLP_ENDPOINT"));
        }

        #[test]
        fn otlp_config_from_env_rejects_invalid_boolean() {
            let _guard = env_guard();
            clear_env();
            // SAFETY: env_guard() serialises env-var mutation across tests in this binary; no concurrent readers.
            unsafe { std::env::set_var("RASTREO_OTLP_METRICS_ENABLED", "maybe") };
            let err = OtlpConfig::from_env().expect_err("non-boolean rejected");
            clear_env();
            let msg = err.to_string();
            assert!(
                msg.contains("RASTREO_OTLP_METRICS_ENABLED"),
                "msg was {msg}"
            );
            assert!(msg.contains("maybe"), "msg was {msg}");
        }

        #[test]
        fn otlp_config_from_env_rejects_invalid_interval() {
            let _guard = env_guard();
            clear_env();
            // SAFETY: env_guard() serialises env-var mutation across tests in this binary; no concurrent readers.
            unsafe {
                std::env::set_var("RASTREO_OTLP_METRICS_ENABLED", "true");
                std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
                std::env::set_var("RASTREO_OTLP_METRICS_INTERVAL_SECS", "not-a-number");
            }
            let err = OtlpConfig::from_env().expect_err("non-numeric rejected");
            clear_env();
            assert!(err
                .to_string()
                .contains("RASTREO_OTLP_METRICS_INTERVAL_SECS"));
        }

        #[test]
        fn otlp_config_accepts_boolean_variants() {
            let _guard = env_guard();
            for variant in ["true", "TRUE", "yes", "on", "1"] {
                clear_env();
                // SAFETY: env_guard() serialises env-var mutation across tests in this binary; no concurrent readers.
                unsafe {
                    std::env::set_var("RASTREO_OTLP_METRICS_ENABLED", variant);
                    std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
                }
                let cfg = OtlpConfig::from_env().expect("from_env").expect("some");
                assert!(cfg.metrics_enabled, "variant {variant} should enable");
            }
            clear_env();
        }

        #[test]
        fn otlp_config_protocol_defaults_to_grpc() {
            let _guard = env_guard();
            clear_env();
            // SAFETY: env_guard() serialises env-var mutation across tests in this binary; no concurrent readers.
            unsafe {
                std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
                std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
            }
            let cfg = OtlpConfig::from_env().expect("from_env").expect("some");
            clear_env();
            assert_eq!(cfg.protocol, OtlpProtocol::Grpc);
        }

        #[test]
        fn otlp_config_protocol_parses_grpc() {
            let _guard = env_guard();
            clear_env();
            // SAFETY: env_guard() serialises env-var mutation across tests in this binary; no concurrent readers.
            unsafe {
                std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
                std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
                std::env::set_var("RASTREO_OTLP_PROTOCOL", "grpc");
            }
            let cfg = OtlpConfig::from_env().expect("from_env").expect("some");
            clear_env();
            assert_eq!(cfg.protocol, OtlpProtocol::Grpc);
        }

        #[test]
        fn otlp_config_protocol_parses_http_protobuf() {
            let _guard = env_guard();
            clear_env();
            // SAFETY: env_guard() serialises env-var mutation across tests in this binary; no concurrent readers.
            unsafe {
                std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
                std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4318");
                std::env::set_var("RASTREO_OTLP_PROTOCOL", "http-protobuf");
            }
            let cfg = OtlpConfig::from_env().expect("from_env").expect("some");
            clear_env();
            assert_eq!(cfg.protocol, OtlpProtocol::HttpProtobuf);
        }

        #[test]
        fn otlp_config_protocol_parses_http_alias() {
            let _guard = env_guard();
            clear_env();
            // SAFETY: env_guard() serialises env-var mutation across tests in this binary; no concurrent readers.
            unsafe {
                std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
                std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4318");
                std::env::set_var("RASTREO_OTLP_PROTOCOL", "http");
            }
            let cfg = OtlpConfig::from_env().expect("from_env").expect("some");
            clear_env();
            assert_eq!(cfg.protocol, OtlpProtocol::HttpProtobuf);
        }

        #[test]
        fn otlp_config_protocol_case_insensitive() {
            let _guard = env_guard();
            for (variant, expected) in [
                ("GRPC", OtlpProtocol::Grpc),
                ("Grpc", OtlpProtocol::Grpc),
                ("HTTP-PROTOBUF", OtlpProtocol::HttpProtobuf),
                ("Http-Protobuf", OtlpProtocol::HttpProtobuf),
                ("HTTP", OtlpProtocol::HttpProtobuf),
            ] {
                clear_env();
                // SAFETY: env_guard() serialises env-var mutation across tests in this binary; no concurrent readers.
                unsafe {
                    std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
                    std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
                    std::env::set_var("RASTREO_OTLP_PROTOCOL", variant);
                }
                let cfg = OtlpConfig::from_env().expect("from_env").expect("some");
                assert_eq!(cfg.protocol, expected, "variant {variant} misparsed");
            }
            clear_env();
        }

        #[test]
        fn otlp_config_rejects_unknown_protocol() {
            let _guard = env_guard();
            clear_env();
            // SAFETY: env_guard() serialises env-var mutation across tests in this binary; no concurrent readers.
            unsafe {
                std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
                std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
                std::env::set_var("RASTREO_OTLP_PROTOCOL", "yaml");
            }
            let err = OtlpConfig::from_env().expect_err("unknown protocol rejected");
            clear_env();
            let msg = err.to_string();
            assert!(msg.contains("RASTREO_OTLP_PROTOCOL"), "msg was {msg}");
            assert!(msg.contains("yaml"), "msg was {msg}");
            assert!(msg.contains("grpc"), "msg was {msg}");
            assert!(msg.contains("http-protobuf"), "msg was {msg}");
        }
    }
}
