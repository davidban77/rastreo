use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use ipnet::IpNet;
use rastreo_core::env::{Env, VarError};
use rastreo_core::observability::otlp_config::{parse_env_bool, parse_env_u64};
use rastreo_core::{
    DiscoverySummary, Resolver, Sink, SinkErrorClass, SinkType, PROBE_KIND_COUNT,
    SINK_ERROR_CLASS_COUNT,
};

#[cfg(feature = "otlp")]
pub use rastreo_core::observability::otlp::OtlpConfig;
#[cfg(feature = "otlp")]
pub use rastreo_core::observability::otlp_config::OtlpProtocol;

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

/// Per-`SinkType` × per-`SinkErrorClass` DLQ delivery counters, credited from the carried
/// class of each quarantined record.
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
    pub fn from_env(env: &dyn Env) -> anyhow::Result<Self> {
        let allowlist: HashSet<String> = match env.var("RASTREO_SCENARIO_LABEL_ALLOWLIST") {
            Ok(raw) => raw
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect(),
            Err(VarError::NotPresent) => HashSet::new(),
            Err(VarError::NotUnicode(_)) => {
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
        let max_length = parse_env_u64(env, "RASTREO_SCENARIO_LABEL_MAX_LENGTH", 64)? as usize;
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
    pub sink_probe_success: AtomicU64,
    pub sink_probe_failure: AtomicU64,
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
            sink_probe_success: AtomicU64::new(0),
            sink_probe_failure: AtomicU64::new(0),
            #[cfg(feature = "otlp")]
            otlp_scan_duration: OnceLock::new(),
        }
    }

    pub fn record_sink_probe_success(&self) {
        self.sink_probe_success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_sink_probe_failure(&self) {
        self.sink_probe_failure.fetch_add(1, Ordering::Relaxed);
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
        for (sink_type, class, count) in &summary.dlq_records_by_type_and_class {
            self.record_dlq(*sink_type, *class, *count);
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

    pub fn record_scan_cancelled(&self, elapsed: Duration, scenario: &str) {
        self.scans_total_cancelled.fetch_add(1, Ordering::Relaxed);
        let seconds = elapsed.as_secs_f64();
        self.scan_duration.observe(seconds, scenario);
        self.record_otlp_scan_duration(seconds, scenario);
    }

    fn record_dlq(&self, sink_type: SinkType, class: SinkErrorClass, count: u64) {
        let bucket = match sink_type {
            SinkType::Kafka => &self.dlq.kafka,
            SinkType::Nats => &self.dlq.nats,
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
    pub fn from_env(env: &dyn Env) -> anyhow::Result<Self> {
        let default = Self::default();
        Ok(Self {
            max_inflight_scans: parse_env_u64(
                env,
                "RASTREO_MAX_INFLIGHT_SCANS",
                default.max_inflight_scans,
            )?,
            sink_error_quarantine: Duration::from_secs(parse_env_u64(
                env,
                "RASTREO_SINK_ERROR_QUARANTINE_SECS",
                default.sink_error_quarantine.as_secs(),
            )?),
            scan_error_quarantine: Duration::from_secs(parse_env_u64(
                env,
                "RASTREO_SCAN_ERROR_QUARANTINE_SECS",
                default.scan_error_quarantine.as_secs(),
            )?),
        })
    }
}

/// Hard cap on the graceful-drain window after the shutdown signal; the server force-exits once it elapses.
#[derive(Debug, Clone)]
pub struct ShutdownConfig {
    pub timeout: Duration,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(60),
        }
    }
}

impl ShutdownConfig {
    /// Read `RASTREO_SHUTDOWN_TIMEOUT_SECS` (default 60, clamped to a 1s minimum), falling back to the default when unset.
    pub fn from_env(env: &dyn Env) -> anyhow::Result<Self> {
        let secs = parse_env_u64(env, "RASTREO_SHUTDOWN_TIMEOUT_SECS", 60)?.max(1);
        Ok(Self {
            timeout: Duration::from_secs(secs),
        })
    }
}

pub const DEFAULT_MAX_TOTAL_HOSTS: usize = 262_144;
pub const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576;
pub const DEFAULT_MAX_RESULT_BYTES: usize = 33_554_432;

/// Read `RASTREO_MAX_RESULT_BYTES` (default 32 MiB), the byte cap on the `POST /scans` response
/// capture. Peak memory is ~3× the cap (NDJSON buffer + parsed records + serialized body), so
/// raising it requires raising the pod's `limits.memory`.
pub fn max_result_bytes_from_env(env: &dyn Env) -> anyhow::Result<usize> {
    Ok(parse_env_u64(
        env,
        "RASTREO_MAX_RESULT_BYTES",
        DEFAULT_MAX_RESULT_BYTES as u64,
    )? as usize)
}

/// SSRF and DoS guards applied to `POST /scans` — an optional target allow-list, an
/// aggregate host cap across all targets in a request, and a request-body size limit.
#[derive(Debug, Clone)]
pub struct TargetGuardConfig {
    pub allowlist: Option<Vec<IpNet>>,
    pub max_total_hosts: Option<usize>,
    pub max_body_bytes: usize,
}

impl Default for TargetGuardConfig {
    fn default() -> Self {
        Self {
            allowlist: None,
            max_total_hosts: Some(DEFAULT_MAX_TOTAL_HOSTS),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }
}

impl TargetGuardConfig {
    /// Read `RASTREO_TARGET_ALLOWLIST` (comma-separated CIDRs or bare IPs; unset ⇒ allow all), `RASTREO_MAX_TOTAL_HOSTS` (0 disables), and `RASTREO_MAX_BODY_BYTES`, falling back to defaults.
    pub fn from_env(env: &dyn Env) -> anyhow::Result<Self> {
        let allowlist = match env.var("RASTREO_TARGET_ALLOWLIST") {
            Ok(raw) => {
                let mut nets = Vec::new();
                for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    // A bare IP parses as a host net (/32 or /128).
                    let net = entry
                        .parse::<IpNet>()
                        .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                        .map_err(|_| {
                            anyhow::anyhow!(
                                "invalid entry in RASTREO_TARGET_ALLOWLIST: {entry:?} is not a \
                                 valid CIDR or IP address"
                            )
                        })?;
                    nets.push(net);
                }
                if nets.is_empty() {
                    None
                } else {
                    Some(nets)
                }
            }
            Err(VarError::NotPresent) => None,
            Err(VarError::NotUnicode(_)) => {
                return Err(anyhow::anyhow!(
                    "invalid value for RASTREO_TARGET_ALLOWLIST: not valid UTF-8"
                ));
            }
        };
        let max_total_hosts = match parse_env_u64(
            env,
            "RASTREO_MAX_TOTAL_HOSTS",
            DEFAULT_MAX_TOTAL_HOSTS as u64,
        )? {
            0 => None,
            n => Some(n as usize),
        };
        let max_body_bytes =
            parse_env_u64(env, "RASTREO_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES as u64)? as usize;
        Ok(Self {
            allowlist,
            max_total_hosts,
            max_body_bytes,
        })
    }
}

#[cfg(not(feature = "otlp"))]
#[derive(Debug, Clone)]
pub struct OtlpConfig;

#[cfg(not(feature = "otlp"))]
impl OtlpConfig {
    pub fn from_env(
        _env: &dyn Env,
        _default_service_name: &str,
        _metrics_supported: bool,
    ) -> anyhow::Result<Option<Self>> {
        Ok(None)
    }
}

pub struct ReadinessState {
    pub inflight_scans: AtomicU64,
    pub last_sink_error: MonotonicStamp,
    pub last_scan_error: MonotonicStamp,
    pub config: ReadinessConfig,
}

impl ReadinessState {
    pub fn new(config: ReadinessConfig) -> Self {
        Self {
            inflight_scans: AtomicU64::new(0),
            last_sink_error: MonotonicStamp::unstamped(),
            last_scan_error: MonotonicStamp::unstamped(),
            config,
        }
    }

    pub fn record_scan_error(&self, is_sink_error: bool) {
        self.last_scan_error.stamp();
        if is_sink_error {
            self.last_sink_error.stamp();
        }
    }
}

impl Default for ReadinessState {
    fn default() -> Self {
        Self::new(ReadinessConfig::default())
    }
}

/// A "how long since" measurement taken on the monotonic clock, so a wall-clock step never moves it.
pub struct MonotonicStamp {
    // tokio's Instant, not std's: identical in production, but `start_paused` can advance it.
    base: tokio::time::Instant,
    since_base_ms: AtomicU64,
}

const UNSTAMPED: u64 = 0;

impl MonotonicStamp {
    pub fn unstamped() -> Self {
        Self {
            base: tokio::time::Instant::now(),
            since_base_ms: AtomicU64::new(UNSTAMPED),
        }
    }

    pub fn stamped() -> Self {
        let stamp = Self::unstamped();
        stamp.stamp();
        stamp
    }

    pub fn stamp(&self) {
        self.since_base_ms
            .store(encode_stamp(self.base.elapsed()), Ordering::Relaxed);
    }

    pub fn age(&self) -> Option<Duration> {
        decode_stamp(self.since_base_ms.load(Ordering::Relaxed))
            .map(|since| self.base.elapsed().saturating_sub(since))
    }

    pub fn age_secs(&self) -> Option<f64> {
        self.age().map(|age| age.as_secs_f64())
    }
}

// Offset by one so a stamp taken in the base millisecond is still distinct from UNSTAMPED.
fn encode_stamp(since_base: Duration) -> u64 {
    u64::try_from(since_base.as_millis())
        .unwrap_or(u64::MAX - 1)
        .saturating_add(1)
}

fn decode_stamp(raw: u64) -> Option<Duration> {
    match raw {
        UNSTAMPED => None,
        n => Some(Duration::from_millis(n - 1)),
    }
}

impl Default for MonotonicStamp {
    fn default() -> Self {
        Self::unstamped()
    }
}

impl std::fmt::Debug for MonotonicStamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MonotonicStamp").field(&self.age()).finish()
    }
}

/// Cached result of the periodic server-side sink probe consumed by `/readyz` and `/metrics`.
pub struct SinkReachability {
    pub reachable: AtomicBool,
    pub last_probe: MonotonicStamp,
    /// When the probe task last began a cycle, whether or not that cycle produced a probe result.
    pub last_tick: MonotonicStamp,
    /// Cycles the probe task has begun; its gap over the probe outcome counters is the skipped-probe count.
    pub ticks: AtomicU64,
    pub last_error: Mutex<Option<String>>,
    // Writable: a sink that builds on a retry relabels itself from the construction hint.
    sink_type: Mutex<Option<SinkType>>,
    pub configured: bool,
    pub probe_interval: Duration,
    pub probe_timeout: Duration,
}

impl SinkReachability {
    /// State for a server with no sink configured; emits no metric series and does not gate `/readyz`.
    pub fn not_configured() -> Self {
        Self {
            reachable: AtomicBool::new(false),
            last_probe: MonotonicStamp::unstamped(),
            last_tick: MonotonicStamp::unstamped(),
            ticks: AtomicU64::new(0),
            last_error: Mutex::new(None),
            sink_type: Mutex::new(None),
            configured: false,
            probe_interval: Duration::from_secs(10),
            probe_timeout: Duration::from_secs(5),
        }
    }

    /// Initial state for a live sink; reports unreachable until the first probe completes.
    pub fn configured(
        sink_type: SinkType,
        probe_interval: Duration,
        probe_timeout: Duration,
    ) -> Self {
        Self {
            reachable: AtomicBool::new(false),
            last_probe: MonotonicStamp::unstamped(),
            last_tick: MonotonicStamp::unstamped(),
            ticks: AtomicU64::new(0),
            last_error: Mutex::new(None),
            sink_type: Mutex::new(Some(sink_type)),
            configured: true,
            probe_interval,
            probe_timeout,
        }
    }

    /// State for a sink that has not built yet; surfaces the failure via `/readyz` while construction is retried.
    pub fn construction_failed(
        sink_type: Option<SinkType>,
        error: String,
        probe_interval: Duration,
        probe_timeout: Duration,
    ) -> Self {
        Self {
            reachable: AtomicBool::new(false),
            last_probe: MonotonicStamp::stamped(),
            last_tick: MonotonicStamp::unstamped(),
            ticks: AtomicU64::new(0),
            last_error: Mutex::new(Some(error)),
            sink_type: Mutex::new(sink_type),
            configured: true,
            probe_interval,
            probe_timeout,
        }
    }

    pub fn sink_type(&self) -> Option<SinkType> {
        *self.sink_type.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_sink_type(&self, sink_type: SinkType) {
        let mut guard = self.sink_type.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(sink_type);
    }

    pub fn record_tick(&self) {
        self.last_tick.stamp();
        self.ticks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_success(&self) {
        self.reachable.store(true, Ordering::Relaxed);
        self.last_probe.stamp();
        let mut guard = self.last_error.lock().unwrap_or_else(|e| e.into_inner());
        *guard = None;
    }

    pub fn record_failure(&self, message: String) {
        self.reachable.store(false, Ordering::Relaxed);
        self.last_probe.stamp();
        let mut guard = self.last_error.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(message);
    }

    pub fn last_error_snapshot(&self) -> Option<String> {
        self.last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn sink_type_label(&self) -> Option<&'static str> {
        match self.sink_type() {
            Some(t) => Some(t.as_label()),
            None if self.configured => Some("unknown"),
            None => None,
        }
    }
}

impl std::fmt::Debug for SinkReachability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SinkReachability")
            .field("configured", &self.configured)
            .field("sink_type", &self.sink_type())
            .field("reachable", &self.reachable.load(Ordering::Relaxed))
            .field("last_probe", &self.last_probe)
            .field("last_tick", &self.last_tick)
            .field("probe_interval", &self.probe_interval)
            .field("probe_timeout", &self.probe_timeout)
            .finish_non_exhaustive()
    }
}

/// Server-side sink reachability probe knobs read from `RASTREO_SINK_PROBE_*` environment variables.
#[derive(Debug, Clone)]
pub struct SinkProbeConfig {
    pub config_path: Option<std::path::PathBuf>,
    pub probe_interval: Duration,
    pub probe_timeout: Duration,
}

impl Default for SinkProbeConfig {
    fn default() -> Self {
        Self {
            config_path: None,
            probe_interval: Duration::from_secs(10),
            probe_timeout: Duration::from_secs(5),
        }
    }
}

impl SinkProbeConfig {
    /// Read `RASTREO_SINK_CONFIG_PATH`, `RASTREO_SINK_PROBE_INTERVAL_SECS`, and `RASTREO_SINK_PROBE_TIMEOUT_SECS`, falling back to defaults when unset.
    pub fn from_env(env: &dyn Env) -> anyhow::Result<Self> {
        let config_path = match env.var("RASTREO_SINK_CONFIG_PATH") {
            Ok(raw) if !raw.trim().is_empty() => Some(std::path::PathBuf::from(raw.trim())),
            Ok(_) | Err(VarError::NotPresent) => None,
            Err(VarError::NotUnicode(_)) => {
                return Err(anyhow::anyhow!(
                    "invalid value for RASTREO_SINK_CONFIG_PATH: not valid UTF-8"
                ));
            }
        };
        let probe_interval =
            Duration::from_secs(parse_env_u64(env, "RASTREO_SINK_PROBE_INTERVAL_SECS", 10)?.max(1));
        let probe_timeout =
            Duration::from_secs(parse_env_u64(env, "RASTREO_SINK_PROBE_TIMEOUT_SECS", 5)?.max(1));
        Ok(Self {
            config_path,
            probe_interval,
            probe_timeout,
        })
    }
}

/// Shared handle to the server-configured sink, protected by an async mutex so scan
/// handlers and the probe task can serialise access without blocking the runtime.
pub type SharedSink = Arc<tokio::sync::Mutex<Box<dyn Sink>>>;

/// Empty until the sink builds, then attached for the process lifetime; shared by every clone of
/// [`AppState`], so a sink that builds late is visible to requests already holding a state clone.
#[derive(Clone, Default)]
pub(crate) struct SinkSlot(Arc<OnceLock<SharedSink>>);

impl SinkSlot {
    pub(crate) fn attached(sink: SharedSink) -> Self {
        let slot = Self::default();
        slot.attach(sink);
        slot
    }

    pub(crate) fn get(&self) -> Option<SharedSink> {
        self.0.get().map(Arc::clone)
    }

    pub(crate) fn attach(&self, sink: SharedSink) {
        let _ = self.0.set(sink);
    }
}

#[derive(Debug, Clone, Default)]
pub enum AuthConfig {
    #[default]
    Disabled,
    Enabled {
        token: String,
    },
}

impl AuthConfig {
    /// Read `RASTREO_API_TOKEN` (enables auth) and `RASTREO_AUTH_DISABLED` (explicit opt-out); errors when neither is set so the scan endpoint is never silently open.
    pub fn from_env(env: &dyn Env) -> anyhow::Result<Self> {
        match env.var("RASTREO_API_TOKEN") {
            Ok(token) if !token.trim().is_empty() => Ok(Self::Enabled {
                token: token.trim().to_string(),
            }),
            Ok(_) | Err(VarError::NotPresent) => {
                if parse_env_bool(env, "RASTREO_AUTH_DISABLED", false)? {
                    tracing::warn!(
                        "RASTREO_AUTH_DISABLED=true: the POST /scans endpoint is UNAUTHENTICATED — \
                         any caller that can reach it can trigger active network probes"
                    );
                    Ok(Self::Disabled)
                } else {
                    Err(anyhow::anyhow!(
                        "RASTREO_API_TOKEN is not set: set it to a shared secret to authenticate \
                         POST /scans, or set RASTREO_AUTH_DISABLED=true to run the scan endpoint \
                         unauthenticated (not recommended)"
                    ))
                }
            }
            Err(VarError::NotUnicode(_)) => Err(anyhow::anyhow!(
                "invalid value for RASTREO_API_TOKEN: not valid UTF-8"
            )),
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub resolver: Arc<dyn Resolver>,
    pub metrics: Arc<Metrics>,
    pub readiness: Arc<ReadinessState>,
    pub(crate) sink: SinkSlot,
    pub sink_reachability: Arc<SinkReachability>,
    pub auth: AuthConfig,
    pub max_body_bytes: usize,
    pub max_result_bytes: usize,
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
            sink: SinkSlot::default(),
            sink_reachability: Arc::new(SinkReachability::not_configured()),
            auth: AuthConfig::default(),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_result_bytes: DEFAULT_MAX_RESULT_BYTES,
        }
    }

    /// The server-configured sink, or `None` while it has not built yet.
    pub fn sink(&self) -> Option<SharedSink> {
        self.sink.get()
    }

    pub fn with_sink(self, sink: Option<SharedSink>, reachability: Arc<SinkReachability>) -> Self {
        let slot = match sink {
            Some(sink) => SinkSlot::attached(sink),
            None => SinkSlot::default(),
        };
        self.with_sink_slot(slot, reachability)
    }

    pub(crate) fn with_sink_slot(
        mut self,
        sink: SinkSlot,
        reachability: Arc<SinkReachability>,
    ) -> Self {
        self.sink = sink;
        self.sink_reachability = reachability;
        self
    }

    pub fn with_auth(mut self, auth: AuthConfig) -> Self {
        self.auth = auth;
        self
    }

    pub fn with_body_limit(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    pub fn with_result_limit(mut self, max_result_bytes: usize) -> Self {
        self.max_result_bytes = max_result_bytes;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rastreo_core::{HickoryResolver, MapEnv};

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

    use rastreo_core::{ProbeErrorKind, ProbeKind, ProbeKindSummary, SinkType};

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
        if probe_errors > 0 {
            s.error_counts.insert(ProbeErrorKind::Other, probe_errors);
        }
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
    fn metrics_record_scan_cancelled_increments_cancelled_and_histogram_only() {
        let metrics = Metrics::new();
        metrics.record_scan_cancelled(Duration::from_millis(50), "unnamed");
        assert_eq!(metrics.scans_total_cancelled.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.scans_total_success.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.scans_total_error.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.scan_duration.all.snapshot().count, 1);
    }

    #[test]
    fn metrics_record_dlq_delivery_credits_kafka_bucket_with_produce_failure() {
        let metrics = Metrics::new();
        let mut summary = summary_completed(1, 0, 1, Vec::new(), 10);
        summary.dlq_records = 3;
        summary.sink_type = Some(SinkType::Kafka);
        summary.dlq_records_by_type_and_class =
            vec![(SinkType::Kafka, SinkErrorClass::ProduceFailure, 3)];
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
        summary.dlq_records_by_type_and_class =
            vec![(SinkType::Nats, SinkErrorClass::PublishFailure, 5)];
        metrics.record_scan_completion(&summary, "unnamed");
        assert_eq!(
            metrics.dlq.nats[SinkErrorClass::PublishFailure.index()].load(Ordering::Relaxed),
            5
        );
    }

    #[test]
    fn metrics_record_dlq_credits_nats_ack_rejection_distinctly_from_publish_failure() {
        let metrics = Metrics::new();
        let mut summary = summary_completed(1, 0, 1, Vec::new(), 10);
        summary.sink_type = Some(SinkType::Nats);
        summary.dlq_records = 2;
        summary.dlq_records_by_type_and_class =
            vec![(SinkType::Nats, SinkErrorClass::AckRejection, 2)];
        metrics.record_scan_completion(&summary, "unnamed");
        assert_eq!(
            metrics.dlq.nats[SinkErrorClass::AckRejection.index()].load(Ordering::Relaxed),
            2,
            "an ack rejection credits the ack_rejection class, not publish_failure"
        );
        assert_eq!(
            metrics.dlq.nats[SinkErrorClass::PublishFailure.index()].load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn metrics_record_dlq_credits_kafka_when_sink_type_is_tee_but_by_class_has_kafka() {
        let metrics = Metrics::new();
        let mut summary = summary_completed(1, 0, 1, Vec::new(), 10);
        summary.sink_type = Some(SinkType::Tee);
        summary.dlq_records = 3;
        summary.dlq_records_by_type_and_class =
            vec![(SinkType::Kafka, SinkErrorClass::ProduceFailure, 3)];
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
    fn metrics_record_dlq_credits_kafka_and_nats_when_by_class_has_both() {
        let metrics = Metrics::new();
        let mut summary = summary_completed(1, 0, 1, Vec::new(), 10);
        summary.sink_type = Some(SinkType::Tee);
        summary.dlq_records = 7;
        summary.dlq_records_by_type_and_class = vec![
            (SinkType::Kafka, SinkErrorClass::ProduceFailure, 4),
            (SinkType::Nats, SinkErrorClass::PublishFailure, 3),
        ];
        metrics.record_scan_completion(&summary, "unnamed");
        assert_eq!(
            metrics.dlq.kafka[SinkErrorClass::ProduceFailure.index()].load(Ordering::Relaxed),
            4
        );
        assert_eq!(
            metrics.dlq.nats[SinkErrorClass::PublishFailure.index()].load(Ordering::Relaxed),
            3
        );
    }

    #[test]
    fn metrics_record_dlq_credits_nothing_when_by_type_and_class_empty() {
        let metrics = Metrics::new();
        let mut summary = summary_completed(1, 0, 1, Vec::new(), 10);
        summary.sink_type = Some(SinkType::Kafka);
        summary.dlq_records = 2;
        assert!(summary.dlq_records_by_type_and_class.is_empty());
        metrics.record_scan_completion(&summary, "unnamed");
        assert_eq!(
            metrics.dlq.kafka[SinkErrorClass::ProduceFailure.index()].load(Ordering::Relaxed),
            0,
            "the DLQ metric credits from per-class attribution, not the scalar total"
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
        let cfg = MetricsConfig::from_env(&MapEnv::new()).expect("from_env");
        assert!(cfg.scenario_allowlist.is_empty());
        assert_eq!(cfg.scenario_max_length, 64);
    }

    #[test]
    fn metrics_config_from_env_parses_comma_separated_allowlist() {
        let env = MapEnv::new()
            .set("RASTREO_SCENARIO_LABEL_ALLOWLIST", "prod, staging ,lab , ,")
            .set("RASTREO_SCENARIO_LABEL_MAX_LENGTH", "32");
        let cfg = MetricsConfig::from_env(&env).expect("from_env");
        assert!(cfg.scenario_allowlist.contains("prod"));
        assert!(cfg.scenario_allowlist.contains("staging"));
        assert!(cfg.scenario_allowlist.contains("lab"));
        assert_eq!(cfg.scenario_allowlist.len(), 3);
        assert_eq!(cfg.scenario_max_length, 32);
    }

    #[test]
    fn metrics_config_from_env_rejects_reserved_all_label() {
        let env = MapEnv::new().set("RASTREO_SCENARIO_LABEL_ALLOWLIST", "prod,_all,lab");
        let err = MetricsConfig::from_env(&env).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains("_all"), "msg was {msg}");
        assert!(msg.contains("reserved"), "msg was {msg}");
    }

    #[test]
    fn metrics_config_from_env_rejects_reserved_other_label() {
        let env = MapEnv::new().set("RASTREO_SCENARIO_LABEL_ALLOWLIST", "other");
        let err = MetricsConfig::from_env(&env).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains("other"), "msg was {msg}");
        assert!(msg.contains("reserved"), "msg was {msg}");
    }

    #[test]
    fn metrics_config_from_env_rejects_non_numeric_max_length() {
        let env = MapEnv::new().set("RASTREO_SCENARIO_LABEL_MAX_LENGTH", "not-a-number");
        let err = MetricsConfig::from_env(&env).expect_err("must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("RASTREO_SCENARIO_LABEL_MAX_LENGTH"),
            "msg: {msg}"
        );
    }

    #[test]
    fn an_unstamped_stamp_reports_no_age() {
        assert!(MonotonicStamp::unstamped().age().is_none());
        assert!(MonotonicStamp::unstamped().age_secs().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_stamp_taken_in_the_base_millisecond_still_reports_an_age() {
        let stamp = MonotonicStamp::stamped();
        assert_eq!(stamp.age(), Some(Duration::ZERO));
    }

    #[tokio::test(start_paused = true)]
    async fn a_stamp_ages_with_the_monotonic_clock_and_not_the_wall_clock() {
        let stamp = MonotonicStamp::stamped();
        tokio::time::advance(Duration::from_secs(3600)).await;
        assert_eq!(
            stamp.age(),
            Some(Duration::from_secs(3600)),
            "the age must track elapsed monotonic time, which no wall-clock reading has seen",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn re_stamping_resets_the_age() {
        let stamp = MonotonicStamp::stamped();
        tokio::time::advance(Duration::from_secs(3600)).await;
        stamp.stamp();
        assert_eq!(stamp.age(), Some(Duration::ZERO));
    }

    #[tokio::test(start_paused = true)]
    async fn readiness_quarantine_stamps_age_on_the_monotonic_clock() {
        let state = ReadinessState::default();
        state.record_scan_error(true);
        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(state.last_scan_error.age(), Some(Duration::from_secs(31)));
        assert_eq!(state.last_sink_error.age(), Some(Duration::from_secs(31)));
    }

    #[tokio::test(start_paused = true)]
    async fn sink_reachability_stamps_age_on_the_monotonic_clock() {
        let reach = SinkReachability::configured(
            SinkType::Kafka,
            Duration::from_secs(10),
            Duration::from_secs(5),
        );
        reach.record_success();
        reach.record_tick();
        tokio::time::advance(Duration::from_secs(120)).await;
        assert_eq!(reach.last_probe.age(), Some(Duration::from_secs(120)));
        assert_eq!(reach.last_tick.age(), Some(Duration::from_secs(120)));
    }

    // No server-side surface publishes a wall-clock timestamp, so any reading here would be a duration.
    #[test]
    fn no_server_source_measures_elapsed_time_on_the_wall_clock() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let banned = [concat!("System", "Time"), concat!("UNIX_", "EPOCH")];
        let mut offenders = Vec::new();
        let mut seen = 0usize;
        walk_rust_sources(&src, &mut |path, body| {
            seen += 1;
            for needle in banned {
                if body.contains(needle) {
                    offenders.push(format!("{} names {needle}", path.display()));
                }
            }
        });
        assert!(seen > 0, "the walk reached no source file");
        assert!(
            offenders.is_empty(),
            "readiness ages must come from the monotonic clock: {offenders:?}",
        );
    }

    fn walk_rust_sources(dir: &std::path::Path, visit: &mut impl FnMut(&std::path::Path, &str)) {
        let entries = std::fs::read_dir(dir).expect("read crate source directory");
        for entry in entries {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                walk_rust_sources(&path, visit);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let body = std::fs::read_to_string(&path).expect("read source file");
                visit(&path, &body);
            }
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
        let cfg = ReadinessConfig::from_env(&MapEnv::new()).expect("from_env");
        assert_eq!(cfg.max_inflight_scans, 100);
        assert_eq!(cfg.sink_error_quarantine, Duration::from_secs(30));
        assert_eq!(cfg.scan_error_quarantine, Duration::from_secs(30));
    }

    #[test]
    fn readiness_config_from_env_reads_custom_values() {
        let env = MapEnv::new()
            .set("RASTREO_MAX_INFLIGHT_SCANS", "7")
            .set("RASTREO_SINK_ERROR_QUARANTINE_SECS", "12")
            .set("RASTREO_SCAN_ERROR_QUARANTINE_SECS", "45");
        let cfg = ReadinessConfig::from_env(&env).expect("from_env");
        assert_eq!(cfg.max_inflight_scans, 7);
        assert_eq!(cfg.sink_error_quarantine, Duration::from_secs(12));
        assert_eq!(cfg.scan_error_quarantine, Duration::from_secs(45));
    }

    #[test]
    fn readiness_config_from_env_rejects_non_numeric_value() {
        let env = MapEnv::new().set("RASTREO_MAX_INFLIGHT_SCANS", "not-a-number");
        let err = ReadinessConfig::from_env(&env).expect_err("must reject non-numeric");
        let msg = err.to_string();
        assert!(msg.contains("RASTREO_MAX_INFLIGHT_SCANS"), "msg was {msg}");
        assert!(msg.contains("not-a-number"), "msg was {msg}");
    }

    #[test]
    fn readiness_config_zero_disables_checks() {
        let env = MapEnv::new()
            .set("RASTREO_MAX_INFLIGHT_SCANS", "0")
            .set("RASTREO_SINK_ERROR_QUARANTINE_SECS", "0")
            .set("RASTREO_SCAN_ERROR_QUARANTINE_SECS", "0");
        let cfg = ReadinessConfig::from_env(&env).expect("from_env");
        assert_eq!(cfg.max_inflight_scans, 0);
        assert_eq!(cfg.sink_error_quarantine, Duration::ZERO);
        assert_eq!(cfg.scan_error_quarantine, Duration::ZERO);
    }

    #[test]
    fn shutdown_config_default_is_sixty_seconds() {
        assert_eq!(ShutdownConfig::default().timeout, Duration::from_secs(60));
    }

    #[test]
    fn shutdown_config_from_env_uses_default_when_unset() {
        let cfg = ShutdownConfig::from_env(&MapEnv::new()).expect("from_env");
        assert_eq!(cfg.timeout, Duration::from_secs(60));
    }

    #[test]
    fn shutdown_config_from_env_reads_custom_value() {
        let env = MapEnv::new().set("RASTREO_SHUTDOWN_TIMEOUT_SECS", "15");
        let cfg = ShutdownConfig::from_env(&env).expect("from_env");
        assert_eq!(cfg.timeout, Duration::from_secs(15));
    }

    #[test]
    fn shutdown_config_from_env_clamps_zero_to_one_second() {
        let env = MapEnv::new().set("RASTREO_SHUTDOWN_TIMEOUT_SECS", "0");
        let cfg = ShutdownConfig::from_env(&env).expect("from_env");
        assert_eq!(cfg.timeout, Duration::from_secs(1));
    }

    #[test]
    fn shutdown_config_from_env_rejects_non_numeric_value() {
        let env = MapEnv::new().set("RASTREO_SHUTDOWN_TIMEOUT_SECS", "soon");
        let err = ShutdownConfig::from_env(&env).expect_err("must reject non-numeric");
        assert!(
            err.to_string().contains("RASTREO_SHUTDOWN_TIMEOUT_SECS"),
            "msg was {err}"
        );
    }

    #[test]
    fn auth_config_default_is_disabled() {
        assert!(matches!(AuthConfig::default(), AuthConfig::Disabled));
    }

    #[test]
    fn auth_config_from_env_enables_with_token() {
        let env = MapEnv::new().set("RASTREO_API_TOKEN", "s3cr3t");
        let cfg = AuthConfig::from_env(&env).expect("from_env");
        match cfg {
            AuthConfig::Enabled { token } => assert_eq!(token, "s3cr3t"),
            AuthConfig::Disabled => panic!("token set must enable auth"),
        }
    }

    #[test]
    fn auth_config_from_env_disabled_via_explicit_opt_out() {
        let env = MapEnv::new().set("RASTREO_AUTH_DISABLED", "true");
        let cfg = AuthConfig::from_env(&env).expect("from_env");
        assert!(matches!(cfg, AuthConfig::Disabled));
    }

    #[test]
    fn auth_config_from_env_fails_closed_when_neither_set() {
        let err = AuthConfig::from_env(&MapEnv::new()).expect_err("must fail closed");
        let msg = err.to_string();
        assert!(msg.contains("RASTREO_API_TOKEN"), "msg: {msg}");
        assert!(msg.contains("RASTREO_AUTH_DISABLED"), "msg: {msg}");
    }

    #[test]
    fn auth_config_from_env_treats_blank_token_as_unset() {
        let env = MapEnv::new().set("RASTREO_API_TOKEN", "   ");
        let err = AuthConfig::from_env(&env).expect_err("a blank token must not enable auth");
        assert!(err.to_string().contains("RASTREO_API_TOKEN"));
    }

    #[test]
    fn auth_config_from_env_trims_trailing_newline_from_token() {
        let env = MapEnv::new().set("RASTREO_API_TOKEN", "s3cret\n");
        let cfg = AuthConfig::from_env(&env).expect("from_env");
        assert!(matches!(cfg, AuthConfig::Enabled { token } if token == "s3cret"));
    }

    #[test]
    fn auth_config_from_env_token_wins_over_disable_flag() {
        let env = MapEnv::new()
            .set("RASTREO_API_TOKEN", "keepme")
            .set("RASTREO_AUTH_DISABLED", "true");
        let cfg = AuthConfig::from_env(&env).expect("from_env");
        assert!(matches!(cfg, AuthConfig::Enabled { token } if token == "keepme"));
    }

    #[test]
    fn readiness_state_record_scan_error_non_sink_only_updates_scan_ts() {
        let state = ReadinessState::default();
        state.record_scan_error(false);
        assert!(state.last_scan_error.age().is_some());
        assert!(state.last_sink_error.age().is_none());
    }

    #[test]
    fn readiness_state_record_scan_error_sink_updates_both_timestamps() {
        let state = ReadinessState::default();
        state.record_scan_error(true);
        assert!(state.last_scan_error.age().is_some());
        assert!(state.last_sink_error.age().is_some());
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

    #[test]
    fn app_state_default_sink_reachability_reports_not_configured() {
        let state = build_state();
        assert!(state.sink().is_none());
        assert!(!state.sink_reachability.configured);
        assert!(state.sink_reachability.sink_type().is_none());
    }

    #[test]
    fn sink_reachability_configured_starts_unreachable_with_no_error() {
        let r = SinkReachability::configured(
            SinkType::Kafka,
            Duration::from_secs(10),
            Duration::from_secs(5),
        );
        assert!(r.configured);
        assert_eq!(r.sink_type(), Some(SinkType::Kafka));
        assert!(!r.reachable.load(Ordering::Relaxed));
        assert!(r.last_probe.age().is_none());
        assert!(r.last_error_snapshot().is_none());
    }

    #[test]
    fn sink_reachability_record_success_clears_error_and_stamps_timestamp() {
        let r = SinkReachability::configured(
            SinkType::Kafka,
            Duration::from_secs(10),
            Duration::from_secs(5),
        );
        r.record_failure("boom".into());
        assert!(!r.reachable.load(Ordering::Relaxed));
        assert_eq!(r.last_error_snapshot().as_deref(), Some("boom"));
        r.record_success();
        assert!(r.reachable.load(Ordering::Relaxed));
        assert!(r.last_error_snapshot().is_none());
        assert!(r.last_probe.age().is_some());
    }

    #[test]
    fn sink_type_label_returns_none_when_not_configured() {
        let r = SinkReachability::not_configured();
        assert!(r.sink_type_label().is_none());
    }

    #[test]
    fn sink_type_label_returns_known_label_when_configured_with_type() {
        let r = SinkReachability::configured(
            SinkType::Kafka,
            Duration::from_secs(10),
            Duration::from_secs(5),
        );
        assert_eq!(r.sink_type_label(), Some("kafka"));
    }

    #[test]
    fn sink_type_label_returns_unknown_when_configured_but_type_none() {
        let r = SinkReachability::construction_failed(
            None,
            "yaml parse failed".into(),
            Duration::from_secs(10),
            Duration::from_secs(5),
        );
        assert_eq!(r.sink_type_label(), Some("unknown"));
    }

    #[test]
    fn sink_reachability_construction_failed_records_error_immediately() {
        let r = SinkReachability::construction_failed(
            Some(SinkType::Nats),
            "sink construction failed: no route to host".into(),
            Duration::from_secs(10),
            Duration::from_secs(5),
        );
        assert!(r.configured);
        assert!(!r.reachable.load(Ordering::Relaxed));
        assert!(r.last_probe.age().is_some());
        assert_eq!(
            r.last_error_snapshot().as_deref(),
            Some("sink construction failed: no route to host"),
        );
    }

    #[test]
    fn sink_reachability_recovers_from_poisoned_last_error_lock() {
        let r = Arc::new(SinkReachability::configured(
            SinkType::Kafka,
            Duration::from_secs(10),
            Duration::from_secs(5),
        ));
        let poisoner = Arc::clone(&r);
        let handle = std::thread::spawn(move || {
            let _guard = poisoner.last_error.lock().expect("initial lock");
            panic!("intentional poison");
        });
        let _ = handle.join();
        assert!(r.last_error.is_poisoned());
        r.record_failure("recovered".into());
        assert_eq!(r.last_error_snapshot().as_deref(), Some("recovered"));
    }

    #[test]
    fn app_state_with_sink_stores_sink_and_reachability() {
        use rastreo_core::MemorySink;
        let base = build_state();
        let sink: SharedSink = Arc::new(tokio::sync::Mutex::new(
            Box::new(MemorySink::new()) as Box<dyn Sink>
        ));
        let reach = Arc::new(SinkReachability::configured(
            SinkType::Memory,
            Duration::from_secs(10),
            Duration::from_secs(5),
        ));
        let state = base.with_sink(Some(Arc::clone(&sink)), Arc::clone(&reach));
        let stored = state.sink().expect("sink stored");
        assert!(Arc::ptr_eq(&stored, &sink));
        assert!(Arc::ptr_eq(&state.sink_reachability, &reach));
    }

    #[test]
    fn app_state_without_a_sink_reports_none() {
        let reach = Arc::new(SinkReachability::construction_failed(
            None,
            "sink config file not found".into(),
            Duration::from_secs(10),
            Duration::from_secs(5),
        ));
        let state = build_state().with_sink(None, reach);
        assert!(state.sink().is_none());
    }

    #[test]
    fn sink_slot_attach_is_visible_to_clones_taken_before_the_attach() {
        use rastreo_core::MemorySink;
        let slot = SinkSlot::default();
        let observer = slot.clone();
        assert!(observer.get().is_none());

        let sink: SharedSink = Arc::new(tokio::sync::Mutex::new(
            Box::new(MemorySink::new()) as Box<dyn Sink>
        ));
        slot.attach(Arc::clone(&sink));

        let seen = observer.get().expect("clone sees the late attach");
        assert!(Arc::ptr_eq(&seen, &sink));
    }

    #[test]
    fn sink_slot_attach_keeps_the_first_sink() {
        use rastreo_core::MemorySink;
        let first: SharedSink = Arc::new(tokio::sync::Mutex::new(
            Box::new(MemorySink::new()) as Box<dyn Sink>
        ));
        let second: SharedSink = Arc::new(tokio::sync::Mutex::new(
            Box::new(MemorySink::new()) as Box<dyn Sink>
        ));
        let slot = SinkSlot::attached(Arc::clone(&first));
        slot.attach(Arc::clone(&second));
        assert!(Arc::ptr_eq(&slot.get().expect("attached"), &first));
    }

    #[test]
    fn sink_reachability_set_sink_type_relabels_an_unknown_sink() {
        let r = SinkReachability::construction_failed(
            None,
            "sink config file not found".into(),
            Duration::from_secs(10),
            Duration::from_secs(5),
        );
        assert_eq!(r.sink_type_label(), Some("unknown"));
        r.set_sink_type(SinkType::Kafka);
        assert_eq!(r.sink_type(), Some(SinkType::Kafka));
        assert_eq!(r.sink_type_label(), Some("kafka"));
    }

    #[test]
    fn sink_probe_config_default_matches_documented_values() {
        let cfg = SinkProbeConfig::default();
        assert!(cfg.config_path.is_none());
        assert_eq!(cfg.probe_interval, Duration::from_secs(10));
        assert_eq!(cfg.probe_timeout, Duration::from_secs(5));
    }

    #[test]
    fn sink_probe_config_from_env_uses_defaults_when_unset() {
        let cfg = SinkProbeConfig::from_env(&MapEnv::new()).expect("from_env");
        assert!(cfg.config_path.is_none());
        assert_eq!(cfg.probe_interval, Duration::from_secs(10));
        assert_eq!(cfg.probe_timeout, Duration::from_secs(5));
    }

    #[test]
    fn sink_probe_config_from_env_reads_custom_values() {
        let env = MapEnv::new()
            .set("RASTREO_SINK_CONFIG_PATH", "/etc/rastreo/sink.yaml")
            .set("RASTREO_SINK_PROBE_INTERVAL_SECS", "30")
            .set("RASTREO_SINK_PROBE_TIMEOUT_SECS", "7");
        let cfg = SinkProbeConfig::from_env(&env).expect("from_env");
        assert_eq!(
            cfg.config_path.as_deref(),
            Some(std::path::Path::new("/etc/rastreo/sink.yaml"))
        );
        assert_eq!(cfg.probe_interval, Duration::from_secs(30));
        assert_eq!(cfg.probe_timeout, Duration::from_secs(7));
    }

    #[test]
    fn sink_probe_config_from_env_ignores_blank_path() {
        let env = MapEnv::new().set("RASTREO_SINK_CONFIG_PATH", "   ");
        let cfg = SinkProbeConfig::from_env(&env).expect("from_env");
        assert!(cfg.config_path.is_none());
    }

    #[test]
    fn sink_probe_config_from_env_trims_whitespace_around_path() {
        let env = MapEnv::new().set("RASTREO_SINK_CONFIG_PATH", "  /tmp/foo.yaml\t");
        let cfg = SinkProbeConfig::from_env(&env).expect("from_env");
        assert_eq!(
            cfg.config_path.as_deref(),
            Some(std::path::Path::new("/tmp/foo.yaml"))
        );
    }

    #[test]
    fn sink_probe_config_from_env_preserves_interior_whitespace() {
        let env = MapEnv::new().set("RASTREO_SINK_CONFIG_PATH", "/tmp/foo bar.yaml");
        let cfg = SinkProbeConfig::from_env(&env).expect("from_env");
        assert_eq!(
            cfg.config_path.as_deref(),
            Some(std::path::Path::new("/tmp/foo bar.yaml"))
        );
    }

    #[test]
    fn sink_probe_config_from_env_clamps_zero_to_one_second() {
        let env = MapEnv::new()
            .set("RASTREO_SINK_PROBE_INTERVAL_SECS", "0")
            .set("RASTREO_SINK_PROBE_TIMEOUT_SECS", "0");
        let cfg = SinkProbeConfig::from_env(&env).expect("from_env");
        assert_eq!(cfg.probe_interval, Duration::from_secs(1));
        assert_eq!(cfg.probe_timeout, Duration::from_secs(1));
    }

    #[test]
    fn sink_probe_config_from_env_rejects_non_numeric_interval() {
        let env = MapEnv::new().set("RASTREO_SINK_PROBE_INTERVAL_SECS", "not-a-number");
        let err = SinkProbeConfig::from_env(&env).expect_err("must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("RASTREO_SINK_PROBE_INTERVAL_SECS"),
            "msg was {msg}"
        );
    }

    #[test]
    fn target_guard_config_default_values() {
        let cfg = TargetGuardConfig::default();
        assert!(cfg.allowlist.is_none());
        assert_eq!(cfg.max_total_hosts, Some(DEFAULT_MAX_TOTAL_HOSTS));
        assert_eq!(cfg.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
    }

    #[test]
    fn target_guard_config_from_env_uses_defaults_when_unset() {
        let cfg = TargetGuardConfig::from_env(&MapEnv::new()).expect("from_env");
        assert!(cfg.allowlist.is_none());
        assert_eq!(cfg.max_total_hosts, Some(262_144));
        assert_eq!(cfg.max_body_bytes, 1_048_576);
    }

    #[test]
    fn target_guard_config_from_env_parses_comma_separated_cidrs() {
        let env = MapEnv::new().set("RASTREO_TARGET_ALLOWLIST", "10.0.0.0/8, 192.168.0.0/16 , ");
        let cfg = TargetGuardConfig::from_env(&env).expect("from_env");
        let nets = cfg.allowlist.expect("allowlist present");
        assert_eq!(
            nets,
            vec![
                "10.0.0.0/8".parse::<IpNet>().unwrap(),
                "192.168.0.0/16".parse::<IpNet>().unwrap(),
            ]
        );
    }

    #[test]
    fn target_guard_config_from_env_parses_bare_ip_as_host_net() {
        let env = MapEnv::new().set("RASTREO_TARGET_ALLOWLIST", "10.0.0.5");
        let cfg = TargetGuardConfig::from_env(&env).expect("from_env");
        let nets = cfg.allowlist.expect("allowlist present");
        assert_eq!(nets, vec!["10.0.0.5/32".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn target_guard_config_from_env_rejects_invalid_cidr() {
        let env = MapEnv::new().set("RASTREO_TARGET_ALLOWLIST", "10.0.0.0/8,not-a-cidr");
        let err = TargetGuardConfig::from_env(&env).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains("RASTREO_TARGET_ALLOWLIST"), "msg was {msg}");
        assert!(msg.contains("not-a-cidr"), "msg was {msg}");
    }

    #[test]
    fn target_guard_config_from_env_zero_max_total_hosts_disables_cap() {
        let env = MapEnv::new().set("RASTREO_MAX_TOTAL_HOSTS", "0");
        let cfg = TargetGuardConfig::from_env(&env).expect("from_env");
        assert!(cfg.max_total_hosts.is_none());
    }

    #[test]
    fn target_guard_config_from_env_reads_custom_caps() {
        let env = MapEnv::new()
            .set("RASTREO_MAX_TOTAL_HOSTS", "500")
            .set("RASTREO_MAX_BODY_BYTES", "4096");
        let cfg = TargetGuardConfig::from_env(&env).expect("from_env");
        assert_eq!(cfg.max_total_hosts, Some(500));
        assert_eq!(cfg.max_body_bytes, 4096);
    }

    #[test]
    fn target_guard_config_from_env_rejects_non_numeric_max_total_hosts() {
        let env = MapEnv::new().set("RASTREO_MAX_TOTAL_HOSTS", "lots");
        let err = TargetGuardConfig::from_env(&env).expect_err("must reject");
        assert!(err.to_string().contains("RASTREO_MAX_TOTAL_HOSTS"));
    }

    #[test]
    fn app_state_defaults_body_limit_to_one_mib() {
        let state = build_state();
        assert_eq!(state.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
    }

    #[test]
    fn app_state_with_body_limit_overrides_default() {
        let state = build_state().with_body_limit(4096);
        assert_eq!(state.max_body_bytes, 4096);
    }

    #[test]
    fn app_state_defaults_result_limit_to_thirty_two_mib() {
        let state = build_state();
        assert_eq!(state.max_result_bytes, DEFAULT_MAX_RESULT_BYTES);
        assert_eq!(DEFAULT_MAX_RESULT_BYTES, 33_554_432);
    }

    #[test]
    fn app_state_with_result_limit_overrides_default() {
        let state = build_state().with_result_limit(4096);
        assert_eq!(state.max_result_bytes, 4096);
    }

    #[test]
    fn max_result_bytes_from_env_uses_default_when_unset() {
        let cap = max_result_bytes_from_env(&MapEnv::new()).expect("from_env");
        assert_eq!(cap, DEFAULT_MAX_RESULT_BYTES);
    }

    #[test]
    fn max_result_bytes_from_env_reads_custom_value() {
        let env = MapEnv::new().set("RASTREO_MAX_RESULT_BYTES", "50000000");
        let cap = max_result_bytes_from_env(&env).expect("from_env");
        assert_eq!(cap, 50_000_000);
    }

    #[test]
    fn max_result_bytes_from_env_rejects_non_numeric_value() {
        let env = MapEnv::new().set("RASTREO_MAX_RESULT_BYTES", "lots");
        let err = max_result_bytes_from_env(&env).expect_err("must reject non-numeric");
        assert!(
            err.to_string().contains("RASTREO_MAX_RESULT_BYTES"),
            "msg: {err}"
        );
    }

    #[cfg(feature = "otlp")]
    mod otlp_tests {
        use crate::state::{OtlpConfig, OtlpProtocol};
        use rastreo_core::MapEnv;
        use std::time::Duration;

        #[test]
        fn otlp_config_from_env_returns_none_when_both_disabled() {
            let cfg =
                OtlpConfig::from_env(&MapEnv::new(), "rastreo-server", true).expect("from_env");
            assert!(cfg.is_none());
        }

        #[test]
        fn otlp_config_from_env_returns_some_when_metrics_enabled() {
            let env = MapEnv::new()
                .set("RASTREO_OTLP_METRICS_ENABLED", "true")
                .set("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
            let cfg = OtlpConfig::from_env(&env, "rastreo-server", true)
                .expect("from_env")
                .expect("some");
            assert!(cfg.metrics_enabled);
            assert!(!cfg.logs_enabled);
            assert_eq!(cfg.endpoint, "http://collector:4317");
            assert_eq!(cfg.metrics_interval, Duration::from_secs(30));
            assert_eq!(cfg.service_name, "rastreo-server");
        }

        #[test]
        fn otlp_config_from_env_returns_some_when_logs_enabled() {
            let env = MapEnv::new()
                .set("RASTREO_OTLP_LOGS_ENABLED", "1")
                .set("RASTREO_OTLP_ENDPOINT", "http://collector:4317")
                .set("RASTREO_OTLP_SERVICE_NAME", "custom-name")
                .set("RASTREO_OTLP_METRICS_INTERVAL_SECS", "10");
            let cfg = OtlpConfig::from_env(&env, "rastreo-server", true)
                .expect("from_env")
                .expect("some");
            assert!(!cfg.metrics_enabled);
            assert!(cfg.logs_enabled);
            assert_eq!(cfg.metrics_interval, Duration::from_secs(10));
            assert_eq!(cfg.service_name, "custom-name");
        }

        #[test]
        fn otlp_config_from_env_trims_endpoint() {
            let env = MapEnv::new()
                .set("RASTREO_OTLP_METRICS_ENABLED", "true")
                .set("RASTREO_OTLP_ENDPOINT", "  http://collector:4317\n");
            let cfg = OtlpConfig::from_env(&env, "rastreo-server", true)
                .expect("from_env")
                .expect("some");
            assert_eq!(cfg.endpoint, "http://collector:4317");
        }

        #[test]
        fn otlp_config_from_env_trims_service_name() {
            let env = MapEnv::new()
                .set("RASTREO_OTLP_METRICS_ENABLED", "true")
                .set("RASTREO_OTLP_ENDPOINT", "http://collector:4317")
                .set("RASTREO_OTLP_SERVICE_NAME", "  edge-scanner \n");
            let cfg = OtlpConfig::from_env(&env, "rastreo-server", true)
                .expect("from_env")
                .expect("some");
            assert_eq!(cfg.service_name, "edge-scanner");
        }

        #[test]
        fn otlp_config_from_env_rejects_metrics_enabled_without_endpoint() {
            let env = MapEnv::new().set("RASTREO_OTLP_METRICS_ENABLED", "true");
            let err = OtlpConfig::from_env(&env, "rastreo-server", true).expect_err("must reject");
            let msg = err.to_string();
            assert!(msg.contains("RASTREO_OTLP_ENDPOINT"), "msg was {msg}");
        }

        #[test]
        fn otlp_config_from_env_rejects_logs_enabled_with_blank_endpoint() {
            let env = MapEnv::new()
                .set("RASTREO_OTLP_LOGS_ENABLED", "true")
                .set("RASTREO_OTLP_ENDPOINT", "   ");
            let err = OtlpConfig::from_env(&env, "rastreo-server", true)
                .expect_err("blank endpoint rejected");
            assert!(err.to_string().contains("RASTREO_OTLP_ENDPOINT"));
        }

        #[test]
        fn otlp_config_from_env_rejects_invalid_boolean() {
            let env = MapEnv::new().set("RASTREO_OTLP_METRICS_ENABLED", "maybe");
            let err = OtlpConfig::from_env(&env, "rastreo-server", true)
                .expect_err("non-boolean rejected");
            let msg = err.to_string();
            assert!(
                msg.contains("RASTREO_OTLP_METRICS_ENABLED"),
                "msg was {msg}"
            );
            assert!(msg.contains("maybe"), "msg was {msg}");
        }

        #[test]
        fn otlp_config_from_env_rejects_invalid_interval() {
            let env = MapEnv::new()
                .set("RASTREO_OTLP_METRICS_ENABLED", "true")
                .set("RASTREO_OTLP_ENDPOINT", "http://collector:4317")
                .set("RASTREO_OTLP_METRICS_INTERVAL_SECS", "not-a-number");
            let err = OtlpConfig::from_env(&env, "rastreo-server", true)
                .expect_err("non-numeric rejected");
            assert!(err
                .to_string()
                .contains("RASTREO_OTLP_METRICS_INTERVAL_SECS"));
        }

        #[test]
        fn otlp_config_accepts_boolean_variants() {
            for variant in ["true", "TRUE", "yes", "on", "1"] {
                let env = MapEnv::new()
                    .set("RASTREO_OTLP_METRICS_ENABLED", variant)
                    .set("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
                let cfg = OtlpConfig::from_env(&env, "rastreo-server", true)
                    .expect("from_env")
                    .expect("some");
                assert!(cfg.metrics_enabled, "variant {variant} should enable");
            }
        }

        #[test]
        fn otlp_config_protocol_defaults_to_grpc() {
            let env = MapEnv::new()
                .set("RASTREO_OTLP_LOGS_ENABLED", "true")
                .set("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
            let cfg = OtlpConfig::from_env(&env, "rastreo-server", true)
                .expect("from_env")
                .expect("some");
            assert_eq!(cfg.protocol, OtlpProtocol::Grpc);
        }

        #[test]
        fn otlp_config_protocol_parses_grpc() {
            let env = MapEnv::new()
                .set("RASTREO_OTLP_LOGS_ENABLED", "true")
                .set("RASTREO_OTLP_ENDPOINT", "http://collector:4317")
                .set("RASTREO_OTLP_PROTOCOL", "grpc");
            let cfg = OtlpConfig::from_env(&env, "rastreo-server", true)
                .expect("from_env")
                .expect("some");
            assert_eq!(cfg.protocol, OtlpProtocol::Grpc);
        }

        #[test]
        fn otlp_config_protocol_parses_http_protobuf() {
            let env = MapEnv::new()
                .set("RASTREO_OTLP_LOGS_ENABLED", "true")
                .set("RASTREO_OTLP_ENDPOINT", "http://collector:4318")
                .set("RASTREO_OTLP_PROTOCOL", "http-protobuf");
            let cfg = OtlpConfig::from_env(&env, "rastreo-server", true)
                .expect("from_env")
                .expect("some");
            assert_eq!(cfg.protocol, OtlpProtocol::HttpProtobuf);
        }

        #[test]
        fn otlp_config_protocol_parses_http_alias() {
            let env = MapEnv::new()
                .set("RASTREO_OTLP_LOGS_ENABLED", "true")
                .set("RASTREO_OTLP_ENDPOINT", "http://collector:4318")
                .set("RASTREO_OTLP_PROTOCOL", "http");
            let cfg = OtlpConfig::from_env(&env, "rastreo-server", true)
                .expect("from_env")
                .expect("some");
            assert_eq!(cfg.protocol, OtlpProtocol::HttpProtobuf);
        }

        #[test]
        fn otlp_config_protocol_case_insensitive() {
            for (variant, expected) in [
                ("GRPC", OtlpProtocol::Grpc),
                ("Grpc", OtlpProtocol::Grpc),
                ("HTTP-PROTOBUF", OtlpProtocol::HttpProtobuf),
                ("Http-Protobuf", OtlpProtocol::HttpProtobuf),
                ("HTTP", OtlpProtocol::HttpProtobuf),
            ] {
                let env = MapEnv::new()
                    .set("RASTREO_OTLP_LOGS_ENABLED", "true")
                    .set("RASTREO_OTLP_ENDPOINT", "http://collector:4317")
                    .set("RASTREO_OTLP_PROTOCOL", variant);
                let cfg = OtlpConfig::from_env(&env, "rastreo-server", true)
                    .expect("from_env")
                    .expect("some");
                assert_eq!(cfg.protocol, expected, "variant {variant} misparsed");
            }
        }

        #[test]
        fn otlp_config_rejects_unknown_protocol() {
            let env = MapEnv::new()
                .set("RASTREO_OTLP_LOGS_ENABLED", "true")
                .set("RASTREO_OTLP_ENDPOINT", "http://collector:4317")
                .set("RASTREO_OTLP_PROTOCOL", "yaml");
            let err = OtlpConfig::from_env(&env, "rastreo-server", true)
                .expect_err("unknown protocol rejected");
            let msg = err.to_string();
            assert!(msg.contains("RASTREO_OTLP_PROTOCOL"), "msg was {msg}");
            assert!(msg.contains("yaml"), "msg was {msg}");
            assert!(msg.contains("grpc"), "msg was {msg}");
            assert!(msg.contains("http-protobuf"), "msg was {msg}");
        }
    }
}
