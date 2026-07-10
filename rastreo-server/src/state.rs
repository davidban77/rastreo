use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rastreo_core::observability::otlp_config::parse_env_u64;
use rastreo_core::{DiscoverySummary, Resolver};

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

pub struct Metrics {
    pub started_at: Instant,
    pub scans_total_success: AtomicU64,
    pub scans_total_error: AtomicU64,
    pub scans_total_cancelled: AtomicU64,
    pub probes_attempted_total: AtomicU64,
    pub probes_errored_total: AtomicU64,
    pub probes_succeeded_total: AtomicU64,
    pub records_emitted_total: AtomicU64,
    pub sink_errors_total: AtomicU64,
    pub(crate) scan_duration_seconds: HistogramShard,
    #[cfg(feature = "otlp")]
    otlp_scan_duration: OnceLock<opentelemetry::metrics::Histogram<f64>>,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            scans_total_success: AtomicU64::new(0),
            scans_total_error: AtomicU64::new(0),
            scans_total_cancelled: AtomicU64::new(0),
            probes_attempted_total: AtomicU64::new(0),
            probes_errored_total: AtomicU64::new(0),
            probes_succeeded_total: AtomicU64::new(0),
            records_emitted_total: AtomicU64::new(0),
            sink_errors_total: AtomicU64::new(0),
            scan_duration_seconds: HistogramShard::new(),
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

    pub fn record_scan_completion(&self, summary: &DiscoverySummary) {
        if summary.cancelled {
            self.scans_total_cancelled.fetch_add(1, Ordering::Relaxed);
        } else {
            self.scans_total_success.fetch_add(1, Ordering::Relaxed);
        }
        self.probes_attempted_total
            .fetch_add(summary.probe_attempts as u64, Ordering::Relaxed);
        self.probes_errored_total
            .fetch_add(summary.probe_errors as u64, Ordering::Relaxed);
        let succeeded = summary.probe_attempts.saturating_sub(summary.probe_errors);
        self.probes_succeeded_total
            .fetch_add(succeeded as u64, Ordering::Relaxed);
        self.records_emitted_total
            .fetch_add(summary.records_emitted as u64, Ordering::Relaxed);
        let seconds = summary.elapsed.as_secs_f64();
        self.scan_duration_seconds.observe(seconds);
        self.record_otlp_scan_duration(seconds);
    }

    pub fn record_scan_error(&self, elapsed: Duration, is_sink_error: bool) {
        self.scans_total_error.fetch_add(1, Ordering::Relaxed);
        if is_sink_error {
            self.sink_errors_total.fetch_add(1, Ordering::Relaxed);
        }
        let seconds = elapsed.as_secs_f64();
        self.scan_duration_seconds.observe(seconds);
        self.record_otlp_scan_duration(seconds);
    }

    #[cfg(feature = "otlp")]
    fn record_otlp_scan_duration(&self, seconds: f64) {
        if let Some(h) = self.otlp_scan_duration.get() {
            h.record(seconds, &[]);
        }
    }

    #[cfg(not(feature = "otlp"))]
    fn record_otlp_scan_duration(&self, _seconds: f64) {}
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
        Self {
            resolver,
            metrics: Arc::new(Metrics::default()),
            readiness: Arc::new(ReadinessState::new(config)),
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

    #[test]
    fn metrics_record_scan_completion_increments_success_counters() {
        let metrics = Metrics::new();
        let summary = DiscoverySummary {
            targets_resolved: 1,
            probe_attempts: 10,
            probe_errors: 2,
            records_emitted: 5,
            cancelled: false,
            elapsed: Duration::from_millis(123),
        };
        metrics.record_scan_completion(&summary);
        assert_eq!(metrics.scans_total_success.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.scans_total_cancelled.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.probes_attempted_total.load(Ordering::Relaxed), 10);
        assert_eq!(metrics.probes_errored_total.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.probes_succeeded_total.load(Ordering::Relaxed), 8);
        assert_eq!(metrics.records_emitted_total.load(Ordering::Relaxed), 5);
        assert_eq!(metrics.scan_duration_seconds.snapshot().count, 1);
    }

    #[test]
    fn probes_succeeded_total_is_monotonic_across_multiple_scans() {
        let metrics = Metrics::new();
        metrics.record_scan_completion(&DiscoverySummary {
            targets_resolved: 1,
            probe_attempts: 10,
            probe_errors: 8,
            records_emitted: 2,
            cancelled: false,
            elapsed: Duration::from_millis(50),
        });
        let first = metrics.probes_succeeded_total.load(Ordering::Relaxed);
        metrics.record_scan_completion(&DiscoverySummary {
            targets_resolved: 1,
            probe_attempts: 100,
            probe_errors: 90,
            records_emitted: 10,
            cancelled: false,
            elapsed: Duration::from_millis(50),
        });
        let second = metrics.probes_succeeded_total.load(Ordering::Relaxed);
        assert_eq!(first, 2);
        assert_eq!(second, 12);
        assert!(second >= first);
    }

    #[test]
    fn metrics_record_scan_completion_with_cancelled_increments_cancelled_counter() {
        let metrics = Metrics::new();
        let summary = DiscoverySummary {
            targets_resolved: 1,
            probe_attempts: 3,
            probe_errors: 0,
            records_emitted: 1,
            cancelled: true,
            elapsed: Duration::from_millis(50),
        };
        metrics.record_scan_completion(&summary);
        assert_eq!(metrics.scans_total_cancelled.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.scans_total_success.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn metrics_record_scan_error_without_sink_error() {
        let metrics = Metrics::new();
        metrics.record_scan_error(Duration::from_millis(50), false);
        assert_eq!(metrics.scans_total_error.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.sink_errors_total.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.scan_duration_seconds.snapshot().count, 1);
    }

    #[test]
    fn metrics_record_scan_error_with_sink_error_flag_increments_sink_counter() {
        let metrics = Metrics::new();
        metrics.record_scan_error(Duration::from_millis(50), true);
        assert_eq!(metrics.scans_total_error.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.sink_errors_total.load(Ordering::Relaxed), 1);
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
