use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rastreo_core::{DiscoverySummary, Resolver};

pub struct HistogramShard {
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

pub struct HistogramSnapshot {
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
    pub records_emitted_total: AtomicU64,
    pub sink_errors_total: AtomicU64,
    pub scan_duration_seconds: HistogramShard,
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
            records_emitted_total: AtomicU64::new(0),
            sink_errors_total: AtomicU64::new(0),
            scan_duration_seconds: HistogramShard::new(),
        }
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
        self.records_emitted_total
            .fetch_add(summary.records_emitted as u64, Ordering::Relaxed);
        self.scan_duration_seconds
            .observe(summary.elapsed.as_secs_f64());
    }

    pub fn record_scan_error(&self, elapsed: Duration, is_sink_error: bool) {
        self.scans_total_error.fetch_add(1, Ordering::Relaxed);
        if is_sink_error {
            self.sink_errors_total.fetch_add(1, Ordering::Relaxed);
        }
        self.scan_duration_seconds.observe(elapsed.as_secs_f64());
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct AppState {
    pub resolver: Arc<dyn Resolver>,
    pub metrics: Arc<Metrics>,
}

impl AppState {
    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        Self {
            resolver,
            metrics: Arc::new(Metrics::default()),
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
        assert_eq!(metrics.records_emitted_total.load(Ordering::Relaxed), 5);
        assert_eq!(metrics.scan_duration_seconds.snapshot().count, 1);
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
}
