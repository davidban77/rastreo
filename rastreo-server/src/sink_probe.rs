use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt;
use rastreo_core::{Sink, SinkType};
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{interval, timeout, MissedTickBehavior};

use crate::state::{AppState, Metrics, SharedSink, SinkProbeConfig, SinkReachability, SinkSlot};

struct ConstructError {
    hint: Option<SinkType>,
    err: anyhow::Error,
}

/// Build the sink referenced by `RASTREO_SINK_CONFIG_PATH` and spawn a background task that, every `probe_interval` until `shutdown` fires, rebuilds the sink while it has not built yet and probes it once it has; failures surface via `/readyz` rather than crashing the server.
pub async fn spawn_sink_probe(
    state: AppState,
    config: &SinkProbeConfig,
    shutdown: watch::Receiver<bool>,
) -> (AppState, Option<JoinHandle<()>>) {
    let Some(path) = config.config_path.as_ref() else {
        return (state, None);
    };

    let slot = SinkSlot::default();
    let mut failures = ConstructionFailures::default();
    let reachability = match load_and_construct_sink(path, config.probe_timeout).await {
        Ok(sink) => {
            let sink_type = sink.kind();
            let reachability = Arc::new(SinkReachability::configured(
                sink_type,
                config.probe_interval,
                config.probe_timeout,
            ));
            let sink: SharedSink = Arc::new(Mutex::new(sink));
            slot.attach(Arc::clone(&sink));
            log_sink_attached(path, sink_type, failures.attempts);
            run_probe(&sink, &reachability, &state.metrics, config.probe_timeout).await;
            reachability
        }
        Err(ConstructError { hint, err }) => {
            // `{err:#}` keeps the cause chain: the outermost context alone names the file, not the reason.
            let detail = format!("{err:#}");
            failures.log(path, hint, &detail);
            state.metrics.record_sink_probe_failure();
            Arc::new(SinkReachability::construction_failed(
                hint,
                construction_error(&detail),
                config.probe_interval,
                config.probe_timeout,
            ))
        }
    };

    reachability.record_tick();

    let handle = spawn_probe_task(
        slot.clone(),
        Arc::clone(&reachability),
        Arc::clone(&state.metrics),
        config.clone(),
        failures,
        shutdown,
    );
    (state.with_sink_slot(slot, reachability), Some(handle))
}

fn construction_error(detail: &str) -> String {
    format!("sink construction failed: {detail}")
}

fn log_sink_attached(path: &Path, sink_type: SinkType, failed_attempts: u32) {
    tracing::info!(
        path = %path.display(),
        sink_type = %sink_type.as_label(),
        failed_attempts,
        "sink attached; it is held for the lifetime of this process and never rebuilt"
    );
}

#[derive(Default)]
struct ConstructionFailures {
    attempts: u32,
    last_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureVolume {
    Warn,
    Debug,
}

impl ConstructionFailures {
    // Loud on a new failure mode and on attempts 1, 2, 4, 8, ...: a day-long outage stays visible without one WARN per tick.
    fn observe(&mut self, detail: &str) -> FailureVolume {
        self.attempts = self.attempts.saturating_add(1);
        let changed = self.last_error.as_deref() != Some(detail);
        self.last_error = Some(detail.to_string());
        if changed || self.attempts.is_power_of_two() {
            FailureVolume::Warn
        } else {
            FailureVolume::Debug
        }
    }

    fn log(&mut self, path: &Path, hint: Option<SinkType>, detail: &str) {
        let volume = self.observe(detail);
        let attempt = self.attempts;
        match volume {
            FailureVolume::Warn => tracing::warn!(
                error = %detail,
                path = %path.display(),
                sink_type = ?hint.map(SinkType::as_label),
                attempt,
                "sink construction failed; retrying every probe interval, /readyz reports sink_unreachable"
            ),
            FailureVolume::Debug => tracing::debug!(
                error = %detail,
                path = %path.display(),
                attempt,
                "sink construction still failing"
            ),
        }
    }
}

async fn load_and_construct_sink(
    path: &std::path::Path,
    construction_timeout: Duration,
) -> Result<Box<dyn Sink>, ConstructError> {
    #[cfg(feature = "config")]
    {
        use anyhow::Context;
        use rastreo_core::config::parse_sink_config;
        use rastreo_core::sink::create_sink;

        let raw = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read sink config at {}", path.display()))
            .map_err(|err| ConstructError { hint: None, err })?;
        let config = parse_sink_config(&raw)
            .with_context(|| format!("failed to parse sink config at {}", path.display()))
            .map_err(|err| ConstructError { hint: None, err })?;
        // A parsed config names its kind even when it cannot be built: `unknown` means unreadable.
        let hint = Some(config.sink_type());
        match timeout(construction_timeout, create_sink(&config)).await {
            Ok(Ok(sink)) => Ok(sink),
            Ok(Err(err)) => Err(ConstructError {
                hint,
                err: anyhow::Error::new(err)
                    .context(format!("failed to build sink from {}", path.display())),
            }),
            Err(_) => {
                let label = hint.map(SinkType::as_label).unwrap_or("unknown");
                Err(ConstructError {
                    hint,
                    err: anyhow::anyhow!(
                        "sink construction timed out after {}s: {label}",
                        construction_timeout.as_secs()
                    ),
                })
            }
        }
    }
    #[cfg(not(feature = "config"))]
    {
        let _ = (path, construction_timeout);
        Err(ConstructError {
            hint: None,
            err: anyhow::anyhow!(
                "RASTREO_SINK_CONFIG_PATH is set but rastreo-server was built without the `config` feature"
            ),
        })
    }
}

fn spawn_probe_task(
    slot: SinkSlot,
    reachability: Arc<SinkReachability>,
    metrics: Arc<Metrics>,
    config: SinkProbeConfig,
    mut failures: ConstructionFailures,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(config.probe_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        ticker.tick().await; // the first tick is immediate; startup already ran this cycle
        loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                _ = ticker.tick() => {
                    guard_panics(probe_tick(
                        &slot,
                        &config,
                        &reachability,
                        &metrics,
                        &mut failures,
                    ))
                    .await;
                }
            }
        }
    })
}

async fn probe_tick(
    slot: &SinkSlot,
    config: &SinkProbeConfig,
    reachability: &Arc<SinkReachability>,
    metrics: &Arc<Metrics>,
    failures: &mut ConstructionFailures,
) {
    // Stamped before the awaits: a cycle that never returns still proves the task reached it.
    reachability.record_tick();
    let sink = match slot.get() {
        Some(sink) => sink,
        None => match retry_construction(config, reachability, metrics, failures).await {
            Some(sink) => {
                slot.attach(Arc::clone(&sink));
                sink
            }
            None => return,
        },
    };
    run_probe(&sink, reachability, metrics, config.probe_timeout).await;
}

// A panic in the tick would otherwise kill the task and freeze /readyz on its last cached value.
async fn guard_panics(tick: impl Future<Output = ()>) {
    if let Err(payload) = AssertUnwindSafe(tick).catch_unwind().await {
        tracing::error!(
            panic = panic_detail(payload.as_ref()),
            "sink probe tick panicked; the task continues on the next interval"
        );
    }
}

fn panic_detail(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&'static str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("panic payload was not a string")
}

async fn retry_construction(
    config: &SinkProbeConfig,
    reachability: &Arc<SinkReachability>,
    metrics: &Arc<Metrics>,
    failures: &mut ConstructionFailures,
) -> Option<SharedSink> {
    let path = config.config_path.as_ref()?;
    match load_and_construct_sink(path, config.probe_timeout).await {
        Ok(sink) => {
            let sink_type = sink.kind();
            reachability.set_sink_type(sink_type);
            log_sink_attached(path, sink_type, failures.attempts);
            Some(Arc::new(Mutex::new(sink)))
        }
        Err(ConstructError { hint, err }) => {
            let detail = format!("{err:#}");
            failures.log(path, hint, &detail);
            if let Some(hint) = hint {
                reachability.set_sink_type(hint);
            }
            reachability.record_failure(construction_error(&detail));
            metrics.record_sink_probe_failure();
            None
        }
    }
}

async fn run_probe(
    sink: &SharedSink,
    reachability: &Arc<SinkReachability>,
    metrics: &Arc<Metrics>,
    timeout_dur: Duration,
) {
    // The lock is held for one sink operation at a time, so losing it for a whole timeout means a
    // single write/flush/close is outlasting the probe. Skip rather than report a verdict we did
    // not measure; the skip is visible as the gap between the tick counter and the probe counters.
    let guard = match timeout(timeout_dur, sink.lock()).await {
        Ok(guard) => guard,
        Err(_) => {
            tracing::debug!(
                timeout_ms = timeout_dur.as_millis(),
                "sink probe skipped: a sink operation held the shared lock past the probe timeout"
            );
            return;
        }
    };
    let probe_result = timeout(timeout_dur, guard.probe()).await;
    match probe_result {
        Ok(Ok(())) => {
            reachability.record_success();
            metrics.record_sink_probe_success();
        }
        Ok(Err(err)) => {
            reachability.record_failure(err.to_string());
            metrics.record_sink_probe_failure();
        }
        Err(_) => {
            reachability.record_failure(format!(
                "sink probe timed out after {}ms",
                timeout_dur.as_millis()
            ));
            metrics.record_sink_probe_failure();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;
    use rastreo_core::error::RastreoError;
    use rastreo_core::SinkType;

    struct AlwaysOk;

    #[async_trait]
    impl Sink for AlwaysOk {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            Ok(())
        }
        fn last_write_delivered(&self) -> bool {
            true
        }
        fn kind(&self) -> SinkType {
            SinkType::Stdout
        }
        async fn probe(&self) -> Result<(), std::io::Error> {
            Ok(())
        }
    }

    struct AlwaysFail;

    #[async_trait]
    impl Sink for AlwaysFail {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            Ok(())
        }
        fn last_write_delivered(&self) -> bool {
            true
        }
        fn kind(&self) -> SinkType {
            SinkType::Kafka
        }
        async fn probe(&self) -> Result<(), std::io::Error> {
            Err(std::io::Error::other("broker unreachable"))
        }
    }

    struct HangingProbe {
        started: Arc<AtomicBool>,
    }

    #[async_trait]
    impl Sink for HangingProbe {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            Ok(())
        }
        fn last_write_delivered(&self) -> bool {
            true
        }
        fn kind(&self) -> SinkType {
            SinkType::Nats
        }
        async fn probe(&self) -> Result<(), std::io::Error> {
            self.started.store(true, Ordering::SeqCst);
            std::future::pending::<()>().await;
            Ok(())
        }
    }

    struct CountedFail(Arc<AtomicUsize>);

    #[async_trait]
    impl Sink for CountedFail {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            Ok(())
        }
        fn last_write_delivered(&self) -> bool {
            true
        }
        fn kind(&self) -> SinkType {
            SinkType::Kafka
        }
        async fn probe(&self) -> Result<(), std::io::Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::other("still broken"))
        }
    }

    fn shared(sink: Box<dyn Sink>) -> SharedSink {
        Arc::new(Mutex::new(sink))
    }

    #[tokio::test]
    async fn run_probe_success_updates_reachability_and_counter() {
        let sink = shared(Box::new(AlwaysOk));
        let reach = Arc::new(SinkReachability::configured(
            SinkType::Stdout,
            Duration::from_secs(1),
            Duration::from_secs(1),
        ));
        let metrics = Arc::new(Metrics::new());
        run_probe(&sink, &reach, &metrics, Duration::from_secs(1)).await;
        assert!(reach.reachable.load(Ordering::Relaxed));
        assert!(reach.last_error_snapshot().is_none());
        assert!(reach.last_probe_epoch_ms.load(Ordering::Relaxed) > 0);
        assert_eq!(metrics.sink_probe_success.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.sink_probe_failure.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn run_probe_failure_records_error_and_counter() {
        let sink = shared(Box::new(AlwaysFail));
        let reach = Arc::new(SinkReachability::configured(
            SinkType::Kafka,
            Duration::from_secs(1),
            Duration::from_secs(1),
        ));
        let metrics = Arc::new(Metrics::new());
        run_probe(&sink, &reach, &metrics, Duration::from_secs(1)).await;
        assert!(!reach.reachable.load(Ordering::Relaxed));
        assert_eq!(
            reach.last_error_snapshot().as_deref(),
            Some("broker unreachable"),
        );
        assert_eq!(metrics.sink_probe_failure.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.sink_probe_success.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn run_probe_timeout_counts_as_failure_with_timeout_message() {
        let started_marker = Arc::new(AtomicBool::new(false));
        let sink = shared(Box::new(HangingProbe {
            started: Arc::clone(&started_marker),
        }));
        let reach = Arc::new(SinkReachability::configured(
            SinkType::Nats,
            Duration::from_secs(1),
            Duration::from_millis(10),
        ));
        let metrics = Arc::new(Metrics::new());
        run_probe(&sink, &reach, &metrics, Duration::from_millis(10)).await;
        assert!(started_marker.load(Ordering::SeqCst));
        assert!(!reach.reachable.load(Ordering::Relaxed));
        let err = reach.last_error_snapshot().expect("error recorded");
        assert!(err.contains("timed out"), "err was: {err}");
        assert_eq!(metrics.sink_probe_failure.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn run_probe_skips_and_preserves_state_when_sink_lock_held() {
        let sink = shared(Box::new(AlwaysOk));
        let reach = Arc::new(SinkReachability::configured(
            SinkType::Stdout,
            Duration::from_secs(1),
            Duration::from_millis(20),
        ));
        let metrics = Arc::new(Metrics::new());

        let holder_sink = Arc::clone(&sink);
        let hold_ready = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let hold_ready_clone = Arc::clone(&hold_ready);
        let release_clone = Arc::clone(&release);
        let hold_handle = tokio::spawn(async move {
            let _guard = holder_sink.lock().await;
            hold_ready_clone.notify_one();
            release_clone.notified().await;
        });
        hold_ready.notified().await;

        let baseline_probe_epoch = reach.last_probe_epoch_ms.load(Ordering::Relaxed);
        let baseline_reachable = reach.reachable.load(Ordering::Relaxed);
        run_probe(&sink, &reach, &metrics, Duration::from_millis(20)).await;
        assert_eq!(
            reach.last_probe_epoch_ms.load(Ordering::Relaxed),
            baseline_probe_epoch,
            "lock-held skip must not stamp last_probe_epoch_ms",
        );
        assert_eq!(
            reach.reachable.load(Ordering::Relaxed),
            baseline_reachable,
            "lock-held skip must not flip reachable",
        );
        assert!(reach.last_error_snapshot().is_none());
        assert_eq!(metrics.sink_probe_success.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.sink_probe_failure.load(Ordering::Relaxed), 0);

        release.notify_one();
        hold_handle.await.expect("holder task");
    }

    #[tokio::test]
    async fn probe_tick_stamps_the_liveness_tick_when_the_sink_lock_is_held() {
        let sink = shared(Box::new(AlwaysOk));
        let slot = SinkSlot::attached(Arc::clone(&sink));
        let reach = Arc::new(SinkReachability::configured(
            SinkType::Stdout,
            Duration::from_millis(50),
            Duration::from_millis(20),
        ));
        let metrics = Arc::new(Metrics::new());
        let config = SinkProbeConfig {
            config_path: None,
            probe_interval: Duration::from_millis(50),
            probe_timeout: Duration::from_millis(20),
        };

        let holder_sink = Arc::clone(&sink);
        let hold_ready = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let hold_ready_clone = Arc::clone(&hold_ready);
        let release_clone = Arc::clone(&release);
        let hold_handle = tokio::spawn(async move {
            let _guard = holder_sink.lock().await;
            hold_ready_clone.notify_one();
            release_clone.notified().await;
        });
        hold_ready.notified().await;

        let mut failures = ConstructionFailures::default();
        probe_tick(&slot, &config, &reach, &metrics, &mut failures).await;

        assert!(
            reach.last_tick_epoch_ms.load(Ordering::Relaxed) > 0,
            "a tick that skips the probe still proves the task is alive",
        );
        assert_eq!(
            reach.last_probe_epoch_ms.load(Ordering::Relaxed),
            0,
            "a skipped probe produces no result to stamp",
        );
        assert_eq!(reach.ticks.load(Ordering::Relaxed), 1);
        assert_eq!(
            metrics.sink_probe_success.load(Ordering::Relaxed)
                + metrics.sink_probe_failure.load(Ordering::Relaxed),
            0,
            "the gap between the tick counter and the probe counters is the skipped-probe count",
        );

        release.notify_one();
        hold_handle.await.expect("holder task");
    }

    #[tokio::test(start_paused = true)]
    async fn a_tick_that_pays_the_lock_wait_and_the_probe_in_full_fits_the_modelled_cycle() {
        use crate::routes::health::longest_legitimate_cycle_secs;

        let probe_interval = Duration::from_secs(1);
        let probe_timeout = Duration::from_secs(4);
        let hold = Duration::from_secs(3);

        let started = Arc::new(AtomicBool::new(false));
        let sink = shared(Box::new(HangingProbe {
            started: Arc::clone(&started),
        }));
        let slot = SinkSlot::attached(Arc::clone(&sink));
        let reach = Arc::new(SinkReachability::configured(
            SinkType::Nats,
            probe_interval,
            probe_timeout,
        ));
        let metrics = Arc::new(Metrics::new());
        let config = SinkProbeConfig {
            config_path: None,
            probe_interval,
            probe_timeout,
        };

        let holder_sink = Arc::clone(&sink);
        let hold_ready = Arc::new(tokio::sync::Notify::new());
        let hold_ready_clone = Arc::clone(&hold_ready);
        // Released just short of the lock timeout, so the tick pays the lock wait and then the probe.
        let hold_handle = tokio::spawn(async move {
            let _guard = holder_sink.lock().await;
            hold_ready_clone.notify_one();
            tokio::time::sleep(hold).await;
        });
        hold_ready.notified().await;

        let mut failures = ConstructionFailures::default();
        let start = tokio::time::Instant::now();
        probe_tick(&slot, &config, &reach, &metrics, &mut failures).await;
        let elapsed = start.elapsed();
        hold_handle.await.expect("holder task");

        assert!(
            started.load(Ordering::SeqCst),
            "the lock must be granted before it times out, so the probe runs too",
        );
        assert_eq!(
            elapsed,
            hold + probe_timeout,
            "the tick must pay both bounded awaits in full",
        );
        assert!(
            elapsed.as_secs_f64() <= longest_legitimate_cycle_secs(probe_interval, probe_timeout),
            "a {elapsed:?} tick does not fit the {}s cycle the staleness window is built from",
            longest_legitimate_cycle_secs(probe_interval, probe_timeout),
        );
    }

    #[tokio::test]
    async fn success_after_failure_clears_last_error() {
        let counter = Arc::new(AtomicUsize::new(0));
        let sink = shared(Box::new(CountedFail(Arc::clone(&counter))));
        let reach = Arc::new(SinkReachability::configured(
            SinkType::Kafka,
            Duration::from_secs(1),
            Duration::from_secs(1),
        ));
        let metrics = Arc::new(Metrics::new());
        run_probe(&sink, &reach, &metrics, Duration::from_secs(1)).await;
        assert!(reach.last_error_snapshot().is_some());

        let ok = shared(Box::new(AlwaysOk));
        run_probe(&ok, &reach, &metrics, Duration::from_secs(1)).await;
        assert!(reach.reachable.load(Ordering::Relaxed));
        assert!(reach.last_error_snapshot().is_none());
        assert_eq!(metrics.sink_probe_failure.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.sink_probe_success.load(Ordering::Relaxed), 1);
    }

    fn make_shutdown() -> (watch::Sender<bool>, watch::Receiver<bool>) {
        watch::channel(false)
    }

    #[tokio::test]
    async fn spawn_sink_probe_with_no_config_path_leaves_state_untouched() {
        use std::sync::Arc as StdArc;

        use rastreo_core::{HickoryResolver, Resolver};

        let resolver: StdArc<dyn Resolver> =
            StdArc::new(HickoryResolver::from_system().expect("resolver"));
        let state = AppState::new(resolver);
        let cfg = SinkProbeConfig::default();
        let (_tx, rx) = make_shutdown();
        let (after, handle) = spawn_sink_probe(state, &cfg, rx).await;
        assert!(after.sink().is_none());
        assert!(!after.sink_reachability.configured);
        assert_eq!(
            after
                .sink_reachability
                .last_tick_epoch_ms
                .load(Ordering::Relaxed),
            0,
            "an unconfigured sink has no probe task, so it must never look stalled",
        );
        assert!(handle.is_none(), "no task spawned when no sink configured");
    }

    #[cfg(feature = "config")]
    #[tokio::test]
    async fn spawn_sink_probe_with_valid_stdout_config_marks_state_configured() {
        use std::sync::Arc as StdArc;

        use rastreo_core::{HickoryResolver, Resolver};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sink.yaml");
        tokio::fs::write(&path, "type: stdout\n")
            .await
            .expect("write yaml");
        let resolver: StdArc<dyn Resolver> =
            StdArc::new(HickoryResolver::from_system().expect("resolver"));
        let state = AppState::new(resolver);
        let cfg = SinkProbeConfig {
            config_path: Some(path),
            probe_interval: Duration::from_secs(60),
            probe_timeout: Duration::from_secs(5),
        };
        let (_tx, rx) = make_shutdown();
        let (after, handle) = spawn_sink_probe(state, &cfg, rx).await;
        assert!(after.sink().is_some());
        assert!(after.sink_reachability.configured);
        assert_eq!(after.sink_reachability.sink_type(), Some(SinkType::Stdout));
        assert!(handle.is_some(), "handle returned for configured sink");
        if let Some(h) = handle {
            h.abort();
        }
    }

    #[cfg(feature = "config")]
    #[tokio::test]
    async fn spawn_sink_probe_runs_first_probe_eagerly_before_returning() {
        use std::sync::Arc as StdArc;

        use rastreo_core::{HickoryResolver, Resolver};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sink.yaml");
        tokio::fs::write(&path, "type: stdout\n")
            .await
            .expect("write yaml");
        let resolver: StdArc<dyn Resolver> =
            StdArc::new(HickoryResolver::from_system().expect("resolver"));
        let state = AppState::new(resolver);
        let cfg = SinkProbeConfig {
            config_path: Some(path),
            probe_interval: Duration::from_secs(3600),
            probe_timeout: Duration::from_secs(5),
        };
        let (_tx, rx) = make_shutdown();
        let (after, handle) = spawn_sink_probe(state, &cfg, rx).await;
        assert!(
            after
                .sink_reachability
                .last_probe_epoch_ms
                .load(Ordering::Relaxed)
                > 0,
            "first probe must complete before spawn_sink_probe returns",
        );
        assert!(after.sink_reachability.reachable.load(Ordering::Relaxed));
        assert_eq!(
            after.metrics.sink_probe_success.load(Ordering::Relaxed),
            1,
            "eager probe must credit the success counter",
        );
        if let Some(h) = handle {
            h.abort();
        }
    }

    #[cfg(feature = "config")]
    #[tokio::test]
    async fn spawn_sink_probe_stamps_the_liveness_tick_on_the_startup_cycle() {
        use std::sync::Arc as StdArc;

        use rastreo_core::{HickoryResolver, Resolver};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sink.yaml");
        tokio::fs::write(&path, "type: stdout\n")
            .await
            .expect("write yaml");
        let resolver: StdArc<dyn Resolver> =
            StdArc::new(HickoryResolver::from_system().expect("resolver"));
        let state = AppState::new(resolver);
        let cfg = SinkProbeConfig {
            config_path: Some(path),
            probe_interval: Duration::from_secs(3600),
            probe_timeout: Duration::from_secs(5),
        };
        let (_tx, rx) = make_shutdown();
        let (after, handle) = spawn_sink_probe(state, &cfg, rx).await;
        assert!(
            after
                .sink_reachability
                .last_tick_epoch_ms
                .load(Ordering::Relaxed)
                > 0,
            "the startup cycle counts as a tick, so /readyz is never gated on it",
        );
        if let Some(h) = handle {
            h.abort();
        }
    }

    #[cfg(feature = "config")]
    #[tokio::test]
    async fn spawn_sink_probe_stamps_the_liveness_tick_when_construction_fails() {
        use std::sync::Arc as StdArc;

        use rastreo_core::{HickoryResolver, Resolver};

        let resolver: StdArc<dyn Resolver> =
            StdArc::new(HickoryResolver::from_system().expect("resolver"));
        let state = AppState::new(resolver);
        let cfg = SinkProbeConfig {
            config_path: Some(std::path::PathBuf::from(
                "/tmp/rastreo-sink-does-not-exist-5512087.yaml",
            )),
            probe_interval: Duration::from_secs(3600),
            probe_timeout: Duration::from_secs(5),
        };
        let (_tx, rx) = make_shutdown();
        let (after, handle) = spawn_sink_probe(state, &cfg, rx).await;
        assert!(
            after
                .sink_reachability
                .last_tick_epoch_ms
                .load(Ordering::Relaxed)
                > 0,
        );
        handle.expect("retry task spawned").abort();
    }

    #[cfg(all(feature = "config", unix))]
    #[tokio::test]
    async fn a_cycle_that_never_returns_still_records_that_it_started() {
        use std::sync::Arc as StdArc;

        use rastreo_core::{HickoryResolver, Resolver};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sink.yaml");
        // A FIFO read blocks until a writer closes, so a tick that is not fed never completes.
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo failed: {status}");

        let startup_path = path.clone();
        tokio::spawn(async move {
            let _ = tokio::fs::write(&startup_path, "type: not-a-real-sink\n").await;
        });

        let resolver: StdArc<dyn Resolver> =
            StdArc::new(HickoryResolver::from_system().expect("resolver"));
        let state = AppState::new(resolver);
        let cfg = SinkProbeConfig {
            config_path: Some(path.clone()),
            probe_interval: Duration::from_millis(50),
            probe_timeout: Duration::from_secs(60),
        };
        let (_tx, rx) = make_shutdown();
        let (after, handle) = spawn_sink_probe(state, &cfg, rx).await;
        let handle = handle.expect("retry task spawned on parse failure");
        let startup_ticks = after.sink_reachability.ticks.load(Ordering::Relaxed);

        // Feeds on a dropped sender too, so a failing assertion cannot leave the read blocked.
        let (feed, feed_signal) = std::sync::mpsc::channel::<()>();
        let feed_path = path.clone();
        let feeder = std::thread::spawn(move || {
            let _ = feed_signal.recv();
            let _ = std::fs::write(&feed_path, "type: stdout\n");
        });

        let reach = StdArc::clone(&after.sink_reachability);
        wait_until("the wedged cycle to record its start", move || {
            reach.ticks.load(Ordering::Relaxed) > startup_ticks
        })
        .await;
        assert_eq!(
            after.metrics.sink_probe_failure.load(Ordering::Relaxed),
            1,
            "the wedged cycle must not have reached a result, so only startup counted",
        );

        handle.abort();
        feed.send(()).expect("release the feeder");
        feeder.join().expect("feeder thread");
    }

    #[cfg(feature = "config")]
    #[tokio::test]
    async fn spawn_sink_probe_with_missing_file_records_error_and_keeps_retrying() {
        use std::sync::Arc as StdArc;

        use rastreo_core::{HickoryResolver, Resolver};

        let resolver: StdArc<dyn Resolver> =
            StdArc::new(HickoryResolver::from_system().expect("resolver"));
        let state = AppState::new(resolver);
        let cfg = SinkProbeConfig {
            config_path: Some(std::path::PathBuf::from(
                "/tmp/rastreo-sink-does-not-exist-9134729.yaml",
            )),
            probe_interval: Duration::from_secs(60),
            probe_timeout: Duration::from_secs(5),
        };
        let (_tx, rx) = make_shutdown();
        let (after, handle) = spawn_sink_probe(state, &cfg, rx).await;
        assert!(after.sink().is_none());
        assert!(after.sink_reachability.configured);
        assert!(after.sink_reachability.last_error_snapshot().is_some());
        assert_eq!(
            after.metrics.sink_probe_failure.load(Ordering::Relaxed),
            1,
            "a failed construction is a failed reachability check",
        );
        let handle = handle.expect("retry task spawned on construction failure");
        handle.abort();
    }

    #[cfg(feature = "config")]
    #[tokio::test]
    async fn spawn_sink_probe_with_malformed_yaml_records_error_and_keeps_retrying() {
        use std::sync::Arc as StdArc;

        use rastreo_core::{HickoryResolver, Resolver};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.yaml");
        tokio::fs::write(&path, "type: not-a-real-sink\n")
            .await
            .expect("write yaml");
        let resolver: StdArc<dyn Resolver> =
            StdArc::new(HickoryResolver::from_system().expect("resolver"));
        let state = AppState::new(resolver);
        let cfg = SinkProbeConfig {
            config_path: Some(path),
            probe_interval: Duration::from_secs(60),
            probe_timeout: Duration::from_secs(5),
        };
        let (_tx, rx) = make_shutdown();
        let (after, handle) = spawn_sink_probe(state, &cfg, rx).await;
        assert!(after.sink().is_none());
        assert!(after.sink_reachability.configured);
        assert!(after.sink_reachability.last_error_snapshot().is_some());
        let handle = handle.expect("retry task spawned on parse failure");
        handle.abort();
    }

    #[cfg(feature = "config")]
    #[tokio::test]
    async fn a_config_that_parses_but_cannot_build_still_reports_its_sink_type() {
        use std::sync::Arc as StdArc;

        use rastreo_core::{HickoryResolver, Resolver};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sink.yaml");
        let records = dir.path().join("records");
        tokio::fs::create_dir(&records).await.expect("create dir");
        tokio::fs::write(&path, format!("type: file\npath: {}\n", records.display()))
            .await
            .expect("write yaml");
        let resolver: StdArc<dyn Resolver> =
            StdArc::new(HickoryResolver::from_system().expect("resolver"));
        let state = AppState::new(resolver);
        let cfg = SinkProbeConfig {
            config_path: Some(path),
            probe_interval: Duration::from_secs(60),
            probe_timeout: Duration::from_secs(5),
        };
        let (_tx, rx) = make_shutdown();
        let (after, handle) = spawn_sink_probe(state, &cfg, rx).await;

        assert!(after.sink().is_none());
        assert_eq!(after.sink_reachability.sink_type(), Some(SinkType::File));
        assert_eq!(after.sink_reachability.sink_type_label(), Some("file"));
        assert!(after.sink_reachability.last_error_snapshot().is_some());
        handle.expect("retry task spawned on build failure").abort();
    }

    #[cfg(all(feature = "config", feature = "kafka"))]
    #[tokio::test]
    async fn spawn_sink_probe_with_hanging_construction_times_out_and_records_error() {
        use std::sync::Arc as StdArc;
        use std::time::Instant;

        use rastreo_core::{HickoryResolver, Resolver};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("kafka.yaml");
        tokio::fs::write(
            &path,
            "type: kafka\nbrokers:\n  - \"240.0.0.1:9092\"\ntopic: rastreo-events\n",
        )
        .await
        .expect("write yaml");
        let resolver: StdArc<dyn Resolver> =
            StdArc::new(HickoryResolver::from_system().expect("resolver"));
        let state = AppState::new(resolver);
        let cfg = SinkProbeConfig {
            config_path: Some(path),
            probe_interval: Duration::from_secs(60),
            probe_timeout: Duration::from_secs(1),
        };

        let start = Instant::now();
        let (_tx, rx) = make_shutdown();
        let (after, handle) = spawn_sink_probe(state, &cfg, rx).await;
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(5),
            "spawn_sink_probe hung past construction timeout: {elapsed:?}",
        );
        assert!(after.sink().is_none());
        assert!(after.sink_reachability.configured);
        assert_eq!(after.sink_reachability.sink_type(), Some(SinkType::Kafka));
        let err = after
            .sink_reachability
            .last_error_snapshot()
            .expect("construction error recorded");
        assert!(
            err.contains("timed out") && err.contains("kafka"),
            "expected timeout + sink-type hint, got: {err}",
        );
        assert_eq!(
            after.metrics.sink_probe_success.load(Ordering::Relaxed),
            0,
            "eager probe must not run when construction fails",
        );
        let handle = handle.expect("retry task spawned on construction timeout");
        handle.abort();
    }

    #[cfg(feature = "config")]
    #[tokio::test]
    async fn spawn_sink_probe_task_exits_when_shutdown_signal_fires() {
        use std::sync::Arc as StdArc;

        use rastreo_core::{HickoryResolver, Resolver};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sink.yaml");
        tokio::fs::write(&path, "type: stdout\n")
            .await
            .expect("write yaml");
        let resolver: StdArc<dyn Resolver> =
            StdArc::new(HickoryResolver::from_system().expect("resolver"));
        let state = AppState::new(resolver);
        let cfg = SinkProbeConfig {
            config_path: Some(path),
            probe_interval: Duration::from_secs(3600),
            probe_timeout: Duration::from_secs(5),
        };
        let (tx, rx) = make_shutdown();
        let (_after, handle) = spawn_sink_probe(state, &cfg, rx).await;
        let handle = handle.expect("task spawned");

        tx.send(true).expect("send shutdown");
        let joined = tokio::time::timeout(Duration::from_millis(500), handle).await;
        assert!(
            joined.is_ok(),
            "probe task must exit within 500ms of shutdown signal",
        );
        joined.unwrap().expect("task joined cleanly");
    }

    #[cfg(all(feature = "config", unix))]
    #[tokio::test]
    async fn shutdown_during_an_in_flight_construction_finishes_it_and_then_exits() {
        use std::sync::Arc as StdArc;

        use rastreo_core::{HickoryResolver, Resolver};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sink.yaml");
        // A FIFO read blocks until a writer closes, so the test decides when the read completes.
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo failed: {status}");

        let startup_path = path.clone();
        tokio::spawn(async move {
            let _ = tokio::fs::write(&startup_path, "type: not-a-real-sink\n").await;
        });

        let resolver: StdArc<dyn Resolver> =
            StdArc::new(HickoryResolver::from_system().expect("resolver"));
        let state = AppState::new(resolver);
        let cfg = SinkProbeConfig {
            config_path: Some(path.clone()),
            probe_interval: Duration::from_millis(50),
            probe_timeout: Duration::from_secs(5),
        };
        let (tx, rx) = make_shutdown();
        let (after, handle) = spawn_sink_probe(state, &cfg, rx).await;
        let handle = handle.expect("retry task spawned on parse failure");
        assert!(after.sink().is_none());

        // Feeds on a dropped sender too, so a failing assertion cannot leave the read blocked.
        let (feed, feed_signal) = std::sync::mpsc::channel::<()>();
        let feed_path = path.clone();
        let feeder = std::thread::spawn(move || {
            let _ = feed_signal.recv();
            let _ = std::fs::write(&feed_path, "type: stdout\n");
        });

        // Long enough for the first retry tick to fire and block on the unfed FIFO.
        tokio::time::sleep(Duration::from_millis(150)).await;
        tx.send(true).expect("send shutdown");
        feed.send(()).expect("release the feeder");

        let joined = tokio::time::timeout(Duration::from_secs(5), handle).await;
        feeder.join().expect("feeder thread");
        assert!(
            joined.is_ok(),
            "probe task must exit once the in-flight construction completes",
        );
        joined.unwrap().expect("task joined cleanly");
        assert!(
            after.sink().is_some(),
            "shutdown must not cancel a construction the tick already started",
        );
    }

    #[tokio::test]
    async fn a_panicking_tick_is_caught_and_the_task_keeps_going() {
        let next_tick_ran = Arc::new(AtomicBool::new(false));
        guard_panics(async { panic!("third-party client panicked") }).await;

        let marker = Arc::clone(&next_tick_ran);
        guard_panics(async move {
            marker.store(true, Ordering::SeqCst);
        })
        .await;
        assert!(next_tick_ran.load(Ordering::SeqCst));
    }

    #[test]
    fn panic_detail_reads_both_string_payload_shapes() {
        assert_eq!(panic_detail(&"boom"), "boom");
        assert_eq!(panic_detail(&String::from("boom")), "boom");
        assert_eq!(panic_detail(&7_u32), "panic payload was not a string");
    }

    #[cfg(feature = "config")]
    async fn wait_until(label: &str, mut condition: impl FnMut() -> bool) {
        let waited = tokio::time::timeout(Duration::from_secs(5), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(waited.is_ok(), "timed out waiting for {label}");
    }

    #[cfg(feature = "config")]
    #[tokio::test]
    async fn sink_that_failed_to_build_attaches_once_its_config_appears() {
        use std::sync::Arc as StdArc;

        use rastreo_core::{HickoryResolver, Resolver};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sink.yaml");
        let resolver: StdArc<dyn Resolver> =
            StdArc::new(HickoryResolver::from_system().expect("resolver"));
        let state = AppState::new(resolver);
        let cfg = SinkProbeConfig {
            config_path: Some(path.clone()),
            probe_interval: Duration::from_millis(50),
            probe_timeout: Duration::from_secs(5),
        };
        let (_tx, rx) = make_shutdown();
        let (after, handle) = spawn_sink_probe(state, &cfg, rx).await;
        let handle = handle.expect("retry task spawned");
        assert!(after.sink().is_none());
        assert_eq!(after.sink_reachability.sink_type_label(), Some("unknown"));

        tokio::fs::write(&path, "type: stdout\n")
            .await
            .expect("write yaml");

        let reach = StdArc::clone(&after.sink_reachability);
        let attached = after.clone();
        wait_until("the sink to attach", move || attached.sink().is_some()).await;
        wait_until("the probe to report reachable", move || {
            reach.reachable.load(Ordering::Relaxed)
        })
        .await;

        assert_eq!(
            after.sink_reachability.sink_type(),
            Some(SinkType::Stdout),
            "the attached sink's real kind must replace the construction hint",
        );
        assert_eq!(after.sink_reachability.sink_type_label(), Some("stdout"));
        assert!(after.sink_reachability.last_error_snapshot().is_none());
        assert!(
            after.metrics.sink_probe_success.load(Ordering::Relaxed) >= 1,
            "the attached sink must be probed, not just stored",
        );
        handle.abort();
    }

    #[cfg(feature = "config")]
    #[tokio::test]
    async fn sink_construction_that_keeps_failing_retries_on_the_interval_without_spinning() {
        use std::sync::Arc as StdArc;
        use std::time::Instant;

        use rastreo_core::{HickoryResolver, Resolver};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("never-written.yaml");
        let resolver: StdArc<dyn Resolver> =
            StdArc::new(HickoryResolver::from_system().expect("resolver"));
        let state = AppState::new(resolver);
        let interval_dur = Duration::from_millis(100);
        let cfg = SinkProbeConfig {
            config_path: Some(path),
            probe_interval: interval_dur,
            probe_timeout: Duration::from_secs(5),
        };
        let (_tx, rx) = make_shutdown();
        let start = Instant::now();
        let (after, handle) = spawn_sink_probe(state, &cfg, rx).await;
        let handle = handle.expect("retry task spawned");
        let first_stamp = after
            .sink_reachability
            .last_probe_epoch_ms
            .load(Ordering::Relaxed);

        let metrics = StdArc::clone(&after.metrics);
        wait_until("two retries to fail", move || {
            metrics.sink_probe_failure.load(Ordering::Relaxed) >= 3
        })
        .await;
        let elapsed = start.elapsed();

        assert!(
            elapsed >= interval_dur * 2,
            "retries must be paced by the probe interval, not spun: {elapsed:?}",
        );
        assert!(after.sink().is_none());
        assert!(!after.sink_reachability.reachable.load(Ordering::Relaxed));
        assert!(after.sink_reachability.last_error_snapshot().is_some());
        assert!(
            after
                .sink_reachability
                .last_probe_epoch_ms
                .load(Ordering::Relaxed)
                > first_stamp,
            "each retry must refresh seconds_since_last_probe on /readyz",
        );
        handle.abort();
    }

    #[test]
    fn identical_construction_failures_warn_on_a_doubling_backoff() {
        let mut failures = ConstructionFailures::default();
        let volumes: Vec<FailureVolume> = (0..8)
            .map(|_| failures.observe("broker unreachable"))
            .collect();
        assert_eq!(
            volumes,
            vec![
                FailureVolume::Warn,
                FailureVolume::Warn,
                FailureVolume::Debug,
                FailureVolume::Warn,
                FailureVolume::Debug,
                FailureVolume::Debug,
                FailureVolume::Debug,
                FailureVolume::Warn,
            ],
        );
        assert_eq!(failures.attempts, 8);
    }

    #[test]
    fn a_new_construction_failure_warns_between_backoff_points() {
        let mut failures = ConstructionFailures::default();
        for _ in 0..5 {
            failures.observe("broker unreachable");
        }
        assert_eq!(
            failures.observe("authorization violation"),
            FailureVolume::Warn
        );
        assert_eq!(
            failures.observe("authorization violation"),
            FailureVolume::Debug
        );
    }
}
