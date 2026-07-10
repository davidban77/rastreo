use std::sync::Arc;
use std::time::Duration;

use rastreo_core::{Sink, SinkType};
use tokio::time::{interval, timeout, MissedTickBehavior};

use crate::state::{AppState, Metrics, SinkProbeConfig, SinkReachability};

struct ConstructError {
    hint: Option<SinkType>,
    err: anyhow::Error,
}

/// Build the sink referenced by `RASTREO_SINK_CONFIG_PATH` and spawn a background probe task; failures surface via `/readyz` rather than crashing the server.
pub async fn spawn_sink_probe(state: AppState, config: &SinkProbeConfig) -> AppState {
    let Some(path) = config.config_path.as_ref() else {
        return state;
    };

    let sink_result = load_and_construct_sink(path, config.probe_timeout).await;
    match sink_result {
        Ok(sink) => {
            let sink_type = sink.kind();
            let reachability = Arc::new(SinkReachability::configured(
                sink_type,
                config.probe_interval,
                config.probe_timeout,
            ));
            let sink: Arc<dyn Sink> = Arc::from(sink);
            run_probe(&sink, &reachability, &state.metrics, config.probe_timeout).await;
            spawn_probe_task(
                Arc::clone(&sink),
                Arc::clone(&reachability),
                Arc::clone(&state.metrics),
                config.probe_interval,
                config.probe_timeout,
            );
            state.with_sink(Some(sink), reachability)
        }
        Err(ConstructError { hint, err }) => {
            tracing::warn!(
                error = %err,
                path = %path.display(),
                sink_type = ?hint.map(SinkType::as_label),
                "sink construction failed; /readyz will report sink_unreachable"
            );
            let reachability = Arc::new(SinkReachability::construction_failed(
                hint,
                format!("sink construction failed: {err}"),
                config.probe_interval,
                config.probe_timeout,
            ));
            state.with_sink(None, reachability)
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
        use rastreo_core::{sink::create_sink, SinkConfig};

        let raw = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read sink config at {}", path.display()))
            .map_err(|err| ConstructError { hint: None, err })?;
        let config: SinkConfig = serde_yaml_ng::from_str(&raw)
            .with_context(|| format!("failed to parse sink config at {}", path.display()))
            .map_err(|err| ConstructError { hint: None, err })?;
        let hint = sink_type_hint(&config);
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

#[cfg(feature = "config")]
fn sink_type_hint(config: &rastreo_core::SinkConfig) -> Option<SinkType> {
    use rastreo_core::SinkConfig;
    match config {
        SinkConfig::Stdout => Some(SinkType::Stdout),
        SinkConfig::File { .. } => Some(SinkType::File),
        SinkConfig::Memory => Some(SinkType::Memory),
        #[cfg(feature = "kafka")]
        SinkConfig::Kafka { .. } => Some(SinkType::Kafka),
        #[cfg(feature = "nats")]
        SinkConfig::Nats { .. } => Some(SinkType::Nats),
        _ => None,
    }
}

fn spawn_probe_task(
    sink: Arc<dyn Sink>,
    reachability: Arc<SinkReachability>,
    metrics: Arc<Metrics>,
    interval_dur: Duration,
    timeout_dur: Duration,
) {
    tokio::spawn(async move {
        let mut ticker = interval(interval_dur);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            run_probe(&sink, &reachability, &metrics, timeout_dur).await;
        }
    });
}

async fn run_probe(
    sink: &Arc<dyn Sink>,
    reachability: &Arc<SinkReachability>,
    metrics: &Arc<Metrics>,
    timeout_dur: Duration,
) {
    match timeout(timeout_dur, sink.probe()).await {
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
        fn kind(&self) -> SinkType {
            SinkType::Kafka
        }
        async fn probe(&self) -> Result<(), std::io::Error> {
            Err(std::io::Error::other("broker unreachable"))
        }
    }

    struct HangingProbe {
        started: AtomicBool,
    }

    #[async_trait]
    impl Sink for HangingProbe {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            Ok(())
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

    struct CountedFail(AtomicUsize);

    #[async_trait]
    impl Sink for CountedFail {
        async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
            Ok(())
        }
        async fn flush(&mut self) -> Result<(), RastreoError> {
            Ok(())
        }
        fn kind(&self) -> SinkType {
            SinkType::Kafka
        }
        async fn probe(&self) -> Result<(), std::io::Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::other("still broken"))
        }
    }

    #[tokio::test]
    async fn run_probe_success_updates_reachability_and_counter() {
        let sink: Arc<dyn Sink> = Arc::new(AlwaysOk);
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
        let sink: Arc<dyn Sink> = Arc::new(AlwaysFail);
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
        let hang = Arc::new(HangingProbe {
            started: AtomicBool::new(false),
        });
        let sink: Arc<dyn Sink> = hang.clone();
        let reach = Arc::new(SinkReachability::configured(
            SinkType::Nats,
            Duration::from_secs(1),
            Duration::from_millis(10),
        ));
        let metrics = Arc::new(Metrics::new());
        run_probe(&sink, &reach, &metrics, Duration::from_millis(10)).await;
        assert!(hang.started.load(Ordering::SeqCst));
        assert!(!reach.reachable.load(Ordering::Relaxed));
        let err = reach.last_error_snapshot().expect("error recorded");
        assert!(err.contains("timed out"), "err was: {err}");
        assert_eq!(metrics.sink_probe_failure.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn success_after_failure_clears_last_error() {
        let counted = Arc::new(CountedFail(AtomicUsize::new(0)));
        let sink: Arc<dyn Sink> = counted.clone();
        let reach = Arc::new(SinkReachability::configured(
            SinkType::Kafka,
            Duration::from_secs(1),
            Duration::from_secs(1),
        ));
        let metrics = Arc::new(Metrics::new());
        run_probe(&sink, &reach, &metrics, Duration::from_secs(1)).await;
        assert!(reach.last_error_snapshot().is_some());

        let ok: Arc<dyn Sink> = Arc::new(AlwaysOk);
        run_probe(&ok, &reach, &metrics, Duration::from_secs(1)).await;
        assert!(reach.reachable.load(Ordering::Relaxed));
        assert!(reach.last_error_snapshot().is_none());
        assert_eq!(metrics.sink_probe_failure.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.sink_probe_success.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn spawn_sink_probe_with_no_config_path_leaves_state_untouched() {
        use std::sync::Arc as StdArc;

        use rastreo_core::{HickoryResolver, Resolver};

        let resolver: StdArc<dyn Resolver> =
            StdArc::new(HickoryResolver::from_system().expect("resolver"));
        let state = AppState::new(resolver);
        let cfg = SinkProbeConfig::default();
        let after = spawn_sink_probe(state, &cfg).await;
        assert!(after.sink.is_none());
        assert!(!after.sink_reachability.configured);
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
        let after = spawn_sink_probe(state, &cfg).await;
        assert!(after.sink.is_some());
        assert!(after.sink_reachability.configured);
        assert_eq!(after.sink_reachability.sink_type, Some(SinkType::Stdout));
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
        let after = spawn_sink_probe(state, &cfg).await;
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
    }

    #[cfg(feature = "config")]
    #[tokio::test]
    async fn spawn_sink_probe_with_missing_file_marks_state_not_configured_with_error() {
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
        let after = spawn_sink_probe(state, &cfg).await;
        assert!(after.sink.is_none());
        assert!(after.sink_reachability.configured);
        assert!(after.sink_reachability.last_error_snapshot().is_some());
    }

    #[cfg(feature = "config")]
    #[tokio::test]
    async fn spawn_sink_probe_with_malformed_yaml_marks_state_not_configured_with_error() {
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
        let after = spawn_sink_probe(state, &cfg).await;
        assert!(after.sink.is_none());
        assert!(after.sink_reachability.configured);
        assert!(after.sink_reachability.last_error_snapshot().is_some());
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
        let after = spawn_sink_probe(state, &cfg).await;
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(5),
            "spawn_sink_probe hung past construction timeout: {elapsed:?}",
        );
        assert!(after.sink.is_none());
        assert!(after.sink_reachability.configured);
        assert_eq!(after.sink_reachability.sink_type, Some(SinkType::Kafka));
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
    }
}
