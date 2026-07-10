#![cfg(feature = "otlp")]

use std::sync::Arc;
use std::time::Duration;

use rastreo_server::observability;
use rastreo_server::state::{Metrics, OtlpConfig};

fn tokio_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

#[test]
fn init_metrics_only_with_unreachable_endpoint_does_not_panic() {
    let rt = tokio_runtime();
    rt.block_on(async {
        let cfg = OtlpConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            metrics_enabled: true,
            logs_enabled: false,
            metrics_interval: Duration::from_secs(30),
            service_name: "rastreo-server-test".to_string(),
        };
        let metrics = Arc::new(Metrics::new());
        let guard = observability::init_metrics_only(&cfg, Arc::clone(&metrics))
            .expect("init_metrics_only");
        // Drop the guard synchronously — shutdown must not panic even with a dead endpoint.
        drop(guard);
    });
}

#[test]
fn init_metrics_only_with_disabled_metrics_returns_empty_guard() {
    let rt = tokio_runtime();
    rt.block_on(async {
        let cfg = OtlpConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            metrics_enabled: false,
            logs_enabled: true,
            metrics_interval: Duration::from_secs(30),
            service_name: "rastreo-server-test".to_string(),
        };
        let metrics = Arc::new(Metrics::new());
        let guard = observability::init_metrics_only(&cfg, metrics).expect("guard");
        drop(guard);
    });
}
