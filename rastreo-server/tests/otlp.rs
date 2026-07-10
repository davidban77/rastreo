#![cfg(feature = "otlp")]

use std::sync::Arc;
use std::time::Duration;

use rastreo_server::observability;
use rastreo_server::state::{Metrics, OtlpConfig, OtlpProtocol};

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
            protocol: OtlpProtocol::Grpc,
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
fn init_metrics_only_with_http_protobuf_protocol_builds_exporter() {
    let rt = tokio_runtime();
    rt.block_on(async {
        let cfg = OtlpConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            protocol: OtlpProtocol::HttpProtobuf,
            metrics_enabled: true,
            logs_enabled: false,
            metrics_interval: Duration::from_secs(30),
            service_name: "rastreo-server-test".to_string(),
        };
        let metrics = Arc::new(Metrics::new());
        let guard = observability::init_metrics_only(&cfg, Arc::clone(&metrics))
            .expect("init_metrics_only with http-protobuf");
        drop(guard);
    });
}

#[test]
fn otlp_scan_duration_emits_all_and_per_scenario_observations() {
    use std::collections::HashSet;

    use opentelemetry::metrics::MeterProvider;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
    use rastreo_core::DiscoverySummary;
    use rastreo_server::state::MetricsConfig;

    let exporter = InMemoryMetricExporter::default();
    let reader = PeriodicReader::builder(exporter.clone()).build();
    let provider = SdkMeterProvider::builder().with_reader(reader).build();
    let meter = provider.meter("rastreo-server-test");
    let histogram = meter
        .f64_histogram("rastreo_server_scan_duration_seconds")
        .with_unit("s")
        .build();

    let mut allow = HashSet::new();
    allow.insert("prod".to_string());
    let metrics = Metrics::with_config(MetricsConfig {
        scenario_allowlist: allow,
        scenario_max_length: 64,
    });
    metrics
        .attach_otlp_scan_duration(histogram)
        .expect("attach histogram");

    let mut summary = DiscoverySummary::default();
    summary.elapsed = Duration::from_millis(123);
    metrics.record_scan_completion(&summary, "prod");

    provider.force_flush().expect("force_flush");
    let exported = exporter.get_finished_metrics().expect("finished metrics");

    let mut scenarios: Vec<String> = Vec::new();
    for rm in &exported {
        for scope in rm.scope_metrics() {
            for metric in scope.metrics() {
                if metric.name() != "rastreo_server_scan_duration_seconds" {
                    continue;
                }
                let AggregatedMetrics::F64(MetricData::Histogram(hist)) = metric.data() else {
                    panic!("expected f64 histogram");
                };
                for dp in hist.data_points() {
                    for kv in dp.attributes() {
                        if kv.key.as_str() == "scenario" {
                            scenarios.push(kv.value.as_str().to_string());
                        }
                    }
                }
            }
        }
    }
    scenarios.sort();
    assert_eq!(
        scenarios,
        vec!["_all".to_string(), "prod".to_string()],
        "OTLP must emit one observation for `_all` and one for the resolved scenario label"
    );
    provider.shutdown().expect("shutdown");
}

#[test]
fn otlp_scan_duration_routes_unlisted_scenario_to_all_and_other() {
    use opentelemetry::metrics::MeterProvider;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
    use rastreo_core::DiscoverySummary;

    let exporter = InMemoryMetricExporter::default();
    let reader = PeriodicReader::builder(exporter.clone()).build();
    let provider = SdkMeterProvider::builder().with_reader(reader).build();
    let meter = provider.meter("rastreo-server-test");
    let histogram = meter
        .f64_histogram("rastreo_server_scan_duration_seconds")
        .with_unit("s")
        .build();

    let metrics = Metrics::new();
    metrics
        .attach_otlp_scan_duration(histogram)
        .expect("attach histogram");

    let mut summary = DiscoverySummary::default();
    summary.elapsed = Duration::from_millis(50);
    metrics.record_scan_completion(&summary, "not-in-allowlist");

    provider.force_flush().expect("force_flush");
    let exported = exporter.get_finished_metrics().expect("finished metrics");

    let mut scenarios: Vec<String> = Vec::new();
    for rm in &exported {
        for scope in rm.scope_metrics() {
            for metric in scope.metrics() {
                if metric.name() != "rastreo_server_scan_duration_seconds" {
                    continue;
                }
                let AggregatedMetrics::F64(MetricData::Histogram(hist)) = metric.data() else {
                    panic!("expected f64 histogram");
                };
                for dp in hist.data_points() {
                    for kv in dp.attributes() {
                        if kv.key.as_str() == "scenario" {
                            scenarios.push(kv.value.as_str().to_string());
                        }
                    }
                }
            }
        }
    }
    scenarios.sort();
    assert_eq!(scenarios, vec!["_all".to_string(), "other".to_string()]);
    provider.shutdown().expect("shutdown");
}

#[test]
fn init_metrics_only_with_disabled_metrics_returns_empty_guard() {
    let rt = tokio_runtime();
    rt.block_on(async {
        let cfg = OtlpConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            protocol: OtlpProtocol::Grpc,
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
