//! OpenTelemetry OTLP exporters for metrics and logs.

#![cfg(feature = "otlp")]

use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Context;
use opentelemetry::{global, KeyValue};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::Resource;
use tracing::Subscriber;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

use crate::state::{Metrics, OtlpConfig, OtlpProtocol};

/// Append the OTLP HTTP signal path to a bare endpoint. The opentelemetry-otlp SDK
/// applies signal-path defaults only on the `OTEL_EXPORTER_OTLP_ENDPOINT` env-var
/// fallback path; the programmatic `.with_endpoint()` builder uses the URL verbatim,
/// so users setting `RASTREO_OTLP_ENDPOINT=http://collector:4318` on HTTP+protobuf
/// would POST to `/` and get 404s. We do the append here so a single endpoint value
/// works for both logs and metrics from the same config.
fn http_endpoint_for_signal(base: &str, signal_path: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    if trimmed.ends_with(signal_path) {
        trimmed.to_string()
    } else {
        format!("{trimmed}{signal_path}")
    }
}

/// RAII guard that shuts down the OTLP providers on drop so pending exports flush before exit.
#[non_exhaustive]
pub struct OtlpGuard {
    meter: Option<SdkMeterProvider>,
    logger: Option<SdkLoggerProvider>,
}

impl OtlpGuard {
    fn empty() -> Self {
        Self {
            meter: None,
            logger: None,
        }
    }
}

impl Drop for OtlpGuard {
    fn drop(&mut self) {
        if let Some(m) = self.meter.take() {
            if let Err(err) = m.shutdown() {
                tracing::warn!(%err, "OTLP meter provider shutdown failed");
            }
        }
        if let Some(l) = self.logger.take() {
            if let Err(err) = l.shutdown() {
                tracing::warn!(%err, "OTLP logger provider shutdown failed");
            }
        }
    }
}

/// Build a `tracing_subscriber::Layer` that ships events to the OTLP log exporter.
pub fn logs_layer<S>(config: &OtlpConfig) -> anyhow::Result<(impl Layer<S>, SdkLoggerProvider)>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let exporter = match config.protocol {
        OtlpProtocol::Grpc => opentelemetry_otlp::LogExporter::builder()
            .with_tonic()
            .with_endpoint(&config.endpoint)
            .build()
            .context("failed to build OTLP gRPC log exporter")?,
        OtlpProtocol::HttpProtobuf => opentelemetry_otlp::LogExporter::builder()
            .with_http()
            .with_endpoint(http_endpoint_for_signal(&config.endpoint, "/v1/logs"))
            .build()
            .context("failed to build OTLP HTTP+protobuf log exporter")?,
    };
    let resource = Resource::builder()
        .with_service_name(config.service_name.clone())
        .build();
    let provider = SdkLoggerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();
    let layer = OpenTelemetryTracingBridge::new(&provider);
    Ok((layer, provider))
}

/// Wire up OTLP metrics (observable counters + gauges + a synchronously recorded histogram) against the running `Metrics`.
pub fn init_metrics(
    config: &OtlpConfig,
    metrics: Arc<Metrics>,
) -> anyhow::Result<SdkMeterProvider> {
    let exporter = match config.protocol {
        OtlpProtocol::Grpc => opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .with_endpoint(&config.endpoint)
            .build()
            .context("failed to build OTLP gRPC metric exporter")?,
        OtlpProtocol::HttpProtobuf => opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .with_endpoint(http_endpoint_for_signal(&config.endpoint, "/v1/metrics"))
            .build()
            .context("failed to build OTLP HTTP+protobuf metric exporter")?,
    };
    let reader = PeriodicReader::builder(exporter)
        .with_interval(config.metrics_interval)
        .build();
    let resource = Resource::builder()
        .with_service_name(config.service_name.clone())
        .build();
    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build();
    global::set_meter_provider(provider.clone());
    register_instruments(&metrics);
    Ok(provider)
}

fn register_instruments(metrics: &Arc<Metrics>) {
    let meter = global::meter("rastreo-server");

    let m = Arc::clone(metrics);
    let _ = meter
        .u64_observable_counter("rastreo_server_scans_total")
        .with_description("POST /scans requests served, partitioned by outcome.")
        .with_callback(move |observer| {
            observer.observe(
                m.scans_total_success.load(Ordering::Relaxed),
                &[KeyValue::new("outcome", "success")],
            );
            observer.observe(
                m.scans_total_error.load(Ordering::Relaxed),
                &[KeyValue::new("outcome", "error")],
            );
            observer.observe(
                m.scans_total_cancelled.load(Ordering::Relaxed),
                &[KeyValue::new("outcome", "cancelled")],
            );
        })
        .build();

    let m = Arc::clone(metrics);
    let _ = meter
        .u64_observable_counter("rastreo_server_probes_total")
        .with_description("Probes executed across all scans, partitioned by outcome.")
        .with_callback(move |observer| {
            let succeeded = m.probes_succeeded_total.load(Ordering::Relaxed);
            let errored = m.probes_errored_total.load(Ordering::Relaxed);
            observer.observe(succeeded, &[KeyValue::new("outcome", "success")]);
            observer.observe(errored, &[KeyValue::new("outcome", "error")]);
        })
        .build();

    let m = Arc::clone(metrics);
    let _ = meter
        .u64_observable_counter("rastreo_server_records_emitted_total")
        .with_description("DeviceRecords emitted across all scans.")
        .with_callback(move |observer| {
            observer.observe(m.records_emitted_total.load(Ordering::Relaxed), &[]);
        })
        .build();

    let m = Arc::clone(metrics);
    let _ = meter
        .u64_observable_counter("rastreo_server_sink_errors_total")
        .with_description("Internal sink errors surfaced via POST /scans.")
        .with_callback(move |observer| {
            observer.observe(m.sink_errors_total.load(Ordering::Relaxed), &[]);
        })
        .build();

    let m = Arc::clone(metrics);
    let _ = meter
        .f64_observable_gauge("rastreo_server_uptime_seconds")
        .with_description("Seconds since rastreo-server started.")
        .with_callback(move |observer| {
            observer.observe(m.started_at.elapsed().as_secs_f64(), &[]);
        })
        .build();

    let version = env!("CARGO_PKG_VERSION");
    let _ = meter
        .u64_observable_gauge("rastreo_server_build_info")
        .with_description(
            "Build info (value is always 1; the version attribute carries the payload).",
        )
        .with_callback(move |observer| {
            observer.observe(1, &[KeyValue::new("version", version)]);
        })
        .build();

    let histogram = meter
        .f64_histogram("rastreo_server_scan_duration_seconds")
        .with_description("Duration of POST /scans request handling.")
        .with_unit("s")
        .build();
    if metrics.attach_otlp_scan_duration(histogram).is_err() {
        tracing::warn!(
            "OTLP scan_duration histogram already attached; leaving prior binding in place"
        );
    }
}

/// Build the metrics exporter when enabled, returning the RAII shutdown guard.
pub fn init_metrics_only(config: &OtlpConfig, metrics: Arc<Metrics>) -> anyhow::Result<OtlpGuard> {
    let mut guard = OtlpGuard::empty();
    if config.metrics_enabled {
        guard.meter = Some(init_metrics(config, metrics)?);
    }
    Ok(guard)
}

/// Attach an already-built `SdkLoggerProvider` to the guard so it shuts down with metrics.
pub fn attach_logger(guard: &mut OtlpGuard, logger: SdkLoggerProvider) {
    guard.logger = Some(logger);
}

#[cfg(test)]
mod tests {
    use super::http_endpoint_for_signal;

    #[test]
    fn http_endpoint_appends_signal_path_to_bare_url() {
        assert_eq!(
            http_endpoint_for_signal("http://collector:4318", "/v1/logs"),
            "http://collector:4318/v1/logs"
        );
        assert_eq!(
            http_endpoint_for_signal("http://collector:4318", "/v1/metrics"),
            "http://collector:4318/v1/metrics"
        );
    }

    #[test]
    fn http_endpoint_strips_trailing_slash_before_appending() {
        assert_eq!(
            http_endpoint_for_signal("http://collector:4318/", "/v1/logs"),
            "http://collector:4318/v1/logs"
        );
    }

    #[test]
    fn http_endpoint_preserves_already_qualified_url() {
        assert_eq!(
            http_endpoint_for_signal("http://collector:4318/v1/logs", "/v1/logs"),
            "http://collector:4318/v1/logs"
        );
        assert_eq!(
            http_endpoint_for_signal("http://collector:4318/v1/logs/", "/v1/logs"),
            "http://collector:4318/v1/logs"
        );
    }
}
