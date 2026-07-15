//! OpenTelemetry OTLP metric exporters and instrument callbacks. The shared logs/tracing
//! bootstrap and RAII shutdown guard live in `rastreo_core::observability::otlp`.

#![cfg(feature = "otlp")]

use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Context;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::Resource;
use rastreo_core::observability::otlp::attach_meter;
use rastreo_core::observability::otlp_config::http_endpoint_for_signal;
use rastreo_core::{ProbeKind, SinkErrorClass, SinkType};

pub use rastreo_core::observability::otlp::OtlpGuard;

use crate::state::{Metrics, OtlpConfig, OtlpProtocol, SinkReachability};

/// Wire up OTLP metrics (observable counters + gauges + a synchronously recorded histogram) against the running `Metrics`.
pub fn init_metrics(
    config: &OtlpConfig,
    metrics: Arc<Metrics>,
    sink_reachability: Arc<SinkReachability>,
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
        _ => anyhow::bail!("unsupported OTLP protocol variant: {:?}", config.protocol),
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
    register_sink_reachability_instruments(&metrics, &sink_reachability);
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
        .with_description(
            "Probes executed across all scans, partitioned by outcome and probe kind.",
        )
        .with_callback(move |observer| {
            for kind in ProbeKind::all() {
                let idx = kind.index();
                let label = kind.label();
                let succeeded = m.probes.succeeded[idx].load(Ordering::Relaxed);
                let errored = m.probes.errored[idx].load(Ordering::Relaxed);
                observer.observe(
                    succeeded,
                    &[
                        KeyValue::new("outcome", "success"),
                        KeyValue::new("probe_kind", label),
                    ],
                );
                observer.observe(
                    errored,
                    &[
                        KeyValue::new("outcome", "error"),
                        KeyValue::new("probe_kind", label),
                    ],
                );
            }
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
        .with_description(
            "Internal sink errors surfaced via POST /scans, partitioned by error class.",
        )
        .with_callback(move |observer| {
            for class in SinkErrorClass::all() {
                let value = m.sink_errors[class.index()].load(Ordering::Relaxed);
                observer.observe(value, &[KeyValue::new("error_class", class.as_label())]);
            }
        })
        .build();

    let m = Arc::clone(metrics);
    let _ = meter
        .u64_observable_counter("rastreo_server_dlq_records_total")
        .with_description(
            "Records delivered to a dead-letter destination, partitioned by sink type and error class.",
        )
        .with_callback(move |observer| {
            let sinks = [(SinkType::Kafka, &m.dlq.kafka), (SinkType::Nats, &m.dlq.nats)];
            for (sink, bucket) in sinks {
                for class in SinkErrorClass::all() {
                    let value = bucket[class.index()].load(Ordering::Relaxed);
                    observer.observe(
                        value,
                        &[
                            KeyValue::new("sink_type", sink.as_label()),
                            KeyValue::new("error_class", class.as_label()),
                        ],
                    );
                }
            }
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

fn register_sink_reachability_instruments(
    metrics: &Arc<Metrics>,
    reachability: &Arc<SinkReachability>,
) {
    let Some(sink_label) = reachability.sink_type_label() else {
        return;
    };
    let meter = global::meter("rastreo-server");

    let m = Arc::clone(metrics);
    let _ = meter
        .u64_observable_counter("rastreo_server_sink_reachability_probe_total")
        .with_description(
            "Server-side sink reachability probes, partitioned by outcome and sink type.",
        )
        .with_callback(move |observer| {
            observer.observe(
                m.sink_probe_success.load(Ordering::Relaxed),
                &[
                    KeyValue::new("outcome", "success"),
                    KeyValue::new("sink_type", sink_label),
                ],
            );
            observer.observe(
                m.sink_probe_failure.load(Ordering::Relaxed),
                &[
                    KeyValue::new("outcome", "failure"),
                    KeyValue::new("sink_type", sink_label),
                ],
            );
        })
        .build();

    let r = Arc::clone(reachability);
    let _ = meter
        .u64_observable_gauge("rastreo_server_sink_reachable")
        .with_description("1 when the last sink probe succeeded, 0 otherwise.")
        .with_callback(move |observer| {
            let value: u64 = if r.reachable.load(Ordering::Relaxed) {
                1
            } else {
                0
            };
            observer.observe(value, &[KeyValue::new("sink_type", sink_label)]);
        })
        .build();
}

/// Build the metrics exporter when enabled, returning the RAII shutdown guard.
pub fn init_metrics_only(
    config: &OtlpConfig,
    metrics: Arc<Metrics>,
    sink_reachability: Arc<SinkReachability>,
) -> anyhow::Result<OtlpGuard> {
    let mut guard = OtlpGuard::empty();
    if config.metrics_enabled {
        attach_meter(
            &mut guard,
            init_metrics(config, metrics, sink_reachability)?,
        );
    }
    Ok(guard)
}
