//! OpenTelemetry OTLP metric exporters and instrument callbacks. The shared logs/tracing
//! bootstrap and RAII shutdown guard live in `rastreo_core::observability::otlp`.

#![cfg(feature = "otlp")]

use std::sync::Arc;

use anyhow::Context;
use opentelemetry::metrics::Meter;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::Resource;
use rastreo_core::observability::otlp::attach_meter;
use rastreo_core::observability::otlp_config::http_endpoint_for_signal;

pub use rastreo_core::observability::otlp::OtlpGuard;

use crate::metrics_defs::{self, Label, MetricContext, MetricDescriptor, MetricKind, MetricValue};
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
    register_instruments(&metrics, &sink_reachability);
    Ok(provider)
}

fn register_instruments(metrics: &Arc<Metrics>, reachability: &Arc<SinkReachability>) {
    let meter = global::meter("rastreo-server");
    register_observables(&meter, metrics, reachability);

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

fn register_observables(
    meter: &Meter,
    metrics: &Arc<Metrics>,
    reachability: &Arc<SinkReachability>,
) {
    for desc in metrics_defs::descriptors() {
        // Sink config is fixed at startup, so a reader that emits nothing now (a conditional
        // series with no sink) never would — skip its instrument entirely to match /metrics.
        if !reader_emits_sample(desc, metrics, reachability) {
            continue;
        }
        register_observable(meter, desc, metrics, reachability);
    }
}

fn reader_emits_sample(
    desc: &MetricDescriptor,
    metrics: &Arc<Metrics>,
    reachability: &Arc<SinkReachability>,
) -> bool {
    let ctx = MetricContext {
        metrics: metrics.as_ref(),
        reachability: reachability.as_ref(),
    };
    let mut any = false;
    (desc.read)(&ctx, &mut |_, _| any = true);
    any
}

fn register_observable(
    meter: &Meter,
    desc: &MetricDescriptor,
    metrics: &Arc<Metrics>,
    reachability: &Arc<SinkReachability>,
) {
    let read = desc.read;
    let m = Arc::clone(metrics);
    let r = Arc::clone(reachability);
    match desc.kind {
        MetricKind::CounterU64 => {
            let _ = meter
                .u64_observable_counter(desc.name)
                .with_description(desc.help)
                .with_callback(move |observer| {
                    let ctx = MetricContext {
                        metrics: m.as_ref(),
                        reachability: r.as_ref(),
                    };
                    read(&ctx, &mut |labels, value| {
                        if let MetricValue::U64(n) = value {
                            observer.observe(n, &key_values(labels));
                        }
                    });
                })
                .build();
        }
        MetricKind::GaugeU64 => {
            let _ = meter
                .u64_observable_gauge(desc.name)
                .with_description(desc.help)
                .with_callback(move |observer| {
                    let ctx = MetricContext {
                        metrics: m.as_ref(),
                        reachability: r.as_ref(),
                    };
                    read(&ctx, &mut |labels, value| {
                        if let MetricValue::U64(n) = value {
                            observer.observe(n, &key_values(labels));
                        }
                    });
                })
                .build();
        }
        MetricKind::GaugeF64 => {
            let _ = meter
                .f64_observable_gauge(desc.name)
                .with_description(desc.help)
                .with_callback(move |observer| {
                    let ctx = MetricContext {
                        metrics: m.as_ref(),
                        reachability: r.as_ref(),
                    };
                    read(&ctx, &mut |labels, value| {
                        if let MetricValue::F64(x) = value {
                            observer.observe(x, &key_values(labels));
                        }
                    });
                })
                .build();
        }
    }
}

fn key_values(labels: &[Label]) -> Vec<KeyValue> {
    labels.iter().map(|&(k, v)| KeyValue::new(k, v)).collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::time::Duration;

    use opentelemetry::metrics::MeterProvider;
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
    use rastreo_core::SinkType;

    #[test]
    fn otlp_instrument_descriptions_come_from_the_descriptor_table() {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("rastreo-server-test");

        let metrics = Arc::new(Metrics::new());
        let reachability = Arc::new(SinkReachability::configured(
            SinkType::Kafka,
            Duration::from_secs(10),
            Duration::from_secs(5),
        ));
        register_observables(&meter, &metrics, &reachability);

        provider.force_flush().expect("force_flush");
        let exported = exporter.get_finished_metrics().expect("finished metrics");

        let mut descriptions: HashMap<String, String> = HashMap::new();
        for rm in &exported {
            for scope in rm.scope_metrics() {
                for metric in scope.metrics() {
                    descriptions
                        .insert(metric.name().to_string(), metric.description().to_string());
                }
            }
        }

        for desc in metrics_defs::descriptors() {
            let actual = descriptions.get(desc.name).unwrap_or_else(|| {
                panic!(
                    "descriptor {} was not registered as an OTLP instrument",
                    desc.name
                )
            });
            assert_eq!(
                actual, desc.help,
                "OTLP description for {} must equal the descriptor help",
                desc.name
            );
        }
        provider.shutdown().expect("shutdown");
    }
}
