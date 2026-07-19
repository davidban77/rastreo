#![cfg(feature = "otlp")]

use std::sync::Arc;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
use rastreo_core::config::DiscoverScenarioConfig;
use rastreo_core::{run_discovery_with_components, HickoryResolver, MemorySink, Resolver, Sink};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;

fn scenario_with_n_targets(n: u8) -> DiscoverScenarioConfig {
    let targets: Vec<String> = (1..=n)
        .map(|i| format!("{{\"Ip\": \"127.0.0.{i}\"}}"))
        .collect();
    let json = format!(
        r#"{{"timeout_ms": 200, "targets": [{}], "probers": [{{"type": "tcp_connect", "ports": [1]}}]}}"#,
        targets.join(", ")
    );
    serde_json::from_str(&json).expect("scenario deserializes")
}

fn discovery_span_names(n: u8) -> Vec<String> {
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let otel_layer = tracing_opentelemetry::layer()
        .with_tracer(provider.tracer("rastreo-test"))
        .with_filter(Targets::new().with_target("rastreo_core", LevelFilter::INFO));
    let subscriber = tracing_subscriber::registry().with(otel_layer);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let scenario = scenario_with_n_targets(n);
    tracing::subscriber::with_default(subscriber, || {
        rt.block_on(async {
            let resolver: Arc<dyn Resolver> =
                Arc::new(HickoryResolver::from_system().expect("resolver"));
            let sink: Box<dyn Sink> = Box::new(MemorySink::new());
            run_discovery_with_components(&scenario, resolver, sink)
                .await
                .expect("discovery");
        });
    });

    provider.force_flush().expect("force_flush");
    let mut names: Vec<String> = exporter
        .get_finished_spans()
        .expect("finished spans")
        .into_iter()
        .map(|s| s.name.to_string())
        .collect();
    names.sort();
    names
}

#[test]
fn discovery_creates_root_and_one_span_per_stage() {
    let names = discovery_span_names(2);
    assert_eq!(names, vec!["finish", "resolve", "scan", "stream"]);
}

#[test]
fn span_count_is_constant_regardless_of_target_count() {
    // The two runs must genuinely differ in target count, or a regressed generator would make
    // the constant-count assertion below tautological.
    assert_ne!(
        scenario_with_n_targets(2).targets.len(),
        scenario_with_n_targets(20).targets.len(),
        "the two runs must have different target counts for this test to be meaningful"
    );
    let two = discovery_span_names(2);
    let twenty = discovery_span_names(20);
    assert_eq!(
        two.len(),
        4,
        "a scan must create exactly four stage spans, got {two:?}"
    );
    assert_eq!(
        two.len(),
        twenty.len(),
        "span count must not scale with target count: 2-target={two:?} 20-target={twenty:?}"
    );
    assert_eq!(two, twenty);
}
