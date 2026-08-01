#![cfg(feature = "config")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rastreo_core::{HickoryResolver, Resolver};
use rastreo_server::routes::health::probe_stale_after_secs;
use rastreo_server::state::{AppState, SinkProbeConfig};
use rastreo_server::{build_app, spawn_sink_probe};
use serde_json::json;

fn resolver() -> Arc<dyn Resolver> {
    Arc::new(HickoryResolver::from_system().expect("system resolver"))
}

async fn serve(state: AppState) -> SocketAddr {
    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind server");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, build_app(state))
            .await
            .expect("serve");
    });
    addr
}

async fn open_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind target");
    let port = listener.local_addr().expect("local_addr").port();
    tokio::spawn(async move { while listener.accept().await.is_ok() {} });
    port
}

async fn readyz(addr: SocketAddr) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = reqwest::get(format!("http://{addr}/readyz"))
        .await
        .expect("send readyz");
    let status = resp.status();
    (status, resp.json().await.expect("readyz body"))
}

async fn metric_value(addr: SocketAddr, series: &str) -> Option<u64> {
    let body = reqwest::get(format!("http://{addr}/metrics"))
        .await
        .expect("send metrics")
        .text()
        .await
        .expect("metrics body");
    body.lines()
        .find_map(|line| line.strip_prefix(series)?.trim().parse().ok())
}

async fn wait_until(label: &str, mut condition: impl FnMut() -> bool) {
    let waited = tokio::time::timeout(Duration::from_secs(10), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(waited.is_ok(), "timed out waiting for {label}");
}

#[tokio::test]
async fn a_sink_configured_after_startup_serves_readyz_and_the_next_scan() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink_config = dir.path().join("sink.yaml");
    let records = dir.path().join("records.ndjson");

    let config = SinkProbeConfig {
        config_path: Some(sink_config.clone()),
        probe_interval: Duration::from_millis(50),
        probe_timeout: Duration::from_secs(5),
    };
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let (state, _probe_task) =
        spawn_sink_probe(AppState::new(resolver()), &config, shutdown_rx).await;
    let addr = serve(state.clone()).await;

    let (status, body) = readyz(addr).await;
    assert_eq!(status, reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "sink_unreachable");
    assert_eq!(body["sink_type"], "unknown");
    assert_eq!(body["sink_attached"], false);

    tokio::fs::write(
        &sink_config,
        format!("type: file\npath: {}\n", records.display()),
    )
    .await
    .expect("write sink config");

    let attached = state.clone();
    wait_until("the sink to attach", move || attached.sink().is_some()).await;
    wait_until("readyz to report reachable", || {
        state
            .sink_reachability
            .reachable
            .load(std::sync::atomic::Ordering::Relaxed)
    })
    .await;

    let (status, body) = readyz(addr).await;
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["sink_reachable"], true);
    assert_eq!(body["sink_attached"], true);
    assert_eq!(body["sink_type"], "file");
    assert_eq!(body["last_probe_error"], serde_json::Value::Null);
    assert!(body["seconds_since_last_probe_tick"].is_number());

    let port = open_port().await;
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/scans"))
        .json(&json!({
            "name": "retry-attached-sink",
            "timeout_ms": 500,
            "targets": [{"Ip": "127.0.0.1"}],
            "probers": [{"type": "tcp_connect", "ports": [port]}],
        }))
        .send()
        .await
        .expect("send scan");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let payload: serde_json::Value = resp.json().await.expect("scan body");
    assert_eq!(payload["summary"]["records_emitted"], 1);

    let written = tokio::fs::read_to_string(&records)
        .await
        .expect("sink file written");
    let lines: Vec<&str> = written.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "the scan must reach the sink that attached on a retry, got: {written:?}"
    );
    assert!(lines[0].contains("127.0.0.1"), "record was: {}", lines[0]);
}

#[tokio::test]
async fn a_sink_operation_outlasting_the_probe_timeout_ages_the_result_but_keeps_the_pod_ready() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink_config = dir.path().join("sink.yaml");
    tokio::fs::write(&sink_config, "type: stdout\n")
        .await
        .expect("write sink config");

    let config = SinkProbeConfig {
        config_path: Some(sink_config),
        probe_interval: Duration::from_millis(50),
        probe_timeout: Duration::from_millis(50),
    };
    let stale_after = probe_stale_after_secs(config.probe_interval, config.probe_timeout);
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let (state, _probe_task) =
        spawn_sink_probe(AppState::new(resolver()), &config, shutdown_rx).await;
    let addr = serve(state.clone()).await;

    // Stands in for a single broker round-trip, flush, or close that runs longer than one probe.
    let sink = state.sink().expect("sink attached at startup");
    let guard = sink.lock().await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let body = loop {
        let (status, body) = readyz(addr).await;
        assert_eq!(
            status,
            reqwest::StatusCode::OK,
            "a sink operation outlasting the probe must not take the pod out of service: {body}"
        );
        let probe_age = body["seconds_since_last_probe"]
            .as_f64()
            .expect("probe age is a number");
        if probe_age > stale_after {
            break body;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the skipped probes never aged the result past the {stale_after}s window: {body}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let ticks = metric_value(
        addr,
        "rastreo_server_sink_probe_ticks_total{sink_type=\"stdout\"}",
    )
    .await
    .expect("tick counter");
    let probes = metric_value(
        addr,
        "rastreo_server_sink_reachability_probe_total{outcome=\"success\",sink_type=\"stdout\"}",
    )
    .await
    .expect("probe success counter")
        + metric_value(
            addr,
            "rastreo_server_sink_reachability_probe_total{outcome=\"failure\",sink_type=\"stdout\"}",
        )
        .await
        .expect("probe failure counter");
    drop(guard);

    let tick_age = body["seconds_since_last_probe_tick"]
        .as_f64()
        .expect("tick age is a number");
    assert!(
        tick_age < stale_after,
        "the task kept ticking through the skipped probes: tick {tick_age}s vs window {stale_after}s",
    );
    assert!(
        ticks > probes,
        "skipped probes must be countable off /metrics: {ticks} cycles vs {probes} probe results",
    );
}
