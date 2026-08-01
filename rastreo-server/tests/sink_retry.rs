#![cfg(feature = "config")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rastreo_core::{HickoryResolver, Resolver};
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
    assert_eq!(body["sink_type"], "file");
    assert_eq!(body["last_probe_error"], serde_json::Value::Null);

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
