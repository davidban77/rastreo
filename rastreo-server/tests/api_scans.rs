use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use rastreo_core::{HickoryResolver, Resolver};
use rastreo_server::build_app;
use rastreo_server::state::AppState;
use serde_json::json;

async fn spawn_server() -> SocketAddr {
    let resolver: Arc<dyn Resolver> =
        Arc::new(HickoryResolver::from_system().expect("system resolver"));
    let state = AppState::new(resolver);
    let app = build_app(state);

    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind server");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    addr
}

async fn spawn_target_listener() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind target");
    let port = listener.local_addr().expect("local_addr").port();
    tokio::spawn(async move {
        loop {
            if listener.accept().await.is_err() {
                return;
            }
        }
    });
    port
}

#[tokio::test]
async fn post_scans_returns_summary_and_records_for_open_loopback_port() {
    let server_addr = spawn_server().await;
    let target_port = spawn_target_listener().await;

    let body = json!({
        "name": "integration-scan",
        "timeout_ms": 500,
        "targets": [{"Ip": "127.0.0.1"}],
        "probers": [{"type": "tcp_connect", "ports": [target_port]}],
    });

    let client = reqwest::Client::new();
    let url = format!("http://{server_addr}/scans");
    let resp = client.post(&url).json(&body).send().await.expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let payload: serde_json::Value = resp.json().await.expect("body json");
    assert_eq!(payload["summary"]["records_emitted"], 1);
    assert!(
        payload["summary"]["elapsed_ms"].is_number(),
        "elapsed_ms must be present, got {payload}"
    );
    let records = payload["records"].as_array().expect("records array");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["mgmt_ip"], "127.0.0.1");
}

#[tokio::test]
async fn post_scans_with_malformed_json_returns_400() {
    let server_addr = spawn_server().await;
    let url = format!("http://{server_addr}/scans");
    let resp = reqwest::Client::new()
        .post(&url)
        .header("content-type", "application/json")
        .body("{not-json}")
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_scans_with_empty_targets_returns_400() {
    let server_addr = spawn_server().await;
    let url = format!("http://{server_addr}/scans");
    let body = json!({
        "targets": [],
        "probers": [{"type": "tcp_connect", "ports": [22]}],
    });
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&body)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let payload: serde_json::Value = resp.json().await.expect("body json");
    assert!(
        payload["error"]
            .as_str()
            .map(|s| s.contains("targets"))
            .unwrap_or(false),
        "error must mention targets, got {payload}"
    );
}

#[tokio::test]
async fn get_health_returns_200() {
    let server_addr = spawn_server().await;
    let url = format!("http://{server_addr}/health");
    let resp = reqwest::Client::new().get(&url).send().await.expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let payload: serde_json::Value = resp.json().await.expect("body json");
    assert_eq!(payload["status"], "ok");
}
