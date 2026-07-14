use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use ipnet::IpNet;
use rastreo_core::{GuardedResolver, HickoryResolver, Resolver};
use rastreo_server::build_app;
use rastreo_server::state::AppState;
use serde_json::json;

async fn spawn_guarded_server(allowlist: Option<Vec<IpNet>>, max_body_bytes: usize) -> SocketAddr {
    let base: Arc<dyn Resolver> =
        Arc::new(HickoryResolver::from_system().expect("system resolver"));
    let resolver: Arc<dyn Resolver> = Arc::new(GuardedResolver::new(base, allowlist, None));
    let state = AppState::new(resolver).with_body_limit(max_body_bytes);
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

fn net(s: &str) -> IpNet {
    s.parse().expect("cidr")
}

#[tokio::test]
async fn post_scans_out_of_allowlist_target_returns_403_and_probes_nothing() {
    let addr = spawn_guarded_server(Some(vec![net("10.0.0.0/8")]), 1_048_576).await;
    let target_port = spawn_target_listener().await;

    let body = json!({
        "targets": [{"Ip": "127.0.0.1"}],
        "probers": [{"type": "tcp_connect", "ports": [target_port]}],
        "timeout_ms": 500,
    });

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/scans"))
        .json(&body)
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
    let payload: serde_json::Value = resp.json().await.expect("body json");
    assert!(
        payload["error"]
            .as_str()
            .map(|s| s.contains("127.0.0.1") && s.contains("allow-list"))
            .unwrap_or(false),
        "403 body must name the offending IP and the allow-list, got {payload}"
    );
    assert!(
        payload.get("records").is_none(),
        "a rejected request must not run a scan: {payload}"
    );
    assert!(payload.get("summary").is_none());
}

#[tokio::test]
async fn post_scans_dry_run_out_of_allowlist_target_surfaces_per_target_error() {
    let addr = spawn_guarded_server(Some(vec![net("10.0.0.0/8")]), 1_048_576).await;

    let body = json!({
        "targets": [{"Ip": "127.0.0.1"}],
        "probers": [{"type": "tcp_connect", "ports": [22]}],
        "timeout_ms": 500,
    });

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/scans?dry_run=true"))
        .json(&body)
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let payload: serde_json::Value = resp.json().await.expect("body json");
    let err = payload["targets"][0]["resolution"]["error"]
        .as_str()
        .expect("out-of-allow-list target surfaces as a per-target error");
    assert!(
        err.contains("127.0.0.1"),
        "the plan names the rejected target: {payload}"
    );
    assert_eq!(
        payload["total_probes"], 0,
        "an all-error plan probes nothing: {payload}"
    );
    assert!(
        payload.get("records").is_none(),
        "a dry-run returns a plan, not a scan response: {payload}"
    );
}

#[tokio::test]
async fn post_scans_in_allowlist_target_scans_normally() {
    let addr = spawn_guarded_server(Some(vec![net("127.0.0.0/8")]), 1_048_576).await;
    let target_port = spawn_target_listener().await;

    let body = json!({
        "targets": [{"Ip": "127.0.0.1"}],
        "probers": [{"type": "tcp_connect", "ports": [target_port]}],
        "timeout_ms": 500,
    });

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/scans"))
        .json(&body)
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let payload: serde_json::Value = resp.json().await.expect("body json");
    assert_eq!(payload["summary"]["records_emitted"], 1);
    assert_eq!(payload["records"].as_array().map(|a| a.len()), Some(1));
    assert_eq!(payload["records"][0]["mgmt_ip"], "127.0.0.1");
}

#[tokio::test]
async fn post_scans_over_body_limit_is_rejected_before_the_handler_runs() {
    let addr = spawn_guarded_server(None, 256).await;

    let oversized = "x".repeat(2048);
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/scans"))
        .header("content-type", "application/json")
        .body(oversized)
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
}
