use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use rastreo_core::{HickoryResolver, Resolver};
use rastreo_server::build_app;
use rastreo_server::state::{AppState, AuthConfig};
use serde_json::json;

const TOKEN: &str = "test-secret-token";

async fn spawn_server(auth: AuthConfig) -> SocketAddr {
    let resolver: Arc<dyn Resolver> =
        Arc::new(HickoryResolver::from_system().expect("system resolver"));
    let state = AppState::new(resolver).with_auth(auth);
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

fn scan_body(port: u16) -> serde_json::Value {
    json!({
        "targets": [{"Ip": "127.0.0.1"}],
        "probers": [{"type": "tcp_connect", "ports": [port]}],
        "timeout_ms": 500,
    })
}

fn enabled() -> AuthConfig {
    AuthConfig::Enabled {
        token: TOKEN.to_string(),
    }
}

#[tokio::test]
async fn post_scans_without_authorization_header_returns_401() {
    let addr = spawn_server(enabled()).await;
    let target_port = spawn_target_listener().await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/scans"))
        .json(&scan_body(target_port))
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let www = resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = resp.text().await.expect("body");
    assert_eq!(www.as_deref(), Some("Bearer"));
    assert!(
        !body.contains(TOKEN),
        "body must not echo the token: {body}"
    );
    let value: serde_json::Value = serde_json::from_str(&body).expect("json body");
    assert_eq!(value["error"], "missing or invalid bearer token");
}

#[tokio::test]
async fn post_scans_dry_run_without_authorization_header_returns_401() {
    let addr = spawn_server(enabled()).await;
    let target_port = spawn_target_listener().await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/scans?dry_run=true"))
        .json(&scan_body(target_port))
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let value: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(value["error"], "missing or invalid bearer token");
    assert!(
        value.get("scenario").is_none(),
        "an unauthenticated dry-run must not return a plan"
    );
}

#[tokio::test]
async fn post_scans_with_basic_auth_scheme_returns_401() {
    let addr = spawn_server(enabled()).await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/scans"))
        .header("authorization", "Basic dXNlcjpwYXNz")
        .json(&scan_body(9))
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn post_scans_with_wrong_bearer_token_returns_401_and_never_runs() {
    let addr = spawn_server(enabled()).await;
    let target_port = spawn_target_listener().await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/scans"))
        .header("authorization", "Bearer wrong-token")
        .json(&scan_body(target_port))
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let body = resp.text().await.expect("body");
    assert!(
        !body.contains("wrong-token"),
        "must not echo presented token"
    );
    assert!(!body.contains(TOKEN), "must not echo expected token");
    let value: serde_json::Value = serde_json::from_str(&body).expect("json body");
    assert!(
        value.get("records").is_none(),
        "rejected request must not run a scan"
    );
    assert!(
        value.get("summary").is_none(),
        "rejected request must not run a scan"
    );
}

#[tokio::test]
async fn post_scans_with_valid_bearer_token_runs_the_scan() {
    let addr = spawn_server(enabled()).await;
    let target_port = spawn_target_listener().await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/scans"))
        .header("authorization", format!("Bearer {TOKEN}"))
        .json(&scan_body(target_port))
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let payload: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(payload["summary"]["records_emitted"], 1);
    assert_eq!(payload["records"].as_array().map(|a| a.len()), Some(1));
}

#[tokio::test]
async fn health_readyz_metrics_are_open_when_auth_enabled() {
    let addr = spawn_server(enabled()).await;
    let client = reqwest::Client::new();
    for path in ["/health", "/healthz", "/readyz", "/metrics"] {
        let resp = client
            .get(format!("http://{addr}{path}"))
            .send()
            .await
            .expect("send");
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::OK,
            "{path} must not require a bearer token"
        );
    }
}

#[tokio::test]
async fn post_scans_passes_through_when_auth_disabled() {
    let addr = spawn_server(AuthConfig::Disabled).await;
    let target_port = spawn_target_listener().await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/scans"))
        .json(&scan_body(target_port))
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let payload: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(payload["summary"]["records_emitted"], 1);
}
