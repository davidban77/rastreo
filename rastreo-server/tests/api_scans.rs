use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use rastreo_core::{
    HickoryResolver, MemorySink, RastreoError, Resolver, Sink, SinkError, SinkErrorClass, SinkType,
};
use rastreo_server::build_app;
use rastreo_server::state::{AppState, AuthConfig, SharedSink, SinkReachability};
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

const TOKEN: &str = "scan-detail-token";
const SINK_DETAIL: &str = "authorization violation: nats: authorization violation";

struct FailingSink;

#[async_trait::async_trait]
impl Sink for FailingSink {
    async fn write(&mut self, _data: &[u8]) -> Result<(), RastreoError> {
        Err(RastreoError::Sink(SinkError::new(
            SinkErrorClass::PublishFailure,
            std::io::Error::other(SINK_DETAIL),
        )))
    }
    async fn flush(&mut self) -> Result<(), RastreoError> {
        Ok(())
    }
    fn last_write_delivered(&self) -> bool {
        true
    }
    fn kind(&self) -> SinkType {
        SinkType::Memory
    }
}

async fn spawn_server_whose_sink_fails(auth: AuthConfig) -> SocketAddr {
    let resolver: Arc<dyn Resolver> =
        Arc::new(HickoryResolver::from_system().expect("system resolver"));
    let shared: SharedSink = Arc::new(tokio::sync::Mutex::new(
        Box::new(FailingSink) as Box<dyn Sink>
    ));
    let reach = Arc::new(SinkReachability::configured(
        SinkType::Memory,
        std::time::Duration::from_secs(10),
        std::time::Duration::from_secs(5),
    ));
    reach.record_success();
    let state = AppState::new(resolver)
        .with_auth(auth)
        .with_sink(Some(shared), reach);
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

fn enabled_auth() -> AuthConfig {
    AuthConfig::Enabled {
        token: TOKEN.to_string(),
    }
}

async fn scan_body_hitting_an_open_port() -> serde_json::Value {
    let target_port = spawn_target_listener().await;
    json!({
        "name": "failing-sink-scan",
        "timeout_ms": 500,
        "targets": [{"Ip": "127.0.0.1"}],
        "probers": [{"type": "tcp_connect", "ports": [target_port]}],
    })
}

#[tokio::test]
async fn post_scans_500_carries_the_error_detail_for_an_authenticated_caller() {
    let addr = spawn_server_whose_sink_fails(enabled_auth()).await;
    let body = scan_body_hitting_an_open_port().await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/scans"))
        .header("authorization", format!("Bearer {TOKEN}"))
        .json(&body)
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    let payload: serde_json::Value = resp.json().await.expect("body json");
    let message = payload["error"].as_str().expect("error string");
    assert!(
        message.contains(SINK_DETAIL),
        "an authenticated caller must be told what failed, got {message:?}"
    );
}

#[tokio::test]
async fn post_scans_500_is_redacted_when_auth_is_disabled() {
    let addr = spawn_server_whose_sink_fails(AuthConfig::Disabled).await;
    let body = scan_body_hitting_an_open_port().await;

    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/scans"))
        .json(&body)
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    let payload: serde_json::Value = resp.json().await.expect("body json");
    assert_eq!(payload["error"], "internal server error");
    assert!(
        !payload.to_string().contains("authorization violation"),
        "an unauthenticated endpoint must not disclose the failure: {payload}"
    );
}

#[tokio::test]
async fn post_scans_400_body_is_unchanged_for_an_authenticated_caller() {
    let addr = spawn_server_whose_sink_fails(enabled_auth()).await;
    let client = reqwest::Client::new();

    let unparsable = json!({
        "targets": [{"Ip": "127.0.0.1"}],
        "probers": [{"type": "carrier_pigeon"}],
    });
    let resp = client
        .post(format!("http://{addr}/scans"))
        .header("authorization", format!("Bearer {TOKEN}"))
        .json(&unparsable)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let payload: serde_json::Value = resp.json().await.expect("body json");
    let message = payload["error"].as_str().expect("error string");
    assert!(
        message.contains("carrier_pigeon"),
        "a 4xx already carried its full message, got {message:?}"
    );

    let empty_targets = json!({
        "targets": [],
        "probers": [{"type": "tcp_connect", "ports": [22]}],
    });
    let resp = client
        .post(format!("http://{addr}/scans"))
        .header("authorization", format!("Bearer {TOKEN}"))
        .json(&empty_targets)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let payload: serde_json::Value = resp.json().await.expect("body json");
    assert_eq!(payload["error"], "scenario.targets must not be empty");
}

#[tokio::test]
async fn readyz_stays_open_and_unchanged_on_a_server_that_discloses_scan_errors() {
    let addr = spawn_server_whose_sink_fails(enabled_auth()).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/readyz"))
        .send()
        .await
        .expect("send");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let payload: serde_json::Value = resp.json().await.expect("body json");
    assert_eq!(payload["status"], "ready");
    assert_eq!(payload["sink_reachable"], true);
    assert!(payload["last_probe_error"].is_null());
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
async fn post_scans_dry_run_returns_plan_and_writes_no_records_to_server_sink() {
    let resolver: Arc<dyn Resolver> =
        Arc::new(HickoryResolver::from_system().expect("system resolver"));
    let server_sink = MemorySink::new();
    let server_handle = server_sink.handle();
    let boxed: Box<dyn Sink> = Box::new(server_sink);
    let shared: SharedSink = Arc::new(tokio::sync::Mutex::new(boxed));
    let reach = Arc::new(SinkReachability::configured(
        SinkType::Memory,
        std::time::Duration::from_secs(10),
        std::time::Duration::from_secs(5),
    ));
    reach.record_success();
    let state = AppState::new(resolver).with_sink(Some(Arc::clone(&shared)), reach);
    let app = build_app(state);

    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind server");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let target_port = spawn_target_listener().await;
    let body = json!({
        "name": "dry-run-scan",
        "timeout_ms": 500,
        "targets": [{"Ip": "127.0.0.1"}],
        "probers": [{"type": "tcp_connect", "ports": [target_port]}],
    });

    let url = format!("http://{addr}/scans?dry_run=true");
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&body)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let payload: serde_json::Value = resp.json().await.expect("body json");
    assert_eq!(payload["scenario"], "dry-run-scan");
    assert!(
        payload["total_probes"].is_number(),
        "plan carries total_probes: {payload}"
    );
    assert_eq!(
        payload["targets"][0]["resolution"]["resolved"][0],
        "127.0.0.1"
    );
    assert!(
        payload.get("records").is_none() && payload.get("summary").is_none(),
        "a dry-run returns a plan, not a scan response: {payload}"
    );

    assert!(
        server_handle.ndjson_lines().is_empty(),
        "a dry-run must not probe or write the server-configured sink"
    );
}

#[tokio::test]
async fn post_scans_dry_run_with_empty_targets_returns_400() {
    let server_addr = spawn_server().await;
    let url = format!("http://{server_addr}/scans?dry_run=true");
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

fn bad_fuser_body() -> serde_json::Value {
    json!({
        "name": "bad-fuser-scenario",
        "targets": [{"Ip": "127.0.0.1"}],
        "probers": [{"type": "tcp_connect", "ports": [22222]}],
        "fuser": {"type": "direct", "confidence_baseline": 2.0},
    })
}

async fn post_scenario(
    server_addr: SocketAddr,
    query: &str,
    body: &serde_json::Value,
) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("http://{server_addr}/scans{query}"))
        .json(body)
        .send()
        .await
        .expect("send")
}

#[tokio::test]
async fn post_scans_dry_run_with_an_invalid_fuser_returns_400() {
    let server_addr = spawn_server().await;
    let resp = post_scenario(server_addr, "?dry_run=true", &bad_fuser_body()).await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let payload: serde_json::Value = resp.json().await.expect("body json");
    assert!(
        payload["error"]
            .as_str()
            .is_some_and(|s| s.contains("confidence_baseline")),
        "error must name the invalid knob, got {payload}"
    );
}

#[tokio::test]
async fn post_scans_answers_a_dry_run_and_a_scan_alike_for_an_invalid_scenario() {
    let server_addr = spawn_server().await;
    let body = bad_fuser_body();
    let dry_run = post_scenario(server_addr, "?dry_run=true", &body).await;
    let scan = post_scenario(server_addr, "", &body).await;
    assert_eq!(dry_run.status(), scan.status());
    assert_eq!(scan.status(), reqwest::StatusCode::BAD_REQUEST);
}

fn uncompilable_classifier_body() -> serde_json::Value {
    json!({
        "name": "bad-classifier-scenario",
        "targets": [{"Ip": "127.0.0.1"}],
        "probers": [{"type": "tcp_connect", "ports": [22222]}],
        "classifier": {
            "type": "rules",
            "platform_rules": [
                {"signal": "ssh_banner", "pattern": "([unclosed", "platform": "broken"}
            ],
        },
    })
}

async fn assert_uncompilable_classifier_is_a_400(query: &str) {
    let server_addr = spawn_server().await;
    let resp = post_scenario(server_addr, query, &uncompilable_classifier_body()).await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let payload: serde_json::Value = resp.json().await.expect("body json");
    assert!(
        payload["error"]
            .as_str()
            .is_some_and(|s| s.contains("([unclosed")),
        "error must name the pattern the caller sent, got {payload}"
    );
}

#[tokio::test]
async fn post_scans_with_an_uncompilable_classifier_rule_returns_400() {
    assert_uncompilable_classifier_is_a_400("").await;
}

#[tokio::test]
async fn post_scans_dry_run_with_an_uncompilable_classifier_rule_returns_400() {
    assert_uncompilable_classifier_is_a_400("?dry_run=true").await;
}

#[tokio::test]
async fn post_scans_dry_run_with_a_retired_field_returns_400() {
    let server_addr = spawn_server().await;
    let body = json!({
        "rate_limit": 50,
        "targets": [{"Ip": "127.0.0.1"}],
        "probers": [{"type": "tcp_connect", "ports": [22]}],
    });
    let resp = post_scenario(server_addr, "?dry_run=true", &body).await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let payload: serde_json::Value = resp.json().await.expect("body json");
    assert!(
        payload["error"]
            .as_str()
            .is_some_and(|s| s.contains("rate_limit")),
        "error must name the retired field, got {payload}"
    );
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

#[tokio::test]
async fn get_healthz_returns_200_ok() {
    let server_addr = spawn_server().await;
    let url = format!("http://{server_addr}/healthz");
    let resp = reqwest::Client::new().get(&url).send().await.expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let payload: serde_json::Value = resp.json().await.expect("body json");
    assert_eq!(payload["status"], "ok");
}

#[tokio::test]
async fn get_readyz_returns_200_ready_on_fresh_server() {
    let server_addr = spawn_server().await;
    let url = format!("http://{server_addr}/readyz");
    let resp = reqwest::Client::new().get(&url).send().await.expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let payload: serde_json::Value = resp.json().await.expect("body json");
    assert_eq!(payload["status"], "ready");
    assert_eq!(payload["inflight_scans"], 0);
    assert!(payload["seconds_since_sink_error"].is_null());
    assert!(payload["seconds_since_scan_error"].is_null());
}

#[tokio::test]
async fn get_readyz_reflects_inflight_counter_during_scan() {
    use rastreo_server::state::ReadinessConfig;

    let resolver: Arc<dyn Resolver> =
        Arc::new(HickoryResolver::from_system().expect("system resolver"));
    let cfg = ReadinessConfig {
        max_inflight_scans: 1,
        sink_error_quarantine: std::time::Duration::from_secs(30),
        scan_error_quarantine: std::time::Duration::from_secs(30),
    };
    let state = AppState::with_readiness(resolver, cfg);
    let app = rastreo_server::build_app(state.clone());

    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind server");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let target_port = spawn_target_listener().await;
    let body = json!({
        "targets": [{"Ip": "127.0.0.1"}],
        "probers": [{"type": "tcp_connect", "ports": [target_port]}],
        "timeout_ms": 500,
    });

    let readyz_url = format!("http://{addr}/readyz");
    let scans_url = format!("http://{addr}/scans");

    let scan_client = reqwest::Client::new();
    let scan_fut = scan_client.post(&scans_url).json(&body).send();

    // Poll /readyz while the scan is inflight — expect at least one probe to see
    // inflight_scans == 1 → 503 with reason. Bounded so a fast scan never hangs the test.
    let probe = async {
        let client = reqwest::Client::new();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            let resp = client.get(&readyz_url).send().await.expect("readyz send");
            let status = resp.status();
            let payload: serde_json::Value = resp.json().await.expect("readyz json");
            if status == reqwest::StatusCode::SERVICE_UNAVAILABLE {
                assert_eq!(payload["reason"], "inflight_scan_limit_exceeded");
                assert_eq!(payload["inflight_scans"], 1);
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        false
    };

    let (scan_resp, saw_inflight) = tokio::join!(scan_fut, probe);
    let scan_resp = scan_resp.expect("scan send");
    assert_eq!(scan_resp.status(), reqwest::StatusCode::OK);
    assert!(
        saw_inflight,
        "/readyz should have observed inflight_scans == 1 mid-scan"
    );

    // After scan completes, /readyz reports inflight_scans == 0.
    let final_resp = reqwest::Client::new()
        .get(&readyz_url)
        .send()
        .await
        .expect("readyz final");
    let final_payload: serde_json::Value = final_resp.json().await.expect("readyz final json");
    assert_eq!(final_payload["inflight_scans"], 0);
}

#[tokio::test]
async fn post_scans_concurrent_requests_serialize_on_shared_sink_and_both_succeed() {
    let resolver: Arc<dyn Resolver> =
        Arc::new(HickoryResolver::from_system().expect("system resolver"));
    let server_sink = MemorySink::new();
    let server_handle = server_sink.handle();
    let boxed: Box<dyn Sink> = Box::new(server_sink);
    let shared: SharedSink = Arc::new(tokio::sync::Mutex::new(boxed));
    let reach = Arc::new(SinkReachability::configured(
        SinkType::Memory,
        std::time::Duration::from_secs(10),
        std::time::Duration::from_secs(5),
    ));
    reach.record_success();
    let state = AppState::new(resolver).with_sink(Some(Arc::clone(&shared)), reach);
    let app = build_app(state);

    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind server");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let port_a = spawn_target_listener().await;
    let port_b = spawn_target_listener().await;
    let url = format!("http://{addr}/scans");
    let body_a = json!({
        "name": "concurrent-a",
        "timeout_ms": 500,
        "targets": [{"Ip": "127.0.0.1"}],
        "probers": [{"type": "tcp_connect", "ports": [port_a]}],
    });
    let body_b = json!({
        "name": "concurrent-b",
        "timeout_ms": 500,
        "targets": [{"Ip": "127.0.0.1"}],
        "probers": [{"type": "tcp_connect", "ports": [port_b]}],
    });

    let client = reqwest::Client::new();
    let a = client.post(&url).json(&body_a).send();
    let b = client.post(&url).json(&body_b).send();
    let (resp_a, resp_b) = tokio::join!(a, b);
    let resp_a = resp_a.expect("scan A send");
    let resp_b = resp_b.expect("scan B send");
    assert_eq!(resp_a.status(), reqwest::StatusCode::OK);
    assert_eq!(resp_b.status(), reqwest::StatusCode::OK);
    let payload_a: serde_json::Value = resp_a.json().await.expect("scan A json");
    let payload_b: serde_json::Value = resp_b.json().await.expect("scan B json");
    assert_eq!(payload_a["summary"]["records_emitted"], 1);
    assert_eq!(payload_b["summary"]["records_emitted"], 1);

    let lines = server_handle.ndjson_lines();
    assert_eq!(
        lines.len(),
        2,
        "shared sink must receive exactly one record from each scan, got {lines:?}",
    );
    let records: Vec<serde_json::Value> = lines
        .iter()
        .map(|l| serde_json::from_str(l).expect("parse ndjson"))
        .collect();
    for r in &records {
        assert_eq!(r["mgmt_ip"], "127.0.0.1", "record missing mgmt_ip: {r}");
    }
    let scenario_names: std::collections::HashSet<String> = records
        .iter()
        .filter_map(|r| {
            r["scan_metadata"]["scenario_name"]
                .as_str()
                .map(str::to_string)
        })
        .collect();
    assert!(
        scenario_names.contains("concurrent-a"),
        "shared sink missing scan A's record; got {scenario_names:?}",
    );
    assert!(
        scenario_names.contains("concurrent-b"),
        "shared sink missing scan B's record; got {scenario_names:?}",
    );
}

#[tokio::test]
async fn post_scans_dual_writes_records_to_server_configured_sink_and_response_body() {
    let resolver: Arc<dyn Resolver> =
        Arc::new(HickoryResolver::from_system().expect("system resolver"));
    let server_sink = MemorySink::new();
    let server_handle = server_sink.handle();
    let boxed: Box<dyn Sink> = Box::new(server_sink);
    let shared: SharedSink = Arc::new(tokio::sync::Mutex::new(boxed));
    let reach = Arc::new(SinkReachability::configured(
        SinkType::Memory,
        std::time::Duration::from_secs(10),
        std::time::Duration::from_secs(5),
    ));
    reach.record_success();
    let state = AppState::new(resolver).with_sink(Some(Arc::clone(&shared)), reach);
    let app = build_app(state);

    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .expect("bind server");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let target_port = spawn_target_listener().await;
    let body = json!({
        "targets": [{"Ip": "127.0.0.1"}],
        "probers": [{"type": "tcp_connect", "ports": [target_port]}],
        "timeout_ms": 500,
    });

    let url = format!("http://{addr}/scans");
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&body)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let payload: serde_json::Value = resp.json().await.expect("body json");
    assert_eq!(payload["summary"]["records_emitted"], 1);
    assert_eq!(
        payload["records"].as_array().map(|a| a.len()).unwrap_or(0),
        1,
        "response body must carry the record"
    );

    let lines = server_handle.ndjson_lines();
    assert_eq!(
        lines.len(),
        1,
        "server-configured sink must receive exactly one record, got {lines:?}"
    );
    let sink_record: serde_json::Value =
        serde_json::from_str(&lines[0]).expect("server sink record parses as JSON");
    assert_eq!(sink_record["mgmt_ip"], "127.0.0.1");
}
