#![cfg(feature = "config")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use rastreo_core::{HickoryResolver, MapEnv, Resolver};
use rastreo_server::state::{AppState, SinkProbeConfig};
use rastreo_server::{build_app, spawn_sink_probe};
use serde_json::json;

const RETIRED_TAG: &str = "oui_enrichment";
const REPLACEMENT: &str = "mib_enrichment";

fn resolver() -> Arc<dyn Resolver> {
    Arc::new(HickoryResolver::from_system().expect("system resolver"))
}

async fn serve(app: Router) -> SocketAddr {
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

async fn post_scans_rejection(tag: &str) -> String {
    let addr = serve(build_app(AppState::new(resolver()))).await;
    let body = json!({
        "targets": [{"Ip": "127.0.0.1"}],
        "probers": [{"type": "tcp_connect", "ports": [22]}],
        "fuser": {"type": tag, "inner": {"type": "direct"}},
    });
    let response = reqwest::Client::new()
        .post(format!("http://{addr}/scans"))
        .json(&body)
        .send()
        .await
        .expect("send");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let payload: serde_json::Value = response.json().await.expect("error body json");
    payload["error"]
        .as_str()
        .expect("error body carries a message")
        .to_string()
}

async fn sink_config_rejection(tag: &str) -> String {
    let file = tempfile::NamedTempFile::new().expect("temp sink config");
    std::fs::write(file.path(), format!("type: {tag}\n")).expect("write sink config");
    let config = SinkProbeConfig {
        config_path: Some(file.path().to_path_buf()),
        ..SinkProbeConfig::default()
    };
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let (state, probe_task) = spawn_sink_probe(
        AppState::new(resolver()),
        &config,
        Arc::new(MapEnv::new()),
        shutdown_rx,
    )
    .await;
    probe_task
        .expect("a rejected sink config is retried until it parses")
        .abort();

    let addr = serve(build_app(state)).await;
    let payload: serde_json::Value = reqwest::get(format!("http://{addr}/readyz"))
        .await
        .expect("send")
        .json()
        .await
        .expect("readyz body json");
    payload["last_probe_error"]
        .as_str()
        .expect("readyz reports why the sink could not be built")
        .to_string()
}

#[tokio::test]
async fn every_server_config_ingestion_surface_rejects_a_retired_type_tag_by_name() {
    for (surface, rejection) in [
        ("POST /scans", post_scans_rejection(RETIRED_TAG).await),
        ("sink config file", sink_config_rejection(RETIRED_TAG).await),
    ] {
        assert!(
            rejection.contains(RETIRED_TAG),
            "{surface} must name `{RETIRED_TAG}`: {rejection}"
        );
        assert!(
            rejection.contains(REPLACEMENT),
            "{surface} must point at `{REPLACEMENT}`: {rejection}"
        );
        assert!(
            !rejection.contains("unknown variant"),
            "{surface} left `{RETIRED_TAG}` to serde: {rejection}"
        );
    }
}
