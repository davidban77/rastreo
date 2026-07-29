#![cfg(all(feature = "config", feature = "nats"))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use rastreo_core::{HickoryResolver, Resolver};
use rastreo_server::state::{AppState, SinkProbeConfig};
use rastreo_server::{build_app, spawn_sink_probe};

const USERNAME: &str = "admin";
const PASSWORD: &str = "hunter2";

fn resolver() -> Arc<dyn Resolver> {
    Arc::new(HickoryResolver::from_system().expect("system resolver"))
}

async fn readyz_body_for_sink_config(yaml: &str) -> serde_json::Value {
    let file = tempfile::NamedTempFile::new().expect("temp sink config");
    std::fs::write(file.path(), yaml).expect("write sink config");
    let config = SinkProbeConfig {
        config_path: Some(file.path().to_path_buf()),
        ..SinkProbeConfig::default()
    };
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let (state, _probe_task) =
        spawn_sink_probe(AppState::new(resolver()), &config, shutdown_rx).await;

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

    reqwest::get(format!("http://{addr}/readyz"))
        .await
        .expect("send")
        .json()
        .await
        .expect("readyz body json")
}

#[tokio::test]
async fn readyz_reports_an_unreachable_nats_sink_without_its_inline_credentials() {
    let yaml = format!(
        "type: nats\nservers: [\"nats://{USERNAME}:{PASSWORD}@127.0.0.1:1\"]\nsubject: rastreo.discovery.records.v1\nstream: RASTREO\n"
    );
    let body = readyz_body_for_sink_config(&yaml).await;
    let rendered = body.to_string();
    assert!(!rendered.contains(PASSWORD), "password leaked: {rendered}");
    assert!(!rendered.contains(USERNAME), "username leaked: {rendered}");

    let reason = body["last_probe_error"]
        .as_str()
        .expect("readyz reports why the sink could not be built");
    assert!(reason.contains("nats://127.0.0.1:1"), "reason: {reason}");
    assert!(reason.contains("failed to connect"), "reason: {reason}");
}
