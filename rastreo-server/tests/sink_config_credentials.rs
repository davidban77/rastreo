#![cfg(feature = "config")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use rastreo_core::{HickoryResolver, Resolver};
use rastreo_server::state::{AppState, SinkProbeConfig};
use rastreo_server::{build_app, spawn_sink_probe};

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

#[cfg(feature = "nats")]
#[tokio::test]
async fn readyz_reports_an_unreachable_nats_sink_without_its_inline_credentials() {
    const USERNAME: &str = "admin";
    const PASSWORD: &str = "hunter2";

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

/// Each expansion syntax as the YAML text resolving to `plaintext`, with the tempfile the `!file` arm must outlive.
fn secret_references_to(
    var: &str,
    plaintext: &str,
) -> Vec<(&'static str, String, Option<tempfile::NamedTempFile>)> {
    use std::io::Write;

    // SAFETY: env var mutation is process-global; the name is unique to this test binary.
    unsafe { std::env::set_var(var, plaintext) };
    let mut file = tempfile::NamedTempFile::new().expect("tempfile");
    file.write_all(plaintext.as_bytes()).expect("write");
    let path = file.path().to_str().expect("utf-8 path").to_string();
    vec![
        ("${VAR}", format!("\"${{{var}}}\""), None),
        ("!file", format!("!file {path}"), Some(file)),
    ]
}

#[tokio::test]
async fn readyz_never_publishes_a_secret_expanded_into_a_malformed_sink_config() {
    const SECRET: &str = "hunter2-plaintext-must-never-surface";
    const VAR: &str = "RASTREO_TEST_SERVER_SINK_SHAPE_SECRET";

    let mut positions: Vec<(&str, &str)> = Vec::new();
    positions.push(("`type`", "type: REF\n"));
    #[cfg(feature = "nats")]
    positions.extend([
        (
            "`servers`",
            "type: nats\nservers: REF\nsubject: rastreo.discovery.records.v1\nstream: RASTREO\n",
        ),
        (
            "`flush_mode`",
            "type: nats\nservers: [\"nats://127.0.0.1:1\"]\nsubject: rastreo.discovery.records.v1\nstream: RASTREO\nflush_mode: REF\n",
        ),
    ]);

    for (position, template) in positions {
        for (delivery, reference, _keep) in secret_references_to(VAR, SECRET) {
            let body = readyz_body_for_sink_config(&template.replace("REF", &reference)).await;
            let rendered = body.to_string();
            assert!(
                !rendered.contains(SECRET),
                "{position} via {delivery} leaked the plaintext on /readyz: {rendered}"
            );
            let reason = body["last_probe_error"]
                .as_str()
                .expect("readyz reports why the sink could not be built");
            assert!(
                reason.contains("after secret expansion"),
                "{position} via {delivery}: {reason}"
            );
            assert!(
                reason.contains(reference.trim_matches('"')),
                "{position} via {delivery} must still name the reference as written: {reason}"
            );
        }
    }
}
