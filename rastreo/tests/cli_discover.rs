use std::process::Command;

#[tokio::test]
async fn discover_against_in_process_listener_emits_ndjson_record() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local_addr").port();

    let bin = env!("CARGO_BIN_EXE_rastreo");
    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args([
                "discover",
                "--target",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--sink",
                "stdout",
                "--timeout-ms",
                "500",
            ])
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    drop(listener);

    assert!(
        output.status.success(),
        "rastreo exited with {:?}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "expected one NDJSON line, got {lines:#?}; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let value: serde_json::Value = serde_json::from_str(lines[0]).expect("parse ndjson line");
    assert_eq!(
        value
            .get("mgmt_ip")
            .and_then(|v| v.as_str())
            .expect("mgmt_ip string"),
        "127.0.0.1"
    );

    let signals = value
        .get("signals")
        .and_then(|v| v.as_array())
        .expect("signals array");
    let has_open_port = signals.iter().any(|s| {
        s.get("OpenPort")
            .and_then(|v| v.as_u64())
            .map(|p| p == u64::from(port))
            .unwrap_or(false)
    });
    assert!(
        has_open_port,
        "expected OpenPort({port}) signal, got {signals:?}"
    );
}

#[test]
fn discover_help_lists_required_flags() {
    let bin = env!("CARGO_BIN_EXE_rastreo");
    let output = Command::new(bin)
        .args(["discover", "--help"])
        .output()
        .expect("spawn rastreo");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("utf-8");
    for needle in [
        "--target",
        "--port",
        "--sink",
        "--output",
        "--concurrency",
        "--timeout-ms",
    ] {
        assert!(
            help.contains(needle),
            "discover --help missing {needle}; full output:\n{help}"
        );
    }
}

#[test]
fn top_level_help_lists_discover_subcommand() {
    let bin = env!("CARGO_BIN_EXE_rastreo");
    let output = Command::new(bin)
        .args(["--help"])
        .output()
        .expect("spawn rastreo");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("utf-8");
    assert!(help.contains("discover"), "help missing discover: {help}");
}

#[test]
fn version_flag_reports_crate_version() {
    let bin = env!("CARGO_BIN_EXE_rastreo");
    let output = Command::new(bin)
        .args(["--version"])
        .output()
        .expect("spawn rastreo");
    assert!(output.status.success());
    let out = String::from_utf8(output.stdout).expect("utf-8");
    assert!(out.contains(env!("CARGO_PKG_VERSION")));
}
