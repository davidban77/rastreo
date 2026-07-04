#[cfg(feature = "config")]
use std::io::Write;
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
        "--file",
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

#[tokio::test]
async fn discover_emits_zero_records_hint_when_no_records() {
    let bin = env!("CARGO_BIN_EXE_rastreo");
    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args([
                "discover",
                "--target",
                "192.0.2.1",
                "--port",
                "1",
                "--sink",
                "stdout",
                "--timeout-ms",
                "100",
            ])
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert!(
        output.status.success(),
        "rastreo exited with {:?}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("records_emitted=0"),
        "stderr missing zero-records summary: {stderr}"
    );
    assert!(
        stderr.contains("hint: 0 records emitted"),
        "stderr missing hint line: {stderr}"
    );
}

#[tokio::test]
async fn discover_no_hint_when_records_emitted_greater_than_zero() {
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

    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        !stderr.contains("hint: 0 records emitted"),
        "stderr should not include the hint when records were emitted: {stderr}"
    );
}

#[cfg(feature = "config")]
fn write_yaml(dir: &tempfile::TempDir, name: &str, contents: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).expect("create yaml");
    f.write_all(contents.as_bytes()).expect("write yaml");
    path
}

#[cfg(feature = "config")]
#[tokio::test]
async fn run_from_file_loads_minimal_tcp_scenario() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = format!(
        "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n    timeout_ms: 500\n    sink:\n      type: stdout\n"
    );
    let path = write_yaml(&dir, "tcp.yml", &yaml);

    let bin = env!("CARGO_BIN_EXE_rastreo");
    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args(["discover", "--file"])
            .arg(&path)
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

    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("records_emitted=1"),
        "stderr missing records_emitted=1: {stderr}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn run_from_file_rejects_unsupported_version() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_yaml(
        &dir,
        "bad.yml",
        "version: 2\nkind: discovery\nscenarios: []\n",
    );

    let bin = env!("CARGO_BIN_EXE_rastreo");
    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args(["discover", "--file"])
            .arg(&path)
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert!(!output.status.success(), "expected nonzero exit");
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("unsupported scenario file version 2"),
        "stderr missing version rejection: {stderr}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn run_from_file_rejects_missing_file() {
    let bin = env!("CARGO_BIN_EXE_rastreo");
    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args([
                "discover",
                "--file",
                "/tmp/definitely-not-a-real-rastreo-file-xyz.yml",
            ])
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert!(!output.status.success(), "expected nonzero exit");
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("failed to read scenario file"),
        "stderr missing read-error message: {stderr}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn run_from_file_rejects_malformed_yaml() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_yaml(&dir, "broken.yml", "version: 1\n  kind: [\n");

    let bin = env!("CARGO_BIN_EXE_rastreo");
    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args(["discover", "--file"])
            .arg(&path)
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert!(!output.status.success(), "expected nonzero exit");
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("failed to parse scenario file"),
        "stderr missing parse-error message: {stderr}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn run_from_file_reports_all_scenarios_in_multi_scenario_file() {
    let listener_a = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a");
    let port_a = listener_a.local_addr().expect("local_addr a").port();
    let listener_b = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind b");
    let port_b = listener_b.local_addr().expect("local_addr b").port();

    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = format!(
        "version: 1\nkind: discovery\ndefaults:\n  timeout_ms: 500\n  sink:\n    type: stdout\nscenarios:\n  - signal_type: discover\n    name: first\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port_a}]\n  - signal_type: discover\n    name: second\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port_b}]\n"
    );
    let path = write_yaml(&dir, "multi.yml", &yaml);

    let bin = env!("CARGO_BIN_EXE_rastreo");
    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args(["discover", "--file"])
            .arg(&path)
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    drop(listener_a);
    drop(listener_b);

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
        2,
        "expected one NDJSON line per scenario, got {lines:#?}"
    );

    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("scenario 'first'"),
        "stderr missing first scenario label: {stderr}"
    );
    assert!(
        stderr.contains("scenario 'second'"),
        "stderr missing second scenario label: {stderr}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn concurrency_flag_overrides_yaml_rate_limit() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = format!(
        "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    rate_limit: 2\n    timeout_ms: 500\n    sink:\n      type: stdout\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n"
    );
    let path = write_yaml(&dir, "rate.yml", &yaml);

    let bin = env!("CARGO_BIN_EXE_rastreo");
    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args(["discover", "--file"])
            .arg(&path)
            .args(["--concurrency", "16"])
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
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("records_emitted=1"),
        "expected one record with overridden concurrency: {stderr}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn timeout_ms_flag_overrides_yaml_timeout_ms() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = format!(
        "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    rate_limit: 8\n    timeout_ms: 500\n    sink:\n      type: stdout\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n"
    );
    let path = write_yaml(&dir, "timeout.yml", &yaml);

    let bin = env!("CARGO_BIN_EXE_rastreo");
    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args(["discover", "--file"])
            .arg(&path)
            .args(["--timeout-ms", "5000"])
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
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("records_emitted=1"),
        "expected one record with overridden timeout: {stderr}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn output_flag_overrides_yaml_file_sink_path() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    let dir = tempfile::tempdir().expect("tempdir");
    let yaml_out = dir.path().join("yaml-out.ndjson");
    let cli_out = dir.path().join("cli-out.ndjson");

    let yaml = format!(
        "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    timeout_ms: 500\n    sink:\n      type: file\n      path: \"{}\"\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n",
        yaml_out.display()
    );
    let yaml_path = write_yaml(&dir, "sink-path.yml", &yaml);

    let bin = env!("CARGO_BIN_EXE_rastreo");
    let cli_out_arg = cli_out.clone();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args(["discover", "--file"])
            .arg(&yaml_path)
            .args(["--sink", "file", "--output"])
            .arg(&cli_out_arg)
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
    assert!(
        cli_out.exists(),
        "cli --output path should have been created"
    );
    assert!(
        !yaml_out.exists(),
        "yaml sink path should NOT have been created when --output overrides it"
    );
    let bytes = std::fs::read(&cli_out).expect("read cli out");
    let lines: Vec<&[u8]> = bytes
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(lines.len(), 1, "expected one NDJSON line in CLI output");
}

#[cfg(feature = "config")]
#[tokio::test]
async fn multi_scenario_partial_failure_continues_and_exits_zero() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = format!(
        "version: 1\nkind: discovery\ndefaults:\n  timeout_ms: 500\n  sink:\n    type: stdout\nscenarios:\n  - signal_type: discover\n    name: bad\n    targets:\n      - Range:\n          start: \"10.0.0.5\"\n          end: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n  - signal_type: discover\n    name: good\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n"
    );
    let path = write_yaml(&dir, "partial.yml", &yaml);

    let bin = env!("CARGO_BIN_EXE_rastreo");
    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args(["discover", "--file"])
            .arg(&path)
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    drop(listener);

    assert!(
        output.status.success(),
        "expected exit 0 when at least one scenario succeeds; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("scenario 'bad'"),
        "stderr missing first scenario label: {stderr}"
    );
    assert!(
        stderr.contains("failed"),
        "stderr missing failure line for bad scenario: {stderr}"
    );
    assert!(
        stderr.contains("scenario 'good'"),
        "stderr missing second scenario label: {stderr}"
    );

    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "expected the good scenario to emit one NDJSON line; stderr: {stderr}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn empty_probers_scenario_is_skipped_with_warning() {
    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: empty\n    timeout_ms: 500\n    sink:\n      type: stdout\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers: []\n";
    let path = write_yaml(&dir, "empty.yml", yaml);

    let bin = env!("CARGO_BIN_EXE_rastreo");
    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args(["discover", "--file"])
            .arg(&path)
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert!(
        output.status.success(),
        "expected exit 0 when the only scenario is skipped; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("no probers configured, skipping"),
        "stderr missing skip warning: {stderr}"
    );
    assert!(
        String::from_utf8(output.stdout).expect("utf-8").is_empty(),
        "stdout should be empty when the scenario is skipped"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn scenario_label_is_consistent_across_running_and_summary_lines() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = format!(
        "version: 1\nkind: discovery\ndefaults:\n  timeout_ms: 500\n  sink:\n    type: stdout\nscenarios:\n  - signal_type: discover\n    name: first\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n  - signal_type: discover\n    name: second\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n"
    );
    let path = write_yaml(&dir, "labels.yml", &yaml);

    let bin = env!("CARGO_BIN_EXE_rastreo");
    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args(["discover", "--file"])
            .arg(&path)
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

    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("running scenario 'first' (1 of 2)"),
        "stderr missing first running line: {stderr}"
    );
    assert!(
        stderr.contains("scenario 'first' (1 of 2) complete:"),
        "stderr missing first summary line with same label: {stderr}"
    );
    assert!(
        stderr.contains("running scenario 'second' (2 of 2)"),
        "stderr missing second running line: {stderr}"
    );
    assert!(
        stderr.contains("scenario 'second' (2 of 2) complete:"),
        "stderr missing second summary line with same label: {stderr}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn sink_flag_overrides_yaml_sink() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    let dir = tempfile::tempdir().expect("tempdir");
    let yaml_path = write_yaml(
        &dir,
        "sink.yml",
        &format!(
            "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    timeout_ms: 500\n    sink:\n      type: stdout\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n"
        ),
    );
    let output_ndjson = dir.path().join("out.ndjson");

    let bin = env!("CARGO_BIN_EXE_rastreo");
    let output_path = output_ndjson.clone();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(bin)
            .args(["discover", "--file"])
            .arg(&yaml_path)
            .args(["--sink", "file", "--output"])
            .arg(&output_path)
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
    let bytes = std::fs::read(&output_ndjson).expect("read out.ndjson");
    let lines: Vec<&[u8]> = bytes
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "sink override must direct records to the file"
    );
    assert!(
        String::from_utf8(output.stdout).expect("utf-8").is_empty(),
        "stdout must be empty when sink overridden to file"
    );
}
