mod common;

#[cfg(feature = "config")]
use std::io::Write;

#[tokio::test]
async fn discover_against_in_process_listener_emits_ndjson_record() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local_addr").port();

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
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
    let output = common::rastreo()
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
    let output = common::rastreo()
        .args(["--help"])
        .output()
        .expect("spawn rastreo");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("utf-8");
    assert!(help.contains("discover"), "help missing discover: {help}");
}

#[test]
fn version_flag_reports_crate_version() {
    let output = common::rastreo()
        .args(["--version"])
        .output()
        .expect("spawn rastreo");
    assert!(output.status.success());
    let out = String::from_utf8(output.stdout).expect("utf-8");
    assert!(out.contains(env!("CARGO_PKG_VERSION")));
}

#[tokio::test]
async fn discover_emits_zero_records_hint_when_no_records() {
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args([
                "discover",
                "--target",
                "192.0.2.1",
                "--probe",
                "tcp_connect",
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
        stderr.contains("records: 0"),
        "stderr missing zero-records summary: {stderr}"
    );
    assert!(
        stderr.contains("hint: 0 records emitted"),
        "stderr missing hint line: {stderr}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn discover_reports_no_probe_error_for_dns_target_on_refused_port() {
    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    timeout_ms: 500\n    sink:\n      type: stdout\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: dns\n        ports: [1]\n        query_names: [\"example.com\"]\n";
    let path = write_yaml(&dir, "dns-refused.yml", yaml);

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args(["discover", "--file"])
            .arg(&path)
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
        stderr.contains("faults: 0"),
        "a server that does not answer must not count as a probe error: {stderr}"
    );
    assert!(
        stderr.contains("records: 0"),
        "stderr missing zero-records summary: {stderr}"
    );
    assert!(
        stderr.contains("hint: 0 records emitted"),
        "stderr missing the zero-records hint: {stderr}"
    );
}

#[tokio::test]
async fn dry_run_prints_no_runtime_hint() {
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args([
                "discover",
                "--target",
                "127.0.0.1",
                "--port",
                "22",
                "--dry-run",
            ])
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        !stderr.contains("hint:"),
        "dry-run must not print any runtime hint: {stderr}"
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(
        !stdout.contains("hint:"),
        "dry-run stdout must not print any runtime hint: {stdout}"
    );
}

#[tokio::test]
async fn discover_no_hint_when_records_emitted_greater_than_zero() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local_addr").port();

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
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

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
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
        stderr.contains("records: 1"),
        "stderr missing the record count: {stderr}"
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

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
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
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
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

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
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

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
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
async fn concurrency_flag_overrides_yaml_max_concurrent() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = format!(
        "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    max_concurrent: 2\n    timeout_ms: 500\n    sink:\n      type: stdout\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n"
    );
    let path = write_yaml(&dir, "rate.yml", &yaml);

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
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
        stderr.contains("records: 1"),
        "expected one record with overridden concurrency: {stderr}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn retired_rate_limit_scenario_fails_with_migration_hint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    rate_limit: 50\n    timeout_ms: 500\n    sink:\n      type: stdout\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
    let path = write_yaml(&dir, "retired.yml", yaml);

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args(["discover", "--file"])
            .arg(&path)
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert!(
        !output.status.success(),
        "an old rate_limit scenario must not run silently"
    );
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(stderr.contains("max_concurrent"), "stderr: {stderr}");
    assert!(stderr.contains("probe_rate"), "stderr: {stderr}");
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
        "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    max_concurrent: 8\n    timeout_ms: 500\n    sink:\n      type: stdout\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n"
    );
    let path = write_yaml(&dir, "timeout.yml", &yaml);

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
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
        stderr.contains("records: 1"),
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

    let cli_out_arg = cli_out.clone();
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
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
async fn scenario_failure_line_carries_the_underlying_cause() {
    let dir = tempfile::tempdir().expect("tempdir");
    let unopenable = dir.path().join("no-such-dir").join("out.ndjson");
    let yaml = format!(
        "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: unwritable\n    timeout_ms: 200\n    sink:\n      type: file\n      path: \"{}\"\n    targets:\n      - Ip: \"192.0.2.1\"\n    probers:\n      - type: tcp_connect\n        ports: [1]\n",
        unopenable.display()
    );
    let path = write_yaml(&dir, "unwritable.yml", &yaml);

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args(["discover", "--file"])
            .arg(&path)
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert!(!output.status.success(), "expected nonzero exit");
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    let failure_line = stderr
        .lines()
        .find(|l| l.contains("failed"))
        .unwrap_or_else(|| panic!("no failure line on stderr: {stderr}"));
    assert!(
        failure_line.contains("output sink failed"),
        "failure line must state the sink failure: {failure_line}"
    );
    assert!(
        failure_line.contains(&unopenable.display().to_string()),
        "failure line must carry the cause, naming the path: {failure_line}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn multi_scenario_partial_failure_continues_and_exits_nonzero() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = format!(
        "version: 1\nkind: discovery\ndefaults:\n  timeout_ms: 500\n  sink:\n    type: stdout\nscenarios:\n  - signal_type: discover\n    name: bad\n    targets:\n      - Range:\n          start: \"10.0.0.5\"\n          end: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n  - signal_type: discover\n    name: good\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n"
    );
    let path = write_yaml(&dir, "partial.yml", &yaml);

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args(["discover", "--file"])
            .arg(&path)
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    drop(listener);

    assert!(
        !output.status.success(),
        "expected nonzero exit when any scenario fails; stderr: {}",
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
    assert!(
        stderr.contains("1 of 2 scenario(s) failed"),
        "stderr missing partial-failure summary: {stderr}"
    );

    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "expected the good scenario to still emit one NDJSON line; stderr: {stderr}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn zero_reachable_hosts_scenario_exits_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: empty-scan\n    timeout_ms: 200\n    sink:\n      type: stdout\n    targets:\n      - Ip: \"192.0.2.1\"\n    probers:\n      - type: tcp_connect\n        ports: [1]\n";
    let path = write_yaml(&dir, "zero-reachable.yml", yaml);

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args(["discover", "--file"])
            .arg(&path)
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert!(
        output.status.success(),
        "a successful scan that found nothing must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("records: 0"),
        "stderr missing zero-records summary: {stderr}"
    );
    assert!(
        !stderr.contains("scenario(s) failed"),
        "an empty scan must not be reported as a scenario failure: {stderr}"
    );
    assert!(
        String::from_utf8(output.stdout).expect("utf-8").is_empty(),
        "stdout should be empty when nothing was reachable"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn empty_probers_scenario_is_skipped_with_warning() {
    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: empty\n    timeout_ms: 500\n    sink:\n      type: stdout\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers: []\n";
    let path = write_yaml(&dir, "empty.yml", yaml);

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
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
async fn scenario_label_is_consistent_across_start_and_completion_banners() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = format!(
        "version: 1\nkind: discovery\ndefaults:\n  timeout_ms: 500\n  sink:\n    type: stdout\nscenarios:\n  - signal_type: discover\n    name: first\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n  - signal_type: discover\n    name: second\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n"
    );
    let path = write_yaml(&dir, "labels.yml", &yaml);

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
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
    for label in ["scenario 'first' (1 of 2)", "scenario 'second' (2 of 2)"] {
        assert!(
            stderr.contains(&format!("▶ {label}")),
            "stderr missing start banner for {label}: {stderr}"
        );
        assert!(
            stderr.contains(&format!("■ {label}")),
            "stderr missing completion banner for {label}: {stderr}"
        );
    }
    assert!(
        stderr.contains("■ 2 scenarios"),
        "stderr missing the aggregate banner: {stderr}"
    );
}

#[tokio::test]
async fn dry_run_flag_driven_prints_plan_and_exits_zero_without_probing() {
    let start = std::time::Instant::now();
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args([
                "discover",
                "--target",
                "127.0.0.1",
                "--probe",
                "tcp_connect",
                "--port",
                "22,80,443",
                "--dry-run",
            ])
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");
    let elapsed = start.elapsed();

    assert!(
        output.status.success(),
        "rastreo exited with {:?}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        elapsed.as_secs() < 5,
        "dry-run must not perform TCP connects; took {elapsed:?}"
    );

    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(
        stdout.contains("[dry-run]"),
        "stdout missing dry-run marker: {stdout}"
    );
    assert!(
        stdout.contains("would run 1 scenario"),
        "stdout missing scenario-count header: {stdout}"
    );
    assert!(
        !stdout.contains("0 probes will execute"),
        "stdout should no longer include misleading '0 probes will execute' line: {stdout}"
    );
    assert!(
        stdout.contains("total probes: 1"),
        "stdout missing total-probes footer (1 IP × 1 tcp_connect prober = 1): {stdout}"
    );
    assert!(
        stdout.contains("tcp_connect (ports 22, 80, 443)"),
        "stdout missing prober line: {stdout}"
    );
    assert!(
        stdout.contains("sink: stdout"),
        "stdout missing sink line: {stdout}"
    );
    assert!(
        stdout.contains("127.0.0.1 → 127.0.0.1"),
        "stdout missing target line: {stdout}"
    );
}

#[cfg(feature = "kafka")]
#[tokio::test]
async fn dry_run_with_kafka_sink_does_not_connect_to_broker() {
    let start = std::time::Instant::now();
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args([
                "discover",
                "--target",
                "127.0.0.1",
                "--port",
                "22",
                "--sink",
                "kafka",
                "--brokers",
                "127.0.0.1:1",
                "--topic",
                "unreachable",
                "--dry-run",
            ])
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");
    let elapsed = start.elapsed();

    assert!(
        output.status.success(),
        "rastreo exited with {:?}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        elapsed.as_secs() < 5,
        "dry-run must not try to reach kafka; took {elapsed:?}"
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(stdout.contains("kafka:"), "{stdout}");
    assert!(stdout.contains("brokers=127.0.0.1:1"), "{stdout}");
    assert!(stdout.contains("topic=unreachable"), "{stdout}");
}

#[cfg(feature = "config")]
#[tokio::test]
async fn dry_run_yaml_mode_prints_per_scenario_blocks_and_total_probes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = "version: 1\nkind: discovery\ndefaults:\n  timeout_ms: 500\n  sink:\n    type: stdout\nscenarios:\n  - signal_type: discover\n    name: first\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n  - signal_type: discover\n    name: second\n    targets:\n      - Cidr: \"10.0.0.0/30\"\n    probers:\n      - type: tcp_connect\n        ports: [80, 443]\n";
    let path = write_yaml(&dir, "multi.yml", yaml);

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args(["discover", "--file"])
            .arg(&path)
            .arg("--dry-run")
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

    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(
        stdout.contains("would run 2 scenarios"),
        "expected scenario count header: {stdout}"
    );
    assert!(
        stdout.contains("scenario: 'first' (1 of 2)"),
        "missing first scenario label: {stdout}"
    );
    assert!(
        stdout.contains("scenario: 'second' (2 of 2)"),
        "missing second scenario label: {stdout}"
    );
    // Total probes: scenario 1 (1 IP × 1 prober = 1) + scenario 2 (2 IPs × 1 prober = 2) = 3
    assert!(
        stdout.contains("total probes: 3"),
        "missing total probes line: {stdout}"
    );
}

#[tokio::test]
async fn dry_run_dns_failure_prints_inline_error_and_still_exits_zero() {
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args([
                "discover",
                "--target",
                "127.0.0.1",
                "--target",
                "nx-does-not-exist-99e2c31b.example.invalid",
                "--port",
                "22",
                "--dry-run",
            ])
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert!(
        output.status.success(),
        "one good target should keep exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(
        stdout.contains("<error:"),
        "expected inline error: {stdout}"
    );
    assert!(
        stdout.contains("127.0.0.1 → 127.0.0.1"),
        "resolved target still listed: {stdout}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn catalog_reference_resolves_and_dry_run_prints_plan() {
    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: office\n    timeout_ms: 500\n    sink:\n      type: stdout\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
    write_yaml(&dir, "office.yml", yaml);
    let catalog_path = dir.path().to_path_buf();

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .env("RASTREO_CATALOG_DIR", &catalog_path)
            .args(["discover", "--file", "@office", "--dry-run"])
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

    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(stdout.contains("[dry-run]"), "stdout: {stdout}");
    assert!(stdout.contains("127.0.0.1 → 127.0.0.1"), "stdout: {stdout}");
    assert!(
        stdout.contains("tcp_connect (ports 22)"),
        "stdout: {stdout}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn catalog_reference_accepts_yml_suffix_in_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: office\n    timeout_ms: 500\n    sink:\n      type: stdout\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
    write_yaml(&dir, "office.yml", yaml);
    let catalog_path = dir.path().to_path_buf();

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .env("RASTREO_CATALOG_DIR", &catalog_path)
            .args(["discover", "--file", "@office.yml", "--dry-run"])
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
}

#[cfg(feature = "config")]
#[tokio::test]
async fn catalog_reference_not_found_prints_actionable_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_yaml(
        &dir,
        "alpha.yml",
        "version: 1\nkind: discovery\nscenarios: []\n",
    );
    let catalog_path = dir.path().to_path_buf();

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .env("RASTREO_CATALOG_DIR", &catalog_path)
            .args(["discover", "--file", "@nonexistent", "--dry-run"])
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert!(!output.status.success(), "expected nonzero exit");
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(stderr.contains("@nonexistent"), "stderr: {stderr}");
    assert!(stderr.contains("searched directories"), "stderr: {stderr}");
    assert!(stderr.contains("@alpha"), "stderr: {stderr}");
}

#[cfg(feature = "config")]
#[tokio::test]
async fn catalog_reference_rejects_path_separators() {
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args(["discover", "--file", "@../etc/passwd", "--dry-run"])
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert!(!output.status.success(), "expected nonzero exit");
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(stderr.contains("path separators"), "stderr: {stderr}");
}

#[cfg(feature = "config")]
#[tokio::test]
async fn catalog_reference_rejects_empty_name() {
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args(["discover", "--file", "@", "--dry-run"])
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert!(!output.status.success(), "expected nonzero exit");
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(stderr.contains("empty"), "stderr: {stderr}");
}

#[cfg(feature = "config")]
#[tokio::test]
async fn plain_path_still_works_when_catalog_env_set() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = format!(
        "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    timeout_ms: 500\n    sink:\n      type: stdout\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n"
    );
    let path = write_yaml(&dir, "plain.yml", &yaml);
    let catalog_path = dir.path().to_path_buf();

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .env("RASTREO_CATALOG_DIR", &catalog_path)
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
        stderr.contains("records: 1"),
        "expected one record: {stderr}"
    );
}

#[tokio::test]
async fn dry_run_format_json_emits_parseable_plan_array() {
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args([
                "discover",
                "--target",
                "127.0.0.1",
                "--probe",
                "tcp_connect",
                "--port",
                "22",
                "--dry-run",
                "--dry-run-format",
                "json",
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

    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("parse json array");
    let arr = value.as_array().expect("json array");
    assert_eq!(
        arr.len(),
        1,
        "one plan for one flag-driven scenario: {stdout}"
    );
    assert_eq!(arr[0]["scenario"], "discovery");
    assert_eq!(arr[0]["total_probes"], 1);
    assert_eq!(arr[0]["sink"], "stdout");
    assert!(arr[0]["targets"].is_array(), "{stdout}");
    assert!(arr[0]["probers"].is_array(), "{stdout}");
    assert!(
        !stdout.contains("[dry-run]"),
        "json mode must not print the text header: {stdout}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn dry_run_format_json_multi_scenario_file_emits_array_of_plans() {
    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = "version: 1\nkind: discovery\ndefaults:\n  timeout_ms: 500\n  sink:\n    type: stdout\nscenarios:\n  - signal_type: discover\n    name: first\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n  - signal_type: discover\n    name: second\n    targets:\n      - Cidr: \"10.0.0.0/30\"\n    probers:\n      - type: tcp_connect\n        ports: [80, 443]\n";
    let path = write_yaml(&dir, "multi.yml", yaml);

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args(["discover", "--file"])
            .arg(&path)
            .args(["--dry-run", "--dry-run-format", "json"])
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

    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("parse json array");
    let arr = value.as_array().expect("json array");
    assert_eq!(arr.len(), 2, "one plan per scenario: {stdout}");
    // Plain names only — no `'name' (N of M)` text decoration in the JSON data.
    assert_eq!(arr[0]["scenario"], "first");
    assert_eq!(arr[1]["scenario"], "second");
}

#[cfg(feature = "config")]
#[tokio::test]
async fn dry_run_format_json_single_scenario_file_uses_plain_scenario_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: solo-scenario\n    timeout_ms: 500\n    sink:\n      type: stdout\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
    let path = write_yaml(&dir, "solo.yml", yaml);

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args(["discover", "--file"])
            .arg(&path)
            .args(["--dry-run", "--dry-run-format", "json"])
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

    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("parse json array");
    let arr = value.as_array().expect("json array");
    assert_eq!(arr.len(), 1, "{stdout}");
    // The plain name a single-scenario dry-run must carry — NOT `'solo-scenario' (1 of 1)`.
    assert_eq!(arr[0]["scenario"], "solo-scenario", "{stdout}");
}

#[tokio::test]
async fn dry_run_format_json_all_targets_failed_exits_nonzero() {
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args([
                "discover",
                "--target",
                "nx-does-not-exist-77f31c.example.invalid",
                "--port",
                "22",
                "--dry-run",
                "--dry-run-format",
                "json",
            ])
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert!(
        !output.status.success(),
        "all-targets-failed must exit nonzero even in json mode"
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("plan json still emitted before the exit error");
    assert_eq!(
        value.as_array().expect("json array").len(),
        1,
        "the plan for the failing target is still rendered: {stdout}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn catalog_list_prints_sorted_names_with_resolved_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_yaml(
        &dir,
        "foo.yml",
        "version: 1\nkind: discovery\nscenarios: []\n",
    );
    write_yaml(
        &dir,
        "bar.yaml",
        "version: 1\nkind: discovery\nscenarios: []\n",
    );
    let catalog_path = dir.path().to_path_buf();

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .env("RASTREO_CATALOG_DIR", &catalog_path)
            .args(["catalog", "list"])
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

    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let bar_pos = stdout.find("@bar").expect("bar listed");
    let foo_pos = stdout.find("@foo").expect("foo listed");
    assert!(bar_pos < foo_pos, "names must be sorted: {stdout}");
    assert!(stdout.contains("foo.yml"), "foo path shown: {stdout}");
    assert!(stdout.contains("bar.yaml"), "bar path shown: {stdout}");
}

#[cfg(feature = "config")]
#[tokio::test]
async fn catalog_list_empty_reports_none_found_and_exits_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let catalog_path = dir.path().to_path_buf();

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .env("RASTREO_CATALOG_DIR", &catalog_path)
            .args(["catalog", "list"])
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert!(
        output.status.success(),
        "an empty catalog is not an error; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("no catalog scenarios found"),
        "stderr missing none-found message: {stderr}"
    );
    assert!(
        !String::from_utf8(output.stdout)
            .expect("utf-8")
            .contains('@'),
        "stdout must not list any entries"
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

    let output_path = output_ndjson.clone();
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
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

#[cfg(feature = "config")]
#[tokio::test]
async fn resume_refuses_a_multi_scenario_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = "version: 1\nkind: discovery\ndefaults:\n  timeout_ms: 500\n  sink:\n    type: file\n    path: \"/tmp/rastreo-resume-refuse.ndjson\"\nscenarios:\n  - signal_type: discover\n    name: first\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n  - signal_type: discover\n    name: second\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [80]\n";
    let path = write_yaml(&dir, "multi.yml", yaml);
    let checkpoint = dir.path().join("scan.checkpoint");

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args(["discover", "--file"])
            .arg(&path)
            .arg("--checkpoint")
            .arg(&checkpoint)
            .arg("--resume")
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert!(
        !output.status.success(),
        "resuming a multi-scenario file must be refused"
    );
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("--resume supports a single-scenario run")
            && stderr.contains("2 scenarios"),
        "stderr must explain the single-scenario limitation: {stderr}"
    );
}
