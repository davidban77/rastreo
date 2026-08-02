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
                "--format",
                "json",
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
        "--format",
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
fn discover_answers_the_retired_dry_run_format_flag_with_its_replacement() {
    let output = common::rastreo()
        .args([
            "discover",
            "--target",
            "127.0.0.1",
            "--dry-run",
            "--dry-run-format",
            "json",
        ])
        .output()
        .expect("spawn rastreo");
    assert!(
        !output.status.success(),
        "--dry-run-format no longer drives anything"
    );
    let stderr = String::from_utf8(output.stderr).expect("utf-8");
    assert!(
        stderr.contains("--format json"),
        "the run must name the format that replaced it; full output:\n{stderr}"
    );
    assert!(
        stderr.contains("--format table"),
        "the run must map the retired text value too; full output:\n{stderr}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).is_empty(),
        "a rejected run prints no plan"
    );
}

#[test]
fn discover_help_omits_the_retired_dry_run_format_flag() {
    let output = common::rastreo()
        .args(["discover", "--help"])
        .output()
        .expect("spawn rastreo");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("utf-8");
    assert!(
        !help.contains("--dry-run-format"),
        "a retired flag is a migration aid, not a documented one; full output:\n{help}"
    );
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
        2,
        "expected a table header and one row, got {lines:#?}; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(lines[0].starts_with("ADDRESS"), "{lines:#?}");

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
    let rows: Vec<&str> = stdout
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with("ADDRESS"))
        .collect();
    assert_eq!(
        rows.len(),
        2,
        "expected one row per scenario, got {rows:#?}"
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
    let rows: Vec<&str> = stdout
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with("ADDRESS"))
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "expected the good scenario to still emit one row; stderr: {stderr}"
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
async fn a_run_whose_only_scenario_was_skipped_probed_nothing_and_says_so() {
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

    assert_eq!(
        output.status.code(),
        Some(1),
        "a run that probed nothing must not report success; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("every scenario in") && stderr.contains("nothing to probe"),
        "stderr must say why the run failed: {stderr}"
    );
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

#[tokio::test]
async fn the_plan_names_the_record_format_the_destination_chose() {
    let dir = tempfile::tempdir().expect("tempdir");
    let records = dir.path().join("records.ndjson");
    let to_a_file = vec![
        "--sink".to_string(),
        "file".to_string(),
        "--output".to_string(),
        records.display().to_string(),
    ];
    for (extra, expected) in [
        (Vec::new(), "    encoder: table\n"),
        (
            vec!["--format".to_string(), "table".to_string()],
            "    encoder: table\n",
        ),
        (to_a_file, "    encoder: ndjson\n"),
    ] {
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
                .args(&extra)
                .output()
                .expect("spawn rastreo")
        })
        .await
        .expect("join");
        let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
        assert!(
            stdout.contains(expected),
            "the plan must confirm what lands in the sink, expected {expected:?}: {stdout}"
        );
    }
    assert!(!records.exists(), "a dry-run opens no sink");
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
async fn dry_run_dns_failure_prints_inline_error_and_refuses() {
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

    assert_eq!(
        output.status.code(),
        Some(1),
        "a target the scan aborts on must fail the rehearsal; stderr: {}",
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
async fn dry_run_json_emits_parseable_plan_array() {
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
                "--format",
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
    assert_eq!(arr[0]["encoder"], "ndjson");
    assert!(arr[0]["targets"].is_array(), "{stdout}");
    assert!(arr[0]["probers"].is_array(), "{stdout}");
    assert!(
        !stdout.contains("[dry-run]"),
        "json mode must not print the text header: {stdout}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn dry_run_json_multi_scenario_file_emits_array_of_plans() {
    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = "version: 1\nkind: discovery\ndefaults:\n  timeout_ms: 500\n  sink:\n    type: stdout\nscenarios:\n  - signal_type: discover\n    name: first\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n  - signal_type: discover\n    name: second\n    targets:\n      - Cidr: \"10.0.0.0/30\"\n    probers:\n      - type: tcp_connect\n        ports: [80, 443]\n";
    let path = write_yaml(&dir, "multi.yml", yaml);

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args(["discover", "--file"])
            .arg(&path)
            .args(["--dry-run", "--format", "json"])
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
async fn dry_run_json_single_scenario_file_uses_plain_scenario_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: solo-scenario\n    timeout_ms: 500\n    sink:\n      type: stdout\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22]\n";
    let path = write_yaml(&dir, "solo.yml", yaml);

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args(["discover", "--file"])
            .arg(&path)
            .args(["--dry-run", "--format", "json"])
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
async fn dry_run_json_all_targets_failed_exits_nonzero() {
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args([
                "discover",
                "--target",
                "nx-does-not-exist-77f31c.example.invalid",
                "--port",
                "22",
                "--dry-run",
                "--format",
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
async fn checkpointing_a_multi_scenario_file_is_refused_before_the_scan() {
    let dir = tempfile::tempdir().expect("tempdir");
    let records = dir.path().join("records.ndjson");
    let yaml = format!("version: 1\nkind: discovery\ndefaults:\n  timeout_ms: 200\n  sink:\n    type: file\n    path: \"{}\"\nscenarios:\n  - signal_type: discover\n    name: first\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22222]\n  - signal_type: discover\n    name: second\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22223]\n", records.display());
    let path = write_yaml(&dir, "multi-checkpoint.yml", &yaml);
    let checkpoint = dir.path().join("scan.checkpoint");

    let args = vec![
        "discover".to_string(),
        "--file".to_string(),
        path.to_string_lossy().into_owned(),
        "--checkpoint".to_string(),
        checkpoint.to_string_lossy().into_owned(),
    ];
    assert_both_refuse(
        &dry_run_then_scan(args).await,
        "--checkpoint supports a single-scenario run",
    );
    assert!(
        !checkpoint.exists(),
        "a checkpoint no --resume could ever read must not be written"
    );
    assert!(
        !records.exists(),
        "a refused checkpoint request must not open the sink"
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
        stderr.contains("--checkpoint supports a single-scenario run")
            && stderr.contains("2 scenarios"),
        "stderr must explain the single-scenario limitation: {stderr}"
    );
}

#[cfg(feature = "config")]
const BAD_FUSER_SCENARIO: &str = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: bad-fuser-scenario\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22222]\n    fuser:\n      type: direct\n      confidence_baseline: 2.0\n";

#[cfg(feature = "config")]
#[tokio::test]
async fn dry_run_refuses_a_scenario_validate_rejects() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_yaml(&dir, "bad-fuser.yml", BAD_FUSER_SCENARIO);

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
        !output.status.success(),
        "a dry-run of an invalid scenario must not exit 0"
    );
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("confidence_baseline") && stderr.contains("bad-fuser-scenario"),
        "stderr must name the scenario and the invalid knob: {stderr}"
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(
        !stdout.contains("fuser:"),
        "an invalid scenario must not be rendered as a runnable plan: {stdout}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn validate_dry_run_and_scan_agree_on_an_invalid_scenario() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_yaml(&dir, "bad-fuser.yml", BAD_FUSER_SCENARIO);

    let file = path.to_string_lossy().to_string();
    let invocations: Vec<Vec<String>> = vec![
        vec!["validate".into(), file.clone()],
        vec![
            "discover".into(),
            "--file".into(),
            file.clone(),
            "--dry-run".into(),
        ],
        vec!["discover".into(), "--file".into(), file],
    ];

    let mut codes = Vec::new();
    for args in invocations {
        let output = tokio::task::spawn_blocking(move || {
            common::rastreo()
                .args(&args)
                .output()
                .expect("spawn rastreo")
        })
        .await
        .expect("join");
        codes.push(output.status.code());
    }

    assert_eq!(
        codes,
        vec![Some(1); 3],
        "validate, dry-run, and a real scan must agree that the scenario is invalid"
    );
}

#[cfg(feature = "config")]
const EMPTY_PORTS_SCENARIO: &str = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: empty-ports-scenario\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: []\n";

#[cfg(feature = "config")]
const BAD_CLASSIFIER_SCENARIO: &str = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: bad-classifier-scenario\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22222]\n    classifier:\n      type: rules\n      platform_rules:\n        - signal: ssh_banner\n          pattern: \"([unclosed\"\n          platform: broken\n";

#[cfg(feature = "config")]
const BACKWARDS_RANGE_SCENARIO: &str = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: backwards-range-scenario\n    targets:\n      - Range:\n          start: \"10.0.0.5\"\n          end: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22222]\n";

#[cfg(feature = "config")]
async fn exit_codes_across_every_surface(yaml: &str, name: &str) -> Vec<Option<i32>> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_yaml(&dir, name, yaml);
    let file = path.to_string_lossy().to_string();
    let invocations: Vec<Vec<String>> = vec![
        vec!["validate".into(), file.clone()],
        vec![
            "discover".into(),
            "--file".into(),
            file.clone(),
            "--dry-run".into(),
        ],
        vec!["discover".into(), "--file".into(), file],
    ];

    let mut codes = Vec::new();
    for args in invocations {
        let output = tokio::task::spawn_blocking(move || {
            common::rastreo()
                .args(&args)
                .output()
                .expect("spawn rastreo")
        })
        .await
        .expect("join");
        codes.push(output.status.code());
    }
    codes
}

#[cfg(feature = "config")]
#[tokio::test]
async fn validate_dry_run_and_scan_agree_on_a_prober_the_factory_refuses() {
    assert_eq!(
        exit_codes_across_every_surface(EMPTY_PORTS_SCENARIO, "empty-ports.yml").await,
        vec![Some(1); 3],
        "a port-less prober must be refused by every surface"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn validate_dry_run_and_scan_agree_on_a_classifier_the_factory_refuses() {
    assert_eq!(
        exit_codes_across_every_surface(BAD_CLASSIFIER_SCENARIO, "bad-classifier.yml").await,
        vec![Some(1); 3],
        "an uncompilable classifier pattern must be refused by every surface"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn validate_dry_run_and_scan_agree_on_a_backwards_range_target() {
    assert_eq!(
        exit_codes_across_every_surface(BACKWARDS_RANGE_SCENARIO, "backwards-range.yml").await,
        vec![Some(1); 3],
        "a range whose start exceeds its end must be refused by every surface"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn dry_run_plans_the_valid_scenarios_around_an_invalid_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = "version: 1\nkind: discovery\ndefaults:\n  timeout_ms: 500\nscenarios:\n  - signal_type: discover\n    name: good-one\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22222]\n  - signal_type: discover\n    name: bad-fuser\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22222]\n    fuser:\n      type: direct\n      confidence_baseline: 2.0\n  - signal_type: discover\n    name: good-two\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22222]\n";
    let path = write_yaml(&dir, "multi-mixed.yml", yaml);

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

    assert_eq!(
        output.status.code(),
        Some(1),
        "a file carrying one invalid scenario must exit 1"
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(
        stdout.contains("would run 2 scenarios")
            && stdout.contains("good-one")
            && stdout.contains("good-two"),
        "the survivors must still be planned: {stdout}"
    );
    assert!(
        !stdout.contains("bad-fuser"),
        "the refused scenario must not be rendered as a runnable plan: {stdout}"
    );
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("bad-fuser") && stderr.contains("confidence_baseline"),
        "stderr must name the refused scenario and the reason: {stderr}"
    );
    assert!(
        stderr.contains("1 of 3 scenario(s) failed"),
        "the tally must match the run's: {stderr}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn the_run_and_the_dry_run_skip_the_same_prober_less_scenario() {
    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: no-probers\n    timeout_ms: 500\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers: []\n";
    let path = write_yaml(&dir, "skip-parity.yml", yaml);

    let mut outcomes = Vec::new();
    for extra in [Vec::new(), vec!["--dry-run".to_string()]] {
        let path = path.clone();
        let output = tokio::task::spawn_blocking(move || {
            common::rastreo()
                .args(["discover", "--file"])
                .arg(&path)
                .args(&extra)
                .output()
                .expect("spawn rastreo")
        })
        .await
        .expect("join");
        let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
        outcomes.push((
            output.status.code(),
            stderr.contains("'no-probers' (1 of 1): no probers configured, skipping"),
        ));
    }

    assert_eq!(
        outcomes[0], outcomes[1],
        "the run and the dry-run must skip the same scenario the same way"
    );
    assert_eq!(
        outcomes[0],
        (Some(1), true),
        "the only scenario was skipped, so nothing was probed and the notice explains why"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn dry_run_of_a_file_of_nothing_but_prober_less_scenarios_refuses() {
    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: no-probers\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers: []\n";
    let path = write_yaml(&dir, "no-probers.yml", yaml);

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

    assert_eq!(
        output.status.code(),
        Some(1),
        "a plan that would probe nothing is not a runnable plan"
    );
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("no probers configured, skipping"),
        "stderr must name the skipped scenario: {stderr}"
    );
    assert!(
        stderr.contains("every scenario in") && stderr.contains("nothing to probe"),
        "stderr must say why the rehearsal failed: {stderr}"
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(
        stdout.contains("would run 0 scenarios"),
        "a skipped scenario must not be counted as runnable: {stdout}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn one_probed_scenario_is_enough_for_a_file_that_also_skips_one() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = format!("version: 1\nkind: discovery\ndefaults:\n  timeout_ms: 500\n  sink:\n    type: stdout\nscenarios:\n  - signal_type: discover\n    name: placeholder\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers: []\n  - signal_type: discover\n    name: real\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n");
    let path = write_yaml(&dir, "one-of-each.yml", &yaml);

    for extra in [Vec::new(), vec!["--dry-run".to_string()]] {
        let path = path.clone();
        let output = tokio::task::spawn_blocking(move || {
            common::rastreo()
                .args(["discover", "--file"])
                .arg(&path)
                .args(&extra)
                .output()
                .expect("spawn rastreo")
        })
        .await
        .expect("join");
        let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
        assert_eq!(
            output.status.code(),
            Some(0),
            "a file that probed one of its two scenarios ran; stderr: {stderr}"
        );
        assert!(
            stderr.contains("'placeholder' (1 of 2): no probers configured, skipping"),
            "the skipped scenario is still explained: {stderr}"
        );
    }
    drop(listener);
}

async fn dry_run_then_scan(args: Vec<String>) -> Vec<(Option<i32>, String)> {
    let mut outcomes = Vec::new();
    for extra in [vec!["--dry-run".to_string()], Vec::new()] {
        let args = args.clone();
        let output = tokio::task::spawn_blocking(move || {
            common::rastreo()
                .args(&args)
                .args(&extra)
                .output()
                .expect("spawn rastreo")
        })
        .await
        .expect("join");
        outcomes.push((
            output.status.code(),
            String::from_utf8(output.stderr).expect("utf-8 stderr"),
        ));
    }
    outcomes
}

fn assert_both_refuse(outcomes: &[(Option<i32>, String)], needle: &str) {
    for (label, (code, stderr)) in ["dry-run", "scan"].iter().zip(outcomes) {
        assert_eq!(*code, Some(1), "the {label} must refuse; stderr: {stderr}");
        assert!(
            stderr.contains(needle),
            "the {label} must name '{needle}': {stderr}"
        );
    }
}

#[cfg(feature = "config")]
#[tokio::test]
async fn the_dry_run_and_the_scan_agree_a_scenario_is_not_resume_safe() {
    let dir = tempfile::tempdir().expect("tempdir");
    let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: cp-scenario\n    timeout_ms: 200\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22222]\n    sink:\n      type: stdout\n";
    let path = write_yaml(&dir, "resume-unsafe.yml", yaml);
    let checkpoint = dir.path().join("scan.checkpoint");

    let args = vec![
        "discover".to_string(),
        "--file".to_string(),
        path.to_string_lossy().into_owned(),
        "--checkpoint".to_string(),
        checkpoint.to_string_lossy().into_owned(),
    ];
    assert_both_refuse(&dry_run_then_scan(args).await, "not resume-safe");
    assert!(
        !checkpoint.exists(),
        "a refused checkpoint request must leave no file behind"
    );
}

const PRIOR_CHECKPOINT: &str = r#"{"checkpoint_version":1,"scan_id":"prior-scan","initiated_at":"2026-01-01T00:00:00Z","resume_fingerprint":"sha256:0000","source_config_hash":null,"dns_pins":[],"highest_flushed_index":0}"#;

#[cfg(feature = "config")]
#[tokio::test]
async fn the_dry_run_and_the_scan_agree_a_checkpoint_path_is_occupied() {
    let dir = tempfile::tempdir().expect("tempdir");
    let records = dir.path().join("records.ndjson");
    let yaml = format!("version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: cp-scenario\n    timeout_ms: 200\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22222]\n    sink:\n      type: file\n      path: \"{}\"\n", records.display());
    let path = write_yaml(&dir, "resume-safe.yml", &yaml);
    let checkpoint = dir.path().join("scan.checkpoint");
    std::fs::write(&checkpoint, PRIOR_CHECKPOINT).expect("occupy checkpoint path");

    let args = vec![
        "discover".to_string(),
        "--file".to_string(),
        path.to_string_lossy().into_owned(),
        "--checkpoint".to_string(),
        checkpoint.to_string_lossy().into_owned(),
    ];
    assert_both_refuse(
        &dry_run_then_scan(args).await,
        "a checkpoint already exists",
    );
    assert_eq!(
        std::fs::read_to_string(&checkpoint).expect("read checkpoint"),
        PRIOR_CHECKPOINT,
        "neither surface may clobber the checkpoint it refused over"
    );
}

#[tokio::test]
async fn the_flag_driven_dry_run_and_scan_agree_a_scenario_is_not_resume_safe() {
    let dir = tempfile::tempdir().expect("tempdir");
    let checkpoint = dir.path().join("scan.checkpoint");

    let args = vec![
        "discover".to_string(),
        "--target".to_string(),
        "127.0.0.1".to_string(),
        "--port".to_string(),
        "22222".to_string(),
        "--timeout-ms".to_string(),
        "200".to_string(),
        "--checkpoint".to_string(),
        checkpoint.to_string_lossy().into_owned(),
    ];
    assert_both_refuse(&dry_run_then_scan(args).await, "not resume-safe");
    assert!(
        !checkpoint.exists(),
        "a refused checkpoint request must leave no file behind"
    );
}

#[tokio::test]
async fn the_flag_driven_dry_run_and_scan_agree_a_checkpoint_path_is_occupied() {
    let dir = tempfile::tempdir().expect("tempdir");
    let checkpoint = dir.path().join("scan.checkpoint");
    std::fs::write(&checkpoint, PRIOR_CHECKPOINT).expect("occupy checkpoint path");
    let records = dir.path().join("records.ndjson");

    let args = vec![
        "discover".to_string(),
        "--target".to_string(),
        "127.0.0.1".to_string(),
        "--port".to_string(),
        "22222".to_string(),
        "--timeout-ms".to_string(),
        "200".to_string(),
        "--sink".to_string(),
        "file".to_string(),
        "--output".to_string(),
        records.to_string_lossy().into_owned(),
        "--checkpoint".to_string(),
        checkpoint.to_string_lossy().into_owned(),
    ];
    assert_both_refuse(
        &dry_run_then_scan(args).await,
        "a checkpoint already exists",
    );
    assert!(
        !records.exists(),
        "a refused checkpoint request must not open the sink"
    );
}

#[tokio::test]
async fn a_resume_with_nothing_to_resume_names_the_concept_and_hints_the_flag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let checkpoint = dir.path().join("absent.checkpoint");

    let args = vec![
        "discover".to_string(),
        "--target".to_string(),
        "127.0.0.1".to_string(),
        "--port".to_string(),
        "22222".to_string(),
        "--timeout-ms".to_string(),
        "200".to_string(),
        "--checkpoint".to_string(),
        checkpoint.to_string_lossy().into_owned(),
        "--resume".to_string(),
    ];
    let outcomes = dry_run_then_scan(args).await;
    assert_both_refuse(&outcomes, "no checkpoint to resume");
    for (label, (_, stderr)) in ["dry-run", "scan"].iter().zip(&outcomes) {
        assert!(
            stderr.contains("hint: --resume continues a checkpoint"),
            "the {label} must map the refusal back to the flag that caused it: {stderr}"
        );
    }
}

#[cfg(feature = "config")]
#[tokio::test]
async fn the_dry_run_and_the_scan_agree_a_resume_needs_a_single_scenario() {
    let dir = tempfile::tempdir().expect("tempdir");
    let records = dir.path().join("records.ndjson");
    let yaml = format!("version: 1\nkind: discovery\ndefaults:\n  timeout_ms: 200\n  sink:\n    type: file\n    path: \"{}\"\nscenarios:\n  - signal_type: discover\n    name: first\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22222]\n  - signal_type: discover\n    name: second\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [22223]\n", records.display());
    let path = write_yaml(&dir, "multi-resume.yml", &yaml);
    let checkpoint = dir.path().join("scan.checkpoint");

    let args = vec![
        "discover".to_string(),
        "--file".to_string(),
        path.to_string_lossy().into_owned(),
        "--checkpoint".to_string(),
        checkpoint.to_string_lossy().into_owned(),
        "--resume".to_string(),
    ];
    assert_both_refuse(
        &dry_run_then_scan(args).await,
        "--checkpoint supports a single-scenario run",
    );
}

// Not a `validate` surface: the host cap belongs to the resolver instance, not to the scenario.
const RESOLVER_REFUSALS: &[(&str, &str, &str)] = &[
    (
        "10.0.0.0/8",
        "      - Cidr: \"10.0.0.0/8\"\n",
        "exceeds the configured limit",
    ),
    (
        "10.0.0.1-10.9.0.1",
        "      - Range:\n          start: \"10.0.0.1\"\n          end: \"10.9.0.1\"\n",
        "exceeds the configured limit",
    ),
];

#[tokio::test]
async fn the_dry_run_and_the_scan_both_name_overlapping_target_specs() {
    let args = vec![
        "discover".to_string(),
        "--target".to_string(),
        "127.0.0.0/30".to_string(),
        "--target".to_string(),
        "127.0.0.1".to_string(),
        "--port".to_string(),
        "22222".to_string(),
        "--timeout-ms".to_string(),
        "200".to_string(),
    ];
    for (label, (code, stderr)) in ["dry-run", "scan"]
        .iter()
        .zip(&dry_run_then_scan(args).await)
    {
        assert_eq!(*code, Some(0), "{label}: {stderr}");
        assert!(
            stderr.contains("target specs overlap"),
            "the {label} must name specs whose addresses are probed twice: {stderr}"
        );
    }
}

#[tokio::test]
async fn the_flag_driven_dry_run_and_scan_agree_on_every_resolver_refusal() {
    for (target, _, needle) in RESOLVER_REFUSALS {
        let args = vec![
            "discover".to_string(),
            "--target".to_string(),
            "127.0.0.1".to_string(),
            "--target".to_string(),
            (*target).to_string(),
            "--port".to_string(),
            "22222".to_string(),
            "--timeout-ms".to_string(),
            "200".to_string(),
        ];
        assert_both_refuse(&dry_run_then_scan(args).await, needle);
    }
}

#[cfg(feature = "config")]
#[tokio::test]
async fn the_dry_run_and_the_scan_agree_on_every_resolver_refusal() {
    for (label, yaml_target, needle) in RESOLVER_REFUSALS {
        let dir = tempfile::tempdir().expect("tempdir");
        let yaml = format!("version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: over-cap\n    timeout_ms: 200\n    targets:\n      - Ip: \"127.0.0.1\"\n{yaml_target}    probers:\n      - type: tcp_connect\n        ports: [22222]\n");
        let path = write_yaml(&dir, "over-cap.yml", &yaml);
        let args = vec![
            "discover".to_string(),
            "--file".to_string(),
            path.to_string_lossy().into_owned(),
        ];
        let outcomes = dry_run_then_scan(args).await;
        assert_both_refuse(&outcomes, needle);
        for (code, stderr) in &outcomes {
            assert_eq!(*code, Some(1), "{label}: {stderr}");
            assert!(
                stderr.contains("1 of 1 scenario(s) failed"),
                "{label}: both surfaces tally the scenario as failed: {stderr}"
            );
        }
    }
}

#[tokio::test]
async fn the_dry_run_names_the_refusing_target_before_it_refuses() {
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args([
                "discover",
                "--target",
                "127.0.0.1",
                "--target",
                "10.0.0.0/8",
                "--port",
                "22222",
                "--timeout-ms",
                "200",
                "--dry-run",
            ])
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(
        stdout.contains("10.0.0.0/8 → <error:") && stdout.contains("127.0.0.1 → 127.0.0.1"),
        "the plan must say which target refused and which resolved: {stdout}"
    );
}

#[cfg(feature = "kafka")]
#[tokio::test]
async fn dry_run_refuses_a_record_format_the_sink_cannot_carry() {
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
                "--format",
                "table",
                "--dry-run",
            ])
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert!(
        !output.status.success(),
        "a format the sink cannot carry must fail the dry-run as it fails the scan"
    );
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("table encoder"),
        "stderr must name the refused encoder: {stderr}"
    );
}
