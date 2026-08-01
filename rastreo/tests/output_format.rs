mod common;

use std::process::Output;

async fn scan_open_port(extra: &[&str]) -> (Output, u16) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local_addr").port();

    let owned: Vec<String> = extra.iter().map(|s| (*s).to_string()).collect();
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args([
                "discover",
                "--target",
                "127.0.0.1",
                "--probe",
                "tcp_connect",
                "--port",
                &port.to_string(),
                "--timeout-ms",
                "500",
            ])
            .args(&owned)
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
    (output, port)
}

const TABLE_HEADER: &str =
    "ADDRESS                      NAME                      PLATFORM              PORTS";

#[tokio::test]
async fn stdout_renders_the_table_with_no_format_flag() {
    let (output, port) = scan_open_port(&[]).await;
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let lines: Vec<&str> = stdout.lines().collect();

    assert_eq!(lines.len(), 2, "expected a header and one row: {lines:#?}");
    assert_eq!(lines[0], TABLE_HEADER);
    assert_eq!(
        lines[1],
        format!(
            "127.0.0.1                    -                         -                     {port}"
        )
    );
}

#[tokio::test]
async fn format_table_renders_the_same_grid_as_the_default() {
    let (output, _) = scan_open_port(&["--format", "table"]).await;
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert_eq!(stdout.lines().next(), Some(TABLE_HEADER));
}

#[tokio::test]
async fn format_text_is_an_alias_for_table() {
    let (output, _) = scan_open_port(&["--format", "text"]).await;
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert_eq!(stdout.lines().next(), Some(TABLE_HEADER));
}

#[tokio::test]
async fn format_json_emits_one_compact_ndjson_object_per_record() {
    let (output, port) = scan_open_port(&["--format", "json"]).await;
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");

    assert!(
        stdout.starts_with("{\"identity_key\":\"ip:127.0.0.1\",\"mgmt_ip\":\"127.0.0.1\","),
        "the ndjson encoder writes compact JSON in field order: {stdout:?}"
    );
    assert!(
        stdout.ends_with("}\n"),
        "every record is terminated by exactly one newline: {stdout:?}"
    );
    assert_eq!(stdout.matches('\n').count(), 1, "{stdout:?}");

    let line = stdout.trim_end_matches('\n');
    assert_eq!(line, line.trim(), "no padding around the object: {line:?}");
    assert!(
        !line.contains("\": "),
        "compact separators, never pretty-printed: {line:?}"
    );

    let mut cursor = 0;
    for field in [
        "identity_key",
        "mgmt_ip",
        "mac",
        "manufacturer",
        "platform",
        "os_version",
        "role",
        "confidence",
        "last_seen",
        "signals",
        "probe_kinds",
        "schema_version",
        "schema_id",
        "possible_alias_of",
        "scan_metadata",
    ] {
        let needle = format!("\"{field}\":");
        let at = line[cursor..]
            .find(&needle)
            .unwrap_or_else(|| panic!("{field} out of order or missing in {line:?}"));
        cursor += at + needle.len();
    }

    let value: serde_json::Value = serde_json::from_str(line).expect("parse ndjson line");
    let signals = value
        .get("signals")
        .and_then(|v| v.as_array())
        .expect("signals");
    assert!(
        signals
            .iter()
            .any(|s| s.get("OpenPort").and_then(|v| v.as_u64()) == Some(u64::from(port))),
        "{signals:?}"
    );
}

#[tokio::test]
async fn format_ndjson_is_an_alias_for_json() {
    let (output, _) = scan_open_port(&["--format", "ndjson"]).await;
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(stdout.starts_with('{'), "{stdout:?}");
}

#[tokio::test]
async fn format_json_leaves_stderr_free_of_banners() {
    let (output, _) = scan_open_port(&["--format", "json"]).await;
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        !stderr.contains("discover  targets:"),
        "start banner survived --format json: {stderr}"
    );
    assert!(
        !stderr.contains("completed in"),
        "completion banner survived --format json: {stderr}"
    );
}

#[tokio::test]
async fn the_default_format_keeps_the_banners() {
    let (output, _) = scan_open_port(&[]).await;
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("discover  targets:"),
        "start banner missing: {stderr}"
    );
}

#[tokio::test]
async fn verbose_restores_the_banners_under_format_json() {
    let (output, _) = scan_open_port(&["--format", "json", "-v"]).await;
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("discover  targets:"),
        "-v must bring the banners back: {stderr}"
    );
}

#[tokio::test]
async fn format_json_keeps_the_hint_when_nothing_answered() {
    let output = tokio::task::spawn_blocking(|| {
        common::rastreo()
            .args([
                "discover",
                "--target",
                "192.0.2.1",
                "--probe",
                "tcp_connect",
                "--port",
                "1",
                "--format",
                "json",
                "--timeout-ms",
                "100",
            ])
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout).expect("utf-8").is_empty(),
        "stdout must stay a clean record stream"
    );
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("hint: 0 records emitted"),
        "the hint is the most useful output of an empty scan: {stderr}"
    );
    assert!(
        !stderr.contains("completed in"),
        "the banner is still suppressed: {stderr}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn format_json_keeps_the_skip_notice_when_a_scenario_has_no_probers() {
    let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: empty\n    sink:\n      type: stdout\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers: []\n";
    let output = run_scenario(yaml, &["--format", "json"]).await;

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stdout).expect("utf-8").is_empty(),
        "stdout must stay a clean record stream"
    );
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("no probers configured, skipping"),
        "a scan that explains nothing is worse than no scan: {stderr}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn quiet_still_silences_the_skip_notice_but_not_the_failure() {
    let yaml = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: empty\n    sink:\n      type: stdout\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers: []\n";
    let output = run_scenario(yaml, &["-q"]).await;

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        !stderr.contains("no probers configured, skipping"),
        "-q silences the notice: {stderr}"
    );
    assert!(
        stderr.contains("nothing to probe"),
        "-q silences status output, not failures: {stderr}"
    );
    assert_eq!(
        stderr.lines().count(),
        1,
        "the failure is the whole of what -q leaves behind: {stderr}"
    );
}

#[tokio::test]
async fn quiet_stays_silent_under_the_table_default() {
    let (output, _) = scan_open_port(&["-q"]).await;
    assert!(
        output.stderr.is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert_eq!(stdout.lines().next(), Some(TABLE_HEADER));
}

#[test]
fn output_without_a_file_sink_is_refused_before_probing() {
    let output = common::rastreo()
        .args([
            "discover",
            "--target",
            "127.0.0.1",
            "--output",
            "/tmp/rastreo-should-not-exist.txt",
        ])
        .output()
        .expect("spawn rastreo");

    assert!(!output.status.success(), "--output alone must fail");
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(stderr.contains("--sink file"), "stderr: {stderr}");
    assert!(
        !std::path::Path::new("/tmp/rastreo-should-not-exist.txt").exists(),
        "the run must fail before any sink is opened"
    );
}

#[cfg(feature = "kafka")]
#[test]
fn broker_flags_without_a_broker_sink_are_refused_before_probing() {
    let output = common::rastreo()
        .args([
            "discover",
            "--target",
            "127.0.0.1",
            "--brokers",
            "127.0.0.1:9092",
            "--topic",
            "t",
        ])
        .output()
        .expect("spawn rastreo");

    assert!(
        !output.status.success(),
        "a broker flag under a stdout sink must fail"
    );
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(stderr.contains("--brokers"), "stderr: {stderr}");
    assert!(stderr.contains("--sink kafka"), "stderr: {stderr}");
}

#[cfg(not(feature = "kafka"))]
#[test]
fn broker_flags_do_not_exist_without_the_kafka_feature() {
    let output = common::rastreo()
        .args([
            "discover",
            "--target",
            "127.0.0.1",
            "--brokers",
            "127.0.0.1:9092",
        ])
        .output()
        .expect("spawn rastreo");

    assert!(
        !output.status.success(),
        "no sink in this build can consume --brokers"
    );
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("--brokers"),
        "the parser must name the unknown flag: {stderr}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn output_alongside_a_scenario_file_is_refused_before_probing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_yaml(&dir, "scan.yml", &stdout_scenario(9));
    let records = dir.path().join("records.ndjson");

    let out = records.clone();
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args(["discover", "--file"])
            .arg(&path)
            .arg("--output")
            .arg(&out)
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    assert!(
        !output.status.success(),
        "--output never reaches a scenario's own sink"
    );
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(stderr.contains("--sink file"), "stderr: {stderr}");
    assert!(!records.exists(), "the run must fail before any sink opens");
}

#[tokio::test]
async fn output_with_a_file_sink_writes_ndjson() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let dir = tempfile::tempdir().expect("tempdir");
    let records = dir.path().join("records.ndjson");

    let path = records.clone();
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args([
                "discover",
                "--target",
                "127.0.0.1",
                "--probe",
                "tcp_connect",
                "--port",
                &port.to_string(),
                "--timeout-ms",
                "500",
                "--sink",
                "file",
                "--output",
            ])
            .arg(&path)
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    drop(listener);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let written = std::fs::read_to_string(&records).expect("read records");
    assert!(
        written.starts_with('{'),
        "a file sink keeps machine records by default: {written:?}"
    );
}

#[tokio::test]
async fn format_table_writes_the_grid_into_the_file_sink() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let dir = tempfile::tempdir().expect("tempdir");
    let records = dir.path().join("records.txt");

    let path = records.clone();
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args([
                "discover",
                "--target",
                "127.0.0.1",
                "--probe",
                "tcp_connect",
                "--port",
                &port.to_string(),
                "--timeout-ms",
                "500",
                "--format",
                "table",
                "--sink",
                "file",
                "--output",
            ])
            .arg(&path)
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    drop(listener);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let written = std::fs::read_to_string(&records).expect("read records");
    assert_eq!(written.lines().next(), Some(TABLE_HEADER));
}

#[test]
fn format_json_with_dry_run_emits_the_plan_array() {
    let output = common::rastreo()
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
        .expect("spawn rastreo");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let plans: serde_json::Value = serde_json::from_str(&stdout).expect("plan array");
    assert_eq!(plans[0]["scenario"], "discovery");
}

#[test]
fn the_default_format_keeps_the_text_dry_run_plan() {
    let output = common::rastreo()
        .args([
            "discover",
            "--target",
            "127.0.0.1",
            "--probe",
            "tcp_connect",
            "--port",
            "22",
            "--dry-run",
        ])
        .output()
        .expect("spawn rastreo");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(
        stdout.contains("[dry-run] would run 1 scenario"),
        "{stdout}"
    );
}

#[tokio::test]
async fn rastreo_format_env_var_selects_the_record_format() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .env("RASTREO_FORMAT", "json")
            .args([
                "discover",
                "--target",
                "127.0.0.1",
                "--probe",
                "tcp_connect",
                "--port",
                &port.to_string(),
                "--timeout-ms",
                "500",
            ])
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    drop(listener);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(stdout.starts_with('{'), "{stdout:?}");
}

#[tokio::test]
async fn the_format_flag_beats_the_env_var() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();

    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .env("RASTREO_FORMAT", "json")
            .args([
                "discover",
                "--target",
                "127.0.0.1",
                "--probe",
                "tcp_connect",
                "--port",
                &port.to_string(),
                "--timeout-ms",
                "500",
                "--format",
                "table",
            ])
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");

    drop(listener);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert_eq!(stdout.lines().next(), Some(TABLE_HEADER));
}

#[cfg(feature = "config")]
fn write_yaml(dir: &tempfile::TempDir, name: &str, contents: &str) -> std::path::PathBuf {
    use std::io::Write as _;
    let path = dir.path().join(name);
    let mut f = std::fs::File::create(&path).expect("create yaml");
    f.write_all(contents.as_bytes()).expect("write yaml");
    path
}

#[cfg(feature = "config")]
fn stdout_scenario(port: u16) -> String {
    format!(
        "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    timeout_ms: 500\n    sink:\n      type: stdout\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n"
    )
}

#[cfg(feature = "config")]
async fn run_scenario(yaml: &str, extra: &[&str]) -> Output {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_yaml(&dir, "scan.yml", yaml);
    let owned: Vec<String> = extra.iter().map(|s| (*s).to_string()).collect();
    tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args(["discover", "--file"])
            .arg(&path)
            .args(&owned)
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join")
}

#[cfg(feature = "config")]
#[tokio::test]
async fn a_scenario_without_an_encoder_renders_the_table_on_stdout() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let output = run_scenario(&stdout_scenario(port), &[]).await;
    drop(listener);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert_eq!(
        stdout.lines().next(),
        Some(TABLE_HEADER),
        "the destination decides on both surfaces: {stdout:?}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn a_scenario_without_an_encoder_keeps_ndjson_in_a_file() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let dir = tempfile::tempdir().expect("tempdir");
    let records = dir.path().join("records.ndjson");
    let yaml = format!(
        "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    timeout_ms: 500\n    sink:\n      type: file\n      path: {}\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n",
        records.display()
    );
    let output = run_scenario(&yaml, &[]).await;
    drop(listener);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let written = std::fs::read_to_string(&records).expect("read records");
    assert!(
        written.starts_with('{'),
        "only stdout is read by a person: {written:?}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn a_scenario_sink_overridden_to_a_file_drops_the_table_default() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let dir = tempfile::tempdir().expect("tempdir");
    let records = dir.path().join("records.ndjson");
    let path = write_yaml(&dir, "scan.yml", &stdout_scenario(port));

    let out = records.clone();
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .args(["discover", "--file"])
            .arg(&path)
            .args(["--sink", "file", "--output"])
            .arg(&out)
            .output()
            .expect("spawn rastreo")
    })
    .await
    .expect("join");
    drop(listener);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let written = std::fs::read_to_string(&records).expect("read records");
    assert!(
        written.starts_with('{'),
        "the merged sink decides, not the scenario's own: {written:?}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn format_table_overrides_a_scenario_encoder() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let yaml = format!(
        "{}    encoder:\n      type: ndjson\n",
        stdout_scenario(port)
    );
    let output = run_scenario(&yaml, &["--format", "table"]).await;
    drop(listener);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert_eq!(stdout.lines().next(), Some(TABLE_HEADER));
}

#[cfg(feature = "config")]
#[tokio::test]
async fn an_absent_format_leaves_a_scenario_table_encoder_at_its_own_width() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let yaml = format!(
        "{}    encoder:\n      type: table\n      width: 60\n",
        stdout_scenario(port)
    );
    let output = run_scenario(&yaml, &[]).await;
    drop(listener);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let header = stdout.lines().next().expect("header");
    assert_eq!(
        header.chars().count(),
        52,
        "the scenario's own width stands: {header:?}"
    );
}

#[cfg(feature = "config")]
#[tokio::test]
async fn rastreo_format_env_var_overrides_a_scenario_encoder() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let yaml = format!(
        "{}    encoder:\n      type: table\n      width: 60\n",
        stdout_scenario(port)
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_yaml(&dir, "scan.yml", &yaml);
    let output = tokio::task::spawn_blocking(move || {
        common::rastreo()
            .env("RASTREO_FORMAT", "json")
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
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(stdout.starts_with('{'), "{stdout:?}");
}

#[cfg(feature = "kafka")]
#[test]
fn format_table_into_a_broker_is_refused() {
    let output = common::rastreo()
        .args([
            "discover",
            "--target",
            "127.0.0.1",
            "--probe",
            "tcp_connect",
            "--port",
            "22",
            "--format",
            "table",
            "--sink",
            "kafka",
            "--brokers",
            "127.0.0.1:1",
            "--topic",
            "t",
        ])
        .output()
        .expect("spawn rastreo");

    assert!(!output.status.success(), "a table cannot reach a broker");
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(stderr.contains("table encoder"), "stderr: {stderr}");
}
