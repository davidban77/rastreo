#![cfg(unix)]

mod common;

use std::fs::File;
use std::io::Read;
use std::net::TcpListener;
use std::process::{Command, Stdio};

// `--dns-query` with no dns probe earns a note, so every run here has an advisory to place.
fn scan_of_one_open_port(port: u16, extra: &[&str]) -> Command {
    let mut cmd = common::rastreo();
    cmd.args([
        "discover",
        "--target",
        "127.0.0.1",
        "--probe",
        "tcp_connect",
        "--port",
        &port.to_string(),
        "--dns-query",
        "example.com",
        "--timeout-ms",
        "500",
    ])
    .args(extra);
    cmd
}

fn open_port(listener: &TcpListener) -> u16 {
    listener.local_addr().expect("local_addr").port()
}

// `rastreo ... > capture 2>&1`
fn merged_redirect(mut cmd: Command) -> (std::process::ExitStatus, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("capture.txt");
    let capture = File::create(&path).expect("create the capture file");

    cmd.stdout(Stdio::from(capture.try_clone().expect("dup the capture")));
    cmd.stderr(Stdio::from(capture));
    let status = cmd.status().expect("spawn rastreo");
    let captured = std::fs::read_to_string(&path).expect("read the capture file");
    (status, captured)
}

fn capture_a_merged_redirect(extra: &[&str]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let (status, captured) = merged_redirect(scan_of_one_open_port(open_port(&listener), extra));
    drop(listener);

    assert!(
        status.success(),
        "rastreo exited with {status:?}: {captured}"
    );
    captured
}

// `rastreo ... 2>&1 | jq`
fn capture_a_merged_pipe(extra: &[&str]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let (mut reader, writer) = std::io::pipe().expect("pipe");

    let mut cmd = scan_of_one_open_port(open_port(&listener), extra);
    cmd.stdout(Stdio::from(writer.try_clone().expect("dup the pipe")));
    cmd.stderr(Stdio::from(writer));
    let mut child = cmd.spawn().expect("spawn rastreo");
    // Every parent-side handle on the write end must go, or the read below never sees end-of-stream.
    drop(cmd);

    let mut captured = String::new();
    reader.read_to_string(&mut captured).expect("read the pipe");
    let status = child.wait().expect("wait for rastreo");
    drop(listener);

    assert!(
        status.success(),
        "rastreo exited with {status:?}: {captured}"
    );
    captured
}

fn assert_every_line_is_a_record(captured: &str) {
    let lines: Vec<&str> = captured.lines().filter(|line| !line.is_empty()).collect();
    assert!(!lines.is_empty(), "the scan emitted no records at all");
    for line in &lines {
        serde_json::from_str::<serde_json::Value>(line)
            .unwrap_or_else(|e| panic!("a consumer parsing this stream reads {line:?}: {e}"));
    }
    assert!(
        lines.iter().any(|line| line.contains("\"identity_key\"")),
        "expected the scanned host's record: {lines:#?}"
    );
}

#[test]
fn a_json_scan_redirected_into_one_file_carries_nothing_but_records() {
    assert_every_line_is_a_record(&capture_a_merged_redirect(&["--format", "json"]));
}

#[test]
fn a_json_scan_piped_through_one_pipe_carries_nothing_but_records() {
    assert_every_line_is_a_record(&capture_a_merged_pipe(&["--format", "json"]));
}

#[test]
fn a_json_scan_keeps_its_advisories_when_the_streams_stay_apart() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let output = scan_of_one_open_port(open_port(&listener), &["--format", "json"])
        .output()
        .expect("spawn rastreo");
    drop(listener);

    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("--dns-query"),
        "a separate stderr cannot corrupt the record stream: {stderr:?}"
    );
    assert_every_line_is_a_record(&String::from_utf8(output.stdout).expect("utf-8 stdout"));
}

#[test]
fn a_table_scan_redirected_into_one_file_keeps_its_advisories() {
    let captured = capture_a_merged_redirect(&["--format", "table"]);
    assert!(
        captured.contains("--dns-query"),
        "a capture nobody parses is read like a terminal: {captured:?}"
    );
    assert!(captured.contains("ADDRESS"), "{captured:?}");
}

#[cfg(feature = "config")]
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    open_port(&listener)
}

fn assert_refused(status: std::process::ExitStatus, captured: &str) {
    assert_eq!(
        status.code(),
        Some(1),
        "a run whose capture carries a diagnosis must exit non-zero: {captured}"
    );
}

#[test]
fn a_refused_run_puts_its_hint_in_the_merged_capture_beside_the_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let checkpoint = dir.path().join("absent.checkpoint");
    let mut cmd = common::rastreo();
    cmd.args([
        "discover",
        "--target",
        "127.0.0.1",
        "--port",
        "22222",
        "--timeout-ms",
        "200",
        "--format",
        "json",
        "--checkpoint",
        &checkpoint.display().to_string(),
        "--resume",
    ]);

    let (status, captured) = merged_redirect(cmd);
    assert_refused(status, &captured);
    assert!(
        captured.contains("no checkpoint to resume"),
        "the refusal itself: {captured:?}"
    );
    assert!(
        captured.contains("hint: --resume continues"),
        "the diagnosis travels with the error it explains: {captured:?}"
    );
}

#[test]
fn a_selection_refusal_puts_its_hint_in_the_merged_capture_beside_the_error() {
    let mut cmd = common::rastreo();
    cmd.args([
        "discover",
        "--target",
        "127.0.0.1",
        "--probe",
        "dns",
        "--format",
        "json",
    ]);

    let (status, captured) = merged_redirect(cmd);
    assert_refused(status, &captured);
    assert!(
        captured.contains("hint: pass --dns-query"),
        "the diagnosis travels with the error it explains: {captured:?}"
    );
}

#[test]
fn a_dry_run_with_nothing_to_probe_puts_its_hint_in_the_merged_capture() {
    let mut cmd = common::rastreo();
    cmd.args([
        "discover",
        "--target",
        "nx-does-not-exist-4f1c8a2e.example.invalid",
        "--port",
        "22",
        "--dry-run",
        "--format",
        "json",
    ]);

    let (status, captured) = merged_redirect(cmd);
    assert_refused(status, &captured);
    assert!(
        captured.contains("hint: Either the network answered that these names have no addresses"),
        "the diagnosis travels with the error it explains: {captured:?}"
    );
}

#[cfg(feature = "config")]
#[test]
fn a_partly_failed_multi_scenario_run_keeps_its_hint_in_the_merged_capture() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let dir = tempfile::tempdir().expect("tempdir");
    let scan = dir.path().join("scan.yml");
    std::fs::write(
        &scan,
        format!(
            "version: 1
kind: discovery
defaults:
  timeout_ms: 500
  sink:
    type: stdout
scenarios:
  - signal_type: discover
    name: good
    targets:
      - Ip: \"127.0.0.1\"
    probers:
      - type: tcp_connect
        ports: [{}]
  - signal_type: discover
    name: bad
    targets:
      - DnsName: \"nx-does-not-exist-6b30d17c.example.invalid\"
    probers:
      - type: tcp_connect
        ports: [22]
",
            open_port(&listener)
        ),
    )
    .expect("write the scenario file");

    let mut cmd = common::rastreo();
    cmd.args([
        "discover",
        "--file",
        &scan.display().to_string(),
        "--format",
        "json",
    ]);
    let (status, captured) = merged_redirect(cmd);
    drop(listener);

    assert_refused(status, &captured);
    assert!(
        captured.contains("\"identity_key\""),
        "the run produced records before it refused: {captured:?}"
    );
    assert!(
        captured.contains("hint: Either the network answered that these names have no addresses"),
        "the diagnosis travels with the error it explains: {captured:?}"
    );
    assert!(
        captured.contains("1 of 2 scenario(s) failed"),
        "the top-level refusal: {captured:?}"
    );
}

#[cfg(feature = "config")]
#[test]
fn a_scenario_writing_its_records_to_a_file_keeps_its_advisories_in_the_merged_capture() {
    let dir = tempfile::tempdir().expect("tempdir");
    let records = dir.path().join("records.ndjson");
    let scan = dir.path().join("scan.yml");
    std::fs::write(
        &scan,
        format!(
            "version: 1
kind: discovery
scenarios:
  - signal_type: discover
    name: to-a-file
    timeout_ms: 200
    sink:
      type: file
      path: \"{}\"
    targets:
      - Ip: \"127.0.0.1\"
    probers:
      - type: tcp_connect
        ports: [{}]
",
            records.display(),
            free_port()
        ),
    )
    .expect("write the scenario file");

    let mut cmd = common::rastreo();
    cmd.args([
        "discover",
        "--file",
        &scan.display().to_string(),
        "--format",
        "json",
    ]);
    let (status, captured) = merged_redirect(cmd);

    assert!(
        status.success(),
        "rastreo exited with {status:?}: {captured}"
    );
    assert!(
        captured.contains("hint: 0 records emitted"),
        "no record reaches this capture, so nothing there can be corrupted: {captured:?}"
    );
}

#[test]
fn a_json_scan_writing_records_elsewhere_keeps_its_advisories_in_the_capture() {
    let dir = tempfile::tempdir().expect("tempdir");
    let records = dir.path().join("records.ndjson");
    let captured = capture_a_merged_redirect(&[
        "--format",
        "json",
        "--sink",
        "file",
        "--output",
        &records.display().to_string(),
    ]);
    assert!(
        captured.contains("--dns-query"),
        "no records reach this capture, so nothing there can be corrupted: {captured:?}"
    );
    assert!(
        std::fs::read_to_string(&records)
            .expect("read the sink file")
            .contains("\"identity_key\""),
        "the records went to the file sink"
    );
}
