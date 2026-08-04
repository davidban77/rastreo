mod common;

use std::fs::File;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::Value;

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
        "--timeout-ms",
        "500",
    ])
    .args(extra);
    cmd
}

fn open_port(listener: &std::net::TcpListener) -> u16 {
    listener.local_addr().expect("local_addr").port()
}

// Every document the suite produces is checked against the contract, not just the one a test names.
fn read_report(path: &Path) -> Value {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read the report at {}: {e}", path.display()));
    let report: Value = serde_json::from_str(&raw).expect("the report is one JSON document");
    assert_tally_is_the_fold_over_the_entries(&report);
    report
}

fn assert_tally_is_the_fold_over_the_entries(report: &Value) {
    let entries = report["scenarios"].as_array().expect("array");
    let counts = &report["aggregate"]["scenario_counts"];
    for outcome in ["completed", "failed", "skipped"] {
        let folded = entries.iter().filter(|e| e["outcome"] == outcome).count();
        assert_eq!(
            counts[outcome], folded,
            "scenario_counts.{outcome} must be the fold over the entries: {report}"
        );
    }
    assert!(
        counts["total"].as_u64().expect("total") >= entries.len() as u64,
        "the run cannot have reached more scenarios than it was asked for: {report}"
    );
}

#[test]
fn a_scan_with_records_flowing_writes_a_report_and_leaves_stdout_byte_identical() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = open_port(&listener);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("run.json");

    let without = scan_of_one_open_port(port, &["--sink", "stdout"])
        .output()
        .expect("spawn rastreo");
    let with = scan_of_one_open_port(
        port,
        &["--sink", "stdout", "--run-report", &path.to_string_lossy()],
    )
    .output()
    .expect("spawn rastreo");
    drop(listener);

    assert!(with.status.success(), "the scan should exit 0");
    assert!(
        !with.stdout.is_empty(),
        "the run must have put records on stdout for the comparison to mean anything"
    );
    assert_eq!(
        with.stdout, without.stdout,
        "the report must not put a byte on the record stream"
    );

    let report = read_report(&path);
    assert_eq!(report["report_version"], 1);
    assert_eq!(report["scenarios"].as_array().expect("array").len(), 1);
    assert_eq!(report["scenarios"][0]["outcome"], "completed");
    assert_eq!(report["scenarios"][0]["summary"]["records_emitted"], 1);
    assert_eq!(report["aggregate"]["scenario_counts"]["total"], 1);
    assert_eq!(report["aggregate"]["scenario_counts"]["completed"], 1);
}

#[test]
fn a_quiet_scan_still_writes_the_report() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = open_port(&listener);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("run.json");

    let output = scan_of_one_open_port(
        port,
        &[
            "-q",
            "--format",
            "json",
            "--run-report",
            &path.to_string_lossy(),
        ],
    )
    .output()
    .expect("spawn rastreo");
    drop(listener);

    assert!(output.status.success(), "the scan should exit 0");
    assert!(
        output.stderr.is_empty(),
        "-q keeps stderr empty: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        read_report(&path)["scenarios"][0]["summary"]["records_emitted"],
        1
    );
}

// Records carry a per-run scan id and timestamp, so the invariant a merged capture can hold is that
// it stays nothing but the record stream — the same one `merged_streams.rs` pins.
#[cfg(unix)]
#[test]
fn a_merged_capture_carries_the_same_record_stream_with_and_without_a_report() {
    fn capture(port: u16, extra: &[&str], dir: &Path) -> String {
        let file = dir.join("capture.txt");
        let handle = File::create(&file).expect("create the capture file");
        let mut cmd = scan_of_one_open_port(port, extra);
        cmd.stdout(Stdio::from(handle.try_clone().expect("dup the capture")));
        cmd.stderr(Stdio::from(handle));
        cmd.status().expect("spawn rastreo");
        std::fs::read_to_string(&file).expect("read the capture file")
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = open_port(&listener);
    let plain = tempfile::tempdir().expect("tempdir");
    let reported = tempfile::tempdir().expect("tempdir");
    let path = reported.path().join("run.json");

    let without = capture(port, &["--format", "json"], plain.path());
    let with = capture(
        port,
        &["--format", "json", "--run-report", &path.to_string_lossy()],
        reported.path(),
    );
    drop(listener);

    let lines: Vec<&str> = with.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        without.lines().filter(|l| !l.is_empty()).count(),
        "the report added a line to the merged capture:\n{with}"
    );
    for line in &lines {
        let record: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("every merged line stays a record: {line} ({e})"));
        assert!(record["mgmt_ip"].is_string(), "{line}");
    }
    assert!(
        !with.contains("run.json"),
        "the report path must not reach the merged capture:\n{with}"
    );
    assert_eq!(
        read_report(&path)["aggregate"]["scenario_counts"]["completed"],
        1
    );
}

fn scan_of_an_unresolvable_target(extra: &[&str]) -> Command {
    let mut cmd = common::rastreo();
    cmd.args([
        "discover",
        "--target",
        "nx-does-not-exist-11d4e07a.example.invalid",
        "--probe",
        "tcp_connect",
        "--port",
        "22",
        "--timeout-ms",
        "500",
    ])
    .args(extra);
    cmd
}

#[test]
fn a_scenario_that_produced_a_summary_and_then_failed_is_named_failed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("run.json");

    let output = scan_of_an_unresolvable_target(&["--run-report", &path.to_string_lossy()])
        .output()
        .expect("spawn rastreo");

    assert_eq!(
        output.status.code(),
        Some(1),
        "a scan that probed nothing did not succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = read_report(&path);
    assert_eq!(report["scenarios"][0]["outcome"], "failed");
    assert_eq!(
        report["scenarios"][0]["summary"]["unresolvable_targets"][0],
        "nx-does-not-exist-11d4e07a.example.invalid"
    );
    assert_eq!(report["aggregate"]["scenario_counts"]["failed"], 1);
    assert_eq!(report["aggregate"]["scenario_counts"]["completed"], 0);
}

#[test]
fn a_target_name_no_lookup_can_be_written_for_leaves_the_rest_of_the_scan_completed() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = open_port(&listener);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("run.json");

    let output = scan_of_one_open_port(
        port,
        &[
            "--target",
            "192.168.1.1:80",
            "--run-report",
            &path.to_string_lossy(),
        ],
    )
    .output()
    .expect("spawn rastreo");

    assert_eq!(
        output.status.code(),
        Some(0),
        "one unusable name must not abort the scan; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = read_report(&path);
    assert_eq!(report["scenarios"][0]["outcome"], "completed");
    assert_eq!(
        report["scenarios"][0]["summary"]["unresolvable_targets"],
        serde_json::json!(["192.168.1.1:80"])
    );
    assert_eq!(report["scenarios"][0]["summary"]["records_emitted"], 1);
}

#[test]
fn an_unwritable_report_path_does_not_replace_the_scans_own_diagnosis() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("no-such-directory").join("run.json");

    let output = scan_of_an_unresolvable_target(&["-q", "--run-report", &path.to_string_lossy()])
        .output()
        .expect("spawn rastreo");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr.contains("every target is unresolvable"),
        "the scan's own refusal is what the operator reads: {stderr}"
    );
    assert!(
        !stderr.contains("run report could not be written"),
        "the report write must not preempt the diagnosis: {stderr}"
    );
}

#[test]
fn a_scan_that_failed_before_a_summary_is_a_failed_entry_carrying_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("run.json");
    let records = dir.path().join("no-such-directory").join("records.ndjson");

    let output = common::rastreo()
        .args([
            "discover",
            "--target",
            "127.0.0.1",
            "--probe",
            "tcp_connect",
            "--port",
            "22",
            "--sink",
            "file",
            "--output",
            &records.to_string_lossy(),
            "--run-report",
            &path.to_string_lossy(),
        ])
        .output()
        .expect("spawn rastreo");

    assert_eq!(
        output.status.code(),
        Some(1),
        "the sink could not be opened; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = read_report(&path);
    assert_eq!(report["scenarios"][0]["outcome"], "failed");
    assert!(
        report["scenarios"][0].get("summary").is_none(),
        "a scan that never returned a summary must not carry one: {report}"
    );
    assert_eq!(report["aggregate"]["scenario_counts"]["failed"], 1);
}

#[test]
fn a_run_that_refused_before_reaching_a_scenario_writes_no_report() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("run.json");

    let output = common::rastreo()
        .args([
            "discover",
            "--target",
            "127.0.0.1",
            "--probe",
            "dns",
            "--run-report",
            &path.to_string_lossy(),
        ])
        .output()
        .expect("spawn rastreo");

    assert_eq!(
        output.status.code(),
        Some(1),
        "a dns probe with no --dns-query is refused; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !path.exists(),
        "a run that reached no scenario has nothing to report"
    );
}

#[test]
fn a_dry_run_refuses_a_report_path() {
    let output = common::rastreo()
        .args([
            "discover",
            "--target",
            "127.0.0.1",
            "--dry-run",
            "--run-report",
            "/tmp/rastreo-dry-run-report.json",
        ])
        .output()
        .expect("spawn rastreo");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--run-report") && stderr.contains("--dry-run"),
        "the refusal names both flags: {stderr}"
    );
}

#[cfg(feature = "config")]
mod scenario_file {
    use super::*;
    use std::io::Write;

    fn write_yaml(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut file = File::create(&path).expect("create the scenario file");
        file.write_all(body.as_bytes()).expect("write the scenario");
        path
    }

    #[test]
    fn a_multi_scenario_file_reports_every_scenario_under_one_path() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = open_port(&listener);
        let dir = tempfile::tempdir().expect("tempdir");
        let scenarios = write_yaml(
            dir.path(),
            "scan.yml",
            &format!("version: 1\nkind: discovery\ndefaults:\n  timeout_ms: 500\n  sink:\n    type: stdout\nscenarios:\n  - signal_type: discover\n    name: first\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n  - signal_type: discover\n    name: second\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n"),
        );
        let path = dir.path().join("run.json");

        let output = common::rastreo()
            .args([
                "discover",
                "--file",
                &scenarios.to_string_lossy(),
                "--run-report",
                &path.to_string_lossy(),
            ])
            .output()
            .expect("spawn rastreo");
        drop(listener);

        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report = read_report(&path);
        let entries = report["scenarios"].as_array().expect("array");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["scenario"], "first");
        assert_eq!(entries[1]["scenario"], "second");
        assert_eq!(entries[0]["outcome"], "completed");
        assert_eq!(entries[1]["outcome"], "completed");
        assert_eq!(report["aggregate"]["scenario_counts"]["total"], 2);
        assert_eq!(report["aggregate"]["scenario_counts"]["completed"], 2);
        assert_eq!(report["aggregate"]["summary"]["records_emitted"], 2);
    }

    #[test]
    fn the_aggregate_folds_every_scenario_and_is_what_the_banner_printed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = open_port(&listener);
        let dir = tempfile::tempdir().expect("tempdir");
        let scenarios = write_yaml(
            dir.path(),
            "scan.yml",
            &format!("version: 1\nkind: discovery\ndefaults:\n  timeout_ms: 500\n  sink:\n    type: file\n    path: {}\nscenarios:\n  - signal_type: discover\n    name: first\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n  - signal_type: discover\n    name: second\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n", dir.path().join("records.ndjson").display()),
        );
        let path = dir.path().join("run.json");

        let output = common::rastreo()
            .args([
                "discover",
                "--file",
                &scenarios.to_string_lossy(),
                "--run-report",
                &path.to_string_lossy(),
            ])
            .output()
            .expect("spawn rastreo");
        drop(listener);

        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        let banner = stderr
            .lines()
            .find(|l| l.contains("2 scenarios"))
            .unwrap_or_else(|| panic!("the aggregate banner is on stderr:\n{stderr}"));
        let report = read_report(&path);
        let summary = &report["aggregate"]["summary"];
        assert_eq!(report["scenarios"][0]["summary"]["records_emitted"], 1);
        assert_eq!(report["scenarios"][1]["summary"]["records_emitted"], 1);
        assert_eq!(
            summary["records_emitted"], 2,
            "the aggregate is the fold over the scenarios, not one of them: {report}"
        );
        for (label, value) in [
            ("hosts:", &summary["targets_resolved"]),
            ("records:", &summary["records_emitted"]),
            ("probes:", &summary["probe_attempts"]),
        ] {
            assert!(
                banner.contains(&format!("{label} {value}")),
                "the banner and the document disagree on {label} ({value}): {banner}"
            );
        }
    }

    #[test]
    fn a_skipped_scenario_gets_an_entry_naming_it_skipped() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = open_port(&listener);
        let dir = tempfile::tempdir().expect("tempdir");
        let scenarios = write_yaml(
            dir.path(),
            "scan.yml",
            &format!("version: 1\nkind: discovery\ndefaults:\n  timeout_ms: 500\n  sink:\n    type: stdout\nscenarios:\n  - signal_type: discover\n    name: runnable\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n  - signal_type: discover\n    name: prober-less\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers: []\n"),
        );
        let path = dir.path().join("run.json");

        let output = common::rastreo()
            .args([
                "discover",
                "--file",
                &scenarios.to_string_lossy(),
                "--run-report",
                &path.to_string_lossy(),
            ])
            .output()
            .expect("spawn rastreo");
        drop(listener);

        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report = read_report(&path);
        let entries = report["scenarios"].as_array().expect("array");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1]["scenario"], "prober-less");
        assert_eq!(entries[1]["outcome"], "skipped");
        assert!(
            entries[1].get("summary").is_none(),
            "a skipped scenario produced no summary to carry: {report}"
        );
        assert_eq!(report["aggregate"]["scenario_counts"]["total"], 2);
        assert_eq!(report["aggregate"]["scenario_counts"]["skipped"], 1);
    }

    #[test]
    fn a_file_whose_every_scenario_was_skipped_reports_each_of_them() {
        let dir = tempfile::tempdir().expect("tempdir");
        let scenarios = write_yaml(
            dir.path(),
            "scan.yml",
            "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    name: empty\n    timeout_ms: 500\n    sink:\n      type: stdout\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers: []\n",
        );
        let path = dir.path().join("run.json");

        let output = common::rastreo()
            .args([
                "discover",
                "--file",
                &scenarios.to_string_lossy(),
                "--run-report",
                &path.to_string_lossy(),
            ])
            .output()
            .expect("spawn rastreo");

        assert_eq!(output.status.code(), Some(1));
        let report = read_report(&path);
        assert_eq!(report["scenarios"][0]["outcome"], "skipped");
        assert_eq!(report["aggregate"]["scenario_counts"]["skipped"], 1);
    }

    #[test]
    fn a_scenario_that_failed_before_probing_is_an_entry_beside_the_one_that_ran() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = open_port(&listener);
        let dir = tempfile::tempdir().expect("tempdir");
        let scenarios = write_yaml(
            dir.path(),
            "scan.yml",
            &format!("version: 1\nkind: discovery\ndefaults:\n  timeout_ms: 500\n  sink:\n    type: stdout\nscenarios:\n  - signal_type: discover\n    name: bad\n    targets:\n      - Range:\n          start: \"10.0.0.5\"\n          end: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n  - signal_type: discover\n    name: good\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n"),
        );
        let path = dir.path().join("run.json");

        let output = common::rastreo()
            .args([
                "discover",
                "--file",
                &scenarios.to_string_lossy(),
                "--run-report",
                &path.to_string_lossy(),
            ])
            .output()
            .expect("spawn rastreo");
        drop(listener);

        assert_eq!(output.status.code(), Some(1));
        let report = read_report(&path);
        let entries = report["scenarios"].as_array().expect("array");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["scenario"], "bad");
        assert_eq!(entries[0]["outcome"], "failed");
        assert!(
            entries[0].get("summary").is_none(),
            "the failed scenario never produced a summary: {report}"
        );
        assert_eq!(entries[1]["scenario"], "good");
        assert_eq!(entries[1]["outcome"], "completed");
        assert!(entries[1]["summary"].is_object());
        assert_eq!(report["aggregate"]["scenario_counts"]["failed"], 1);
        assert_eq!(report["aggregate"]["scenario_counts"]["completed"], 1);
    }

    #[test]
    fn a_report_records_the_run_a_checkpoint_could_not() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = open_port(&listener);
        let dir = tempfile::tempdir().expect("tempdir");
        let scenarios = write_yaml(
            dir.path(),
            "scan.yml",
            &format!("version: 1\nkind: discovery\ndefaults:\n  timeout_ms: 500\n  sink:\n    type: stdout\nscenarios:\n  - signal_type: discover\n    name: first\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n  - signal_type: discover\n    name: second\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [{port}]\n"),
        );
        let path = dir.path().join("run.json");

        let output = common::rastreo()
            .args([
                "discover",
                "--file",
                &scenarios.to_string_lossy(),
                "--run-report",
                &path.to_string_lossy(),
            ])
            .output()
            .expect("spawn rastreo");
        drop(listener);

        assert!(output.status.success());
        assert_eq!(
            read_report(&path)["scenarios"]
                .as_array()
                .expect("array")
                .len(),
            2,
            "one path carries every scenario rather than being overwritten per scenario"
        );
    }
}
