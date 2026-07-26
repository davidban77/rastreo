mod common;

// Overlapping specs make the pipeline emit a WARN, so a leaked RUST_LOG has something to print.
const OVERLAPPING_TARGETS: [&str; 4] = ["--target", "127.0.0.1", "--target", "127.0.0.0/29"];

fn scan_args() -> Vec<&'static str> {
    let mut args = vec!["discover"];
    args.extend(OVERLAPPING_TARGETS);
    args.extend(["-p", "9", "--timeout-ms", "50"]);
    args
}

#[test]
fn quiet_leaves_stderr_empty_on_a_successful_scan() {
    let output = common::rastreo()
        .args(scan_args())
        .arg("-q")
        .output()
        .expect("spawn rastreo");

    assert!(output.status.success(), "scan should exit 0");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.is_empty(),
        "quiet stderr must be empty, got: {stderr}"
    );
}

#[test]
fn quiet_beats_an_ambient_rust_log() {
    let output = common::rastreo()
        .args(scan_args())
        .arg("-q")
        .env("RUST_LOG", "debug")
        .output()
        .expect("spawn rastreo");

    assert!(output.status.success(), "scan should exit 0");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.is_empty(),
        "an explicit -q must override RUST_LOG, got: {stderr}"
    );
}

#[test]
fn an_ambient_rust_log_still_wins_when_no_verbosity_flag_is_given() {
    let output = common::rastreo()
        .args(scan_args())
        .env("RUST_LOG", "error")
        .output()
        .expect("spawn rastreo");

    assert!(output.status.success(), "scan should exit 0");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("target specs overlap"),
        "RUST_LOG=error should have filtered the pipeline warning, got: {stderr}"
    );
}

#[test]
fn without_quiet_the_banners_are_printed() {
    let output = common::rastreo()
        .args(scan_args())
        .output()
        .expect("spawn rastreo");

    assert!(output.status.success(), "scan should exit 0");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("▶ discover"), "stderr: {stderr}");
    assert!(stderr.contains("■ discover"), "stderr: {stderr}");
}

#[test]
fn quiet_suppresses_the_zero_records_hint() {
    let output = common::rastreo()
        .args(scan_args())
        .arg("-q")
        .output()
        .expect("spawn rastreo");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("hint:"), "stderr: {stderr}");
}

#[test]
fn a_piped_run_emits_no_ansi_escape_sequences() {
    let output = common::rastreo()
        .args(scan_args())
        .arg("-v")
        .output()
        .expect("spawn rastreo");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.is_empty(), "expected banners on a normal run");
    assert!(
        !stderr.contains('\u{1b}'),
        "piped stderr must carry no colour or cursor escapes, got: {stderr:?}"
    );
}

#[test]
fn no_color_suppresses_colour_on_an_otherwise_colour_capable_terminal() {
    let output = common::rastreo()
        .args(scan_args())
        .env("IGNORE_IS_TERMINAL", "1")
        .env("COLORTERM", "truecolor")
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn rastreo");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains('\u{1b}'),
        "NO_COLOR must win, got: {stderr:?}"
    );
}

#[test]
fn colour_is_emitted_when_the_environment_forces_it() {
    let output = common::rastreo()
        .args(scan_args())
        .env("CLICOLOR_FORCE", "1")
        .output()
        .expect("spawn rastreo");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains('\u{1b}'),
        "CLICOLOR_FORCE should paint the banners, got: {stderr:?}"
    );
}

#[test]
fn rastreo_ascii_swaps_the_glyph_table() {
    let output = common::rastreo()
        .args(scan_args())
        .env("RASTREO_ASCII", "1")
        .output()
        .expect("spawn rastreo");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("> discover"), "stderr: {stderr}");
    assert!(stderr.contains("# discover"), "stderr: {stderr}");
    assert!(!stderr.contains('▶'), "stderr: {stderr}");
    assert!(!stderr.contains('■'), "stderr: {stderr}");
}

#[test]
fn a_non_utf8_locale_falls_back_to_ascii_glyphs() {
    let output = common::rastreo()
        .args(scan_args())
        .env("LC_ALL", "C")
        .output()
        .expect("spawn rastreo");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("> discover"), "stderr: {stderr}");
    assert!(!stderr.contains('▶'), "stderr: {stderr}");
}

#[test]
fn verbose_adds_the_probes_by_kind_breakdown() {
    let output = common::rastreo()
        .args(scan_args())
        .arg("-v")
        .output()
        .expect("spawn rastreo");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("probes by kind") && stderr.contains("tcp_connect"),
        "stderr: {stderr}"
    );
}

#[test]
fn normal_verbosity_omits_the_detail_lines() {
    let output = common::rastreo()
        .args(scan_args())
        .output()
        .expect("spawn rastreo");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("probes by kind"), "stderr: {stderr}");
}

#[cfg(feature = "config")]
fn scenario_file(dir: &tempfile::TempDir, name: &str, contents: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, contents).expect("write scenario");
    path
}

// Scenario 'bad' carries a reversed range, so it fails before probing; 'good' runs to completion.
#[cfg(feature = "config")]
const ONE_BAD_ONE_GOOD: &str = "version: 1\nkind: discovery\ndefaults:\n  timeout_ms: 50\n  sink:\n    type: stdout\nscenarios:\n  - signal_type: discover\n    name: bad\n    targets:\n      - Range:\n          start: \"10.0.0.5\"\n          end: \"10.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [9]\n  - signal_type: discover\n    name: good\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [9]\n";

// A workspace-wide build unifies every prober feature on, so the gated variant must be one nothing
// else enables; each test asserts the parse failed, so a build that turns it on fails loudly.
#[cfg(all(feature = "config", not(feature = "mib_enrichment")))]
const FEATURE_GATED_SCENARIO: &str = "version: 1\nkind: discovery\nscenarios:\n  - signal_type: discover\n    fuser:\n      type: mib_enrichment\n    targets:\n      - Ip: \"127.0.0.1\"\n    probers:\n      - type: tcp_connect\n        ports: [9]\n";

#[cfg(feature = "config")]
#[test]
fn quiet_keeps_a_scenario_failure_and_drops_every_banner() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = scenario_file(&dir, "partial.yml", ONE_BAD_ONE_GOOD);

    let output = common::rastreo()
        .args(["discover", "-q", "--file"])
        .arg(&path)
        .output()
        .expect("spawn rastreo");

    assert!(!output.status.success(), "a failed scenario must exit 1");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("scenario 'bad'") && stderr.contains("failed"),
        "-q suppresses status output, not failures: {stderr}"
    );
    assert!(
        !stderr.contains('▶'),
        "start banner leaked under -q: {stderr}"
    );
    assert!(
        !stderr.contains("completed in") && !stderr.contains("cancelled after"),
        "completion banner leaked under -q: {stderr}"
    );
}

#[cfg(feature = "config")]
#[test]
fn the_aggregate_banner_counts_only_the_scenarios_that_completed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = scenario_file(&dir, "partial.yml", ONE_BAD_ONE_GOOD);

    let output = common::rastreo()
        .args(["discover", "--file"])
        .arg(&path)
        .output()
        .expect("spawn rastreo");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("1 of 2 scenarios"),
        "the aggregate must not claim a scenario that failed: {stderr}"
    );
    assert!(!stderr.contains("■ 2 scenarios"), "stderr: {stderr}");
}

#[cfg(all(feature = "config", not(feature = "mib_enrichment")))]
#[test]
fn quiet_suppresses_the_feature_gate_hint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = scenario_file(&dir, "gated.yml", FEATURE_GATED_SCENARIO);

    let output = common::rastreo()
        .args(["discover", "-q", "--file"])
        .arg(&path)
        .output()
        .expect("spawn rastreo");

    assert!(
        !output.status.success(),
        "the mib_enrichment fuser must be unknown to this build, or the test proves nothing"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("hint:"),
        "-q must suppress the feature-gate hint: {stderr}"
    );
    assert!(
        stderr.contains("failed to parse scenario file"),
        "the parse error must still surface: {stderr}"
    );
}

#[cfg(all(feature = "config", not(feature = "mib_enrichment")))]
#[test]
fn quiet_suppresses_the_feature_gate_hint_on_validate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = scenario_file(&dir, "gated.yml", FEATURE_GATED_SCENARIO);

    let output = common::rastreo()
        .args(["validate", "-q"])
        .arg(&path)
        .output()
        .expect("spawn rastreo");

    assert!(
        !output.status.success(),
        "the mib_enrichment fuser must be unknown to this build, or the test proves nothing"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("hint:"),
        "-q must suppress the feature-gate hint: {stderr}"
    );
}

#[cfg(all(feature = "config", not(feature = "mib_enrichment")))]
#[test]
fn the_feature_gate_hint_follows_the_hint_grammar() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = scenario_file(&dir, "gated.yml", FEATURE_GATED_SCENARIO);

    let output = common::rastreo()
        .args(["discover", "--file"])
        .arg(&path)
        .output()
        .expect("spawn rastreo");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("⚠ hint: 'mib_enrichment' requires the 'mib_enrichment' Cargo feature"),
        "the feature-gate hint must use the themed hint grammar: {stderr}"
    );
}
