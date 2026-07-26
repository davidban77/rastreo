mod common;

#[test]
fn top_level_help_lists_log_format_flag() {
    let output = common::rastreo()
        .args(["--help"])
        .output()
        .expect("spawn rastreo");

    assert!(
        output.status.success(),
        "help exited with {:?}",
        output.status
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--log-format"),
        "expected --log-format in top-level help; got {stdout}"
    );
    assert!(
        stdout.contains("RASTREO_LOG_FORMAT"),
        "expected env var reference in help; got {stdout}"
    );
}

#[test]
fn discover_subcommand_help_inherits_log_format_flag() {
    let output = common::rastreo()
        .args(["discover", "--help"])
        .output()
        .expect("spawn rastreo");

    assert!(
        output.status.success(),
        "help exited with {:?}",
        output.status
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--log-format"),
        "expected --log-format on subcommand (global flag); got {stdout}"
    );
}

#[test]
fn invalid_log_format_value_is_rejected() {
    let output = common::rastreo()
        .args([
            "--log-format",
            "yaml",
            "discover",
            "--target",
            "127.0.0.1",
            "-p",
            "22",
        ])
        .output()
        .expect("spawn rastreo");

    assert!(
        !output.status.success(),
        "expected non-zero exit for invalid log-format value"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid value") || stderr.contains("possible values"),
        "expected clap invalid-value error; got {stderr}"
    );
}
