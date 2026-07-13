use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn json_log_format_emits_listening_line_as_json() {
    let bin = env!("CARGO_BIN_EXE_rastreo-server");
    let mut child = Command::new(bin)
        .args(["--log-format", "json", "--port", "0"])
        .env_remove("RUST_LOG")
        .env_remove("RASTREO_LOG_FORMAT")
        .env_remove("RASTREO_SERVER_PORT")
        .env_remove("RASTREO_SERVER_BIND")
        .env_remove("RASTREO_SERVER_REQUEST_TIMEOUT_MS")
        .env("RASTREO_AUTH_DISABLED", "true")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rastreo-server");

    let stderr = child.stderr.take().expect("take stderr");
    let mut reader = BufReader::new(stderr);

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut listening_line: Option<String> = None;
    while Instant::now() < deadline {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim().to_string();
                if trimmed.is_empty() {
                    continue;
                }
                if trimmed.contains("rastreo-server listening") {
                    listening_line = Some(trimmed);
                    break;
                }
            }
            Err(_) => break,
        }
    }

    let _ = child.kill();
    let _ = child.wait();

    let line = listening_line.expect("expected `rastreo-server listening` log line before timeout");
    let value: serde_json::Value = serde_json::from_str(&line)
        .unwrap_or_else(|e| panic!("listening line was not valid JSON: {line:?} ({e})"));

    let level = value
        .get("level")
        .and_then(|v| v.as_str())
        .expect("level string");
    assert_eq!(level, "INFO", "expected INFO level; got {level:?}");

    let target = value
        .get("target")
        .and_then(|v| v.as_str())
        .expect("target string");
    assert_eq!(
        target, "rastreo_server",
        "expected target `rastreo_server`; got {target:?}"
    );

    let message = value
        .get("fields")
        .and_then(|f| f.get("message"))
        .and_then(|v| v.as_str())
        .expect("fields.message string");
    assert!(
        message.contains("rastreo-server listening"),
        "expected message to contain listening banner; got {message:?}"
    );
}

#[test]
fn text_log_format_default_does_not_emit_json() {
    let bin = env!("CARGO_BIN_EXE_rastreo-server");
    let mut child = Command::new(bin)
        .args(["--port", "0"])
        .env_remove("RUST_LOG")
        .env_remove("RASTREO_LOG_FORMAT")
        .env_remove("RASTREO_SERVER_PORT")
        .env_remove("RASTREO_SERVER_BIND")
        .env_remove("RASTREO_SERVER_REQUEST_TIMEOUT_MS")
        .env("RASTREO_AUTH_DISABLED", "true")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rastreo-server");

    let stderr = child.stderr.take().expect("take stderr");
    let mut reader = BufReader::new(stderr);

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut listening_line: Option<String> = None;
    while Instant::now() < deadline {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim().to_string();
                if trimmed.is_empty() {
                    continue;
                }
                if trimmed.contains("rastreo-server listening") {
                    listening_line = Some(trimmed);
                    break;
                }
            }
            Err(_) => break,
        }
    }

    let _ = child.kill();
    let _ = child.wait();

    let line = listening_line.expect("expected listening log line before timeout");
    assert!(
        serde_json::from_str::<serde_json::Value>(&line).is_err(),
        "text-format listening line should not parse as JSON: {line:?}"
    );
}

#[test]
fn help_lists_log_format_flag() {
    let bin = env!("CARGO_BIN_EXE_rastreo-server");
    let output = Command::new(bin)
        .args(["--help"])
        .env_remove("RUST_LOG")
        .env_remove("RASTREO_LOG_FORMAT")
        .output()
        .expect("spawn rastreo-server");

    assert!(
        output.status.success(),
        "help exited with {:?}",
        output.status
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--log-format"),
        "expected --log-format in help; got {stdout}"
    );
    assert!(
        stdout.contains("RASTREO_LOG_FORMAT"),
        "expected RASTREO_LOG_FORMAT env in help; got {stdout}"
    );
}
