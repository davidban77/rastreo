#![cfg(unix)]

mod common;

use std::io::Read;
use std::os::fd::{FromRawFd, OwnedFd};
use std::process::{Command, Stdio};

struct Pty {
    controller: OwnedFd,
    device: OwnedFd,
}

fn open_pty(cols: u16) -> Pty {
    let mut controller = -1;
    let mut device = -1;
    let mut size = libc::winsize {
        ws_row: 24,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // `openpty` differs in constness across platforms; a `*mut` coerces to either shape.
    let rc = unsafe {
        libc::openpty(
            &mut controller,
            &mut device,
            std::ptr::null_mut(),
            std::ptr::null_mut::<libc::termios>() as _,
            &mut size as *mut libc::winsize as _,
        )
    };
    assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
    unsafe {
        Pty {
            controller: OwnedFd::from_raw_fd(controller),
            device: OwnedFd::from_raw_fd(device),
        }
    }
}

fn run_on_a_terminal(mut cmd: Command, cols: u16) -> String {
    let pty = open_pty(cols);
    let dup = || Stdio::from(pty.device.try_clone().expect("dup pty device"));
    cmd.stdin(dup()).stdout(dup()).stderr(dup());
    let mut child = cmd.spawn().expect("spawn rastreo on a pty");
    // Every parent-side handle on the device must go, or the controller never sees end-of-stream.
    drop(cmd);
    drop(pty.device);

    let mut controller = std::fs::File::from(pty.controller);
    let mut captured = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match controller.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => captured.extend_from_slice(&buf[..n]),
            Err(err) if err.raw_os_error() == Some(libc::EIO) => break,
            Err(err) => panic!("read from the pty controller: {err}"),
        }
    }
    let status = child.wait().expect("wait for rastreo");
    let text = String::from_utf8_lossy(&captured).into_owned();
    assert!(status.success(), "rastreo exited with {status:?}: {text}");
    text
}

// The chrome the CLI paints on stderr, and the record stream stdout carries.
const CHROME: &[&str] = &["targets:", "completed in", "hosts:", "elapsed:"];
const RECORDS: &[&str] = &["ADDRESS", "PLATFORM"];

fn assert_no_row_carries_both(captured: &str) {
    for row in captured.split('\n') {
        let chrome = CHROME.iter().find(|needle| row.contains(**needle));
        let record = RECORDS.iter().find(|needle| row.contains(**needle));
        assert!(
            chrome.is_none() || record.is_none(),
            "chrome ({chrome:?}) and a record ({record:?}) share a terminal row: {row:?}"
        );
    }
}

fn scan_one_open_port(extra: &[&str], cols: u16) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = listener.local_addr().expect("local_addr").port();
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
    let captured = run_on_a_terminal(cmd, cols);
    drop(listener);
    captured
}

#[test]
fn the_table_header_starts_its_own_row_on_a_terminal() {
    for cols in [40, 80, 120, 200] {
        let captured = scan_one_open_port(&[], cols);
        let header = captured
            .split('\n')
            .find(|row| row.contains("ADDRESS"))
            .unwrap_or_else(|| panic!("no table header at {cols} columns: {captured:?}"));
        assert!(
            header.starts_with("ADDRESS"),
            "the header must not be fused onto a progress redraw at {cols} columns: {header:?}"
        );
        assert_no_row_carries_both(&captured);
    }
}

#[test]
fn the_progress_line_stays_off_a_terminal_that_carries_records() {
    let captured = scan_one_open_port(&[], 120);
    assert!(
        !captured.contains("rate:"),
        "the progress line cannot own a row records are landing on: {captured:?}"
    );
    assert!(
        captured.contains("completed in"),
        "the completion banner still prints: {captured:?}"
    );
}

#[test]
fn a_file_sink_keeps_the_progress_line_on_the_terminal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let records = dir.path().join("records.ndjson");
    let captured = scan_one_open_port(
        &["--sink", "file", "--output", &records.display().to_string()],
        120,
    );
    assert!(
        captured.contains("rate:"),
        "nothing else writes to this terminal, so the progress line is safe: {captured:?}"
    );
    assert_no_row_carries_both(&captured);
}

#[test]
fn a_verbose_json_run_keeps_its_banners_off_the_record_rows() {
    let captured = scan_one_open_port(&["--format", "json", "-v"], 120);
    assert!(
        captured.contains("completed in"),
        "-v restores the banners under --format json: {captured:?}"
    );
    for row in captured.split('\n') {
        let record_row = row.contains("\"identity_key\"");
        let chrome_row = CHROME.iter().any(|needle| row.contains(*needle));
        assert!(
            !(record_row && chrome_row),
            "a JSON record shares a row with chrome: {row:?}"
        );
    }
}
