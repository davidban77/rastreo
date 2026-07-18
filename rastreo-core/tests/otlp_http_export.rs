#![cfg(feature = "otlp")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use opentelemetry::trace::{Tracer, TracerProvider as _};
use rastreo_core::observability::otlp::{traces_layer, OtlpConfig};
use rastreo_core::observability::otlp_config::OtlpProtocol;
use tracing_subscriber::Registry;

// The batch processor exports from a plain std::thread with no tokio reactor, so an async HTTP client panics there and no POST ever reaches the mock; only a blocking client delivers.
#[test]
fn http_export_reaches_collector_without_runtime_panic() {
    let (endpoint, request_lines, mock) = spawn_mock_collector();

    let cfg = OtlpConfig {
        endpoint,
        protocol: OtlpProtocol::HttpProtobuf,
        metrics_enabled: false,
        logs_enabled: false,
        traces_enabled: true,
        metrics_interval: Duration::from_secs(30),
        service_name: "rastreo-http-export-test".to_string(),
    };

    let (_layer, provider) =
        traces_layer::<Registry>(&cfg).expect("build http+protobuf span provider");
    provider
        .tracer("rastreo-http-export-test")
        .in_span("probe", |_| {});
    let _ = provider.force_flush();

    let request_line = request_lines
        .recv_timeout(Duration::from_secs(5))
        .expect("HTTP export thread must POST to the collector without a runtime panic");
    assert!(
        request_line.starts_with("POST /v1/traces"),
        "expected a POST to /v1/traces, got: {request_line}"
    );

    let _ = provider.shutdown();
    let _ = mock.join();
}

fn spawn_mock_collector() -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock collector");
    let addr = listener.local_addr().expect("mock collector addr");
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let request_line = read_request(&mut stream);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            let _ = stream.flush();
            let _ = tx.send(request_line);
        }
    });
    (format!("http://{addr}"), rx, handle)
}

fn read_request(stream: &mut TcpStream) -> String {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut header_end: Option<usize> = None;
    let mut content_length = 0usize;
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if header_end.is_none() {
                    if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                        header_end = Some(pos + 4);
                        content_length = content_length_of(&buf[..pos]);
                    }
                }
                if let Some(end) = header_end {
                    if buf.len() >= end + content_length {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    let line_end = buf
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..line_end]).into_owned()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn content_length_of(headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(headers).to_ascii_lowercase();
    text.lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|rest| rest.trim().parse().ok())
        .unwrap_or(0)
}
