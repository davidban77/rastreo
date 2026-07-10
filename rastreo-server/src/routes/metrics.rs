//! GET /metrics — Prometheus text format with rastreo-server operational signals.

use std::fmt::Write as _;
use std::sync::atomic::Ordering;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::state::{AppState, HistogramShard};

const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

pub async fn get_metrics(State(state): State<AppState>) -> Result<Response, Response> {
    let mut buf = String::with_capacity(2048);

    write_scans_total(&state, &mut buf).map_err(internal)?;
    write_probes_total(&state, &mut buf).map_err(internal)?;
    write_records_emitted_total(&state, &mut buf).map_err(internal)?;
    write_sink_errors_total(&state, &mut buf).map_err(internal)?;
    write_scan_duration_seconds(&state, &mut buf).map_err(internal)?;
    write_uptime_seconds(&state, &mut buf).map_err(internal)?;
    write_build_info(&mut buf).map_err(internal)?;

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        buf,
    )
        .into_response())
}

fn internal(_: std::fmt::Error) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "failed to emit server metrics",
    )
        .into_response()
}

fn write_scans_total(state: &AppState, buf: &mut String) -> std::fmt::Result {
    let success = state.metrics.scans_total_success.load(Ordering::Relaxed);
    let error = state.metrics.scans_total_error.load(Ordering::Relaxed);
    let cancelled = state.metrics.scans_total_cancelled.load(Ordering::Relaxed);
    writeln!(
        buf,
        "# HELP rastreo_server_scans_total POST /scans requests served, partitioned by outcome."
    )?;
    writeln!(buf, "# TYPE rastreo_server_scans_total counter")?;
    writeln!(
        buf,
        "rastreo_server_scans_total{{outcome=\"success\"}} {success}"
    )?;
    writeln!(
        buf,
        "rastreo_server_scans_total{{outcome=\"error\"}} {error}"
    )?;
    writeln!(
        buf,
        "rastreo_server_scans_total{{outcome=\"cancelled\"}} {cancelled}"
    )?;
    Ok(())
}

fn write_probes_total(state: &AppState, buf: &mut String) -> std::fmt::Result {
    let success = state.metrics.probes_succeeded_total.load(Ordering::Relaxed);
    let errored = state.metrics.probes_errored_total.load(Ordering::Relaxed);
    writeln!(
        buf,
        "# HELP rastreo_server_probes_total Probes executed across all scans, partitioned by outcome."
    )?;
    writeln!(buf, "# TYPE rastreo_server_probes_total counter")?;
    writeln!(
        buf,
        "rastreo_server_probes_total{{outcome=\"success\"}} {success}"
    )?;
    writeln!(
        buf,
        "rastreo_server_probes_total{{outcome=\"error\"}} {errored}"
    )?;
    Ok(())
}

fn write_records_emitted_total(state: &AppState, buf: &mut String) -> std::fmt::Result {
    let value = state.metrics.records_emitted_total.load(Ordering::Relaxed);
    writeln!(
        buf,
        "# HELP rastreo_server_records_emitted_total DeviceRecords emitted across all scans."
    )?;
    writeln!(buf, "# TYPE rastreo_server_records_emitted_total counter")?;
    writeln!(buf, "rastreo_server_records_emitted_total {value}")
}

fn write_sink_errors_total(state: &AppState, buf: &mut String) -> std::fmt::Result {
    let value = state.metrics.sink_errors_total.load(Ordering::Relaxed);
    writeln!(
        buf,
        "# HELP rastreo_server_sink_errors_total Internal sink errors surfaced via POST /scans."
    )?;
    writeln!(buf, "# TYPE rastreo_server_sink_errors_total counter")?;
    writeln!(buf, "rastreo_server_sink_errors_total {value}")
}

fn write_scan_duration_seconds(state: &AppState, buf: &mut String) -> std::fmt::Result {
    let snap = state.metrics.scan_duration_seconds.snapshot();
    writeln!(
        buf,
        "# HELP rastreo_server_scan_duration_seconds Duration of POST /scans request handling."
    )?;
    writeln!(buf, "# TYPE rastreo_server_scan_duration_seconds histogram")?;
    for (i, bound) in HistogramShard::BUCKET_BOUNDS.iter().enumerate() {
        writeln!(
            buf,
            "rastreo_server_scan_duration_seconds_bucket{{le=\"{bound}\"}} {}",
            snap.buckets[i]
        )?;
    }
    writeln!(
        buf,
        "rastreo_server_scan_duration_seconds_bucket{{le=\"+Inf\"}} {}",
        snap.plus_inf
    )?;
    writeln!(buf, "rastreo_server_scan_duration_seconds_sum {}", snap.sum)?;
    writeln!(
        buf,
        "rastreo_server_scan_duration_seconds_count {}",
        snap.count
    )
}

fn write_uptime_seconds(state: &AppState, buf: &mut String) -> std::fmt::Result {
    let uptime = state.metrics.started_at.elapsed().as_secs_f64();
    writeln!(
        buf,
        "# HELP rastreo_server_uptime_seconds Seconds since rastreo-server started."
    )?;
    writeln!(buf, "# TYPE rastreo_server_uptime_seconds gauge")?;
    writeln!(buf, "rastreo_server_uptime_seconds {uptime}")
}

fn write_build_info(buf: &mut String) -> std::fmt::Result {
    let version = escape_label(env!("CARGO_PKG_VERSION"));
    writeln!(
        buf,
        "# HELP rastreo_server_build_info Build info (version label always 1)."
    )?;
    writeln!(buf, "# TYPE rastreo_server_build_info gauge")?;
    writeln!(buf, "rastreo_server_build_info{{version=\"{version}\"}} 1")
}

/// Escape a Prometheus label value per the exposition format spec — backslash, double-quote, and newline.
fn escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use axum::body::to_bytes;
    use rastreo_core::{DiscoverySummary, HickoryResolver, Resolver};

    fn build_state() -> AppState {
        let resolver: Arc<dyn Resolver> =
            Arc::new(HickoryResolver::from_system().expect("system resolver"));
        AppState::new(resolver)
    }

    async fn body_string(resp: Response) -> String {
        let (parts, body) = resp.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.expect("collect body");
        let s = String::from_utf8(bytes.to_vec()).expect("utf-8");
        assert_eq!(parts.status, StatusCode::OK);
        s
    }

    #[tokio::test]
    async fn get_metrics_returns_ok_with_prometheus_content_type() {
        let state = build_state();
        let resp = get_metrics(State(state)).await.expect("ok");
        assert_eq!(resp.status(), StatusCode::OK);
        let ctype = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .expect("content-type header");
        assert_eq!(ctype, PROMETHEUS_CONTENT_TYPE);
        let body = body_string(resp).await;
        for expected in [
            "# HELP rastreo_server_scans_total",
            "# TYPE rastreo_server_scans_total counter",
            "# HELP rastreo_server_probes_total",
            "# HELP rastreo_server_records_emitted_total",
            "# HELP rastreo_server_sink_errors_total",
            "# HELP rastreo_server_scan_duration_seconds",
            "# TYPE rastreo_server_scan_duration_seconds histogram",
            "# HELP rastreo_server_uptime_seconds",
            "# HELP rastreo_server_build_info",
            "rastreo_server_scans_total{outcome=\"success\"} 0",
            "rastreo_server_scans_total{outcome=\"error\"} 0",
            "rastreo_server_scans_total{outcome=\"cancelled\"} 0",
            "rastreo_server_probes_total{outcome=\"success\"} 0",
            "rastreo_server_probes_total{outcome=\"error\"} 0",
            "rastreo_server_records_emitted_total 0",
            "rastreo_server_sink_errors_total 0",
            "rastreo_server_scan_duration_seconds_bucket{le=\"0.005\"} 0",
            "rastreo_server_scan_duration_seconds_bucket{le=\"+Inf\"} 0",
            "rastreo_server_scan_duration_seconds_sum 0",
            "rastreo_server_scan_duration_seconds_count 0",
        ] {
            assert!(
                body.contains(expected),
                "metrics body must contain `{expected}`; body was:\n{body}"
            );
        }
    }

    #[tokio::test]
    async fn get_metrics_includes_build_info_with_version() {
        let state = build_state();
        let resp = get_metrics(State(state)).await.expect("ok");
        let body = body_string(resp).await;
        let expected = format!(
            "rastreo_server_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        );
        assert!(
            body.contains(&expected),
            "build_info line not found; body was:\n{body}"
        );
    }

    #[tokio::test]
    async fn get_metrics_reflects_recorded_scan_completion() {
        let state = build_state();
        let summary = DiscoverySummary {
            targets_resolved: 1,
            probe_attempts: 10,
            probe_errors: 2,
            records_emitted: 5,
            cancelled: false,
            elapsed: Duration::from_millis(123),
        };
        state.metrics.record_scan_completion(&summary);

        let resp = get_metrics(State(state)).await.expect("ok");
        let body = body_string(resp).await;
        assert!(body.contains("rastreo_server_scans_total{outcome=\"success\"} 1"));
        assert!(body.contains("rastreo_server_scans_total{outcome=\"cancelled\"} 0"));
        assert!(body.contains("rastreo_server_probes_total{outcome=\"success\"} 8"));
        assert!(body.contains("rastreo_server_probes_total{outcome=\"error\"} 2"));
        assert!(body.contains("rastreo_server_records_emitted_total 5"));
        assert!(body.contains("rastreo_server_scan_duration_seconds_count 1"));
        // 0.123s falls in the le=0.25 bucket (index 5) and every higher bucket.
        assert!(
            body.contains("rastreo_server_scan_duration_seconds_bucket{le=\"0.25\"} 1"),
            "histogram bucket for 0.123s should be >= 1 at le=0.25; body was:\n{body}"
        );
    }

    #[tokio::test]
    async fn get_metrics_reflects_cancelled_scan() {
        let state = build_state();
        let summary = DiscoverySummary {
            targets_resolved: 1,
            probe_attempts: 3,
            probe_errors: 0,
            records_emitted: 1,
            cancelled: true,
            elapsed: Duration::from_millis(40),
        };
        state.metrics.record_scan_completion(&summary);
        let resp = get_metrics(State(state)).await.expect("ok");
        let body = body_string(resp).await;
        assert!(body.contains("rastreo_server_scans_total{outcome=\"cancelled\"} 1"));
        assert!(body.contains("rastreo_server_scans_total{outcome=\"success\"} 0"));
    }

    #[tokio::test]
    async fn get_metrics_reflects_error_scan() {
        let state = build_state();
        state
            .metrics
            .record_scan_error(Duration::from_millis(50), false);
        let resp = get_metrics(State(state)).await.expect("ok");
        let body = body_string(resp).await;
        assert!(body.contains("rastreo_server_scans_total{outcome=\"error\"} 1"));
        assert!(body.contains("rastreo_server_sink_errors_total 0"));
    }

    #[tokio::test]
    async fn get_metrics_reflects_sink_error() {
        let state = build_state();
        state
            .metrics
            .record_scan_error(Duration::from_millis(50), true);
        let resp = get_metrics(State(state)).await.expect("ok");
        let body = body_string(resp).await;
        assert!(body.contains("rastreo_server_scans_total{outcome=\"error\"} 1"));
        assert!(body.contains("rastreo_server_sink_errors_total 1"));
    }

    #[tokio::test]
    async fn get_metrics_uptime_seconds_increases_monotonically() {
        let state = build_state();
        let first = uptime_value(State(state.clone())).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        let second = uptime_value(State(state)).await;
        assert!(
            second >= first,
            "uptime must be monotonic: first={first}, second={second}"
        );
    }

    async fn uptime_value(state: State<AppState>) -> f64 {
        let resp = get_metrics(state).await.expect("ok");
        let body = body_string(resp).await;
        let line = body
            .lines()
            .find(|l| l.starts_with("rastreo_server_uptime_seconds "))
            .expect("uptime line");
        let value = line
            .strip_prefix("rastreo_server_uptime_seconds ")
            .expect("strip prefix");
        value.parse().expect("parse f64")
    }

    #[test]
    fn escape_label_handles_backslash_quote_and_newline() {
        assert_eq!(escape_label(r#"a\b"c"#), r#"a\\b\"c"#);
        assert_eq!(escape_label("line\nbreak"), "line\\nbreak");
        assert_eq!(escape_label("plain"), "plain");
    }
}
