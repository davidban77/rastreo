//! GET /metrics — Prometheus text format with rastreo-server operational signals.

use std::fmt::Write as _;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::metrics_defs::{self, Label, MetricContext, MetricDescriptor, MetricValue};
use crate::state::{AppState, HistogramShard};

const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

pub async fn get_metrics(State(state): State<AppState>) -> Result<Response, Response> {
    let mut buf = String::with_capacity(2048);
    let ctx = MetricContext {
        metrics: &state.metrics,
        reachability: &state.sink_reachability,
    };

    for desc in metrics_defs::descriptors() {
        // The scan-duration histogram occupies its byte-identical slot just before uptime.
        if desc.name == HISTOGRAM_SUCCESSOR {
            write_scan_duration_seconds(&state, &mut buf).map_err(internal)?;
        }
        write_metric(desc, &ctx, &mut buf).map_err(internal)?;
    }

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)],
        buf,
    )
        .into_response())
}

const HISTOGRAM_SUCCESSOR: &str = "rastreo_server_uptime_seconds";

fn internal(_: std::fmt::Error) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "failed to emit server metrics",
    )
        .into_response()
}

fn write_metric(
    desc: &MetricDescriptor,
    ctx: &MetricContext,
    buf: &mut String,
) -> std::fmt::Result {
    let mut wrote_header = false;
    let mut result = Ok(());
    (desc.read)(ctx, &mut |labels, value| {
        if result.is_err() {
            return;
        }
        if !wrote_header {
            wrote_header = true;
            if let Err(e) = write_metric_header(buf, desc) {
                result = Err(e);
                return;
            }
        }
        result = write_sample(buf, desc.name, labels, value);
    });
    result
}

fn write_metric_header(buf: &mut String, desc: &MetricDescriptor) -> std::fmt::Result {
    writeln!(buf, "# HELP {} {}", desc.name, desc.help)?;
    writeln!(buf, "# TYPE {} {}", desc.name, desc.kind.prometheus_type())
}

fn write_sample(
    buf: &mut String,
    name: &str,
    labels: &[Label],
    value: MetricValue,
) -> std::fmt::Result {
    buf.push_str(name);
    if let Some((&(first_key, first_val), rest)) = labels.split_first() {
        write!(buf, "{{{first_key}=\"{}\"", escape_label(first_val))?;
        for &(key, val) in rest {
            write!(buf, ",{key}=\"{}\"", escape_label(val))?;
        }
        buf.push('}');
    }
    match value {
        MetricValue::U64(n) => writeln!(buf, " {n}"),
        MetricValue::F64(x) => writeln!(buf, " {x}"),
    }
}

fn write_scan_duration_seconds(state: &AppState, buf: &mut String) -> std::fmt::Result {
    writeln!(
        buf,
        "# HELP rastreo_server_scan_duration_seconds Duration of POST /scans request handling, partitioned by scenario."
    )?;
    writeln!(buf, "# TYPE rastreo_server_scan_duration_seconds histogram")?;
    write_scan_duration_histogram(&state.metrics.scan_duration.all.snapshot(), "_all", buf)?;
    write_scan_duration_histogram(&state.metrics.scan_duration.other.snapshot(), "other", buf)?;
    let per_scenario = state
        .metrics
        .scan_duration
        .per_scenario
        .read()
        .unwrap_or_else(|e| e.into_inner());
    let mut names: Vec<&String> = per_scenario.keys().collect();
    names.sort();
    for name in names {
        if let Some(shard) = per_scenario.get(name) {
            write_scan_duration_histogram(&shard.snapshot(), name, buf)?;
        }
    }
    Ok(())
}

fn write_scan_duration_histogram(
    snap: &crate::state::HistogramSnapshot,
    scenario: &str,
    buf: &mut String,
) -> std::fmt::Result {
    for (i, bound) in HistogramShard::BUCKET_BOUNDS.iter().enumerate() {
        writeln!(
            buf,
            "rastreo_server_scan_duration_seconds_bucket{{scenario=\"{scenario}\",le=\"{bound}\"}} {}",
            snap.buckets[i]
        )?;
    }
    writeln!(
        buf,
        "rastreo_server_scan_duration_seconds_bucket{{scenario=\"{scenario}\",le=\"+Inf\"}} {}",
        snap.plus_inf
    )?;
    writeln!(
        buf,
        "rastreo_server_scan_duration_seconds_sum{{scenario=\"{scenario}\"}} {}",
        snap.sum
    )?;
    writeln!(
        buf,
        "rastreo_server_scan_duration_seconds_count{{scenario=\"{scenario}\"}} {}",
        snap.count
    )
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
    use rastreo_core::{
        DiscoverySummary, HickoryResolver, ProbeKind, ProbeKindSummary, Resolver, SinkErrorClass,
        SinkType,
    };

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
            "# HELP rastreo_server_dlq_records_total",
            "# TYPE rastreo_server_dlq_records_total counter",
            "# HELP rastreo_server_scan_duration_seconds",
            "# TYPE rastreo_server_scan_duration_seconds histogram",
            "# HELP rastreo_server_uptime_seconds",
            "# HELP rastreo_server_build_info",
            "rastreo_server_scans_total{outcome=\"success\"} 0",
            "rastreo_server_scans_total{outcome=\"error\"} 0",
            "rastreo_server_scans_total{outcome=\"cancelled\"} 0",
            "rastreo_server_probes_total{outcome=\"success\",probe_kind=\"tcp_connect\"} 0",
            "rastreo_server_probes_total{outcome=\"error\",probe_kind=\"tcp_connect\"} 0",
            "rastreo_server_probes_total{outcome=\"success\",probe_kind=\"reverse_dns\"} 0",
            "rastreo_server_records_emitted_total 0",
            "rastreo_server_sink_errors_total{error_class=\"publish_failure\"} 0",
            "rastreo_server_sink_errors_total{error_class=\"produce_failure\"} 0",
            "rastreo_server_sink_errors_total{error_class=\"ack_rejection\"} 0",
            "rastreo_server_dlq_records_total{sink_type=\"kafka\",error_class=\"produce_failure\"} 0",
            "rastreo_server_dlq_records_total{sink_type=\"nats\",error_class=\"publish_failure\"} 0",
            "rastreo_server_scan_duration_seconds_bucket{scenario=\"_all\",le=\"0.005\"} 0",
            "rastreo_server_scan_duration_seconds_bucket{scenario=\"_all\",le=\"+Inf\"} 0",
            "rastreo_server_scan_duration_seconds_sum{scenario=\"_all\"} 0",
            "rastreo_server_scan_duration_seconds_count{scenario=\"_all\"} 0",
            "rastreo_server_scan_duration_seconds_bucket{scenario=\"other\",le=\"0.005\"} 0",
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

    fn build_kind_summary(kind: ProbeKind, attempted: usize, errored: usize) -> ProbeKindSummary {
        let mut s = ProbeKindSummary::default();
        s.kind = kind;
        s.attempted = attempted;
        s.errored = errored;
        s
    }

    #[tokio::test]
    async fn get_metrics_reflects_recorded_scan_completion() {
        let state = build_state();
        let mut summary = DiscoverySummary::default();
        summary.targets_resolved = 1;
        summary.probe_attempts = 10;
        summary.records_emitted = 5;
        summary.probes_by_kind = vec![build_kind_summary(ProbeKind::TcpConnect, 10, 2)];
        summary.sink_type = Some(SinkType::Memory);
        summary.elapsed = Duration::from_millis(123);
        state.metrics.record_scan_completion(&summary, "unnamed");

        let resp = get_metrics(State(state)).await.expect("ok");
        let body = body_string(resp).await;
        assert!(body.contains("rastreo_server_scans_total{outcome=\"success\"} 1"));
        assert!(body.contains("rastreo_server_scans_total{outcome=\"cancelled\"} 0"));
        assert!(body.contains(
            "rastreo_server_probes_total{outcome=\"success\",probe_kind=\"tcp_connect\"} 8"
        ));
        assert!(body.contains(
            "rastreo_server_probes_total{outcome=\"error\",probe_kind=\"tcp_connect\"} 2"
        ));
        assert!(body.contains("rastreo_server_records_emitted_total 5"));
        assert!(body.contains("rastreo_server_scan_duration_seconds_count{scenario=\"_all\"} 1"));
        // 0.123s falls in the le=0.25 bucket and every higher bucket.
        assert!(
            body.contains(
                "rastreo_server_scan_duration_seconds_bucket{scenario=\"_all\",le=\"0.25\"} 1"
            ),
            "histogram bucket for 0.123s should be >= 1 at le=0.25; body was:\n{body}"
        );
    }

    #[tokio::test]
    async fn get_metrics_reflects_cancelled_scan() {
        let state = build_state();
        let mut summary = DiscoverySummary::default();
        summary.targets_resolved = 1;
        summary.probe_attempts = 3;
        summary.records_emitted = 1;
        summary.cancelled = true;
        summary.elapsed = Duration::from_millis(40);
        state.metrics.record_scan_completion(&summary, "unnamed");
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
            .record_scan_error(Duration::from_millis(50), None, "unnamed");
        let resp = get_metrics(State(state)).await.expect("ok");
        let body = body_string(resp).await;
        assert!(body.contains("rastreo_server_scans_total{outcome=\"error\"} 1"));
        assert!(
            body.contains("rastreo_server_sink_errors_total{error_class=\"publish_failure\"} 0")
        );
    }

    #[tokio::test]
    async fn get_metrics_reflects_sink_error_by_class() {
        let state = build_state();
        state.metrics.record_scan_error(
            Duration::from_millis(50),
            Some(SinkErrorClass::PublishFailure),
            "unnamed",
        );
        let resp = get_metrics(State(state)).await.expect("ok");
        let body = body_string(resp).await;
        assert!(body.contains("rastreo_server_scans_total{outcome=\"error\"} 1"));
        assert!(
            body.contains("rastreo_server_sink_errors_total{error_class=\"publish_failure\"} 1")
        );
        assert!(body.contains("rastreo_server_sink_errors_total{error_class=\"ack_rejection\"} 0"));
    }

    #[tokio::test]
    async fn get_metrics_reflects_dlq_records_for_kafka() {
        let state = build_state();
        let mut summary = DiscoverySummary::default();
        summary.targets_resolved = 1;
        summary.probe_attempts = 1;
        summary.records_emitted = 1;
        summary.dlq_records = 7;
        summary.sink_type = Some(SinkType::Kafka);
        summary.dlq_records_by_type_and_class =
            vec![(SinkType::Kafka, SinkErrorClass::ProduceFailure, 7)];
        summary.elapsed = Duration::from_millis(20);
        state.metrics.record_scan_completion(&summary, "unnamed");
        let resp = get_metrics(State(state)).await.expect("ok");
        let body = body_string(resp).await;
        assert!(body.contains(
            "rastreo_server_dlq_records_total{sink_type=\"kafka\",error_class=\"produce_failure\"} 7"
        ));
    }

    #[tokio::test]
    async fn get_metrics_reflects_dlq_records_for_nats_ack_rejection() {
        let state = build_state();
        let mut summary = DiscoverySummary::default();
        summary.targets_resolved = 1;
        summary.probe_attempts = 1;
        summary.records_emitted = 1;
        summary.dlq_records = 4;
        summary.sink_type = Some(SinkType::Nats);
        summary.dlq_records_by_type_and_class =
            vec![(SinkType::Nats, SinkErrorClass::AckRejection, 4)];
        summary.elapsed = Duration::from_millis(20);
        state.metrics.record_scan_completion(&summary, "unnamed");
        let resp = get_metrics(State(state)).await.expect("ok");
        let body = body_string(resp).await;
        assert!(body.contains(
            "rastreo_server_dlq_records_total{sink_type=\"nats\",error_class=\"ack_rejection\"} 4"
        ));
        assert!(body.contains(
            "rastreo_server_dlq_records_total{sink_type=\"nats\",error_class=\"publish_failure\"} 0"
        ));
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

    #[tokio::test]
    async fn get_metrics_omits_sink_reachability_series_when_sink_not_configured() {
        let state = build_state();
        let resp = get_metrics(State(state)).await.expect("ok");
        let body = body_string(resp).await;
        assert!(
            !body.contains("rastreo_server_sink_reachable"),
            "no sink series expected when unconfigured; body was:\n{body}"
        );
        assert!(
            !body.contains("rastreo_server_sink_reachability_probe_total"),
            "no probe counter expected when unconfigured; body was:\n{body}"
        );
        assert!(
            !body.contains("rastreo_server_sink_probe_ticks_total"),
            "no tick counter expected when unconfigured; body was:\n{body}"
        );
    }

    #[tokio::test]
    async fn get_metrics_reports_sink_reachable_gauge_and_probe_counters_when_configured() {
        use std::sync::Arc;

        use crate::state::SinkReachability;

        let mut state = build_state();
        let reach = Arc::new(SinkReachability::configured(
            SinkType::Kafka,
            Duration::from_secs(10),
            Duration::from_secs(5),
        ));
        reach.record_success();
        reach.record_tick();
        reach.record_tick();
        reach.record_tick();
        reach.record_tick();
        state.metrics.record_sink_probe_success();
        state.metrics.record_sink_probe_success();
        state.metrics.record_sink_probe_failure();
        state.sink_reachability = reach;
        let resp = get_metrics(State(state)).await.expect("ok");
        let body = body_string(resp).await;
        for expected in [
            "# HELP rastreo_server_sink_reachability_probe_total",
            "# TYPE rastreo_server_sink_reachability_probe_total counter",
            "rastreo_server_sink_reachability_probe_total{outcome=\"success\",sink_type=\"kafka\"} 2",
            "rastreo_server_sink_reachability_probe_total{outcome=\"failure\",sink_type=\"kafka\"} 1",
            "# HELP rastreo_server_sink_probe_ticks_total",
            "# TYPE rastreo_server_sink_probe_ticks_total counter",
            "rastreo_server_sink_probe_ticks_total{sink_type=\"kafka\"} 4",
            "# HELP rastreo_server_sink_reachable",
            "# TYPE rastreo_server_sink_reachable gauge",
            "rastreo_server_sink_reachable{sink_type=\"kafka\"} 1",
        ] {
            assert!(
                body.contains(expected),
                "metrics body must contain `{expected}`; body was:\n{body}",
            );
        }
    }

    #[tokio::test]
    async fn get_metrics_reports_sink_reachable_zero_with_unknown_label_on_construction_failure() {
        use std::sync::Arc;

        use crate::state::SinkReachability;

        let mut state = build_state();
        let reach = Arc::new(SinkReachability::construction_failed(
            None,
            "yaml parse failed".into(),
            Duration::from_secs(10),
            Duration::from_secs(5),
        ));
        state.metrics.record_sink_probe_failure();
        state.sink_reachability = reach;
        let resp = get_metrics(State(state)).await.expect("ok");
        let body = body_string(resp).await;
        for expected in [
            "rastreo_server_sink_reachable{sink_type=\"unknown\"} 0",
            "rastreo_server_sink_reachability_probe_total{outcome=\"success\",sink_type=\"unknown\"} 0",
            "rastreo_server_sink_reachability_probe_total{outcome=\"failure\",sink_type=\"unknown\"} 1",
        ] {
            assert!(
                body.contains(expected),
                "metrics body must contain `{expected}`; body was:\n{body}",
            );
        }
    }

    #[tokio::test]
    async fn get_metrics_sink_reachable_gauge_reports_zero_when_unreachable() {
        use std::sync::Arc;

        use crate::state::SinkReachability;

        let mut state = build_state();
        let reach = Arc::new(SinkReachability::configured(
            SinkType::Nats,
            Duration::from_secs(10),
            Duration::from_secs(5),
        ));
        reach.record_failure("no route".into());
        state.sink_reachability = reach;
        let resp = get_metrics(State(state)).await.expect("ok");
        let body = body_string(resp).await;
        assert!(
            body.contains("rastreo_server_sink_reachable{sink_type=\"nats\"} 0"),
            "gauge must be 0 when unreachable; body was:\n{body}"
        );
    }

    #[tokio::test]
    async fn prometheus_help_lines_are_generated_from_the_descriptor_table() {
        use std::sync::Arc;

        use crate::state::SinkReachability;

        let mut state = build_state();
        state.sink_reachability = Arc::new(SinkReachability::configured(
            SinkType::Kafka,
            Duration::from_secs(10),
            Duration::from_secs(5),
        ));
        let resp = get_metrics(State(state)).await.expect("ok");
        let body = body_string(resp).await;
        for desc in crate::metrics_defs::descriptors() {
            let expected = format!("# HELP {} {}", desc.name, desc.help);
            assert!(
                body.contains(&expected),
                "metrics body must contain `{expected}`; body was:\n{body}"
            );
        }
    }
}
