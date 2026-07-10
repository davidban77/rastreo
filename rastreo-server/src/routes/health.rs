use std::sync::atomic::Ordering;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use crate::state::{current_epoch_ms, AppState, SinkReachability};

pub async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// Backward-compat alias for `/healthz`.
pub async fn health() -> Json<Value> {
    healthz().await
}

pub async fn readyz(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let readiness = &state.readiness;
    let config = &readiness.config;
    let inflight = readiness.inflight_scans.load(Ordering::Relaxed);
    let last_sink_ms = readiness.last_sink_error_epoch_ms.load(Ordering::Relaxed);
    let last_scan_ms = readiness.last_scan_error_epoch_ms.load(Ordering::Relaxed);
    let now_ms = current_epoch_ms();

    let seconds_since_sink_error = seconds_since(now_ms, last_sink_ms);
    let seconds_since_scan_error = seconds_since(now_ms, last_scan_ms);

    let reach = &state.sink_reachability;
    let sink_reachable = reachability_state(reach);
    let seconds_since_last_probe =
        seconds_since(now_ms, reach.last_probe_epoch_ms.load(Ordering::Relaxed));
    let last_probe_error = reach.last_error_snapshot();

    let reason = classify(
        inflight,
        config.max_inflight_scans,
        sink_reachable,
        seconds_since_sink_error,
        config.sink_error_quarantine.as_secs_f64(),
        seconds_since_scan_error,
        config.scan_error_quarantine.as_secs_f64(),
    );

    let sink_json = seconds_since_sink_error
        .map(|s| json!(s))
        .unwrap_or(Value::Null);
    let scan_json = seconds_since_scan_error
        .map(|s| json!(s))
        .unwrap_or(Value::Null);
    let probe_json = seconds_since_last_probe
        .map(|s| json!(s))
        .unwrap_or(Value::Null);
    let sink_reachable_json = match sink_reachable {
        Some(v) => json!(v),
        None => Value::Null,
    };
    let sink_type_json = reach
        .sink_type_label()
        .map(|s| json!(s))
        .unwrap_or(Value::Null);
    let last_probe_error_json = last_probe_error
        .clone()
        .map(Value::String)
        .unwrap_or(Value::Null);

    match reason {
        None => (
            StatusCode::OK,
            Json(json!({
                "status": "ready",
                "inflight_scans": inflight,
                "max_inflight_scans": config.max_inflight_scans,
                "seconds_since_sink_error": sink_json,
                "seconds_since_scan_error": scan_json,
                "sink_reachable": sink_reachable_json,
                "sink_type": sink_type_json,
                "seconds_since_last_probe": probe_json,
                "last_probe_error": last_probe_error_json,
            })),
        ),
        Some(reason) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "not_ready",
                "reason": reason,
                "inflight_scans": inflight,
                "max_inflight_scans": config.max_inflight_scans,
                "seconds_since_sink_error": sink_json,
                "seconds_since_scan_error": scan_json,
                "sink_reachable": sink_reachable_json,
                "sink_type": sink_type_json,
                "seconds_since_last_probe": probe_json,
                "last_probe_error": last_probe_error_json,
            })),
        ),
    }
}

// None => sink is not configured (axis contributes nothing to the gate);
// Some(true) => reachable; Some(false) => unreachable.
fn reachability_state(reach: &SinkReachability) -> Option<bool> {
    if !reach.configured {
        return None;
    }
    Some(reach.reachable.load(Ordering::Relaxed))
}

fn seconds_since(now_ms: u64, then_ms: u64) -> Option<f64> {
    if then_ms == 0 {
        return None;
    }
    let delta_ms = now_ms.saturating_sub(then_ms);
    Some(delta_ms as f64 / 1000.0)
}

fn classify(
    inflight: u64,
    max_inflight: u64,
    sink_reachable: Option<bool>,
    seconds_since_sink: Option<f64>,
    sink_quarantine_secs: f64,
    seconds_since_scan: Option<f64>,
    scan_quarantine_secs: f64,
) -> Option<&'static str> {
    if max_inflight > 0 && inflight >= max_inflight {
        return Some("inflight_scan_limit_exceeded");
    }
    if matches!(sink_reachable, Some(false)) {
        return Some("sink_unreachable");
    }
    if sink_quarantine_secs > 0.0 {
        if let Some(s) = seconds_since_sink {
            if s < sink_quarantine_secs {
                return Some("sink_error_within_quarantine");
            }
        }
    }
    if scan_quarantine_secs > 0.0 {
        if let Some(s) = seconds_since_scan {
            if s < scan_quarantine_secs {
                return Some("scan_error_within_quarantine");
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use rastreo_core::{HickoryResolver, Resolver};

    use crate::state::ReadinessConfig;

    fn build_state_with(config: ReadinessConfig) -> AppState {
        let resolver: Arc<dyn Resolver> =
            Arc::new(HickoryResolver::from_system().expect("system resolver"));
        AppState::with_readiness(resolver, config)
    }

    fn build_state() -> AppState {
        build_state_with(ReadinessConfig::default())
    }

    #[tokio::test]
    async fn healthz_returns_ok_status_body() {
        let Json(body) = healthz().await;
        assert_eq!(body["status"], "ok");
    }

    #[tokio::test]
    async fn health_alias_returns_same_body_as_healthz() {
        let Json(healthz_body) = healthz().await;
        let Json(health_body) = health().await;
        assert_eq!(healthz_body, health_body);
    }

    #[tokio::test]
    async fn readyz_default_state_returns_200_ready() {
        let state = build_state();
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ready");
        assert_eq!(body["inflight_scans"], 0);
        assert_eq!(body["max_inflight_scans"], 100);
        assert!(body["seconds_since_sink_error"].is_null());
        assert!(body["seconds_since_scan_error"].is_null());
        assert!(
            body["sink_reachable"].is_null(),
            "sink_reachable must be null when sink is not configured"
        );
        assert!(body["sink_type"].is_null());
        assert!(body["seconds_since_last_probe"].is_null());
        assert!(body["last_probe_error"].is_null());
        assert!(body.get("reason").is_none());
    }

    #[tokio::test]
    async fn readyz_inflight_at_limit_returns_503_with_inflight_reason() {
        let state = build_state_with(ReadinessConfig {
            max_inflight_scans: 2,
            sink_error_quarantine: Duration::from_secs(30),
            scan_error_quarantine: Duration::from_secs(30),
        });
        state.readiness.inflight_scans.store(2, Ordering::Relaxed);
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "not_ready");
        assert_eq!(body["reason"], "inflight_scan_limit_exceeded");
        assert_eq!(body["inflight_scans"], 2);
        assert_eq!(body["max_inflight_scans"], 2);
    }

    #[tokio::test]
    async fn readyz_recent_sink_error_returns_503_with_sink_reason() {
        let state = build_state_with(ReadinessConfig {
            max_inflight_scans: 100,
            sink_error_quarantine: Duration::from_secs(30),
            scan_error_quarantine: Duration::from_secs(30),
        });
        state.readiness.record_scan_error(true);
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["reason"], "sink_error_within_quarantine");
    }

    #[tokio::test]
    async fn readyz_recent_scan_error_only_returns_503_with_scan_reason() {
        let state = build_state_with(ReadinessConfig {
            max_inflight_scans: 100,
            sink_error_quarantine: Duration::from_secs(30),
            scan_error_quarantine: Duration::from_secs(30),
        });
        state.readiness.record_scan_error(false);
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["reason"], "scan_error_within_quarantine");
        assert!(body["seconds_since_sink_error"].is_null());
        assert!(body["seconds_since_scan_error"].is_number());
    }

    #[tokio::test]
    async fn readyz_reason_priority_inflight_beats_sink_and_scan() {
        let state = build_state_with(ReadinessConfig {
            max_inflight_scans: 1,
            sink_error_quarantine: Duration::from_secs(30),
            scan_error_quarantine: Duration::from_secs(30),
        });
        state.readiness.inflight_scans.store(1, Ordering::Relaxed);
        state.readiness.record_scan_error(true);
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["reason"], "inflight_scan_limit_exceeded");
    }

    #[tokio::test]
    async fn readyz_reason_priority_sink_beats_scan() {
        let state = build_state_with(ReadinessConfig {
            max_inflight_scans: 100,
            sink_error_quarantine: Duration::from_secs(30),
            scan_error_quarantine: Duration::from_secs(30),
        });
        state.readiness.record_scan_error(true);
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["reason"], "sink_error_within_quarantine");
    }

    #[tokio::test]
    async fn readyz_disabled_inflight_check_ignores_saturation() {
        let state = build_state_with(ReadinessConfig {
            max_inflight_scans: 0,
            sink_error_quarantine: Duration::from_secs(30),
            scan_error_quarantine: Duration::from_secs(30),
        });
        state
            .readiness
            .inflight_scans
            .store(9_999, Ordering::Relaxed);
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ready");
    }

    #[tokio::test]
    async fn readyz_disabled_sink_quarantine_ignores_recent_error() {
        let state = build_state_with(ReadinessConfig {
            max_inflight_scans: 100,
            sink_error_quarantine: Duration::ZERO,
            scan_error_quarantine: Duration::ZERO,
        });
        state.readiness.record_scan_error(true);
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ready");
    }

    #[test]
    fn classify_returns_none_for_healthy_state() {
        assert_eq!(classify(0, 100, None, None, 30.0, None, 30.0), None);
    }

    #[test]
    fn classify_returns_none_when_error_outside_quarantine_window() {
        assert_eq!(
            classify(0, 100, None, Some(60.0), 30.0, Some(60.0), 30.0),
            None,
            "an error 60s ago with a 30s window must not gate readiness"
        );
    }

    #[test]
    fn classify_returns_sink_unreachable_when_reachability_is_false() {
        assert_eq!(
            classify(0, 100, Some(false), None, 30.0, None, 30.0),
            Some("sink_unreachable"),
        );
    }

    #[test]
    fn classify_returns_none_when_sink_reachable_true() {
        assert_eq!(classify(0, 100, Some(true), None, 30.0, None, 30.0), None);
    }

    #[test]
    fn classify_priority_inflight_beats_sink_unreachable() {
        assert_eq!(
            classify(1, 1, Some(false), None, 30.0, None, 30.0),
            Some("inflight_scan_limit_exceeded"),
        );
    }

    #[test]
    fn classify_priority_sink_unreachable_beats_sink_quarantine_and_scan_quarantine() {
        assert_eq!(
            classify(0, 100, Some(false), Some(1.0), 30.0, Some(1.0), 30.0),
            Some("sink_unreachable"),
        );
    }

    #[tokio::test]
    async fn readyz_sink_unreachable_returns_503_with_sink_unreachable_reason() {
        use std::sync::Arc;
        use std::time::Duration;

        use crate::state::SinkReachability;

        let mut state = build_state();
        let reach = Arc::new(SinkReachability::configured(
            rastreo_core::SinkType::Kafka,
            Duration::from_secs(10),
            Duration::from_secs(5),
        ));
        reach.record_failure("broker down".into());
        state.sink_reachability = reach;
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["reason"], "sink_unreachable");
        assert_eq!(body["sink_reachable"], false);
        assert_eq!(body["sink_type"], "kafka");
        assert_eq!(body["last_probe_error"], "broker down");
        assert!(body["seconds_since_last_probe"].is_number());
    }

    #[tokio::test]
    async fn readyz_sink_reachable_returns_200_with_true() {
        use std::sync::Arc;
        use std::time::Duration;

        use crate::state::SinkReachability;

        let mut state = build_state();
        let reach = Arc::new(SinkReachability::configured(
            rastreo_core::SinkType::Stdout,
            Duration::from_secs(10),
            Duration::from_secs(5),
        ));
        reach.record_success();
        state.sink_reachability = reach;
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["sink_reachable"], true);
        assert_eq!(body["sink_type"], "stdout");
        assert!(body["last_probe_error"].is_null());
        assert!(body["seconds_since_last_probe"].is_number());
    }

    #[tokio::test]
    async fn readyz_sink_unreachable_beats_sink_quarantine_and_scan_quarantine() {
        use std::sync::Arc;
        use std::time::Duration;

        use crate::state::SinkReachability;

        let mut state = build_state_with(ReadinessConfig {
            max_inflight_scans: 100,
            sink_error_quarantine: Duration::from_secs(30),
            scan_error_quarantine: Duration::from_secs(30),
        });
        let reach = Arc::new(SinkReachability::configured(
            rastreo_core::SinkType::Nats,
            Duration::from_secs(10),
            Duration::from_secs(5),
        ));
        reach.record_failure("no route".into());
        state.sink_reachability = reach;
        state.readiness.record_scan_error(true);
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["reason"], "sink_unreachable");
    }

    #[tokio::test]
    async fn readyz_inflight_beats_sink_unreachable() {
        use std::sync::Arc;
        use std::time::Duration;

        use crate::state::SinkReachability;

        let mut state = build_state_with(ReadinessConfig {
            max_inflight_scans: 1,
            sink_error_quarantine: Duration::from_secs(30),
            scan_error_quarantine: Duration::from_secs(30),
        });
        state.readiness.inflight_scans.store(1, Ordering::Relaxed);
        let reach = Arc::new(SinkReachability::configured(
            rastreo_core::SinkType::Kafka,
            Duration::from_secs(10),
            Duration::from_secs(5),
        ));
        reach.record_failure("broker down".into());
        state.sink_reachability = reach;
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["reason"], "inflight_scan_limit_exceeded");
    }
}
