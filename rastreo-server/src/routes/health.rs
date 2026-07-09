use std::sync::atomic::Ordering;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use crate::state::{current_epoch_ms, AppState};

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

    let reason = classify(
        inflight,
        config.max_inflight_scans,
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

    match reason {
        None => (
            StatusCode::OK,
            Json(json!({
                "status": "ready",
                "inflight_scans": inflight,
                "max_inflight_scans": config.max_inflight_scans,
                "seconds_since_sink_error": sink_json,
                "seconds_since_scan_error": scan_json,
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
            })),
        ),
    }
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
    seconds_since_sink: Option<f64>,
    sink_quarantine_secs: f64,
    seconds_since_scan: Option<f64>,
    scan_quarantine_secs: f64,
) -> Option<&'static str> {
    if max_inflight > 0 && inflight >= max_inflight {
        return Some("inflight_scan_limit_exceeded");
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
        assert_eq!(classify(0, 100, None, 30.0, None, 30.0), None);
    }

    #[test]
    fn classify_returns_none_when_error_outside_quarantine_window() {
        assert_eq!(
            classify(0, 100, Some(60.0), 30.0, Some(60.0), 30.0),
            None,
            "an error 60s ago with a 30s window must not gate readiness"
        );
    }
}
