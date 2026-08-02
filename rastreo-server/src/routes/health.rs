use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use crate::state::{AppState, SinkReachability};

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

    let seconds_since_sink_error = readiness.last_sink_error.age_secs();
    let seconds_since_scan_error = readiness.last_scan_error.age_secs();

    let reach = &state.sink_reachability;
    let sink_reachable = reachability_state(reach);
    let sink_attached = reach.configured.then(|| state.sink().is_some());
    let seconds_since_last_probe = reach.last_probe.age_secs();
    let seconds_since_last_probe_tick = reach.last_tick.age_secs();
    let last_probe_error = reach.last_error_snapshot();

    let reason = classify(&ReadinessSignals {
        inflight,
        max_inflight: config.max_inflight_scans,
        sink_reachable,
        seconds_since_sink_error,
        sink_quarantine_secs: config.sink_error_quarantine.as_secs_f64(),
        seconds_since_scan_error,
        scan_quarantine_secs: config.scan_error_quarantine.as_secs_f64(),
        seconds_since_last_probe_tick,
        probe_stale_after_secs: probe_stale_after_secs(reach.probe_interval, reach.probe_timeout),
    });

    let sink_json = seconds_json(seconds_since_sink_error);
    let scan_json = seconds_json(seconds_since_scan_error);
    let probe_json = seconds_json(seconds_since_last_probe);
    let probe_tick_json = seconds_json(seconds_since_last_probe_tick);
    let sink_reachable_json = bool_json(sink_reachable);
    let sink_attached_json = bool_json(sink_attached);
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
                "sink_attached": sink_attached_json,
                "sink_type": sink_type_json,
                "seconds_since_last_probe": probe_json,
                "seconds_since_last_probe_tick": probe_tick_json,
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
                "sink_attached": sink_attached_json,
                "sink_type": sink_type_json,
                "seconds_since_last_probe": probe_json,
                "seconds_since_last_probe_tick": probe_tick_json,
                "last_probe_error": last_probe_error_json,
            })),
        ),
    }
}

fn seconds_json(value: Option<f64>) -> Value {
    value.map(|s| json!(s)).unwrap_or(Value::Null)
}

fn bool_json(value: Option<bool>) -> Value {
    value.map(Value::Bool).unwrap_or(Value::Null)
}

// None => sink is not configured (axis contributes nothing to the gate);
// Some(true) => reachable; Some(false) => unreachable.
fn reachability_state(reach: &SinkReachability) -> Option<bool> {
    if !reach.configured {
        return None;
    }
    Some(reach.reachable.load(Ordering::Relaxed))
}

struct ReadinessSignals {
    inflight: u64,
    max_inflight: u64,
    sink_reachable: Option<bool>,
    seconds_since_sink_error: Option<f64>,
    sink_quarantine_secs: f64,
    seconds_since_scan_error: Option<f64>,
    scan_quarantine_secs: f64,
    seconds_since_last_probe_tick: Option<f64>,
    probe_stale_after_secs: f64,
}

// A budget for each bounded await a cycle can make — rebuilding the sink, taking the sink lock, and the probe — plus up to an interval before the next cycle starts.
pub(crate) fn longest_legitimate_cycle_secs(
    probe_interval: Duration,
    probe_timeout: Duration,
) -> f64 {
    probe_interval.as_secs_f64() + 3.0 * probe_timeout.as_secs_f64()
}

/// Age of `seconds_since_last_probe_tick` above which `/readyz` reports `sink_probe_stalled`.
pub fn probe_stale_after_secs(probe_interval: Duration, probe_timeout: Duration) -> f64 {
    3.0 * longest_legitimate_cycle_secs(probe_interval, probe_timeout)
}

fn sink_probe_is_stalled(signals: &ReadinessSignals) -> bool {
    let Some(age) = signals.seconds_since_last_probe_tick else {
        return false;
    };
    signals.sink_reachable.is_some() && age > signals.probe_stale_after_secs
}

fn classify(signals: &ReadinessSignals) -> Option<&'static str> {
    if signals.max_inflight > 0 && signals.inflight >= signals.max_inflight {
        return Some("inflight_scan_limit_exceeded");
    }
    // Ahead of sink_unreachable: a stalled task means the cached reachability verdict is no longer vouched for.
    if sink_probe_is_stalled(signals) {
        return Some("sink_probe_stalled");
    }
    if matches!(signals.sink_reachable, Some(false)) {
        return Some("sink_unreachable");
    }
    if signals.sink_quarantine_secs > 0.0 {
        if let Some(s) = signals.seconds_since_sink_error {
            if s < signals.sink_quarantine_secs {
                return Some("sink_error_within_quarantine");
            }
        }
    }
    if signals.scan_quarantine_secs > 0.0 {
        if let Some(s) = signals.seconds_since_scan_error {
            if s < signals.scan_quarantine_secs {
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
        assert!(
            body["sink_attached"].is_null(),
            "sink_attached must be null when sink is not configured"
        );
        assert!(body["sink_type"].is_null());
        assert!(body["seconds_since_last_probe"].is_null());
        assert!(body["seconds_since_last_probe_tick"].is_null());
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

    const DEFAULT_INTERVAL: Duration = Duration::from_secs(10);
    const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

    fn healthy_signals() -> ReadinessSignals {
        ReadinessSignals {
            inflight: 0,
            max_inflight: 100,
            sink_reachable: None,
            seconds_since_sink_error: None,
            sink_quarantine_secs: 30.0,
            seconds_since_scan_error: None,
            scan_quarantine_secs: 30.0,
            seconds_since_last_probe_tick: None,
            probe_stale_after_secs: probe_stale_after_secs(DEFAULT_INTERVAL, DEFAULT_TIMEOUT),
        }
    }

    #[test]
    fn classify_returns_none_for_healthy_state() {
        assert_eq!(classify(&healthy_signals()), None);
    }

    #[test]
    fn classify_returns_none_when_error_outside_quarantine_window() {
        assert_eq!(
            classify(&ReadinessSignals {
                seconds_since_sink_error: Some(60.0),
                seconds_since_scan_error: Some(60.0),
                ..healthy_signals()
            }),
            None,
            "an error 60s ago with a 30s window must not gate readiness"
        );
    }

    #[test]
    fn classify_returns_sink_unreachable_when_reachability_is_false() {
        assert_eq!(
            classify(&ReadinessSignals {
                sink_reachable: Some(false),
                ..healthy_signals()
            }),
            Some("sink_unreachable"),
        );
    }

    #[test]
    fn classify_returns_none_when_sink_reachable_true() {
        assert_eq!(
            classify(&ReadinessSignals {
                sink_reachable: Some(true),
                ..healthy_signals()
            }),
            None
        );
    }

    #[test]
    fn classify_priority_inflight_beats_sink_unreachable() {
        assert_eq!(
            classify(&ReadinessSignals {
                inflight: 1,
                max_inflight: 1,
                sink_reachable: Some(false),
                ..healthy_signals()
            }),
            Some("inflight_scan_limit_exceeded"),
        );
    }

    #[test]
    fn classify_priority_sink_unreachable_beats_sink_quarantine_and_scan_quarantine() {
        assert_eq!(
            classify(&ReadinessSignals {
                sink_reachable: Some(false),
                seconds_since_sink_error: Some(1.0),
                seconds_since_scan_error: Some(1.0),
                ..healthy_signals()
            }),
            Some("sink_unreachable"),
        );
    }

    #[test]
    fn classify_returns_sink_probe_stalled_when_the_tick_stamp_is_older_than_the_threshold() {
        let stale_after = probe_stale_after_secs(DEFAULT_INTERVAL, DEFAULT_TIMEOUT);
        assert_eq!(
            classify(&ReadinessSignals {
                sink_reachable: Some(true),
                seconds_since_last_probe_tick: Some(stale_after + 0.1),
                ..healthy_signals()
            }),
            Some("sink_probe_stalled"),
        );
    }

    #[test]
    fn classify_returns_none_when_the_tick_stamp_is_within_the_threshold() {
        let stale_after = probe_stale_after_secs(DEFAULT_INTERVAL, DEFAULT_TIMEOUT);
        assert_eq!(
            classify(&ReadinessSignals {
                sink_reachable: Some(true),
                seconds_since_last_probe_tick: Some(stale_after),
                ..healthy_signals()
            }),
            None,
        );
    }

    #[test]
    fn classify_returns_none_for_a_stale_tick_when_no_sink_is_configured() {
        assert_eq!(
            classify(&ReadinessSignals {
                sink_reachable: None,
                seconds_since_last_probe_tick: Some(86_400.0),
                ..healthy_signals()
            }),
            None,
        );
    }

    #[test]
    fn classify_returns_none_before_the_first_tick_has_been_stamped() {
        assert_eq!(
            classify(&ReadinessSignals {
                sink_reachable: Some(true),
                seconds_since_last_probe_tick: None,
                ..healthy_signals()
            }),
            None,
        );
    }

    #[test]
    fn classify_priority_sink_probe_stalled_beats_sink_unreachable() {
        let stale_after = probe_stale_after_secs(DEFAULT_INTERVAL, DEFAULT_TIMEOUT);
        assert_eq!(
            classify(&ReadinessSignals {
                sink_reachable: Some(false),
                seconds_since_last_probe_tick: Some(stale_after + 0.1),
                ..healthy_signals()
            }),
            Some("sink_probe_stalled"),
            "a verdict the server can no longer vouch for must not be reported as a broker outage",
        );
    }

    #[test]
    fn classify_priority_inflight_beats_sink_probe_stalled() {
        let stale_after = probe_stale_after_secs(DEFAULT_INTERVAL, DEFAULT_TIMEOUT);
        assert_eq!(
            classify(&ReadinessSignals {
                inflight: 1,
                max_inflight: 1,
                sink_reachable: Some(true),
                seconds_since_last_probe_tick: Some(stale_after + 0.1),
                ..healthy_signals()
            }),
            Some("inflight_scan_limit_exceeded"),
        );
    }

    #[test]
    fn staleness_threshold_is_three_cycles_of_one_interval_and_three_probe_timeouts() {
        for interval_secs in [1_u64, 5, 10, 60, 3600] {
            for timeout_secs in [1_u64, 5, 30, 60] {
                let (i, t) = (interval_secs as f64, timeout_secs as f64);
                let cycle = i + t + t + t;
                assert_eq!(
                    longest_legitimate_cycle_secs(
                        Duration::from_secs(interval_secs),
                        Duration::from_secs(timeout_secs),
                    ),
                    cycle,
                    "interval={interval_secs}s timeout={timeout_secs}s: a cycle budgets one \
                     interval plus one probe timeout for each of construction, the lock, and the probe",
                );
                assert_eq!(
                    probe_stale_after_secs(
                        Duration::from_secs(interval_secs),
                        Duration::from_secs(timeout_secs),
                    ),
                    cycle + cycle + cycle,
                    "interval={interval_secs}s timeout={timeout_secs}s: the window must hold three \
                     whole cycles",
                );
            }
        }
    }

    #[test]
    fn staleness_threshold_on_default_probe_settings_is_75_seconds() {
        assert_eq!(
            probe_stale_after_secs(DEFAULT_INTERVAL, DEFAULT_TIMEOUT),
            75.0,
        );
        assert_eq!(
            longest_legitimate_cycle_secs(DEFAULT_INTERVAL, DEFAULT_TIMEOUT),
            25.0,
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
    async fn readyz_reports_unknown_sink_type_when_construction_failed_without_type() {
        use std::sync::Arc;
        use std::time::Duration;

        use crate::state::SinkReachability;

        let mut state = build_state();
        let reach = Arc::new(SinkReachability::construction_failed(
            None,
            "sink construction failed: yaml parse error".into(),
            Duration::from_secs(10),
            Duration::from_secs(5),
        ));
        state.sink_reachability = reach;
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["reason"], "sink_unreachable");
        assert_eq!(body["sink_reachable"], false);
        assert_eq!(body["sink_type"], "unknown");
        assert_eq!(
            body["last_probe_error"],
            "sink construction failed: yaml parse error"
        );
        assert!(body["seconds_since_last_probe"].is_number());
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

    fn configured_reach(sink_type: rastreo_core::SinkType) -> Arc<SinkReachability> {
        Arc::new(SinkReachability::configured(
            sink_type,
            DEFAULT_INTERVAL,
            DEFAULT_TIMEOUT,
        ))
    }

    fn shared_memory_sink() -> Option<(crate::state::SharedSink, rastreo_core::SinkType)> {
        Some((
            Arc::new(tokio::sync::Mutex::new(
                Box::new(rastreo_core::MemorySink::new()) as Box<dyn rastreo_core::Sink>,
            )),
            rastreo_core::SinkType::Memory,
        ))
    }

    fn past_the_staleness_window() -> Duration {
        Duration::from_secs_f64(probe_stale_after_secs(DEFAULT_INTERVAL, DEFAULT_TIMEOUT) + 1.0)
    }

    #[tokio::test]
    async fn readyz_reports_sink_attached_false_when_the_configured_sink_never_built() {
        let reach = configured_reach(rastreo_core::SinkType::Kafka);
        reach.record_failure("broker down".into());
        reach.record_tick();
        let state = build_state().with_sink(None, reach);
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["reason"], "sink_unreachable");
        assert_eq!(body["sink_attached"], false);
        assert_eq!(body["sink_reachable"], false);
    }

    #[tokio::test]
    async fn readyz_reports_sink_attached_true_when_the_configured_sink_is_unreachable() {
        let reach = configured_reach(rastreo_core::SinkType::Kafka);
        reach.record_failure("broker down".into());
        reach.record_tick();
        let state = build_state().with_sink(shared_memory_sink(), reach);
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["reason"], "sink_unreachable");
        assert_eq!(
            body["sink_attached"], true,
            "an attached sink that fails its probe must not read the same as one that never built",
        );
        assert_eq!(body["sink_reachable"], false);
    }

    #[tokio::test(start_paused = true)]
    async fn readyz_reports_a_stale_probe_tick_as_sink_probe_stalled() {
        let reach = configured_reach(rastreo_core::SinkType::Kafka);
        reach.record_success();
        reach.record_tick();
        let state = build_state().with_sink(shared_memory_sink(), reach);
        tokio::time::advance(past_the_staleness_window()).await;
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["reason"], "sink_probe_stalled");
        assert!(body["seconds_since_last_probe_tick"].is_number());
    }

    #[tokio::test(start_paused = true)]
    async fn readyz_stays_ready_while_a_long_scan_holds_the_sink_lock() {
        let reach = configured_reach(rastreo_core::SinkType::Kafka);
        reach.record_success();
        // A scan holding the lock skips the probe, so the result ages while the task keeps ticking.
        tokio::time::advance(Duration::from_secs(600)).await;
        reach.record_tick();
        let state = build_state().with_sink(shared_memory_sink(), reach);
        state.readiness.inflight_scans.store(1, Ordering::Relaxed);
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ready");
        assert!(
            body["seconds_since_last_probe"]
                .as_f64()
                .expect("probe age is a number")
                > 500.0,
            "the probe result must still report its true age",
        );
        assert!(
            body["seconds_since_last_probe_tick"]
                .as_f64()
                .expect("tick age is a number")
                < 5.0,
        );
    }

    #[tokio::test(start_paused = true)]
    async fn readyz_leaves_the_sink_error_quarantine_once_the_monotonic_window_passes() {
        let state = build_state_with(ReadinessConfig {
            max_inflight_scans: 100,
            sink_error_quarantine: Duration::from_secs(30),
            scan_error_quarantine: Duration::from_secs(30),
        });
        state.readiness.record_scan_error(true);
        let (status, Json(body)) = readyz(State(state.clone())).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["reason"], "sink_error_within_quarantine");

        tokio::time::advance(Duration::from_secs(31)).await;
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the quarantine must expire on elapsed monotonic time: {body}",
        );
        assert_eq!(body["seconds_since_sink_error"], 31.0);
    }

    #[tokio::test(start_paused = true)]
    async fn readyz_leaves_the_scan_error_quarantine_once_the_monotonic_window_passes() {
        let state = build_state_with(ReadinessConfig {
            max_inflight_scans: 100,
            sink_error_quarantine: Duration::ZERO,
            scan_error_quarantine: Duration::from_secs(30),
        });
        state.readiness.record_scan_error(false);
        let (status, _) = readyz(State(state.clone())).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        tokio::time::advance(Duration::from_secs(31)).await;
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::OK, "body was {body}");
        assert_eq!(body["seconds_since_scan_error"], 31.0);
    }

    #[tokio::test]
    async fn readyz_stays_ready_before_the_first_probe_tick_is_stamped() {
        let reach = configured_reach(rastreo_core::SinkType::Kafka);
        reach.record_success();
        let state = build_state().with_sink(shared_memory_sink(), reach);
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["seconds_since_last_probe_tick"].is_null());
    }

    #[tokio::test(start_paused = true)]
    async fn readyz_never_gates_on_staleness_when_no_sink_is_configured() {
        let state = build_state();
        state.sink_reachability.record_tick();
        tokio::time::advance(past_the_staleness_window()).await;
        let (status, Json(body)) = readyz(State(state)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ready");
        assert!(body["sink_attached"].is_null());
    }
}
