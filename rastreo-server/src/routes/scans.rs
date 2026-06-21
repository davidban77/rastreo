use axum::extract::State;
use axum::Json;
use rastreo_core::config::DiscoverScenarioConfig;
use rastreo_core::{run_discovery_with_components, DeviceRecord, DiscoverySummary, MemorySink};
use serde::Serialize;

use crate::error::AppError;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub summary: DiscoverySummary,
    pub records: Vec<DeviceRecord>,
}

/// Run a discovery scenario synchronously; the client-supplied `sink` field is ignored and records are returned in the response body.
pub async fn create_scan(
    State(state): State<AppState>,
    Json(scenario): Json<DiscoverScenarioConfig>,
) -> Result<Json<ScanResponse>, AppError> {
    if scenario.targets.is_empty() {
        return Err(AppError::bad_request("scenario.targets must not be empty"));
    }
    if scenario.probers.is_empty() {
        return Err(AppError::bad_request("scenario.probers must not be empty"));
    }

    let memory_sink = MemorySink::new();
    let handle = memory_sink.handle();

    let summary =
        run_discovery_with_components(&scenario, state.resolver.clone(), Box::new(memory_sink))
            .await?;

    let records: Vec<DeviceRecord> = handle
        .ndjson_lines()
        .into_iter()
        .filter_map(|line| serde_json::from_str(&line).ok())
        .collect();

    Ok(Json(ScanResponse { summary, records }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Duration;

    use axum::http::StatusCode;
    use rastreo_core::config::BaseProbeConfig;
    use rastreo_core::{HickoryResolver, ProberConfig, Resolver, Target};

    fn state_with_system_resolver() -> AppState {
        let resolver: Arc<dyn Resolver> =
            Arc::new(HickoryResolver::from_system().expect("system resolver"));
        AppState::new(resolver)
    }

    fn scenario(targets: Vec<Target>, probers: Vec<ProberConfig>) -> DiscoverScenarioConfig {
        DiscoverScenarioConfig::new(BaseProbeConfig::default(), targets, probers)
    }

    #[tokio::test]
    async fn create_scan_with_empty_targets_returns_400() {
        let state = state_with_system_resolver();
        let scenario = scenario(
            Vec::new(),
            vec![ProberConfig::TcpConnect { ports: vec![22] }],
        );
        let err = create_scan(State(state), Json(scenario))
            .await
            .expect_err("empty targets must error");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("targets"));
    }

    #[tokio::test]
    async fn create_scan_with_empty_probers_returns_400() {
        let state = state_with_system_resolver();
        let scenario = scenario(
            vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            Vec::new(),
        );
        let err = create_scan(State(state), Json(scenario))
            .await
            .expect_err("empty probers must error");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("probers"));
    }

    #[tokio::test]
    async fn create_scan_returns_summary_and_records_for_open_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let state = state_with_system_resolver();
        let mut s = scenario(
            vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            vec![ProberConfig::TcpConnect { ports: vec![port] }],
        );
        s.base.timeout_ms = Some(500);

        let Json(response) = create_scan(State(state), Json(s))
            .await
            .expect("create_scan");
        assert_eq!(response.summary.records_emitted, 1);
        assert_eq!(response.records.len(), 1);
        assert_eq!(
            response.records[0].mgmt_ip,
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
    }

    #[test]
    fn scan_response_serializes_summary_with_elapsed_ms_field() {
        let response = ScanResponse {
            summary: DiscoverySummary {
                targets_resolved: 1,
                probe_attempts: 1,
                probe_errors: 0,
                records_emitted: 1,
                elapsed: Duration::from_millis(42),
            },
            records: Vec::new(),
        };
        let value: serde_json::Value = serde_json::to_value(&response).expect("serialize");
        assert_eq!(value["summary"]["elapsed_ms"], 42);
        assert_eq!(value["summary"]["records_emitted"], 1);
        assert!(value["records"].is_array());
        assert_eq!(value["records"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn create_scan_returns_records_with_identity_key_for_open_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let state = state_with_system_resolver();
        let mut s = scenario(
            vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            vec![ProberConfig::TcpConnect { ports: vec![port] }],
        );
        s.base.timeout_ms = Some(500);

        let Json(response) = create_scan(State(state), Json(s))
            .await
            .expect("create_scan");

        let value: serde_json::Value = serde_json::to_value(&response).expect("serialize response");
        let records = value["records"].as_array().expect("records array");
        assert_eq!(records.len(), 1);
        assert!(
            records[0]["identity_key"].is_string(),
            "identity_key must serialize as string"
        );
        assert_eq!(records[0]["mgmt_ip"], "127.0.0.1");
        assert_eq!(value["summary"]["records_emitted"], 1);
    }
}
