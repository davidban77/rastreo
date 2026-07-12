use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use rastreo_core::config::DiscoverScenarioConfig;
use rastreo_core::{
    classify_sink_error, hint_for_error_kind, run_discovery_with_components, DeviceRecord,
    DiscoverySummary, EncoderConfig, MemorySink, Sink, TeeChild, TeeSink,
};
use serde::Serialize;

use crate::error::AppError;
use crate::state::{AppState, ReadinessState};

struct InflightGuard(Arc<ReadinessState>);

impl InflightGuard {
    fn new(state: Arc<ReadinessState>) -> Self {
        state.inflight_scans.fetch_add(1, Ordering::Relaxed);
        Self(state)
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.inflight_scans.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub summary: DiscoverySummary,
    pub records: Vec<DeviceRecord>,
    /// Operator guidance for the first probe fault, keyed on its [`rastreo_core::ProbeErrorKind`]; absent when no probe faulted or the kind carries no specific action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// Run a discovery scenario synchronously; the client-supplied `sink` field is ignored and records are returned in the response body.
pub async fn create_scan(
    State(state): State<AppState>,
    Json(scenario): Json<DiscoverScenarioConfig>,
) -> Result<Json<ScanResponse>, AppError> {
    let start = std::time::Instant::now();
    let _inflight = InflightGuard::new(state.readiness.clone());

    let scenario_label = scenario
        .base
        .name
        .clone()
        .unwrap_or_else(|| "unnamed".to_string());

    if scenario.targets.is_empty() {
        state
            .metrics
            .record_scan_error(start.elapsed(), None, &scenario_label);
        state.readiness.record_scan_error(false);
        return Err(AppError::bad_request("scenario.targets must not be empty"));
    }
    if scenario.probers.is_empty() {
        state
            .metrics
            .record_scan_error(start.elapsed(), None, &scenario_label);
        state.readiness.record_scan_error(false);
        return Err(AppError::bad_request("scenario.probers must not be empty"));
    }

    let mut scenario = scenario;
    if scenario.base.sink.is_some() {
        tracing::warn!(
            sink = ?scenario.base.sink,
            "client-supplied sink ignored; server returns records via response body"
        );
        scenario.base.sink = None;
    }
    if matches!(scenario.base.encoder, Some(ref e) if !matches!(e, EncoderConfig::Ndjson)) {
        tracing::warn!(
            encoder = ?scenario.base.encoder,
            "client-supplied encoder ignored; server forces NDJSON encoding"
        );
    }
    // Pin the encoder server-side so the MemorySink read-back parses line-by-line as JSON.
    scenario.base.encoder = Some(EncoderConfig::Ndjson);

    let memory_sink = MemorySink::new();
    let handle = memory_sink.handle();

    // Memory child first so the response body captures every record even if the shared sink aborts mid-scan.
    let mut children: Vec<TeeChild> = vec![TeeChild::Owned(Box::new(memory_sink))];
    if let Some(server_sink) = state.sink.as_ref() {
        children.push(TeeChild::Shared(Arc::clone(server_sink)));
    }
    let pipeline_sink: Box<dyn Sink> = Box::new(TeeSink::new(children));

    // MemorySink has no buffer to flush; TimeoutLayer handles request-lifecycle drop, so the
    // non-cancellable wrapper is correct here.
    let summary_result =
        run_discovery_with_components(&scenario, state.resolver.clone(), pipeline_sink).await;

    match summary_result {
        Ok(summary) => {
            state
                .metrics
                .record_scan_completion(&summary, &scenario_label);
            let records: Vec<DeviceRecord> = handle
                .ndjson_lines()
                .into_iter()
                .filter_map(|line| serde_json::from_str(&line).ok())
                .collect();
            let hint = summary
                .first_probe_error
                .as_ref()
                .and_then(|fault| hint_for_error_kind(fault.kind))
                .map(String::from);
            Ok(Json(ScanResponse {
                summary,
                records,
                hint,
            }))
        }
        Err(err) => {
            let sink_class = match &err {
                rastreo_core::RastreoError::Sink(io) => Some(classify_sink_error(io)),
                _ => None,
            };
            let is_sink_error = sink_class.is_some();
            state
                .metrics
                .record_scan_error(start.elapsed(), sink_class, &scenario_label);
            state.readiness.record_scan_error(is_sink_error);
            Err(err.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Duration;

    use axum::http::StatusCode;
    use rastreo_core::config::BaseProbeConfig;
    use rastreo_core::{HickoryResolver, ProberConfig, Resolver, SinkConfig, Target};

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
        let mut summary = DiscoverySummary::default();
        summary.targets_resolved = 1;
        summary.probe_attempts = 1;
        summary.records_emitted = 1;
        summary.elapsed = Duration::from_millis(42);
        let response = ScanResponse {
            summary,
            records: Vec::new(),
            hint: None,
        };
        let value: serde_json::Value = serde_json::to_value(&response).expect("serialize");
        assert_eq!(value["summary"]["elapsed_ms"], 42);
        assert_eq!(value["summary"]["records_emitted"], 1);
        assert!(value["records"].is_array());
        assert_eq!(value["records"].as_array().unwrap().len(), 0);
        assert!(
            value.get("hint").is_none(),
            "hint must be skipped when None: {value}"
        );
    }

    #[tokio::test]
    async fn create_scan_pins_encoder_to_ndjson_when_client_omits_encoder() {
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
        assert!(s.base.encoder.is_none(), "client omits encoder");

        let Json(response) = create_scan(State(state), Json(s))
            .await
            .expect("create_scan");
        assert_eq!(response.summary.records_emitted, 1);
        assert_eq!(response.records.len(), 1);
    }

    #[tokio::test]
    async fn create_scan_pins_encoder_to_ndjson_when_client_supplies_ndjson() {
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
        s.base.encoder = Some(EncoderConfig::Ndjson);

        let Json(response) = create_scan(State(state), Json(s))
            .await
            .expect("create_scan");
        assert_eq!(response.summary.records_emitted, 1);
        assert_eq!(response.records.len(), 1);
    }

    #[tokio::test]
    async fn create_scan_ignores_client_supplied_sink_and_returns_records() {
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
        s.base.sink = Some(SinkConfig::Stdout);

        let Json(response) = create_scan(State(state), Json(s))
            .await
            .expect("create_scan");
        assert_eq!(response.summary.records_emitted, 1);
        assert_eq!(response.records.len(), 1);
    }

    #[tokio::test]
    async fn create_scan_writes_records_to_server_configured_sink_and_response() {
        use crate::state::{SharedSink, SinkReachability};
        use rastreo_core::SinkType;
        use tokio::sync::Mutex;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let base = state_with_system_resolver();
        let sink = MemorySink::new();
        let handle = sink.handle();
        let shared: SharedSink =
            Arc::new(Mutex::new(Box::new(sink) as Box<dyn rastreo_core::Sink>));
        let reach = Arc::new(SinkReachability::configured(
            SinkType::Memory,
            Duration::from_secs(10),
            Duration::from_secs(5),
        ));
        reach.record_success();
        let state = base.with_sink(Some(Arc::clone(&shared)), reach);

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
        let lines = handle.ndjson_lines();
        assert_eq!(
            lines.len(),
            1,
            "server sink must receive exactly one record"
        );
    }

    #[tokio::test]
    async fn create_scan_without_server_sink_still_returns_records_in_response_body() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let state = state_with_system_resolver();
        assert!(state.sink.is_none());
        let mut s = scenario(
            vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            vec![ProberConfig::TcpConnect { ports: vec![port] }],
        );
        s.base.timeout_ms = Some(500);

        let Json(response) = create_scan(State(state), Json(s))
            .await
            .expect("create_scan");
        assert_eq!(response.records.len(), 1);
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

    #[tokio::test]
    async fn create_scan_omits_hint_on_a_clean_scan() {
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
        assert!(response.summary.first_probe_error.is_none());
        assert!(
            response.hint.is_none(),
            "a clean scan must not carry a hint"
        );
        let value: serde_json::Value = serde_json::to_value(&response).expect("serialize");
        assert!(
            value.get("hint").is_none(),
            "hint must be omitted from the wire on a clean scan: {value}"
        );
    }

    #[cfg(feature = "snmp")]
    #[tokio::test]
    async fn create_scan_snmp_decode_fault_carries_the_matching_hint() {
        use rastreo_core::prober::snmp::{SnmpVersion, UsmCredentials};
        use rastreo_core::prober::Community;
        use rastreo_core::ProbeErrorKind;

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind agent");
        let agent_port = socket.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                if let Ok((_, peer)) = socket.recv_from(&mut buf).await {
                    let _ = socket.send_to(&[0xff, 0xfe, 0xfd, 0xfc], peer).await;
                }
            }
        });

        let state = state_with_system_resolver();
        let mut s = scenario(
            vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            vec![ProberConfig::Snmp {
                ports: vec![agent_port],
                version: SnmpVersion::V2c,
                community: Community("public".into()),
                credentials: UsmCredentials::default(),
            }],
        );
        s.base.timeout_ms = Some(500);

        let Json(response) = create_scan(State(state), Json(s))
            .await
            .expect("create_scan");
        let fault = response
            .summary
            .first_probe_error
            .as_ref()
            .expect("the decode fault must be latched");
        assert_eq!(fault.kind, ProbeErrorKind::DecodeFailed);
        assert_eq!(
            response.hint.as_deref(),
            rastreo_core::hint_for_error_kind(ProbeErrorKind::DecodeFailed),
            "the /scans hint must match the shared core hint for the fault kind"
        );
        let value: serde_json::Value = serde_json::to_value(&response).expect("serialize");
        let wire_hint = value["hint"].as_str().expect("hint present on wire");
        assert!(wire_hint.contains("could not parse"));
        assert!(
            !wire_hint.starts_with("hint:"),
            "the wire `hint` field must not carry the CLI presentation prefix: {wire_hint}"
        );
    }
}
