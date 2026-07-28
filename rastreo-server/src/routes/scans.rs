use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rastreo_core::config::DiscoverScenarioConfig;
use rastreo_core::{
    hint_for_error_kind, resolve_scenario_targets, run_discovery, DeviceRecord, DiscoveryPlan,
    DiscoveryProgress, DiscoverySummary, EncoderConfig, MemorySink, PlanKnobs, RunOptions, Sink,
    TeeChild, TeeSink,
};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

const PROGRESS_LOG_INTERVAL: Duration = Duration::from_secs(5);

use crate::error::AppError;
use crate::state::{AppState, Metrics, ReadinessState};

const DEFAULT_CONCURRENCY: u32 = 64;
const DEFAULT_TIMEOUT_MS: u64 = 1000;

struct InflightGuard(Arc<ReadinessState>);

impl InflightGuard {
    fn try_acquire(state: Arc<ReadinessState>, max_inflight: u64) -> Option<Self> {
        let prior = state.inflight_scans.fetch_add(1, Ordering::Relaxed);
        if max_inflight > 0 && prior + 1 > max_inflight {
            // Roll back the speculative increment so a rejected request never inflates the gauge.
            state.inflight_scans.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(Self(state))
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.inflight_scans.fetch_sub(1, Ordering::Relaxed);
    }
}

struct ScanOutcomeGuard {
    metrics: Arc<Metrics>,
    start: Instant,
    scenario: String,
    armed: bool,
}

impl ScanOutcomeGuard {
    fn new(metrics: Arc<Metrics>, start: Instant, scenario: String) -> Self {
        Self {
            metrics,
            start,
            scenario,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ScanOutcomeGuard {
    fn drop(&mut self) {
        // Records the timeout path: a request-timeout drops the scan future still-armed, before the match records the real outcome.
        if self.armed {
            self.metrics
                .record_scan_cancelled(self.start.elapsed(), &self.scenario);
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub summary: DiscoverySummary,
    pub records: Vec<DeviceRecord>,
    /// True when the response capture hit `RASTREO_MAX_RESULT_BYTES`: `records` is a subset, `summary.records_emitted` is the true total, and any server-configured sink still received every record.
    pub truncated: bool,
    /// Operator guidance for the first probe fault, keyed on its [`rastreo_core::ProbeErrorKind`]; absent when no probe faulted or the kind carries no specific action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ScanParams {
    #[serde(default)]
    pub dry_run: bool,
}

fn scenario_label(scenario: &DiscoverScenarioConfig) -> String {
    scenario
        .base
        .name
        .clone()
        .unwrap_or_else(|| "unnamed".to_string())
}

/// Submit a discovery scenario. `?dry_run=true` resolves targets and returns the [`DiscoveryPlan`] without probing or writing a sink; otherwise the scenario runs synchronously and records are returned in the response body (the client-supplied `sink` field is ignored on the real-scan path).
pub async fn create_scan(
    State(state): State<AppState>,
    Query(params): Query<ScanParams>,
    Json(scenario): Json<DiscoverScenarioConfig>,
) -> Result<Response, AppError> {
    let start = Instant::now();
    let label = scenario_label(&scenario);

    if scenario.targets.is_empty() {
        state
            .metrics
            .record_scan_error(start.elapsed(), None, &label);
        state.readiness.record_scan_error(false);
        return Err(AppError::bad_request("scenario.targets must not be empty"));
    }
    if scenario.probers.is_empty() {
        state
            .metrics
            .record_scan_error(start.elapsed(), None, &label);
        state.readiness.record_scan_error(false);
        return Err(AppError::bad_request("scenario.probers must not be empty"));
    }

    if params.dry_run {
        return Ok(Json(dry_run_plan(&state, &scenario, label).await).into_response());
    }

    Ok(run_scan(state, scenario, start, label)
        .await?
        .into_response())
}

async fn dry_run_plan(
    state: &AppState,
    scenario: &DiscoverScenarioConfig,
    label: String,
) -> DiscoveryPlan {
    let resolutions = resolve_scenario_targets(scenario, state.resolver.as_ref()).await;
    let knobs = PlanKnobs {
        max_concurrent: scenario
            .base
            .max_concurrent
            .unwrap_or(DEFAULT_CONCURRENCY)
            .max(1),
        probe_rate: scenario.base.probe_rate,
        retries: scenario.base.retries.unwrap_or(0),
        timeout_ms: scenario.base.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS),
    };
    DiscoveryPlan::new(label, scenario, &resolutions, knobs)
}

async fn run_scan(
    state: AppState,
    scenario: DiscoverScenarioConfig,
    start: Instant,
    scenario_label: String,
) -> Result<Json<ScanResponse>, AppError> {
    let Some(_inflight) = InflightGuard::try_acquire(
        state.readiness.clone(),
        state.readiness.config.max_inflight_scans,
    ) else {
        return Err(AppError::too_many_requests(
            "inflight scan limit reached; retry once running scans complete",
        ));
    };

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

    let memory_sink = MemorySink::with_max_bytes(state.max_result_bytes);
    let handle = memory_sink.handle();

    // Memory child first so the response body captures every record even if the shared sink aborts mid-scan.
    let mut children: Vec<TeeChild> = vec![TeeChild::Owned(Box::new(memory_sink))];
    if let Some(server_sink) = state.sink.as_ref() {
        children.push(TeeChild::Shared(Arc::clone(server_sink)));
    }
    let pipeline_sink: Box<dyn Sink> = Box::new(TeeSink::new(children));

    let mut outcome_guard =
        ScanOutcomeGuard::new(Arc::clone(&state.metrics), start, scenario_label.clone());
    let (progress_tx, progress_rx) = watch::channel(DiscoveryProgress::default());
    let progress_task = spawn_progress_logger(progress_rx, scenario_label.clone());
    let summary_result = run_discovery(
        RunOptions::new(&scenario)
            .resolver(state.resolver.clone())
            .sink(pipeline_sink)
            .progress(progress_tx),
    )
    .await;
    progress_task.abort();

    match summary_result {
        Ok(summary) => {
            state
                .metrics
                .record_scan_completion(&summary, &scenario_label);
            outcome_guard.disarm();
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
                truncated: handle.truncated(),
                hint,
            }))
        }
        Err(err) => {
            let sink_class = err.sink_error_class();
            let is_sink_error = sink_class.is_some();
            state
                .metrics
                .record_scan_error(start.elapsed(), sink_class, &scenario_label);
            state.readiness.record_scan_error(is_sink_error);
            outcome_guard.disarm();
            Err(err.into())
        }
    }
}

// POST /scans is synchronous, so mid-scan progress can't be a response field; ops read it from the server log instead.
fn spawn_progress_logger(
    rx: watch::Receiver<DiscoveryProgress>,
    scenario: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(PROGRESS_LOG_INTERVAL);
        ticker.tick().await; // the first tick fires immediately; skip it
        loop {
            ticker.tick().await;
            // Exit when the scan's sender is gone, so the task never leaks if abort() is skipped by an unwind.
            if rx.has_changed().is_err() {
                break;
            }
            let snapshot = rx.borrow().clone();
            if should_log_progress(&snapshot) {
                tracing::info!(
                    scenario = %scenario,
                    targets_completed = snapshot.targets_completed,
                    targets_total = snapshot.targets_total,
                    records = snapshot.records_emitted,
                    "scan progress"
                );
            }
        }
    })
}

fn should_log_progress(p: &DiscoveryProgress) -> bool {
    p.targets_total > 0 && p.targets_completed < p.targets_total
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

    fn state_with_max_inflight(max: u64) -> AppState {
        use crate::state::ReadinessConfig;
        let resolver: Arc<dyn Resolver> =
            Arc::new(HickoryResolver::from_system().expect("system resolver"));
        AppState::with_readiness(
            resolver,
            ReadinessConfig {
                max_inflight_scans: max,
                ..ReadinessConfig::default()
            },
        )
    }

    fn readiness_with_cap(max: u64) -> Arc<ReadinessState> {
        use crate::state::ReadinessConfig;
        Arc::new(ReadinessState::new(ReadinessConfig {
            max_inflight_scans: max,
            ..ReadinessConfig::default()
        }))
    }

    fn scenario(targets: Vec<Target>, probers: Vec<ProberConfig>) -> DiscoverScenarioConfig {
        DiscoverScenarioConfig::new(BaseProbeConfig::default(), targets, probers)
    }

    async fn run_real(
        state: AppState,
        scenario: DiscoverScenarioConfig,
    ) -> Result<Json<ScanResponse>, AppError> {
        let label = scenario_label(&scenario);
        run_scan(state, scenario, Instant::now(), label).await
    }

    #[tokio::test]
    async fn create_scan_with_empty_targets_returns_400() {
        let state = state_with_system_resolver();
        let scenario = scenario(
            Vec::new(),
            vec![ProberConfig::TcpConnect { ports: vec![22] }],
        );
        let err = create_scan(State(state), Query(ScanParams::default()), Json(scenario))
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
        let err = create_scan(State(state), Query(ScanParams::default()), Json(scenario))
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

        let Json(response) = run_real(state, s).await.expect("create_scan");
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
            truncated: false,
            hint: None,
        };
        let value: serde_json::Value = serde_json::to_value(&response).expect("serialize");
        assert_eq!(value["summary"]["elapsed_ms"], 42);
        assert_eq!(value["summary"]["records_emitted"], 1);
        assert!(value["records"].is_array());
        assert_eq!(value["records"].as_array().unwrap().len(), 0);
        assert_eq!(value["truncated"], false);
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

        let Json(response) = run_real(state, s).await.expect("create_scan");
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

        let Json(response) = run_real(state, s).await.expect("create_scan");
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

        let Json(response) = run_real(state, s).await.expect("create_scan");
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

        let Json(response) = run_real(state, s).await.expect("create_scan");
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
    async fn create_scan_drains_batched_server_sink_at_completion() {
        use crate::state::{SharedSink, SinkReachability};
        use rastreo_core::{RastreoError, Sink, SinkType};
        use std::sync::Mutex as StdMutex;
        use tokio::sync::Mutex;

        #[derive(Default)]
        struct BufferingInner {
            committed: StdMutex<Vec<Vec<u8>>>,
        }

        struct BufferingSink {
            inner: Arc<BufferingInner>,
            buffer: Vec<Vec<u8>>,
        }

        #[async_trait::async_trait]
        impl Sink for BufferingSink {
            async fn write(&mut self, data: &[u8]) -> Result<(), RastreoError> {
                self.buffer.push(data.to_vec());
                Ok(())
            }
            async fn flush(&mut self) -> Result<(), RastreoError> {
                let mut committed = self
                    .inner
                    .committed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                committed.extend(self.buffer.drain(..));
                Ok(())
            }
            fn last_write_delivered(&self) -> bool {
                self.buffer.is_empty()
            }
            fn kind(&self) -> SinkType {
                SinkType::Kafka
            }
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let base = state_with_system_resolver();
        let inner = Arc::new(BufferingInner::default());
        let sink = BufferingSink {
            inner: Arc::clone(&inner),
            buffer: Vec::new(),
        };
        let shared: SharedSink = Arc::new(Mutex::new(Box::new(sink) as Box<dyn Sink>));
        let reach = Arc::new(SinkReachability::configured(
            SinkType::Kafka,
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

        let Json(response) = run_real(state, s).await.expect("create_scan");
        assert_eq!(response.summary.records_emitted, 1);
        let committed = inner.committed.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            committed.len(),
            1,
            "the server's batched sink must be drained before the response returns"
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

        let Json(response) = run_real(state, s).await.expect("create_scan");
        assert_eq!(response.records.len(), 1);
    }

    #[tokio::test]
    async fn create_scan_under_result_cap_returns_all_records_untruncated() {
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

        let Json(response) = run_real(state, s).await.expect("create_scan");
        assert_eq!(response.summary.records_emitted, 1);
        assert_eq!(response.records.len(), 1);
        assert!(!response.truncated, "a scan under the cap is not truncated");
        let value: serde_json::Value = serde_json::to_value(&response).expect("serialize");
        assert_eq!(value["truncated"], false);
    }

    #[tokio::test]
    async fn create_scan_truncates_response_when_records_exceed_result_cap() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        // A tiny cap drops the sole record from the response capture; the scan still completes.
        let state = state_with_system_resolver().with_result_limit(10);
        let mut s = scenario(
            vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            vec![ProberConfig::TcpConnect { ports: vec![port] }],
        );
        s.base.timeout_ms = Some(500);

        let Json(response) = run_real(state, s).await.expect("create_scan");
        assert_eq!(
            response.summary.records_emitted, 1,
            "records_emitted is the true total, unaffected by the response cap"
        );
        assert!(
            response.truncated,
            "an over-cap response must flag truncation"
        );
        assert!(
            response.records.len() < response.summary.records_emitted,
            "the response carries only the records that fit under the cap"
        );
        let value: serde_json::Value = serde_json::to_value(&response).expect("serialize");
        assert_eq!(value["truncated"], true);
    }

    #[tokio::test]
    async fn create_scan_configured_sink_receives_all_records_even_when_response_truncated() {
        use crate::state::{SharedSink, SinkReachability};
        use rastreo_core::SinkType;
        use tokio::sync::Mutex;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let base = state_with_system_resolver().with_result_limit(10);
        // The server-configured sink is UNcapped — the cap is on the response capture only.
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

        let Json(response) = run_real(state, s).await.expect("create_scan");
        assert!(response.truncated, "the response capture hit the tiny cap");
        assert!(
            response.records.is_empty(),
            "no record fits under the 10-byte response cap"
        );
        assert_eq!(response.summary.records_emitted, 1);
        let lines = handle.ndjson_lines();
        assert_eq!(
            lines.len(),
            1,
            "the server-configured sink is uncapped and receives every record"
        );
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

        let Json(response) = run_real(state, s).await.expect("create_scan");

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

        let Json(response) = run_real(state, s).await.expect("create_scan");
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

        let Json(response) = run_real(state, s).await.expect("create_scan");
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

    #[test]
    fn scan_params_default_is_not_dry_run() {
        assert!(!ScanParams::default().dry_run);
    }

    fn progress(completed: usize, total: usize) -> DiscoveryProgress {
        let mut p = DiscoveryProgress::default();
        p.targets_completed = completed;
        p.targets_total = total;
        p
    }

    #[test]
    fn should_log_progress_true_mid_scan() {
        assert!(should_log_progress(&progress(3, 10)));
    }

    #[test]
    fn should_log_progress_false_before_resolution_is_known() {
        assert!(!should_log_progress(&progress(0, 0)));
    }

    #[test]
    fn should_log_progress_false_once_every_target_is_drained() {
        assert!(!should_log_progress(&progress(10, 10)));
    }

    #[tokio::test(start_paused = true)]
    async fn progress_logger_terminates_when_sender_dropped() {
        let (tx, rx) = watch::channel(DiscoveryProgress::default());
        let task = spawn_progress_logger(rx, "test-scenario".to_string());
        drop(tx);

        let joined =
            tokio::time::timeout(PROGRESS_LOG_INTERVAL * 3 + Duration::from_secs(1), task).await;
        assert!(
            joined.is_ok(),
            "logger must self-terminate once the sender is dropped, not spin on the ticker forever"
        );
        joined
            .expect("did not time out")
            .expect("logger task joins cleanly");
    }

    #[test]
    fn try_acquire_under_cap_admits_and_increments() {
        let readiness = readiness_with_cap(2);
        let guard = InflightGuard::try_acquire(readiness.clone(), 2).expect("under cap admits");
        assert_eq!(readiness.inflight_scans.load(Ordering::Relaxed), 1);
        drop(guard);
        assert_eq!(readiness.inflight_scans.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn try_acquire_at_cap_returns_none_and_rolls_back_the_gauge() {
        let readiness = readiness_with_cap(1);
        let _held = InflightGuard::try_acquire(readiness.clone(), 1).expect("first admits");
        assert_eq!(readiness.inflight_scans.load(Ordering::Relaxed), 1);

        let rejected = InflightGuard::try_acquire(readiness.clone(), 1);
        assert!(rejected.is_none(), "a scan over the cap must be rejected");
        assert_eq!(
            readiness.inflight_scans.load(Ordering::Relaxed),
            1,
            "a rejected acquire must roll back its increment, leaving the gauge unchanged"
        );
    }

    #[test]
    fn try_acquire_with_cap_zero_never_rejects() {
        let readiness = readiness_with_cap(0);
        let mut held = Vec::new();
        for _ in 0..1000 {
            held.push(
                InflightGuard::try_acquire(readiness.clone(), 0).expect("cap 0 is unlimited"),
            );
        }
        assert_eq!(readiness.inflight_scans.load(Ordering::Relaxed), 1000);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn try_acquire_admits_exactly_cap_under_concurrency() {
        let readiness = readiness_with_cap(4);
        let held: Arc<std::sync::Mutex<Vec<InflightGuard>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for _ in 0..64 {
            let readiness = readiness.clone();
            let held = held.clone();
            tasks.push(tokio::spawn(async move {
                if let Some(guard) = InflightGuard::try_acquire(readiness, 4) {
                    held.lock().unwrap_or_else(|e| e.into_inner()).push(guard);
                }
            }));
        }
        for task in tasks {
            task.await.expect("join");
        }
        let admitted = held.lock().unwrap_or_else(|e| e.into_inner()).len();
        assert_eq!(admitted, 4, "cap=4 admits exactly 4 concurrent scans");
        assert_eq!(
            readiness.inflight_scans.load(Ordering::Relaxed),
            4,
            "rejected acquires rolled back; only the 4 held guards count"
        );
    }

    #[tokio::test]
    async fn run_scan_at_inflight_cap_returns_429_and_leaves_gauge_unchanged() {
        let state = state_with_max_inflight(1);
        state
            .readiness
            .inflight_scans
            .fetch_add(1, Ordering::Relaxed);
        let s = scenario(
            vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            vec![ProberConfig::TcpConnect { ports: vec![22] }],
        );

        let err = run_real(state.clone(), s)
            .await
            .expect_err("a scan at the inflight cap must be rejected");
        assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            state.readiness.inflight_scans.load(Ordering::Relaxed),
            1,
            "a 429'd scan must not leave the inflight gauge incremented"
        );
    }

    #[tokio::test]
    async fn run_scan_with_cap_zero_is_never_rejected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let state = state_with_max_inflight(0);
        state
            .readiness
            .inflight_scans
            .fetch_add(500, Ordering::Relaxed);
        let mut s = scenario(
            vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            vec![ProberConfig::TcpConnect { ports: vec![port] }],
        );
        s.base.timeout_ms = Some(500);

        let Json(response) = run_real(state, s)
            .await
            .expect("cap 0 disables admission control");
        assert_eq!(response.summary.records_emitted, 1);
    }

    #[test]
    fn scan_outcome_guard_armed_drop_records_cancelled() {
        let metrics = Arc::new(Metrics::new());
        drop(ScanOutcomeGuard::new(
            Arc::clone(&metrics),
            Instant::now(),
            "unnamed".to_string(),
        ));
        assert_eq!(metrics.scans_total_cancelled.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.scan_duration.all.snapshot().count, 1);
    }

    #[test]
    fn scan_outcome_guard_disarmed_drop_records_nothing() {
        let metrics = Arc::new(Metrics::new());
        let mut guard =
            ScanOutcomeGuard::new(Arc::clone(&metrics), Instant::now(), "unnamed".to_string());
        guard.disarm();
        drop(guard);
        assert_eq!(metrics.scans_total_cancelled.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.scan_duration.all.snapshot().count, 0);
    }

    #[tokio::test]
    async fn run_scan_dropped_mid_scan_records_cancelled() {
        let state = state_with_system_resolver();
        let metrics = Arc::clone(&state.metrics);
        let mut s = scenario(
            vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            vec![ProberConfig::TcpConnect { ports: vec![9] }],
        );
        s.base.timeout_ms = Some(5000);
        let label = scenario_label(&s);

        // Poll run_scan exactly once — enough to arm the guard at its first await — then drop it,
        // exactly as a request-timeout drops the handler future mid-scan.
        let mut scan = Box::pin(run_scan(state, s, Instant::now(), label));
        tokio::select! {
            biased;
            _ = scan.as_mut() => panic!("scan must not complete before it is dropped"),
            _ = std::future::ready(()) => {}
        }
        drop(scan);

        assert_eq!(
            metrics.scans_total_cancelled.load(Ordering::Relaxed),
            1,
            "a scan dropped mid-await must record a cancelled outcome"
        );
        assert_eq!(metrics.scans_total_success.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.scans_total_error.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn run_scan_normal_completion_does_not_record_cancelled() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let state = state_with_system_resolver();
        let metrics = Arc::clone(&state.metrics);
        let mut s = scenario(
            vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            vec![ProberConfig::TcpConnect { ports: vec![port] }],
        );
        s.base.timeout_ms = Some(500);

        let Json(response) = run_real(state, s).await.expect("create_scan");
        assert_eq!(response.summary.records_emitted, 1);
        assert_eq!(
            metrics.scans_total_cancelled.load(Ordering::Relaxed),
            0,
            "a completed scan must disarm the guard"
        );
        assert_eq!(metrics.scans_total_success.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn dry_run_is_not_subject_to_the_inflight_cap() {
        let state = state_with_max_inflight(1);
        state
            .readiness
            .inflight_scans
            .fetch_add(1, Ordering::Relaxed);
        let s = scenario(
            vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            vec![ProberConfig::TcpConnect { ports: vec![22] }],
        );

        let response = create_scan(State(state), Query(ScanParams { dry_run: true }), Json(s))
            .await
            .expect("a dry-run consumes no inflight slot and is never 429'd");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn dry_run_plan_resolves_targets_and_applies_pipeline_defaults() {
        use rastreo_core::TargetResolution;

        let state = state_with_system_resolver();
        let s = scenario(
            vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            vec![ProberConfig::TcpConnect {
                ports: vec![22, 80],
            }],
        );
        let plan = dry_run_plan(&state, &s, "unit-plan".to_string()).await;

        assert_eq!(plan.scenario, "unit-plan");
        assert_eq!(plan.max_concurrent, DEFAULT_CONCURRENCY);
        assert_eq!(plan.timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(plan.retries, 0);
        assert_eq!(plan.probers.len(), 1);
        assert_eq!(plan.total_probes, 1);
        assert!(matches!(
            &plan.targets[0].resolution,
            TargetResolution::Resolved(ips) if ips.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST))
        ));
    }

    #[tokio::test]
    async fn create_scan_dry_run_returns_plan_and_does_not_write_server_sink() {
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
        let shared: SharedSink = Arc::new(Mutex::new(Box::new(sink) as Box<dyn Sink>));
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

        let response = create_scan(State(state), Query(ScanParams { dry_run: true }), Json(s))
            .await
            .expect("dry-run");
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("plan json");
        assert!(
            value["total_probes"].is_number(),
            "plan carries total_probes: {value}"
        );
        assert!(value["probers"].is_array());
        assert_eq!(
            value["targets"][0]["resolution"]["resolved"][0],
            "127.0.0.1"
        );
        assert!(
            value.get("records").is_none(),
            "dry-run body is a plan, not a scan response"
        );
        assert!(
            value.get("summary").is_none(),
            "dry-run body is a plan, not a scan response"
        );
        assert!(
            handle.ndjson_lines().is_empty(),
            "dry-run must not open or write the server-configured sink"
        );
    }

    #[tokio::test]
    async fn create_scan_dry_run_with_empty_targets_returns_400() {
        let state = state_with_system_resolver();
        let s = scenario(
            Vec::new(),
            vec![ProberConfig::TcpConnect { ports: vec![22] }],
        );
        let err = create_scan(State(state), Query(ScanParams { dry_run: true }), Json(s))
            .await
            .expect_err("dry-run of an invalid scenario must 400");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("targets"));
    }

    #[cfg(feature = "nats")]
    #[tokio::test]
    async fn create_scan_dry_run_nats_sink_strips_credentials_from_plan() {
        let state = state_with_system_resolver();
        let mut s = scenario(
            vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            vec![ProberConfig::TcpConnect { ports: vec![22] }],
        );
        s.base.sink = Some(SinkConfig::Nats {
            servers: vec!["nats://u:p@broker:4222".into()],
            subject: "rastreo.devices".into(),
            stream: "RASTREO".into(),
            links_subject: None,
            profiles_subject: None,
            credentials: rastreo_core::NatsCredentials::default(),
            flush_mode: rastreo_core::NatsFlushMode::default(),
            dead_letter: None,
            retry: rastreo_core::SinkRetry::default(),
        });

        let plan = dry_run_plan(&state, &s, "nats-plan".to_string()).await;
        assert_eq!(
            plan.sink,
            "nats: servers=nats://broker:4222 subject=rastreo.devices stream=RASTREO"
        );
        assert!(
            !plan.sink.contains("u:p"),
            "dry-run plan must not leak credentials: {}",
            plan.sink
        );
    }
}
