use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::DiscoverScenarioConfig;
use crate::encoder::{create_encoder, EncoderConfig};
use crate::error::{ConfigError, RastreoError};
use crate::fuser::{create_fuser, FuserConfig};
use crate::model::{ProbeCtx, ProbeOutcome};
use crate::prober::create_prober;
use crate::resolver::{HickoryResolver, Resolver};
use crate::scheduler::{BoundedScheduler, Scheduler};
use crate::sink::{create_sink, Sink, SinkConfig};

const DEFAULT_TIMEOUT_MS: u64 = 1000;
const DEFAULT_CONCURRENCY: u32 = 64;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DiscoverySummary {
    pub targets_resolved: usize,
    pub probe_attempts: usize,
    pub probe_errors: usize,
    pub records_emitted: usize,
    #[serde(rename = "elapsed_ms", serialize_with = "serialize_duration_as_millis")]
    pub elapsed: Duration,
}

fn serialize_duration_as_millis<S: serde::Serializer>(
    d: &Duration,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_u128(d.as_millis())
}

pub async fn run_discovery(
    scenario: &DiscoverScenarioConfig,
) -> Result<DiscoverySummary, RastreoError> {
    let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system()?);
    let sink_config = scenario.base.sink.clone().unwrap_or(SinkConfig::Stdout);
    let sink = create_sink(&sink_config).await?;
    run_discovery_with_components(scenario, resolver, sink).await
}

pub async fn run_discovery_with_components(
    scenario: &DiscoverScenarioConfig,
    resolver: Arc<dyn Resolver>,
    mut sink: Box<dyn Sink>,
) -> Result<DiscoverySummary, RastreoError> {
    if scenario.probers.is_empty() {
        return Err(ConfigError::invalid("scenario.probers must not be empty").into());
    }

    let start = Instant::now();

    let resolved = resolver.resolve_many(&scenario.targets).await?;
    let targets_resolved = resolved.len();

    let concurrency = scenario
        .base
        .rate_limit
        .unwrap_or(DEFAULT_CONCURRENCY)
        .max(1) as usize;
    let scheduler = BoundedScheduler::new(concurrency);

    let timeout_ms = scenario.base.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    let ctx = ProbeCtx {
        timeout: Duration::from_millis(timeout_ms),
        retries: 0,
    };

    let encoder_config = scenario
        .base
        .encoder
        .clone()
        .unwrap_or(EncoderConfig::Ndjson);
    let encoder = create_encoder(&encoder_config)?;

    let fuser_config = scenario.base.fuser.clone().unwrap_or(FuserConfig::Direct {
        include_unreachable: None,
        confidence_baseline: None,
        confidence_per_signal: None,
    });
    let fuser = create_fuser(&fuser_config)?;

    let mut all_outcomes: Vec<ProbeOutcome> = Vec::new();
    let mut probe_attempts: usize = 0;
    let mut probe_errors: usize = 0;

    for prober_config in &scenario.probers {
        let prober: Arc<dyn crate::prober::Prober> = Arc::from(create_prober(prober_config)?);
        let results = scheduler.run(prober, resolved.clone(), ctx.clone()).await;
        probe_attempts += results.len();
        for result in results {
            match result {
                Ok(outcome) => all_outcomes.push(outcome),
                Err(err) => {
                    probe_errors += 1;
                    tracing::debug!(error = %err, "probe failed");
                }
            }
        }
    }

    let records = fuser.fuse_many(all_outcomes)?;

    let mut buf: Vec<u8> = Vec::new();
    let mut records_emitted: usize = 0;
    for record in &records {
        buf.clear();
        encoder.encode_record(record, &mut buf)?;
        sink.write(&buf).await?;
        records_emitted += 1;
    }
    sink.flush().await?;

    Ok(DiscoverySummary {
        targets_resolved,
        probe_attempts,
        probe_errors,
        records_emitted,
        elapsed: start.elapsed(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::config::BaseProbeConfig;
    use crate::error::ConfigError;
    use crate::model::Target;
    use crate::prober::ProberConfig;

    fn scenario_with_probers(probers: Vec<ProberConfig>) -> DiscoverScenarioConfig {
        DiscoverScenarioConfig {
            base: BaseProbeConfig::default(),
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers,
        }
    }

    #[tokio::test]
    async fn run_discovery_empty_probers_returns_config_error() {
        let scenario = scenario_with_probers(Vec::new());
        let err = run_discovery(&scenario).await.expect_err("empty probers");
        match err {
            RastreoError::Config(ConfigError::InvalidValue(msg)) => {
                assert!(msg.contains("probers"), "unexpected message: {msg}");
            }
            other => panic!("expected ConfigError::InvalidValue, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_discovery_emits_record_for_open_loopback_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("records.ndjson");

        let base = BaseProbeConfig {
            sink: Some(SinkConfig::File { path: path.clone() }),
            timeout_ms: Some(500),
            ..Default::default()
        };

        let scenario = DiscoverScenarioConfig {
            base,
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let summary = run_discovery(&scenario).await.expect("run_discovery");
        assert_eq!(summary.targets_resolved, 1);
        assert_eq!(summary.probe_attempts, 1);
        assert_eq!(summary.probe_errors, 0);
        assert_eq!(summary.records_emitted, 1);

        let bytes = std::fs::read(&path).expect("read");
        let lines: Vec<&[u8]> = bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(lines.len(), 1);
        let record: crate::model::DeviceRecord =
            serde_json::from_slice(lines[0]).expect("parse json");
        assert_eq!(record.mgmt_ip, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(record
            .signals
            .iter()
            .any(|s| matches!(s, crate::model::Signal::OpenPort(p) if *p == port)));
    }

    #[tokio::test]
    async fn run_discovery_unreachable_target_emits_no_records() {
        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let closed_port = closed_listener.local_addr().expect("local_addr").port();
        drop(closed_listener);

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("none.ndjson");

        let base = BaseProbeConfig {
            sink: Some(SinkConfig::File { path: path.clone() }),
            timeout_ms: Some(200),
            ..Default::default()
        };

        let scenario = DiscoverScenarioConfig {
            base,
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect {
                ports: vec![closed_port],
            }],
        };

        let summary = run_discovery(&scenario).await.expect("run_discovery");
        assert_eq!(summary.targets_resolved, 1);
        assert_eq!(summary.probe_attempts, 1);
        assert_eq!(summary.records_emitted, 0);

        let bytes = std::fs::read(&path).expect("read");
        assert!(bytes.is_empty(), "no records expected, got {bytes:?}");
    }

    #[tokio::test]
    async fn run_discovery_with_components_uses_provided_resolver() {
        use crate::model::ResolvedTarget;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingResolver {
            inner: HickoryResolver,
            calls: AtomicUsize,
        }

        #[async_trait::async_trait]
        impl Resolver for CountingResolver {
            async fn resolve(
                &self,
                target: &crate::model::Target,
            ) -> Result<Vec<ResolvedTarget>, RastreoError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.inner.resolve(target).await
            }
        }

        let resolver = Arc::new(CountingResolver {
            inner: HickoryResolver::from_system().expect("init"),
            calls: AtomicUsize::new(0),
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let resolver_dyn: Arc<dyn Resolver> = resolver.clone();
        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();
        let sink: Box<dyn Sink> = Box::new(mem);
        let _summary = run_discovery_with_components(&scenario, resolver_dyn, sink)
            .await
            .expect("run_discovery_with_components");

        assert!(resolver.calls.load(Ordering::SeqCst) >= 1);
        assert!(!handle.bytes().is_empty());
    }

    #[tokio::test]
    async fn run_discovery_with_components_uses_provided_sink() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let resolver: Arc<dyn Resolver> = Arc::new(HickoryResolver::from_system().expect("init"));
        let mem = crate::sink::MemorySink::new();
        let handle = mem.handle();

        let scenario = DiscoverScenarioConfig {
            base: BaseProbeConfig {
                timeout_ms: Some(500),
                ..Default::default()
            },
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let summary = run_discovery_with_components(&scenario, resolver, Box::new(mem))
            .await
            .expect("run_discovery_with_components");
        assert_eq!(summary.records_emitted, 1);
        let lines = handle.ndjson_lines();
        assert_eq!(lines.len(), 1);
        let record: crate::model::DeviceRecord =
            serde_json::from_str(&lines[0]).expect("parse json");
        assert_eq!(record.mgmt_ip, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn discovery_summary_serializes_elapsed_as_millis_field() {
        let summary = DiscoverySummary {
            targets_resolved: 1,
            probe_attempts: 2,
            probe_errors: 0,
            records_emitted: 1,
            elapsed: Duration::from_millis(142),
        };
        let json: serde_json::Value = serde_json::to_value(&summary).expect("serialize");
        assert_eq!(json["elapsed_ms"], 142);
        assert_eq!(json["records_emitted"], 1);
        assert!(json.get("elapsed").is_none());
    }

    #[tokio::test]
    async fn run_discovery_applies_default_concurrency_and_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("defaults.ndjson");

        let base = BaseProbeConfig {
            sink: Some(SinkConfig::File { path }),
            ..Default::default()
        };

        let scenario = DiscoverScenarioConfig {
            base,
            targets: vec![Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            probers: vec![ProberConfig::TcpConnect { ports: vec![port] }],
        };

        let summary = run_discovery(&scenario).await.expect("run_discovery");
        assert_eq!(summary.records_emitted, 1);
    }
}
