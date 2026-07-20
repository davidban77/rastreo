//! OTLP/tracing bootstrap shared by the `rastreo` CLI and `rastreo-server`. Behind the `otlp`
//! feature so the OpenTelemetry logs stack and `tracing-subscriber` stay out of the default build.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::Context;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::tonic_types::metadata::MetadataMap;
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig, WithTonicConfig};
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing::Subscriber;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

use crate::observability::otlp_config::{
    http_endpoint_for_signal, parse_env_bool, parse_env_headers, parse_env_protocol, parse_env_u64,
    OtlpProtocol,
};

const DEFAULT_METRICS_INTERVAL_SECS: u64 = 30;

/// OpenTelemetry OTLP exporter configuration read from `RASTREO_OTLP_*` environment variables.
#[derive(Clone)]
pub struct OtlpConfig {
    pub endpoint: String,
    pub protocol: OtlpProtocol,
    pub metrics_enabled: bool,
    pub logs_enabled: bool,
    pub traces_enabled: bool,
    pub metrics_interval: Duration,
    pub service_name: String,
    pub headers: Vec<(String, String)>,
}

impl std::fmt::Debug for OtlpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Header values carry bearer tokens / API keys — render a count only, never the entries.
        f.debug_struct("OtlpConfig")
            .field("endpoint", &self.endpoint)
            .field("protocol", &self.protocol)
            .field("metrics_enabled", &self.metrics_enabled)
            .field("logs_enabled", &self.logs_enabled)
            .field("traces_enabled", &self.traces_enabled)
            .field("metrics_interval", &self.metrics_interval)
            .field("service_name", &self.service_name)
            .field(
                "headers",
                &format_args!("<{} redacted>", self.headers.len()),
            )
            .finish()
    }
}

impl OtlpConfig {
    /// Read the OTLP configuration, defaulting `service_name` to `default_service_name` when the
    /// env var is unset. When `metrics_supported` is false the metrics env vars are not read at all
    /// (the caller cannot export metrics). Returns `None` when nothing is enabled.
    pub fn from_env(
        default_service_name: &str,
        metrics_supported: bool,
    ) -> anyhow::Result<Option<Self>> {
        let metrics_enabled =
            metrics_supported && parse_env_bool("RASTREO_OTLP_METRICS_ENABLED", false)?;
        let logs_enabled = parse_env_bool("RASTREO_OTLP_LOGS_ENABLED", false)?;
        let traces_enabled = parse_env_bool("RASTREO_OTLP_TRACES_ENABLED", false)?;
        // A traces-only config must still return Some, else trace export silently no-ops.
        if !metrics_enabled && !logs_enabled && !traces_enabled {
            return Ok(None);
        }
        let endpoint = match std::env::var("RASTREO_OTLP_ENDPOINT") {
            Ok(raw) if !raw.trim().is_empty() => raw.trim().to_string(),
            Ok(_) | Err(std::env::VarError::NotPresent) => {
                return Err(anyhow::anyhow!(
                    "RASTREO_OTLP_ENDPOINT is required when RASTREO_OTLP_METRICS_ENABLED, \
                     RASTREO_OTLP_LOGS_ENABLED, or RASTREO_OTLP_TRACES_ENABLED is true; set it \
                     to your OTLP collector URL (for example http://otel-collector:4317 for gRPC \
                     or http://otel-collector:4318 for HTTP+protobuf)"
                ));
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(anyhow::anyhow!(
                    "invalid value for RASTREO_OTLP_ENDPOINT: not valid UTF-8"
                ));
            }
        };
        let protocol = parse_env_protocol("RASTREO_OTLP_PROTOCOL", OtlpProtocol::Grpc)?;
        let metrics_interval = Duration::from_secs(if metrics_supported {
            parse_env_u64(
                "RASTREO_OTLP_METRICS_INTERVAL_SECS",
                DEFAULT_METRICS_INTERVAL_SECS,
            )?
        } else {
            DEFAULT_METRICS_INTERVAL_SECS
        });
        let service_name = std::env::var("RASTREO_OTLP_SERVICE_NAME")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| default_service_name.to_string());
        let headers = parse_env_headers("RASTREO_OTLP_HEADERS")?;
        Ok(Some(Self {
            endpoint,
            protocol,
            metrics_enabled,
            logs_enabled,
            traces_enabled,
            metrics_interval,
            service_name,
            headers,
        }))
    }
}

/// RAII guard that shuts down the OTLP providers on drop so pending exports flush before exit.
#[non_exhaustive]
pub struct OtlpGuard {
    meter: Option<SdkMeterProvider>,
    logger: Option<SdkLoggerProvider>,
    tracer: Option<SdkTracerProvider>,
}

impl OtlpGuard {
    pub fn empty() -> Self {
        Self {
            meter: None,
            logger: None,
            tracer: None,
        }
    }
}

impl Drop for OtlpGuard {
    fn drop(&mut self) {
        if let Some(m) = self.meter.take() {
            if let Err(err) = m.shutdown() {
                tracing::warn!(%err, "OTLP meter provider shutdown failed");
            }
        }
        if let Some(l) = self.logger.take() {
            if let Err(err) = l.shutdown() {
                tracing::warn!(%err, "OTLP logger provider shutdown failed");
            }
        }
        if let Some(t) = self.tracer.take() {
            if let Err(err) = t.shutdown() {
                tracing::warn!(%err, "OTLP tracer provider shutdown failed");
            }
        }
    }
}

pub fn attach_logger(guard: &mut OtlpGuard, logger: SdkLoggerProvider) {
    guard.logger = Some(logger);
}

pub fn attach_tracer(guard: &mut OtlpGuard, tracer: SdkTracerProvider) {
    guard.tracer = Some(tracer);
}

pub fn attach_meter(guard: &mut OtlpGuard, meter: SdkMeterProvider) {
    guard.meter = Some(meter);
}

fn validated_pairs(
    headers: &[(String, String)],
) -> anyhow::Result<Vec<(http::HeaderName, http::HeaderValue)>> {
    headers
        .iter()
        .map(|(name, value)| {
            let key = http::HeaderName::from_bytes(name.as_bytes())
                .with_context(|| format!("OTLP header name {name:?} is not a valid HTTP token"))?;
            // The error never includes `value`: it may be a bearer token or API key.
            let val = http::HeaderValue::from_str(value).with_context(|| {
                format!("OTLP header {name:?} has a value that is not valid ASCII")
            })?;
            Ok((key, val))
        })
        .collect()
}

fn grpc_metadata(headers: &[(String, String)]) -> anyhow::Result<MetadataMap> {
    let mut map = http::HeaderMap::with_capacity(headers.len());
    for (key, value) in validated_pairs(headers)? {
        map.insert(key, value);
    }
    Ok(MetadataMap::from_headers(map))
}

fn http_header_map(headers: &[(String, String)]) -> anyhow::Result<HashMap<String, String>> {
    // Validate up front so a bad header fails startup here instead of being silently dropped by the HTTP exporter's own build-time header conversion.
    validated_pairs(headers)?;
    Ok(headers.iter().cloned().collect())
}

/// Attach OTLP headers to a gRPC (tonic) exporter builder; a no-op when `headers` is empty.
pub fn apply_grpc_headers<B: WithTonicConfig>(
    builder: B,
    headers: &[(String, String)],
) -> anyhow::Result<B> {
    if headers.is_empty() {
        return Ok(builder);
    }
    Ok(builder.with_metadata(grpc_metadata(headers)?))
}

/// Attach OTLP headers to an HTTP+protobuf exporter builder; a no-op when `headers` is empty.
pub fn apply_http_headers<B: WithHttpConfig>(
    builder: B,
    headers: &[(String, String)],
) -> anyhow::Result<B> {
    if headers.is_empty() {
        return Ok(builder);
    }
    Ok(builder.with_headers(http_header_map(headers)?))
}

/// Build a `tracing_subscriber::Layer` that ships events to the OTLP log exporter.
pub fn logs_layer<S>(config: &OtlpConfig) -> anyhow::Result<(impl Layer<S>, SdkLoggerProvider)>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let exporter = match config.protocol {
        OtlpProtocol::Grpc => apply_grpc_headers(
            opentelemetry_otlp::LogExporter::builder()
                .with_tonic()
                .with_endpoint(&config.endpoint),
            &config.headers,
        )?
        .build()
        .context("failed to build OTLP gRPC log exporter")?,
        OtlpProtocol::HttpProtobuf => apply_http_headers(
            opentelemetry_otlp::LogExporter::builder()
                .with_http()
                .with_endpoint(http_endpoint_for_signal(&config.endpoint, "/v1/logs")),
            &config.headers,
        )?
        .build()
        .context("failed to build OTLP HTTP+protobuf log exporter")?,
    };
    let resource = Resource::builder()
        .with_service_name(config.service_name.clone())
        .build();
    let provider = SdkLoggerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();
    let layer = OpenTelemetryTracingBridge::new(&provider);
    Ok((layer, provider))
}

/// Build a `tracing_subscriber::Layer` that ships pipeline-stage spans to the OTLP trace exporter.
pub fn traces_layer<S>(config: &OtlpConfig) -> anyhow::Result<(impl Layer<S>, SdkTracerProvider)>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let exporter = match config.protocol {
        OtlpProtocol::Grpc => apply_grpc_headers(
            opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(&config.endpoint),
            &config.headers,
        )?
        .build()
        .context("failed to build OTLP gRPC span exporter")?,
        OtlpProtocol::HttpProtobuf => apply_http_headers(
            opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_endpoint(http_endpoint_for_signal(&config.endpoint, "/v1/traces")),
            &config.headers,
        )?
        .build()
        .context("failed to build OTLP HTTP+protobuf span exporter")?,
    };
    let resource = Resource::builder()
        .with_service_name(config.service_name.clone())
        .build();
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();
    // Trim thread attributes and inactivity timing: their per-span cost would be load-bearing if span count grew.
    let layer = tracing_opentelemetry::layer()
        .with_tracer(provider.tracer("rastreo"))
        .with_threads(false)
        .with_tracked_inactivity(false);
    Ok((layer, provider))
}

static OTLP_LOGGER_PROVIDER: OnceLock<SdkLoggerProvider> = OnceLock::new();
static OTLP_TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

/// The logger provider stashed by [`init_tracing`], if OTLP log export was enabled. Callers attach
/// it to an [`OtlpGuard`] so its shutdown runs at process exit.
pub fn stashed_logger_provider() -> Option<SdkLoggerProvider> {
    OTLP_LOGGER_PROVIDER.get().cloned()
}

/// The tracer provider stashed by [`init_tracing`], if OTLP trace export was enabled. Callers attach
/// it to an [`OtlpGuard`] so its shutdown runs at process exit.
pub fn stashed_tracer_provider() -> Option<SdkTracerProvider> {
    OTLP_TRACER_PROVIDER.get().cloned()
}

/// Install the tracing subscriber: an stderr fmt layer (`json` selects JSON lines) at `base_level`,
/// plus the OTLP log layer when logs are enabled and the OTLP trace layer when traces are enabled.
pub fn init_tracing(
    base_level: &str,
    json: bool,
    otlp_config: Option<&OtlpConfig>,
) -> anyhow::Result<()> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(base_level));
    let fmt_layer: Box<dyn Layer<_> + Send + Sync> = if json {
        Box::new(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .json(),
        )
    } else {
        Box::new(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
    };
    let registry = tracing_subscriber::registry().with(filter).with(fmt_layer);

    let logs = match otlp_config {
        Some(cfg) if cfg.logs_enabled => {
            let (layer, provider) = logs_layer(cfg)?;
            OTLP_LOGGER_PROVIDER
                .set(provider)
                .map_err(|_| anyhow::anyhow!("OTLP logger provider already initialized"))?;
            Some(layer)
        }
        _ => None,
    };
    let traces = match otlp_config {
        Some(cfg) if cfg.traces_enabled => {
            let (layer, provider) = traces_layer(cfg)?;
            OTLP_TRACER_PROVIDER
                .set(provider)
                .map_err(|_| anyhow::anyhow!("OTLP tracer provider already initialized"))?;
            Some(layer)
        }
        _ => None,
    };

    registry.with(logs).with(traces).init();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::Mutex;
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    const KEYS: [&str; 8] = [
        "RASTREO_OTLP_ENDPOINT",
        "RASTREO_OTLP_METRICS_ENABLED",
        "RASTREO_OTLP_LOGS_ENABLED",
        "RASTREO_OTLP_TRACES_ENABLED",
        "RASTREO_OTLP_METRICS_INTERVAL_SECS",
        "RASTREO_OTLP_SERVICE_NAME",
        "RASTREO_OTLP_PROTOCOL",
        "RASTREO_OTLP_HEADERS",
    ];

    fn clear() {
        for k in KEYS {
            // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
            unsafe { std::env::remove_var(k) };
        }
    }

    #[test]
    fn from_env_returns_none_when_both_disabled() {
        let _g = env_guard();
        clear();
        assert!(OtlpConfig::from_env("svc", true)
            .expect("from_env")
            .is_none());
    }

    #[test]
    fn from_env_uses_provided_default_service_name() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
        }
        let rastreo = OtlpConfig::from_env("rastreo", false)
            .expect("from_env")
            .expect("some");
        let server = OtlpConfig::from_env("rastreo-server", true)
            .expect("from_env")
            .expect("some");
        clear();
        assert_eq!(rastreo.service_name, "rastreo");
        assert_eq!(server.service_name, "rastreo-server");
    }

    #[test]
    fn from_env_service_name_env_overrides_default() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
            std::env::set_var("RASTREO_OTLP_SERVICE_NAME", "  edge \n");
        }
        let cfg = OtlpConfig::from_env("svc", true)
            .expect("from_env")
            .expect("some");
        clear();
        assert_eq!(cfg.service_name, "edge");
    }

    #[test]
    fn from_env_metrics_enabled_parses_interval_default() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_METRICS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
        }
        let cfg = OtlpConfig::from_env("svc", true)
            .expect("from_env")
            .expect("some");
        clear();
        assert!(cfg.metrics_enabled);
        assert!(!cfg.logs_enabled);
        assert_eq!(cfg.metrics_interval, Duration::from_secs(30));
    }

    #[test]
    fn from_env_without_metrics_support_ignores_metrics_enabled() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_METRICS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
        }
        let cfg = OtlpConfig::from_env("svc", false).expect("from_env");
        clear();
        assert!(
            cfg.is_none(),
            "metrics env var must be inert without support"
        );
    }

    #[test]
    fn from_env_without_metrics_support_ignores_malformed_interval() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
            std::env::set_var("RASTREO_OTLP_METRICS_INTERVAL_SECS", "not-a-number");
        }
        let cfg = OtlpConfig::from_env("svc", false)
            .expect("malformed interval must be inert without support")
            .expect("some");
        clear();
        assert!(cfg.logs_enabled);
        assert!(!cfg.metrics_enabled);
        assert_eq!(cfg.metrics_interval, Duration::from_secs(30));
    }

    #[test]
    fn from_env_trims_endpoint() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "  http://collector:4317\n");
        }
        let cfg = OtlpConfig::from_env("svc", true)
            .expect("from_env")
            .expect("some");
        clear();
        assert_eq!(cfg.endpoint, "http://collector:4317");
    }

    #[test]
    fn from_env_requires_endpoint() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe { std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true") };
        let err = OtlpConfig::from_env("svc", true).expect_err("must reject");
        clear();
        assert!(err.to_string().contains("RASTREO_OTLP_ENDPOINT"));
    }

    #[test]
    fn from_env_protocol_defaults_to_grpc() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
        }
        let cfg = OtlpConfig::from_env("svc", true)
            .expect("from_env")
            .expect("some");
        clear();
        assert_eq!(cfg.protocol, OtlpProtocol::Grpc);
    }

    #[test]
    fn from_env_traces_only_returns_some() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_TRACES_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
        }
        let cfg = OtlpConfig::from_env("svc", false)
            .expect("from_env")
            .expect("traces-only must not be a silent no-op");
        clear();
        assert!(cfg.traces_enabled);
        assert!(!cfg.metrics_enabled);
        assert!(!cfg.logs_enabled);
    }

    #[test]
    fn from_env_traces_only_requires_endpoint() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe { std::env::set_var("RASTREO_OTLP_TRACES_ENABLED", "true") };
        let err = OtlpConfig::from_env("svc", false).expect_err("must reject");
        clear();
        let msg = err.to_string();
        assert!(msg.contains("RASTREO_OTLP_ENDPOINT"), "msg was {msg}");
        assert!(msg.contains("RASTREO_OTLP_TRACES_ENABLED"), "msg was {msg}");
    }

    #[test]
    fn empty_guard_drops_without_panic() {
        let guard = OtlpGuard::empty();
        drop(guard);
    }

    #[tokio::test]
    async fn logs_layer_builds_grpc_exporter() {
        let cfg = OtlpConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            protocol: OtlpProtocol::Grpc,
            metrics_enabled: false,
            logs_enabled: true,
            traces_enabled: false,
            metrics_interval: Duration::from_secs(30),
            service_name: "rastreo-core-test".to_string(),
            headers: Vec::new(),
        };
        let (_layer, provider) =
            logs_layer::<tracing_subscriber::Registry>(&cfg).expect("build grpc log layer");
        provider.shutdown().expect("shutdown");
    }

    #[tokio::test]
    async fn logs_layer_builds_http_protobuf_exporter() {
        let cfg = OtlpConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            protocol: OtlpProtocol::HttpProtobuf,
            metrics_enabled: false,
            logs_enabled: true,
            traces_enabled: false,
            metrics_interval: Duration::from_secs(30),
            service_name: "rastreo-core-test".to_string(),
            headers: Vec::new(),
        };
        let (_layer, provider) =
            logs_layer::<tracing_subscriber::Registry>(&cfg).expect("build http log layer");
        provider.shutdown().expect("shutdown");
    }

    fn traces_cfg(protocol: OtlpProtocol) -> OtlpConfig {
        OtlpConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            protocol,
            metrics_enabled: false,
            logs_enabled: false,
            traces_enabled: true,
            metrics_interval: Duration::from_secs(30),
            service_name: "rastreo-core-test".to_string(),
            headers: Vec::new(),
        }
    }

    #[tokio::test]
    async fn traces_layer_builds_grpc_exporter() {
        let cfg = traces_cfg(OtlpProtocol::Grpc);
        let (_layer, provider) =
            traces_layer::<tracing_subscriber::Registry>(&cfg).expect("build grpc span layer");
        provider.shutdown().expect("shutdown");
    }

    #[tokio::test]
    async fn traces_layer_builds_http_protobuf_exporter() {
        let cfg = traces_cfg(OtlpProtocol::HttpProtobuf);
        let (_layer, provider) =
            traces_layer::<tracing_subscriber::Registry>(&cfg).expect("build http span layer");
        provider.shutdown().expect("shutdown");
    }

    #[tokio::test]
    async fn guard_with_tracer_drops_without_panic() {
        let cfg = traces_cfg(OtlpProtocol::Grpc);
        let (_layer, provider) =
            traces_layer::<tracing_subscriber::Registry>(&cfg).expect("build span layer");
        let mut guard = OtlpGuard::empty();
        attach_tracer(&mut guard, provider);
        drop(guard);
    }

    #[test]
    fn from_env_reads_headers() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
            std::env::set_var(
                "RASTREO_OTLP_HEADERS",
                "authorization=Bearer t,x-scope-orgid=tenant",
            );
        }
        let cfg = OtlpConfig::from_env("svc", true)
            .expect("from_env")
            .expect("some");
        clear();
        assert_eq!(
            cfg.headers,
            vec![
                ("authorization".to_string(), "Bearer t".to_string()),
                ("x-scope-orgid".to_string(), "tenant".to_string()),
            ]
        );
    }

    #[test]
    fn from_env_rejects_malformed_headers() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
            std::env::set_var("RASTREO_OTLP_HEADERS", "authorization");
        }
        let err = OtlpConfig::from_env("svc", true).expect_err("must reject");
        clear();
        assert!(err.to_string().contains("RASTREO_OTLP_HEADERS"));
    }

    #[test]
    fn debug_redacts_header_values() {
        let cfg = OtlpConfig {
            endpoint: "http://collector:4317".to_string(),
            protocol: OtlpProtocol::Grpc,
            metrics_enabled: false,
            logs_enabled: true,
            traces_enabled: false,
            metrics_interval: Duration::from_secs(30),
            service_name: "rastreo-core-test".to_string(),
            headers: vec![(
                "authorization".to_string(),
                "Bearer supersecret".to_string(),
            )],
        };
        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains("supersecret"),
            "Debug must not leak header values, got {rendered}"
        );
        assert!(
            !rendered.contains("authorization"),
            "Debug must not leak header names, got {rendered}"
        );
        assert!(
            rendered.contains("<1 redacted>"),
            "Debug must show a redacted header count, got {rendered}"
        );
    }

    #[test]
    fn validated_pairs_accepts_valid_headers() {
        let pairs = validated_pairs(&[("authorization".to_string(), "Bearer t".to_string())])
            .expect("valid");
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0.as_str(), "authorization");
    }

    #[test]
    fn validated_pairs_rejects_invalid_value_without_leaking_it() {
        let err = validated_pairs(&[("authorization".to_string(), "bad\nvalue".to_string())])
            .expect_err("control char rejected");
        let msg = format!("{err:#}");
        assert!(
            !msg.contains("bad\nvalue"),
            "error must not leak the value, got {msg}"
        );
    }

    #[test]
    fn validated_pairs_rejects_invalid_name() {
        let err = validated_pairs(&[("bad name".to_string(), "v".to_string())])
            .expect_err("bad name rejected");
        assert!(format!("{err:#}").contains("bad name"));
    }

    #[tokio::test]
    async fn logs_layer_builds_grpc_exporter_with_headers() {
        let cfg = OtlpConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            protocol: OtlpProtocol::Grpc,
            metrics_enabled: false,
            logs_enabled: true,
            traces_enabled: false,
            metrics_interval: Duration::from_secs(30),
            service_name: "rastreo-core-test".to_string(),
            headers: vec![("authorization".to_string(), "Bearer t".to_string())],
        };
        let (_layer, provider) = logs_layer::<tracing_subscriber::Registry>(&cfg)
            .expect("build grpc log layer with headers");
        provider.shutdown().expect("shutdown");
    }

    #[tokio::test]
    async fn traces_layer_builds_http_exporter_with_headers() {
        let cfg = OtlpConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            protocol: OtlpProtocol::HttpProtobuf,
            metrics_enabled: false,
            logs_enabled: false,
            traces_enabled: true,
            metrics_interval: Duration::from_secs(30),
            service_name: "rastreo-core-test".to_string(),
            headers: vec![("x-scope-orgid".to_string(), "tenant".to_string())],
        };
        let (_layer, provider) = traces_layer::<tracing_subscriber::Registry>(&cfg)
            .expect("build http span layer with headers");
        provider.shutdown().expect("shutdown");
    }
}
