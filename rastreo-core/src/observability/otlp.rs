//! OTLP/tracing bootstrap shared by the `rastreo` CLI and `rastreo-server`. Behind the `otlp`
//! feature so the OpenTelemetry logs stack and `tracing-subscriber` stay out of the default build.

use std::sync::OnceLock;
use std::time::Duration;

use anyhow::Context;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::Resource;
use tracing::Subscriber;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

use crate::observability::otlp_config::{
    http_endpoint_for_signal, parse_env_bool, parse_env_protocol, parse_env_u64, OtlpProtocol,
};

const DEFAULT_METRICS_INTERVAL_SECS: u64 = 30;

/// OpenTelemetry OTLP exporter configuration read from `RASTREO_OTLP_*` environment variables.
#[derive(Debug, Clone)]
pub struct OtlpConfig {
    pub endpoint: String,
    pub protocol: OtlpProtocol,
    pub metrics_enabled: bool,
    pub logs_enabled: bool,
    pub metrics_interval: Duration,
    pub service_name: String,
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
        if !metrics_enabled && !logs_enabled {
            return Ok(None);
        }
        let endpoint = match std::env::var("RASTREO_OTLP_ENDPOINT") {
            Ok(raw) if !raw.trim().is_empty() => raw.trim().to_string(),
            Ok(_) | Err(std::env::VarError::NotPresent) => {
                return Err(anyhow::anyhow!(
                    "RASTREO_OTLP_ENDPOINT is required when RASTREO_OTLP_METRICS_ENABLED or \
                     RASTREO_OTLP_LOGS_ENABLED is true; set it to your OTLP collector URL \
                     (for example http://otel-collector:4317 for gRPC or \
                     http://otel-collector:4318 for HTTP+protobuf)"
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
        Ok(Some(Self {
            endpoint,
            protocol,
            metrics_enabled,
            logs_enabled,
            metrics_interval,
            service_name,
        }))
    }
}

/// RAII guard that shuts down the OTLP providers on drop so pending exports flush before exit.
#[non_exhaustive]
pub struct OtlpGuard {
    meter: Option<SdkMeterProvider>,
    logger: Option<SdkLoggerProvider>,
}

impl OtlpGuard {
    pub fn empty() -> Self {
        Self {
            meter: None,
            logger: None,
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
    }
}

pub fn attach_logger(guard: &mut OtlpGuard, logger: SdkLoggerProvider) {
    guard.logger = Some(logger);
}

pub fn attach_meter(guard: &mut OtlpGuard, meter: SdkMeterProvider) {
    guard.meter = Some(meter);
}

/// Build a `tracing_subscriber::Layer` that ships events to the OTLP log exporter.
pub fn logs_layer<S>(config: &OtlpConfig) -> anyhow::Result<(impl Layer<S>, SdkLoggerProvider)>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let exporter = match config.protocol {
        OtlpProtocol::Grpc => opentelemetry_otlp::LogExporter::builder()
            .with_tonic()
            .with_endpoint(&config.endpoint)
            .build()
            .context("failed to build OTLP gRPC log exporter")?,
        OtlpProtocol::HttpProtobuf => opentelemetry_otlp::LogExporter::builder()
            .with_http()
            .with_endpoint(http_endpoint_for_signal(&config.endpoint, "/v1/logs"))
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

static OTLP_LOGGER_PROVIDER: OnceLock<SdkLoggerProvider> = OnceLock::new();

/// The logger provider stashed by [`init_tracing`], if OTLP log export was enabled. Callers attach
/// it to an [`OtlpGuard`] so its shutdown runs at process exit.
pub fn stashed_logger_provider() -> Option<SdkLoggerProvider> {
    OTLP_LOGGER_PROVIDER.get().cloned()
}

/// Install the tracing subscriber: an stderr fmt layer (`json` selects JSON lines) at `base_level`,
/// plus the OTLP log layer when `otlp_config` has logs enabled.
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

    match otlp_config {
        Some(cfg) if cfg.logs_enabled => {
            let (otlp_layer, provider) = logs_layer(cfg)?;
            OTLP_LOGGER_PROVIDER
                .set(provider)
                .map_err(|_| anyhow::anyhow!("OTLP logger provider already initialized"))?;
            registry.with(otlp_layer).init();
        }
        _ => {
            registry.init();
        }
    }
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

    const KEYS: [&str; 6] = [
        "RASTREO_OTLP_ENDPOINT",
        "RASTREO_OTLP_METRICS_ENABLED",
        "RASTREO_OTLP_LOGS_ENABLED",
        "RASTREO_OTLP_METRICS_INTERVAL_SECS",
        "RASTREO_OTLP_SERVICE_NAME",
        "RASTREO_OTLP_PROTOCOL",
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
            metrics_interval: Duration::from_secs(30),
            service_name: "rastreo-core-test".to_string(),
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
            metrics_interval: Duration::from_secs(30),
            service_name: "rastreo-core-test".to_string(),
        };
        let (_layer, provider) =
            logs_layer::<tracing_subscriber::Registry>(&cfg).expect("build http log layer");
        provider.shutdown().expect("shutdown");
    }
}
