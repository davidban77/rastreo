//! OpenTelemetry OTLP exporter wiring for the `rastreo` CLI.

#[cfg(feature = "otlp")]
pub use rastreo_core::observability::otlp_config::OtlpProtocol;

#[cfg(feature = "otlp")]
use rastreo_core::observability::otlp_config::{parse_env_bool, parse_env_protocol};

/// OpenTelemetry OTLP exporter configuration read from `RASTREO_OTLP_*` environment variables.
///
/// The CLI supports logs export only. `RASTREO_OTLP_METRICS_ENABLED=true` is rejected at parse
/// time because the CLI is short-running and cannot produce useful periodic metrics.
#[cfg(feature = "otlp")]
#[derive(Debug, Clone)]
pub struct OtlpConfig {
    pub endpoint: String,
    pub protocol: OtlpProtocol,
    pub logs_enabled: bool,
    pub service_name: String,
}

#[cfg(feature = "otlp")]
impl OtlpConfig {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let metrics_enabled = parse_env_bool("RASTREO_OTLP_METRICS_ENABLED", false)?;
        if metrics_enabled {
            return Err(anyhow::anyhow!(
                "RASTREO_OTLP_METRICS_ENABLED=true is not supported on the `rastreo` CLI. \
                 The CLI is short-running and does not export metrics via OTLP. \
                 Set RASTREO_OTLP_LOGS_ENABLED=true to ship structured logs via OTLP instead."
            ));
        }
        let logs_enabled = parse_env_bool("RASTREO_OTLP_LOGS_ENABLED", false)?;
        if !logs_enabled {
            return Ok(None);
        }
        let endpoint = match std::env::var("RASTREO_OTLP_ENDPOINT") {
            Ok(raw) if !raw.trim().is_empty() => raw,
            Ok(_) | Err(std::env::VarError::NotPresent) => {
                return Err(anyhow::anyhow!(
                    "RASTREO_OTLP_ENDPOINT is required when RASTREO_OTLP_LOGS_ENABLED is true; \
                     set it to your OTLP collector URL \
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
        let service_name = std::env::var("RASTREO_OTLP_SERVICE_NAME")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "rastreo".to_string());
        Ok(Some(Self {
            endpoint,
            protocol,
            logs_enabled,
            service_name,
        }))
    }
}

#[cfg(not(feature = "otlp"))]
#[derive(Debug, Clone)]
pub struct OtlpConfig;

#[cfg(not(feature = "otlp"))]
impl OtlpConfig {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        Ok(None)
    }
}

#[cfg(feature = "otlp")]
mod otlp_runtime {
    use super::{OtlpConfig, OtlpProtocol};
    use anyhow::Context;
    use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::logs::SdkLoggerProvider;
    use opentelemetry_sdk::Resource;
    use rastreo_core::observability::otlp_config::http_endpoint_for_signal;
    use tracing::Subscriber;
    use tracing_subscriber::registry::LookupSpan;
    use tracing_subscriber::Layer;

    #[non_exhaustive]
    pub struct OtlpGuard {
        pub(crate) logger: Option<SdkLoggerProvider>,
    }

    impl OtlpGuard {
        pub(crate) fn empty() -> Self {
            Self { logger: None }
        }
    }

    impl Drop for OtlpGuard {
        fn drop(&mut self) {
            if let Some(l) = self.logger.take() {
                if let Err(err) = l.shutdown() {
                    tracing::warn!(%err, "OTLP logger provider shutdown failed");
                }
            }
        }
    }

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
            _ => anyhow::bail!("unsupported OTLP protocol variant: {:?}", config.protocol),
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

    pub fn init_metrics_only(_config: &OtlpConfig) -> anyhow::Result<OtlpGuard> {
        Ok(OtlpGuard::empty())
    }

    pub fn attach_logger(guard: &mut OtlpGuard, logger: SdkLoggerProvider) {
        guard.logger = Some(logger);
    }
}

#[cfg(feature = "otlp")]
pub use otlp_runtime::{attach_logger, init_metrics_only, logs_layer, OtlpGuard};

#[cfg(all(test, feature = "otlp"))]
mod tests {
    use super::*;

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
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
    fn otlp_config_from_env_returns_none_when_both_disabled() {
        let _g = env_guard();
        clear();
        assert!(OtlpConfig::from_env().expect("from_env").is_none());
    }

    #[test]
    fn otlp_config_from_env_reads_logs_enabled_with_endpoint() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
        }
        let cfg = OtlpConfig::from_env().expect("from_env").expect("some");
        clear();
        assert!(cfg.logs_enabled);
        assert_eq!(cfg.endpoint, "http://collector:4317");
        assert_eq!(cfg.service_name, "rastreo");
    }

    #[test]
    fn otlp_config_from_env_rejects_metrics_enabled_true_on_cli() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_METRICS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
        }
        let err = OtlpConfig::from_env().expect_err("must reject metrics on CLI");
        clear();
        let msg = err.to_string();
        assert!(
            msg.contains("not supported on the `rastreo` CLI"),
            "msg was: {msg}"
        );
        assert!(msg.contains("RASTREO_OTLP_LOGS_ENABLED"), "msg was: {msg}");
    }

    #[test]
    fn otlp_config_from_env_rejects_enabled_without_endpoint() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe { std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true") };
        let err = OtlpConfig::from_env().expect_err("must reject");
        clear();
        assert!(err.to_string().contains("RASTREO_OTLP_ENDPOINT"));
    }

    #[test]
    fn otlp_config_from_env_rejects_invalid_boolean() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe { std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "sometimes") };
        let err = OtlpConfig::from_env().expect_err("must reject");
        clear();
        assert!(err.to_string().contains("RASTREO_OTLP_LOGS_ENABLED"));
    }

    #[test]
    fn otlp_config_protocol_defaults_to_grpc() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
        }
        let cfg = OtlpConfig::from_env().expect("from_env").expect("some");
        clear();
        assert_eq!(cfg.protocol, OtlpProtocol::Grpc);
    }

    #[test]
    fn otlp_config_protocol_parses_grpc() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
            std::env::set_var("RASTREO_OTLP_PROTOCOL", "grpc");
        }
        let cfg = OtlpConfig::from_env().expect("from_env").expect("some");
        clear();
        assert_eq!(cfg.protocol, OtlpProtocol::Grpc);
    }

    #[test]
    fn otlp_config_protocol_parses_http_protobuf() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4318");
            std::env::set_var("RASTREO_OTLP_PROTOCOL", "http-protobuf");
        }
        let cfg = OtlpConfig::from_env().expect("from_env").expect("some");
        clear();
        assert_eq!(cfg.protocol, OtlpProtocol::HttpProtobuf);
    }

    #[test]
    fn otlp_config_protocol_parses_http_alias() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4318");
            std::env::set_var("RASTREO_OTLP_PROTOCOL", "http");
        }
        let cfg = OtlpConfig::from_env().expect("from_env").expect("some");
        clear();
        assert_eq!(cfg.protocol, OtlpProtocol::HttpProtobuf);
    }

    #[test]
    fn otlp_config_protocol_case_insensitive() {
        let _g = env_guard();
        for (variant, expected) in [
            ("GRPC", OtlpProtocol::Grpc),
            ("Grpc", OtlpProtocol::Grpc),
            ("HTTP-PROTOBUF", OtlpProtocol::HttpProtobuf),
            ("Http-Protobuf", OtlpProtocol::HttpProtobuf),
            ("HTTP", OtlpProtocol::HttpProtobuf),
        ] {
            clear();
            // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
            unsafe {
                std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
                std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
                std::env::set_var("RASTREO_OTLP_PROTOCOL", variant);
            }
            let cfg = OtlpConfig::from_env().expect("from_env").expect("some");
            assert_eq!(cfg.protocol, expected, "variant {variant} misparsed");
        }
        clear();
    }

    #[test]
    fn otlp_config_rejects_unknown_protocol() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
            std::env::set_var("RASTREO_OTLP_PROTOCOL", "yaml");
        }
        let err = OtlpConfig::from_env().expect_err("unknown protocol rejected");
        clear();
        let msg = err.to_string();
        assert!(msg.contains("RASTREO_OTLP_PROTOCOL"), "msg was {msg}");
        assert!(msg.contains("yaml"), "msg was {msg}");
        assert!(msg.contains("grpc"), "msg was {msg}");
        assert!(msg.contains("http-protobuf"), "msg was {msg}");
    }
}
