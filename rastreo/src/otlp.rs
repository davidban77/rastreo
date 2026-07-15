//! OTLP config + guard wiring for the `rastreo` CLI (thin wrapper over rastreo-core).

#[cfg(feature = "otlp")]
pub use rastreo_core::observability::otlp::{
    attach_logger, stashed_logger_provider, OtlpConfig, OtlpGuard,
};

/// Read OTLP config for the CLI. The CLI exports logs only, so `RASTREO_OTLP_METRICS_ENABLED=true`
/// is rejected up front; otherwise it defers to the shared parser with `service_name` default
/// `"rastreo"`.
#[cfg(feature = "otlp")]
pub fn config_from_env() -> anyhow::Result<Option<OtlpConfig>> {
    use rastreo_core::observability::otlp_config::parse_env_bool;

    if parse_env_bool("RASTREO_OTLP_METRICS_ENABLED", false)? {
        return Err(anyhow::anyhow!(
            "RASTREO_OTLP_METRICS_ENABLED=true is not supported on the `rastreo` CLI. \
             The CLI is short-running and does not export metrics via OTLP. \
             Set RASTREO_OTLP_LOGS_ENABLED=true to ship structured logs via OTLP instead."
        ));
    }
    OtlpConfig::from_env("rastreo", false)
}

#[cfg(not(feature = "otlp"))]
#[derive(Debug, Clone)]
pub struct OtlpConfig;

#[cfg(not(feature = "otlp"))]
pub fn config_from_env() -> anyhow::Result<Option<OtlpConfig>> {
    Ok(None)
}

#[cfg(all(test, feature = "otlp"))]
mod tests {
    use super::*;
    use rastreo_core::observability::otlp_config::OtlpProtocol;

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
    fn config_from_env_returns_none_when_both_disabled() {
        let _g = env_guard();
        clear();
        assert!(config_from_env().expect("config_from_env").is_none());
    }

    #[test]
    fn config_from_env_reads_logs_enabled_with_endpoint() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
        }
        let cfg = config_from_env().expect("config_from_env").expect("some");
        clear();
        assert!(cfg.logs_enabled);
        assert_eq!(cfg.endpoint, "http://collector:4317");
        assert_eq!(cfg.service_name, "rastreo");
    }

    #[test]
    fn config_from_env_rejects_metrics_enabled_true_on_cli() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_METRICS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
        }
        let err = config_from_env().expect_err("must reject metrics on CLI");
        clear();
        let msg = err.to_string();
        assert!(
            msg.contains("not supported on the `rastreo` CLI"),
            "msg was: {msg}"
        );
        assert!(msg.contains("RASTREO_OTLP_LOGS_ENABLED"), "msg was: {msg}");
    }

    #[test]
    fn config_from_env_ignores_malformed_metrics_interval() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
            std::env::set_var("RASTREO_OTLP_METRICS_INTERVAL_SECS", "not-a-number");
        }
        let cfg = config_from_env()
            .expect("malformed interval must be inert on the CLI")
            .expect("some");
        clear();
        assert!(cfg.logs_enabled);
        assert!(!cfg.metrics_enabled);
    }

    #[test]
    fn config_from_env_rejects_enabled_without_endpoint() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe { std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true") };
        let err = config_from_env().expect_err("must reject");
        clear();
        assert!(err.to_string().contains("RASTREO_OTLP_ENDPOINT"));
    }

    #[test]
    fn config_from_env_rejects_invalid_boolean() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe { std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "sometimes") };
        let err = config_from_env().expect_err("must reject");
        clear();
        assert!(err.to_string().contains("RASTREO_OTLP_LOGS_ENABLED"));
    }

    #[test]
    fn config_from_env_protocol_defaults_to_grpc() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
        }
        let cfg = config_from_env().expect("config_from_env").expect("some");
        clear();
        assert_eq!(cfg.protocol, OtlpProtocol::Grpc);
    }

    #[test]
    fn config_from_env_protocol_parses_http_alias() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4318");
            std::env::set_var("RASTREO_OTLP_PROTOCOL", "http");
        }
        let cfg = config_from_env().expect("config_from_env").expect("some");
        clear();
        assert_eq!(cfg.protocol, OtlpProtocol::HttpProtobuf);
    }

    #[test]
    fn config_from_env_rejects_unknown_protocol() {
        let _g = env_guard();
        clear();
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe {
            std::env::set_var("RASTREO_OTLP_LOGS_ENABLED", "true");
            std::env::set_var("RASTREO_OTLP_ENDPOINT", "http://collector:4317");
            std::env::set_var("RASTREO_OTLP_PROTOCOL", "yaml");
        }
        let err = config_from_env().expect_err("unknown protocol rejected");
        clear();
        let msg = err.to_string();
        assert!(msg.contains("RASTREO_OTLP_PROTOCOL"), "msg was {msg}");
        assert!(msg.contains("yaml"), "msg was {msg}");
    }
}
