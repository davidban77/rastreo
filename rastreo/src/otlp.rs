//! OTLP config + guard wiring for the `rastreo` CLI (thin wrapper over rastreo-core).

use rastreo_core::Env;

#[cfg(feature = "otlp")]
pub use rastreo_core::observability::otlp::{
    attach_logger, attach_tracer, stashed_logger_provider, stashed_tracer_provider, OtlpConfig,
    OtlpGuard,
};

/// Read OTLP config for the CLI. The CLI exports logs only, so `RASTREO_OTLP_METRICS_ENABLED=true`
/// is rejected up front; otherwise it defers to the shared parser with `service_name` default
/// `"rastreo"`.
#[cfg(feature = "otlp")]
pub fn config_from_env(env: &dyn Env) -> anyhow::Result<Option<OtlpConfig>> {
    use rastreo_core::observability::otlp_config::parse_env_bool;

    if parse_env_bool(env, "RASTREO_OTLP_METRICS_ENABLED", false)? {
        return Err(anyhow::anyhow!(
            "RASTREO_OTLP_METRICS_ENABLED=true is not supported on the `rastreo` CLI. \
             The CLI is short-running and does not export metrics via OTLP. \
             Set RASTREO_OTLP_LOGS_ENABLED=true to ship structured logs via OTLP instead."
        ));
    }
    OtlpConfig::from_env(env, "rastreo", false)
}

#[cfg(not(feature = "otlp"))]
#[derive(Debug, Clone)]
pub struct OtlpConfig;

#[cfg(not(feature = "otlp"))]
pub fn config_from_env(_env: &dyn Env) -> anyhow::Result<Option<OtlpConfig>> {
    Ok(None)
}

#[cfg(all(test, feature = "otlp"))]
mod tests {
    use super::*;
    use rastreo_core::observability::otlp_config::OtlpProtocol;
    use rastreo_core::MapEnv;

    const ENDPOINT: &str = "http://collector:4317";

    fn logs_to(endpoint: &str) -> MapEnv {
        MapEnv::new()
            .set("RASTREO_OTLP_LOGS_ENABLED", "true")
            .set("RASTREO_OTLP_ENDPOINT", endpoint)
    }

    #[test]
    fn config_from_env_returns_none_when_both_disabled() {
        assert!(config_from_env(&MapEnv::new())
            .expect("config_from_env")
            .is_none());
    }

    #[test]
    fn config_from_env_reads_logs_enabled_with_endpoint() {
        let cfg = config_from_env(&logs_to(ENDPOINT))
            .expect("config_from_env")
            .expect("some");
        assert!(cfg.logs_enabled);
        assert_eq!(cfg.endpoint, ENDPOINT);
        assert_eq!(cfg.service_name, "rastreo");
    }

    #[test]
    fn config_from_env_rejects_metrics_enabled_true_on_cli() {
        let env = MapEnv::new()
            .set("RASTREO_OTLP_METRICS_ENABLED", "true")
            .set("RASTREO_OTLP_ENDPOINT", ENDPOINT);
        let err = config_from_env(&env).expect_err("must reject metrics on CLI");
        let msg = err.to_string();
        assert!(
            msg.contains("not supported on the `rastreo` CLI"),
            "msg was: {msg}"
        );
        assert!(msg.contains("RASTREO_OTLP_LOGS_ENABLED"), "msg was: {msg}");
    }

    #[test]
    fn config_from_env_ignores_malformed_metrics_interval() {
        let env = logs_to(ENDPOINT).set("RASTREO_OTLP_METRICS_INTERVAL_SECS", "not-a-number");
        let cfg = config_from_env(&env)
            .expect("malformed interval must be inert on the CLI")
            .expect("some");
        assert!(cfg.logs_enabled);
        assert!(!cfg.metrics_enabled);
    }

    #[test]
    fn config_from_env_rejects_enabled_without_endpoint() {
        let env = MapEnv::new().set("RASTREO_OTLP_LOGS_ENABLED", "true");
        let err = config_from_env(&env).expect_err("must reject");
        assert!(err.to_string().contains("RASTREO_OTLP_ENDPOINT"));
    }

    #[test]
    fn config_from_env_rejects_invalid_boolean() {
        let env = MapEnv::new().set("RASTREO_OTLP_LOGS_ENABLED", "sometimes");
        let err = config_from_env(&env).expect_err("must reject");
        assert!(err.to_string().contains("RASTREO_OTLP_LOGS_ENABLED"));
    }

    #[test]
    fn config_from_env_protocol_defaults_to_grpc() {
        let cfg = config_from_env(&logs_to(ENDPOINT))
            .expect("config_from_env")
            .expect("some");
        assert_eq!(cfg.protocol, OtlpProtocol::Grpc);
    }

    #[test]
    fn config_from_env_protocol_parses_http_alias() {
        let env = logs_to("http://collector:4318").set("RASTREO_OTLP_PROTOCOL", "http");
        let cfg = config_from_env(&env)
            .expect("config_from_env")
            .expect("some");
        assert_eq!(cfg.protocol, OtlpProtocol::HttpProtobuf);
    }

    #[test]
    fn config_from_env_rejects_unknown_protocol() {
        let env = logs_to(ENDPOINT).set("RASTREO_OTLP_PROTOCOL", "yaml");
        let err = config_from_env(&env).expect_err("unknown protocol rejected");
        let msg = err.to_string();
        assert!(msg.contains("RASTREO_OTLP_PROTOCOL"), "msg was {msg}");
        assert!(msg.contains("yaml"), "msg was {msg}");
    }
}
