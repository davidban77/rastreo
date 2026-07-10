//! Shared OTLP config primitives: `OtlpProtocol` enum, permissive boolean/integer/protocol env parsers, and the HTTP+protobuf signal-path helper. Kept dep-free (`std` + `thiserror`) so it compiles under `--no-default-features` and both binaries can import it without pulling the OpenTelemetry chain.

/// Error surfaced when parsing OTLP env-var configuration at startup.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OtlpEnvError {
    #[error(
        "invalid value for {name}: {value:?} is not a supported OTLP protocol \
             (expected `grpc`, `http-protobuf`, or `http`)"
    )]
    UnknownProtocol { name: String, value: String },

    #[error("invalid value for {name}: {value:?} is not a boolean (expected true/false)")]
    NotBoolean { name: String, value: String },

    #[error("invalid value for {name}: {value:?} is not a non-negative integer ({source})")]
    NotU64 {
        name: String,
        value: String,
        #[source]
        source: std::num::ParseIntError,
    },

    #[error("invalid value for {name}: not valid UTF-8")]
    NotUtf8 { name: String },
}

/// OTLP transport protocol selected at startup via `RASTREO_OTLP_PROTOCOL`. Non-exhaustive
/// so future transports can be added without a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum OtlpProtocol {
    /// gRPC via tonic. Default. Endpoint is a URL like `http://collector:4317`.
    #[default]
    Grpc,
    /// HTTP+protobuf via reqwest. Endpoint is a base URL like `http://collector:4318`;
    /// callers append `/v1/logs` or `/v1/metrics` per signal via [`http_endpoint_for_signal`].
    HttpProtobuf,
}

/// Parse `name` as an [`OtlpProtocol`], case-insensitively, accepting `grpc`,
/// `http-protobuf`, or the `http` alias. Returns `default` when the variable is unset.
pub fn parse_env_protocol(name: &str, default: OtlpProtocol) -> Result<OtlpProtocol, OtlpEnvError> {
    match std::env::var(name) {
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "grpc" => Ok(OtlpProtocol::Grpc),
            "http-protobuf" | "http" => Ok(OtlpProtocol::HttpProtobuf),
            other => Err(OtlpEnvError::UnknownProtocol {
                name: name.to_string(),
                value: other.to_string(),
            }),
        },
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err(OtlpEnvError::NotUtf8 {
            name: name.to_string(),
        }),
    }
}

/// Parse `name` as a boolean, accepting `true`/`false`/`1`/`0`/`yes`/`no`/`on`/`off`
/// so operators can use whichever spelling their config store prefers. Returns
/// `default` when the variable is unset.
pub fn parse_env_bool(name: &str, default: bool) -> Result<bool, OtlpEnvError> {
    match std::env::var(name) {
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(true),
            "false" | "0" | "no" | "off" => Ok(false),
            _ => Err(OtlpEnvError::NotBoolean {
                name: name.to_string(),
                value: raw,
            }),
        },
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err(OtlpEnvError::NotUtf8 {
            name: name.to_string(),
        }),
    }
}

/// Parse `name` as an unsigned integer of seconds. Returns `default` when the variable
/// is unset.
pub fn parse_env_u64(name: &str, default: u64) -> Result<u64, OtlpEnvError> {
    match std::env::var(name) {
        Ok(raw) => raw.parse::<u64>().map_err(|source| OtlpEnvError::NotU64 {
            name: name.to_string(),
            value: raw,
            source,
        }),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err(OtlpEnvError::NotUtf8 {
            name: name.to_string(),
        }),
    }
}

/// Append the OTLP HTTP signal path to a bare endpoint. The `opentelemetry-otlp` SDK
/// applies signal-path defaults only on the `OTEL_EXPORTER_OTLP_ENDPOINT` env-var
/// fallback path; the programmatic `.with_endpoint()` builder uses the URL verbatim,
/// so users setting `RASTREO_OTLP_ENDPOINT=http://collector:4318` on HTTP+protobuf
/// would POST to `/` and get 404s. This helper does the append so one endpoint value
/// works for both logs and metrics.
pub fn http_endpoint_for_signal(base: &str, signal_path: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    if trimmed.ends_with(signal_path) {
        trimmed.to_string()
    } else {
        format!("{trimmed}{signal_path}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    #[test]
    fn parse_env_protocol_returns_default_when_unset() {
        let _g = env_guard();
        let var = "RASTREO_TEST_OTLP_PROTOCOL_UNSET";
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe { std::env::remove_var(var) };
        let out = parse_env_protocol(var, OtlpProtocol::Grpc).expect("default");
        assert_eq!(out, OtlpProtocol::Grpc);
    }

    #[test]
    fn parse_env_protocol_reads_grpc_variant() {
        let _g = env_guard();
        let var = "RASTREO_TEST_OTLP_PROTOCOL_GRPC";
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe { std::env::set_var(var, "grpc") };
        let out = parse_env_protocol(var, OtlpProtocol::HttpProtobuf).expect("grpc");
        // SAFETY: same guard.
        unsafe { std::env::remove_var(var) };
        assert_eq!(out, OtlpProtocol::Grpc);
    }

    #[test]
    fn parse_env_protocol_reads_http_protobuf_variant() {
        let _g = env_guard();
        let var = "RASTREO_TEST_OTLP_PROTOCOL_HTTP_PROTOBUF";
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe { std::env::set_var(var, "http-protobuf") };
        let out = parse_env_protocol(var, OtlpProtocol::Grpc).expect("http-protobuf");
        // SAFETY: same guard.
        unsafe { std::env::remove_var(var) };
        assert_eq!(out, OtlpProtocol::HttpProtobuf);
    }

    #[test]
    fn parse_env_protocol_accepts_http_alias() {
        let _g = env_guard();
        let var = "RASTREO_TEST_OTLP_PROTOCOL_HTTP_ALIAS";
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe { std::env::set_var(var, "http") };
        let out = parse_env_protocol(var, OtlpProtocol::Grpc).expect("http alias");
        // SAFETY: same guard.
        unsafe { std::env::remove_var(var) };
        assert_eq!(out, OtlpProtocol::HttpProtobuf);
    }

    #[test]
    fn parse_env_protocol_is_case_insensitive() {
        let _g = env_guard();
        for (variant, expected) in [
            ("GRPC", OtlpProtocol::Grpc),
            ("Grpc", OtlpProtocol::Grpc),
            ("HTTP-PROTOBUF", OtlpProtocol::HttpProtobuf),
            ("Http-Protobuf", OtlpProtocol::HttpProtobuf),
            ("HTTP", OtlpProtocol::HttpProtobuf),
        ] {
            let var = "RASTREO_TEST_OTLP_PROTOCOL_CASE";
            // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
            unsafe { std::env::set_var(var, variant) };
            let out = parse_env_protocol(var, OtlpProtocol::Grpc).expect("parse");
            // SAFETY: same guard.
            unsafe { std::env::remove_var(var) };
            assert_eq!(out, expected, "variant {variant} misparsed");
        }
    }

    #[test]
    fn parse_env_protocol_rejects_unknown_value() {
        let _g = env_guard();
        let var = "RASTREO_TEST_OTLP_PROTOCOL_BAD";
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe { std::env::set_var(var, "yaml") };
        let err = parse_env_protocol(var, OtlpProtocol::Grpc).expect_err("must reject");
        // SAFETY: same guard.
        unsafe { std::env::remove_var(var) };
        let msg = err.to_string();
        assert!(msg.contains(var), "msg was {msg}");
        assert!(msg.contains("yaml"), "msg was {msg}");
        assert!(msg.contains("grpc"), "msg was {msg}");
        assert!(msg.contains("http-protobuf"), "msg was {msg}");
    }

    #[test]
    fn parse_env_bool_returns_default_when_unset() {
        let _g = env_guard();
        let var = "RASTREO_TEST_OTLP_BOOL_UNSET";
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe { std::env::remove_var(var) };
        assert!(parse_env_bool(var, true).expect("default true"));
        assert!(!parse_env_bool(var, false).expect("default false"));
    }

    #[test]
    fn parse_env_bool_accepts_common_true_forms() {
        let _g = env_guard();
        let var = "RASTREO_TEST_OTLP_BOOL_TRUE";
        for form in ["true", "TRUE", "1", "yes", "on", "  ON  "] {
            // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
            unsafe { std::env::set_var(var, form) };
            let out = parse_env_bool(var, false).expect("truthy");
            assert!(out, "form {form:?} should parse true");
        }
        // SAFETY: same guard.
        unsafe { std::env::remove_var(var) };
    }

    #[test]
    fn parse_env_bool_accepts_common_false_forms() {
        let _g = env_guard();
        let var = "RASTREO_TEST_OTLP_BOOL_FALSE";
        for form in ["false", "FALSE", "0", "no", "off"] {
            // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
            unsafe { std::env::set_var(var, form) };
            let out = parse_env_bool(var, true).expect("falsy");
            assert!(!out, "form {form:?} should parse false");
        }
        // SAFETY: same guard.
        unsafe { std::env::remove_var(var) };
    }

    #[test]
    fn parse_env_bool_rejects_unknown_value() {
        let _g = env_guard();
        let var = "RASTREO_TEST_OTLP_BOOL_BAD";
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe { std::env::set_var(var, "maybe") };
        let err = parse_env_bool(var, false).expect_err("must reject");
        // SAFETY: same guard.
        unsafe { std::env::remove_var(var) };
        assert!(err.to_string().contains(var));
        assert!(err.to_string().contains("maybe"));
    }

    #[test]
    fn parse_env_u64_returns_default_when_unset() {
        let _g = env_guard();
        let var = "RASTREO_TEST_OTLP_U64_UNSET";
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe { std::env::remove_var(var) };
        assert_eq!(parse_env_u64(var, 42).expect("default"), 42);
    }

    #[test]
    fn parse_env_u64_reads_numeric_value() {
        let _g = env_guard();
        let var = "RASTREO_TEST_OTLP_U64_OK";
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe { std::env::set_var(var, "17") };
        let out = parse_env_u64(var, 0).expect("parse");
        // SAFETY: same guard.
        unsafe { std::env::remove_var(var) };
        assert_eq!(out, 17);
    }

    #[test]
    fn parse_env_u64_rejects_non_numeric_value() {
        let _g = env_guard();
        let var = "RASTREO_TEST_OTLP_U64_BAD";
        // SAFETY: env_guard() serialises env-var mutation across tests; no concurrent readers.
        unsafe { std::env::set_var(var, "not-a-number") };
        let err = parse_env_u64(var, 0).expect_err("must reject");
        // SAFETY: same guard.
        unsafe { std::env::remove_var(var) };
        assert!(err.to_string().contains(var));
        assert!(err.to_string().contains("not-a-number"));
    }

    #[test]
    fn http_endpoint_appends_signal_path_to_bare_url() {
        assert_eq!(
            http_endpoint_for_signal("http://collector:4318", "/v1/logs"),
            "http://collector:4318/v1/logs"
        );
        assert_eq!(
            http_endpoint_for_signal("http://collector:4318", "/v1/metrics"),
            "http://collector:4318/v1/metrics"
        );
    }

    #[test]
    fn http_endpoint_strips_trailing_slash_before_appending() {
        assert_eq!(
            http_endpoint_for_signal("http://collector:4318/", "/v1/logs"),
            "http://collector:4318/v1/logs"
        );
    }

    #[test]
    fn http_endpoint_preserves_already_qualified_url() {
        assert_eq!(
            http_endpoint_for_signal("http://collector:4318/v1/logs", "/v1/logs"),
            "http://collector:4318/v1/logs"
        );
        assert_eq!(
            http_endpoint_for_signal("http://collector:4318/v1/logs/", "/v1/logs"),
            "http://collector:4318/v1/logs"
        );
    }

    #[test]
    fn otlp_protocol_default_is_grpc() {
        assert_eq!(OtlpProtocol::default(), OtlpProtocol::Grpc);
    }
}
