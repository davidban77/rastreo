//! Shared OTLP config primitives: `OtlpProtocol` enum, permissive boolean/integer/protocol/header env parsers, and the HTTP+protobuf signal-path helper. Kept dep-free (`std` + `thiserror`) so it compiles under `--no-default-features` and both binaries can import it without pulling the OpenTelemetry chain.

use crate::env::{Env, VarError};

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

    #[error("invalid value for {name}: {value:?} is not a non-negative integer")]
    NotU64 {
        name: String,
        value: String,
        #[source]
        source: std::num::ParseIntError,
    },

    #[error(
        "invalid value for {name}: header entry #{position} is not a valid `key=value` pair \
             (expected a lowercase HTTP-token name before `=`)"
    )]
    MalformedHeaders { name: String, position: usize },

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
pub fn parse_env_protocol(
    env: &dyn Env,
    name: &str,
    default: OtlpProtocol,
) -> Result<OtlpProtocol, OtlpEnvError> {
    match env.var(name) {
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "grpc" => Ok(OtlpProtocol::Grpc),
            "http-protobuf" | "http" => Ok(OtlpProtocol::HttpProtobuf),
            other => Err(OtlpEnvError::UnknownProtocol {
                name: name.to_string(),
                value: other.to_string(),
            }),
        },
        Err(VarError::NotPresent) => Ok(default),
        Err(VarError::NotUnicode(_)) => Err(OtlpEnvError::NotUtf8 {
            name: name.to_string(),
        }),
    }
}

/// Parse `name` as a boolean, accepting `true`/`false`/`1`/`0`/`yes`/`no`/`on`/`off`
/// so operators can use whichever spelling their config store prefers. Returns
/// `default` when the variable is unset.
pub fn parse_env_bool(env: &dyn Env, name: &str, default: bool) -> Result<bool, OtlpEnvError> {
    match env.var(name) {
        Ok(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(true),
            "false" | "0" | "no" | "off" => Ok(false),
            _ => Err(OtlpEnvError::NotBoolean {
                name: name.to_string(),
                value: raw,
            }),
        },
        Err(VarError::NotPresent) => Ok(default),
        Err(VarError::NotUnicode(_)) => Err(OtlpEnvError::NotUtf8 {
            name: name.to_string(),
        }),
    }
}

/// Parse `name` as an unsigned integer of seconds. Returns `default` when the variable
/// is unset.
pub fn parse_env_u64(env: &dyn Env, name: &str, default: u64) -> Result<u64, OtlpEnvError> {
    match env.var(name) {
        Ok(raw) => raw.parse::<u64>().map_err(|source| OtlpEnvError::NotU64 {
            name: name.to_string(),
            value: raw,
            source,
        }),
        Err(VarError::NotPresent) => Ok(default),
        Err(VarError::NotUnicode(_)) => Err(OtlpEnvError::NotUtf8 {
            name: name.to_string(),
        }),
    }
}

/// Parse `name` as OTel-format headers: comma-separated `key=value` entries, split on the
/// first `=` per entry so values may contain `=`. Names are lowercased and validated as HTTP
/// tokens so the parsed set applies cleanly to both the gRPC and HTTP exporters. Returns an
/// empty vector when the variable is unset or blank; rejects an entry with no `=` or an
/// empty/invalid name.
pub fn parse_env_headers(env: &dyn Env, name: &str) -> Result<Vec<(String, String)>, OtlpEnvError> {
    let raw = match env.var(name) {
        Ok(raw) => raw,
        Err(VarError::NotPresent) => return Ok(Vec::new()),
        Err(VarError::NotUnicode(_)) => {
            return Err(OtlpEnvError::NotUtf8 {
                name: name.to_string(),
            })
        }
    };
    let mut headers = Vec::new();
    // `position` is the 1-based index of the comma-separated entry as the operator typed it.
    for (index, entry) in raw.split(',').enumerate() {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = match entry.split_once('=') {
            Some(parts) => parts,
            None => {
                return Err(OtlpEnvError::MalformedHeaders {
                    name: name.to_string(),
                    position: index + 1,
                })
            }
        };
        let key = raw_key.trim().to_ascii_lowercase();
        if key.is_empty() || !is_header_name_token(&key) {
            return Err(OtlpEnvError::MalformedHeaders {
                name: name.to_string(),
                position: index + 1,
            });
        }
        headers.push((key, raw_value.trim().to_string()));
    }
    Ok(headers)
}

fn is_header_name_token(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
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
    use crate::env::MapEnv;

    const VAR: &str = "RASTREO_TEST_OTLP_VALUE";

    fn unset() -> MapEnv {
        MapEnv::new()
    }

    fn env(value: &str) -> MapEnv {
        MapEnv::new().set(VAR, value)
    }

    #[test]
    fn parse_env_protocol_returns_default_when_unset() {
        let out = parse_env_protocol(&unset(), VAR, OtlpProtocol::Grpc).expect("default");
        assert_eq!(out, OtlpProtocol::Grpc);
    }

    #[test]
    fn parse_env_protocol_reads_grpc_variant() {
        let out = parse_env_protocol(&env("grpc"), VAR, OtlpProtocol::HttpProtobuf).expect("grpc");
        assert_eq!(out, OtlpProtocol::Grpc);
    }

    #[test]
    fn parse_env_protocol_reads_http_protobuf_variant() {
        let out = parse_env_protocol(&env("http-protobuf"), VAR, OtlpProtocol::Grpc)
            .expect("http-protobuf");
        assert_eq!(out, OtlpProtocol::HttpProtobuf);
    }

    #[test]
    fn parse_env_protocol_accepts_http_alias() {
        let out = parse_env_protocol(&env("http"), VAR, OtlpProtocol::Grpc).expect("http alias");
        assert_eq!(out, OtlpProtocol::HttpProtobuf);
    }

    #[test]
    fn parse_env_protocol_is_case_insensitive() {
        for (variant, expected) in [
            ("GRPC", OtlpProtocol::Grpc),
            ("Grpc", OtlpProtocol::Grpc),
            ("HTTP-PROTOBUF", OtlpProtocol::HttpProtobuf),
            ("Http-Protobuf", OtlpProtocol::HttpProtobuf),
            ("HTTP", OtlpProtocol::HttpProtobuf),
        ] {
            let out = parse_env_protocol(&env(variant), VAR, OtlpProtocol::Grpc).expect("parse");
            assert_eq!(out, expected, "variant {variant} misparsed");
        }
    }

    #[test]
    fn parse_env_protocol_rejects_unknown_value() {
        let err =
            parse_env_protocol(&env("yaml"), VAR, OtlpProtocol::Grpc).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains(VAR), "msg was {msg}");
        assert!(msg.contains("yaml"), "msg was {msg}");
        assert!(msg.contains("grpc"), "msg was {msg}");
        assert!(msg.contains("http-protobuf"), "msg was {msg}");
    }

    #[test]
    fn parse_env_bool_returns_default_when_unset() {
        assert!(parse_env_bool(&unset(), VAR, true).expect("default true"));
        assert!(!parse_env_bool(&unset(), VAR, false).expect("default false"));
    }

    #[test]
    fn parse_env_bool_accepts_common_true_forms() {
        for form in ["true", "TRUE", "1", "yes", "on", "  ON  "] {
            let out = parse_env_bool(&env(form), VAR, false).expect("truthy");
            assert!(out, "form {form:?} should parse true");
        }
    }

    #[test]
    fn parse_env_bool_accepts_common_false_forms() {
        for form in ["false", "FALSE", "0", "no", "off"] {
            let out = parse_env_bool(&env(form), VAR, true).expect("falsy");
            assert!(!out, "form {form:?} should parse false");
        }
    }

    #[test]
    fn parse_env_bool_rejects_unknown_value() {
        let err = parse_env_bool(&env("maybe"), VAR, false).expect_err("must reject");
        assert!(err.to_string().contains(VAR));
        assert!(err.to_string().contains("maybe"));
    }

    #[test]
    fn parse_env_u64_returns_default_when_unset() {
        assert_eq!(parse_env_u64(&unset(), VAR, 42).expect("default"), 42);
    }

    #[test]
    fn parse_env_u64_reads_numeric_value() {
        assert_eq!(parse_env_u64(&env("17"), VAR, 0).expect("parse"), 17);
    }

    #[test]
    fn parse_env_u64_rejects_non_numeric_value() {
        let err = parse_env_u64(&env("not-a-number"), VAR, 0).expect_err("must reject");
        assert!(err.to_string().contains(VAR));
        assert!(err.to_string().contains("not-a-number"));
    }

    #[test]
    fn parse_env_headers_returns_empty_when_unset() {
        assert!(parse_env_headers(&unset(), VAR).expect("unset").is_empty());
    }

    #[test]
    fn parse_env_headers_returns_empty_when_blank() {
        assert!(parse_env_headers(&env("   "), VAR)
            .expect("blank")
            .is_empty());
    }

    #[test]
    fn parse_env_headers_reads_single_header() {
        let out = parse_env_headers(&env("authorization=Bearer abc123"), VAR).expect("single");
        assert_eq!(
            out,
            vec![("authorization".to_string(), "Bearer abc123".to_string())]
        );
    }

    #[test]
    fn parse_env_headers_reads_multiple_headers() {
        let out = parse_env_headers(&env("authorization=Bearer t,x-scope-orgid=tenant-1"), VAR)
            .expect("multi");
        assert_eq!(
            out,
            vec![
                ("authorization".to_string(), "Bearer t".to_string()),
                ("x-scope-orgid".to_string(), "tenant-1".to_string()),
            ]
        );
    }

    #[test]
    fn parse_env_headers_splits_on_first_equals_only() {
        let out = parse_env_headers(&env("authorization=Basic dXNlcjpwYXNz=="), VAR)
            .expect("value with =");
        assert_eq!(
            out,
            vec![(
                "authorization".to_string(),
                "Basic dXNlcjpwYXNz==".to_string()
            )]
        );
    }

    #[test]
    fn parse_env_headers_trims_whitespace_around_key_and_value() {
        let out = parse_env_headers(&env("  authorization  =  Bearer t  ,  x-a = b "), VAR)
            .expect("trim");
        assert_eq!(
            out,
            vec![
                ("authorization".to_string(), "Bearer t".to_string()),
                ("x-a".to_string(), "b".to_string()),
            ]
        );
    }

    #[test]
    fn parse_env_headers_lowercases_names() {
        let out = parse_env_headers(&env("Authorization=Bearer t,X-Scope-OrgID=tenant"), VAR)
            .expect("case");
        assert_eq!(
            out,
            vec![
                ("authorization".to_string(), "Bearer t".to_string()),
                ("x-scope-orgid".to_string(), "tenant".to_string()),
            ]
        );
    }

    #[test]
    fn parse_env_headers_rejects_entry_without_equals() {
        let err = parse_env_headers(&env("authorization"), VAR).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains(VAR), "msg was {msg}");
        assert!(msg.contains("#1"), "msg was {msg}");
        assert!(msg.contains("key=value"), "msg was {msg}");
        assert!(!msg.contains("authorization"), "msg leaked entry: {msg}");
    }

    #[test]
    fn parse_env_headers_rejects_empty_key_without_leaking_value() {
        let err = parse_env_headers(&env("=supersecrettoken"), VAR).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains(VAR), "msg was {msg}");
        assert!(msg.contains("#1"), "msg was {msg}");
        assert!(
            !msg.contains("supersecrettoken"),
            "error must not leak the header value, msg was {msg}"
        );
    }

    #[test]
    fn parse_env_headers_rejects_non_token_name() {
        let err = parse_env_headers(&env("bad name=value"), VAR).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains(VAR), "msg was {msg}");
        assert!(msg.contains("#1"), "msg was {msg}");
    }

    #[test]
    fn parse_env_headers_invalid_name_does_not_leak_credential() {
        // A pasted `Basic <base64>` credential: the pre-`=` substring `Basic dXNlcjpwYXNz`
        // fails token validation on the space, but must never reach the error.
        let err = parse_env_headers(&env("Basic dXNlcjpwYXNz=="), VAR).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains(VAR), "msg was {msg}");
        assert!(
            !msg.contains("dXNlcjpwYXNz"),
            "error must not leak the pasted credential, msg was {msg}"
        );
    }

    #[test]
    fn parse_env_headers_bare_token_does_not_leak_credential() {
        let err = parse_env_headers(&env("glc_secretexampletoken"), VAR).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains(VAR), "msg was {msg}");
        assert!(
            !msg.contains("glc_secretexampletoken"),
            "error must not leak a bare pasted token, msg was {msg}"
        );
    }

    #[test]
    fn parse_env_headers_missing_equals_does_not_leak_trailing_secret() {
        let err =
            parse_env_headers(&env("authorization mysecrettoken"), VAR).expect_err("must reject");
        assert!(
            !err.to_string().contains("mysecrettoken"),
            "error must not leak a mistyped value, msg was {err}"
        );
    }

    #[test]
    fn parse_env_headers_skips_empty_entries() {
        let out = parse_env_headers(&env("authorization=Bearer t,,"), VAR)
            .expect("trailing comma tolerated");
        assert_eq!(
            out,
            vec![("authorization".to_string(), "Bearer t".to_string())]
        );
    }

    #[cfg(unix)]
    #[test]
    fn every_parser_refuses_a_value_that_is_not_utf8() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let env = MapEnv::new().set(VAR, OsString::from_vec(vec![0x66, 0xff, 0x6f]));
        for msg in [
            parse_env_protocol(&env, VAR, OtlpProtocol::Grpc)
                .expect_err("protocol")
                .to_string(),
            parse_env_bool(&env, VAR, false)
                .expect_err("bool")
                .to_string(),
            parse_env_u64(&env, VAR, 0).expect_err("u64").to_string(),
            parse_env_headers(&env, VAR)
                .expect_err("headers")
                .to_string(),
        ] {
            assert!(msg.contains(VAR), "msg was {msg}");
            assert!(msg.contains("not valid UTF-8"), "msg was {msg}");
        }
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
