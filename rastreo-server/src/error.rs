use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rastreo_core::{RastreoError, ResolverError};
use serde::Serialize;

use crate::routes::auth::ErrorDisclosure;

const REDACTED_SERVER_ERROR: &str = "internal server error";

#[derive(Debug)]
pub struct AppError {
    pub status: StatusCode,
    pub message: String,
}

impl AppError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    pub fn too_many_requests(message: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, message)
    }

    /// Maps a [`RastreoError`] to a response; 5xx detail is disclosed only when `disclosure` proves the caller authenticated.
    pub fn from_rastreo(err: RastreoError, disclosure: ErrorDisclosure) -> Self {
        let status = status_for(&err);
        let disclose = disclosure.caller_authenticated();
        if status.is_server_error() {
            tracing::error!(
                ?err,
                status = %status,
                disclosed = disclose,
                "internal server error returned to client"
            );
        }
        Self {
            status,
            message: response_message(&err, status, disclose),
        }
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: &self.message,
        };
        (self.status, Json(body)).into_response()
    }
}

/// Redacts 5xx detail; a route that can prove its caller authenticated uses [`AppError::from_rastreo`].
impl From<RastreoError> for AppError {
    fn from(err: RastreoError) -> Self {
        Self::from_rastreo(err, ErrorDisclosure::default())
    }
}

// Map client-supplied input errors to 4xx; everything internal to 500.
fn status_for(err: &RastreoError) -> StatusCode {
    match err {
        RastreoError::Config(_) => StatusCode::BAD_REQUEST,
        RastreoError::Resolver(inner) => match inner {
            ResolverError::DnsLookupFailed { .. } => StatusCode::SERVICE_UNAVAILABLE,
            ResolverError::TargetNotAllowed { .. } => StatusCode::FORBIDDEN,
            _ => StatusCode::BAD_REQUEST,
        },
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn response_message(err: &dyn std::error::Error, status: StatusCode, disclose: bool) -> String {
    if status.is_client_error() {
        err.to_string()
    } else if disclose {
        error_chain(err)
    } else {
        REDACTED_SERVER_ERROR.to_string()
    }
}

// A transparent umbrella variant renders as its inner Display alone; the cause it wraps is the actionable part.
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut rendered = err.to_string();
    let mut next = err.source();
    while let Some(source) = next {
        rendered.push_str(": ");
        rendered.push_str(&source.to_string());
        next = source.source();
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;
    use rastreo_core::{ConfigError, EncoderError, ProbeError, ResolverError, RuntimeError};

    #[test]
    fn config_error_maps_to_400() {
        let err: AppError = RastreoError::Config(ConfigError::InvalidValue("bad".into())).into();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("bad"));
    }

    #[test]
    fn resolver_error_dns_no_records_maps_to_400() {
        let err: AppError = RastreoError::Resolver(ResolverError::DnsNoRecords {
            name: "missing.lab".into(),
        })
        .into();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("missing.lab"));
    }

    #[test]
    fn dns_lookup_failed_maps_to_503_with_a_redacted_body() {
        let err: AppError = RastreoError::Resolver(ResolverError::DnsLookupFailed {
            name: "internal.lab".into(),
            source: hickory_resolver::net::NetError::NoConnections.into(),
        })
        .into();
        assert_eq!(err.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.message, "internal server error");
    }

    #[test]
    fn resolver_error_cidr_too_large_maps_to_400() {
        let err: AppError = RastreoError::Resolver(ResolverError::CidrTooLarge {
            cidr: "10.0.0.0/8".into(),
            hosts: 16_777_214,
            limit: 65_536,
        })
        .into();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn resolver_error_target_not_allowed_maps_to_403() {
        use std::net::{IpAddr, Ipv4Addr};
        let err: AppError = RastreoError::Resolver(ResolverError::TargetNotAllowed {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        })
        .into();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert!(
            err.message.contains("192.168.1.1"),
            "the 403 body names the offending IP: {}",
            err.message
        );
    }

    #[test]
    fn resolver_error_aggregate_host_cap_exceeded_maps_to_400() {
        let err: AppError = RastreoError::Resolver(ResolverError::AggregateHostCapExceeded {
            hosts: 300_000,
            limit: 262_144,
        })
        .into();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn resolver_error_invalid_range_maps_to_400() {
        let err: AppError = RastreoError::Resolver(ResolverError::InvalidRange {
            start: "10.0.0.10".into(),
            end: "10.0.0.5".into(),
        })
        .into();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn resolver_error_range_too_large_maps_to_400() {
        let err: AppError = RastreoError::Resolver(ResolverError::RangeTooLarge {
            start: "10.0.0.0".into(),
            end: "10.255.255.255".into(),
            hosts: 16_777_216,
            limit: 65_536,
        })
        .into();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn resolver_error_mixed_family_range_maps_to_400() {
        let err: AppError = RastreoError::Resolver(ResolverError::MixedFamilyRange {
            start: "10.0.0.0".into(),
            end: "::1".into(),
        })
        .into();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn probe_error_maps_to_500() {
        let err: AppError =
            RastreoError::Probe(ProbeError::Other("snmp probe failed on port 161".into())).into();
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn encoder_error_maps_to_500() {
        let err: AppError = RastreoError::Encoder(EncoderError::NotSupported("nope".into())).into();
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn runtime_error_maps_to_500() {
        let err: AppError = RastreoError::Runtime(RuntimeError::TaskPanicked("p".into())).into();
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn sink_error_maps_to_500_with_a_redacted_body() {
        use rastreo_core::{SinkError, SinkErrorClass};
        let io = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe");
        let err: AppError =
            RastreoError::Sink(SinkError::new(SinkErrorClass::WriteFailure, io)).into();
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.message, "internal server error");
    }

    #[test]
    fn app_error_for_runtime_panic_does_not_leak_panic_message() {
        let err: AppError = RastreoError::Runtime(RuntimeError::TaskPanicked(
            "worker thread panicked at src/foo.rs:42".into(),
        ))
        .into();
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.message, "internal server error");
        assert!(!err.message.contains("worker thread"));
        assert!(!err.message.contains("src/foo.rs"));
    }

    #[test]
    fn app_error_for_4xx_preserves_message_detail() {
        let err: AppError = RastreoError::Config(ConfigError::InvalidValue(
            "max_concurrent must be positive".into(),
        ))
        .into();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("max_concurrent"));
        assert!(err.message.contains("must be positive"));
    }

    #[test]
    fn unauthorized_maps_to_401() {
        let err = AppError::unauthorized("missing or invalid bearer token");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.message, "missing or invalid bearer token");
    }

    #[test]
    fn too_many_requests_maps_to_429() {
        let err = AppError::too_many_requests("inflight scan limit reached");
        assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(err.message, "inflight scan limit reached");
    }

    fn sink_failure(detail: &str) -> RastreoError {
        use rastreo_core::{SinkError, SinkErrorClass};
        RastreoError::Sink(SinkError::new(
            SinkErrorClass::PublishFailure,
            std::io::Error::other(detail.to_string()),
        ))
    }

    #[test]
    fn a_5xx_for_an_authenticated_caller_carries_the_cause_chain() {
        let err = sink_failure("authorization violation: nats: authorization violation");
        let message = response_message(&err, StatusCode::INTERNAL_SERVER_ERROR, true);
        assert!(
            message.contains("authorization violation: nats: authorization violation"),
            "the disclosed body must reach the cause, not stop at the umbrella: {message}"
        );
    }

    #[test]
    fn a_5xx_for_an_unauthenticated_caller_is_redacted() {
        let err = sink_failure("authorization violation");
        let message = response_message(&err, StatusCode::INTERNAL_SERVER_ERROR, false);
        assert_eq!(message, REDACTED_SERVER_ERROR);
    }

    #[test]
    fn a_4xx_body_does_not_change_with_disclosure() {
        let err = RastreoError::Config(ConfigError::InvalidValue("max_concurrent".into()));
        assert_eq!(
            response_message(&err, StatusCode::BAD_REQUEST, true),
            response_message(&err, StatusCode::BAD_REQUEST, false)
        );
        assert!(response_message(&err, StatusCode::BAD_REQUEST, false).contains("max_concurrent"));
    }

    #[derive(Debug)]
    struct Cause;

    impl std::fmt::Display for Cause {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("the cause")
        }
    }

    impl std::error::Error for Cause {}

    #[derive(Debug)]
    struct Wrapper(Cause);

    impl std::fmt::Display for Wrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("the wrapper")
        }
    }

    impl std::error::Error for Wrapper {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn a_4xx_body_never_grows_a_cause_chain_for_an_authenticated_caller() {
        assert_eq!(
            response_message(&Wrapper(Cause), StatusCode::BAD_REQUEST, true),
            "the wrapper"
        );
    }

    #[test]
    fn a_disclosed_5xx_body_appends_every_cause() {
        assert_eq!(
            response_message(&Wrapper(Cause), StatusCode::INTERNAL_SERVER_ERROR, true),
            "the wrapper: the cause"
        );
    }

    #[test]
    fn from_rastreo_with_the_default_disclosure_redacts() {
        let err =
            AppError::from_rastreo(sink_failure("broker refused"), ErrorDisclosure::default());
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.message, REDACTED_SERVER_ERROR);
        assert!(!err.message.contains("broker refused"));
    }

    #[test]
    fn error_chain_of_a_sourceless_error_is_its_display() {
        let err = RastreoError::Config(ConfigError::InvalidValue("bad".into()));
        assert_eq!(error_chain(&err), err.to_string());
    }

    #[tokio::test]
    async fn into_response_serializes_error_body() {
        use axum::body::to_bytes;

        let err = AppError::bad_request("targets must not be empty");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body_bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("collect body");
        let value: serde_json::Value =
            serde_json::from_slice(&body_bytes).expect("parse body json");
        assert_eq!(value["error"], "targets must not be empty");
    }
}
