use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rastreo_core::{RastreoError, ResolverError};
use serde::Serialize;

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

// Map client-supplied input errors to 4xx; everything internal to 500.
impl From<RastreoError> for AppError {
    fn from(err: RastreoError) -> Self {
        let status = match &err {
            RastreoError::Config(_) => StatusCode::BAD_REQUEST,
            RastreoError::Resolver(inner) => match inner {
                ResolverError::DnsLookupFailed { .. } => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::BAD_REQUEST,
            },
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self {
            status,
            message: err.to_string(),
        }
    }
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
        let err: AppError = RastreoError::Probe(ProbeError::Timeout { timeout_ms: 500 }).into();
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
    fn sink_error_maps_to_500() {
        let io = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe");
        let err: AppError = RastreoError::Sink(io).into();
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
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
