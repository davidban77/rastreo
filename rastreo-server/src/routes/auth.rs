use axum::extract::{Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;

use crate::error::AppError;
use crate::state::{AppState, AuthConfig};

pub async fn require_bearer(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let AuthConfig::Enabled { token } = &state.auth else {
        return next.run(request).await;
    };

    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    match presented {
        // Constant-time compare on purpose: `==` would leak the shared secret via timing.
        Some(candidate) if bool::from(candidate.as_bytes().ct_eq(token.as_bytes())) => {
            next.run(request).await
        }
        _ => unauthorized(),
    }
}

fn unauthorized() -> Response {
    let mut response = AppError::unauthorized("missing or invalid bearer token").into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static("Bearer"),
    );
    response
}
