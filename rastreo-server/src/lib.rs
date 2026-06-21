pub mod error;
pub mod routes;
pub mod state;

use std::time::Duration;

use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

pub fn build_app(state: AppState) -> Router {
    build_app_with_timeout(state, DEFAULT_REQUEST_TIMEOUT)
}

pub fn build_app_with_timeout(state: AppState, request_timeout: Duration) -> Router {
    Router::new()
        .route("/health", get(routes::health::health))
        .route("/scans", post(routes::scans::create_scan))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            request_timeout,
        ))
}
