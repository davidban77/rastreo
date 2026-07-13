pub mod error;
#[cfg(feature = "otlp")]
pub mod observability;
pub mod routes;
pub mod sink_probe;
pub mod state;

use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use axum::Router;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

pub use sink_probe::spawn_sink_probe;

pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

pub fn build_app(state: AppState) -> Router {
    build_app_with_timeout(state, DEFAULT_REQUEST_TIMEOUT)
}

pub fn build_app_with_timeout(state: AppState, request_timeout: Duration) -> Router {
    let scans = Router::new()
        .route("/scans", post(routes::scans::create_scan))
        .route_layer(from_fn_with_state(
            state.clone(),
            routes::auth::require_bearer,
        ))
        .route_layer(DefaultBodyLimit::max(state.max_body_bytes));

    // Layer order matters: TraceLayer is added last so it wraps TimeoutLayer and logs timeouts.
    Router::new()
        .route("/health", get(routes::health::health))
        .route("/healthz", get(routes::health::healthz))
        .route("/readyz", get(routes::health::readyz))
        .route("/metrics", get(routes::metrics::get_metrics))
        .merge(scans)
        .with_state(state)
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            request_timeout,
        ))
        .layer(TraceLayer::new_for_http())
}
