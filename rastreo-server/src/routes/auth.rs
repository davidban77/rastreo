use std::convert::Infallible;

use axum::extract::{FromRequestParts, Request, State};
use axum::http::header;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;

use crate::error::AppError;
use crate::state::{AppState, AuthConfig};

/// Proof the caller authenticated. Only [`require_bearer`] can build the disclosing value; the [`Default`] and the extractor on a route it does not cover withhold.
#[derive(Debug, Clone, Copy, Default)]
pub struct ErrorDisclosure {
    caller_authenticated: bool,
}

impl ErrorDisclosure {
    pub fn caller_authenticated(self) -> bool {
        self.caller_authenticated
    }
}

impl<S> FromRequestParts<S> for ErrorDisclosure
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(parts.extensions.get::<Self>().copied().unwrap_or_default())
    }
}

pub async fn require_bearer(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let AuthConfig::Enabled { token } = &state.auth else {
        return next.run(request).await;
    };

    let authenticated = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        // Constant-time compare on purpose: `==` would leak the shared secret via timing.
        .is_some_and(|candidate| bool::from(candidate.as_bytes().ct_eq(token.as_bytes())));

    if !authenticated {
        return unauthorized();
    }

    request.extensions_mut().insert(ErrorDisclosure {
        caller_authenticated: true,
    });
    next.run(request).await
}

fn unauthorized() -> Response {
    let mut response = AppError::unauthorized("missing or invalid bearer token").into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static("Bearer"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::http::StatusCode;
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;
    use axum::Router;
    use rastreo_core::{HickoryResolver, Resolver};
    use tower::ServiceExt;

    const TOKEN: &str = "unit-test-token";

    async fn report_disclosure(disclosure: ErrorDisclosure) -> String {
        disclosure.caller_authenticated().to_string()
    }

    fn guarded_app(auth: AuthConfig) -> Router {
        let resolver: Arc<dyn Resolver> =
            Arc::new(HickoryResolver::from_system().expect("system resolver"));
        let state = AppState::new(resolver).with_auth(auth);
        Router::new()
            .route("/guarded", get(report_disclosure))
            .route_layer(from_fn_with_state(state.clone(), require_bearer))
            .with_state(state)
    }

    fn open_app() -> Router {
        let resolver: Arc<dyn Resolver> =
            Arc::new(HickoryResolver::from_system().expect("system resolver"));
        let state = AppState::new(resolver).with_auth(AuthConfig::Enabled {
            token: TOKEN.to_string(),
        });
        Router::new()
            .route("/open", get(report_disclosure))
            .with_state(state)
    }

    async fn get_body(app: Router, path: &str, bearer: Option<&str>) -> (StatusCode, String) {
        let mut request = axum::http::Request::builder().uri(path);
        if let Some(token) = bearer {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let response = app
            .oneshot(request.body(Body::empty()).expect("build request"))
            .await
            .expect("route the request");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("collect body");
        (
            status,
            String::from_utf8(bytes.to_vec()).expect("utf8 body"),
        )
    }

    fn enabled() -> AuthConfig {
        AuthConfig::Enabled {
            token: TOKEN.to_string(),
        }
    }

    #[test]
    fn default_disclosure_withholds() {
        assert!(!ErrorDisclosure::default().caller_authenticated());
    }

    #[tokio::test]
    async fn valid_token_reaches_the_handler_with_a_disclosing_value() {
        let (status, body) = get_body(guarded_app(enabled()), "/guarded", Some(TOKEN)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "true");
    }

    #[tokio::test]
    async fn auth_disabled_reaches_the_handler_with_a_withholding_value() {
        let (status, body) = get_body(guarded_app(AuthConfig::Disabled), "/guarded", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "false");
    }

    #[tokio::test]
    async fn wrong_token_never_reaches_the_handler() {
        let (status, _) = get_body(guarded_app(enabled()), "/guarded", Some("wrong")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_route_outside_the_middleware_withholds_though_auth_is_enabled() {
        let (status, body) = get_body(open_app(), "/open", Some(TOKEN)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body, "false",
            "auth being enabled is not proof that this caller authenticated"
        );
    }
}
