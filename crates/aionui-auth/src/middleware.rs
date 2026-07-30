#![allow(clippy::disallowed_types)]

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use aionui_common::ApiError;
use aionui_db::IUserRepository;

use crate::JwtService;
use crate::extract::extract_token_from_headers;

/// Authenticated user injected into request extensions by the auth middleware.
///
/// Route handlers extract this from `request.extensions()` to identify
/// the current user.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    /// User ID from the database.
    pub id: String,
    /// Username.
    pub username: String,
}

/// Shared state for the authentication middleware.
#[derive(Clone)]
pub struct AuthState {
    pub jwt_service: Arc<JwtService>,
    pub user_repo: Arc<dyn IUserRepository>,
    /// When `true`, skip JWT verification and inject a fixed default user.
    pub local: bool,
    /// SECURITY (D-01): per-session loopback token required for local-mode requests.
    ///
    /// `Some(token)` → every local-mode request must present this exact token
    /// (constant-time compared) via `Authorization: Bearer` or the session cookie.
    /// This closes the no-auth hole where any other local process — or a browser
    /// CSRF drive-by against `127.0.0.1` — could act as `system_default_user`.
    /// Sending a bearer token also forces a CORS preflight, which the loopback-only
    /// CORS layer rejects, so cross-origin pages cannot forge authenticated calls.
    ///
    /// `None` → legacy open local mode. Reachable only when `AppServices` is built
    /// directly (tests / dev); the production server refuses to start local mode
    /// without a token (see `init_environment`).
    pub local_token: Option<Arc<str>>,
}

/// Constant-time byte-slice equality, so validating the loopback token does not
/// leak its contents through comparison timing. Returns `false` on length mismatch.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Authentication middleware that verifies JWT tokens and injects `CurrentUser`.
///
/// Flow:
/// 1. Extract bearer token from `Authorization` header or `aionui-session` cookie
/// 2. Verify JWT signature, expiration, and blacklist
/// 3. Look up user in the database to ensure they still exist
/// 4. Insert [`CurrentUser`] into request extensions
///
/// Returns HTTP 401 for authentication failures.
///
/// Use with `axum::middleware::from_fn_with_state`.
pub async fn auth_middleware(
    State(state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // In local mode, skip JWT verification and inject a fixed default user — but only
    // after proving possession of the per-session loopback token when one is configured
    // (SECURITY D-01). Without this, any local process or browser CSRF drive-by could act
    // as `system_default_user`.
    if state.local {
        if let Some(expected) = &state.local_token {
            let provided = extract_token_from_headers(request.headers())
                .ok_or_else(|| ApiError::Unauthorized("Authentication required".into()))?;
            if !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
                tracing::debug!("local token mismatch");
                return Err(ApiError::Unauthorized("Invalid local token".into()));
            }
        }
        request.extensions_mut().insert(CurrentUser {
            id: "system_default_user".to_string(),
            username: "system_default_user".to_string(),
        });
        return Ok(next.run(request).await);
    }

    let token = extract_token_from_headers(request.headers())
        .ok_or_else(|| ApiError::Unauthorized("Authentication required".into()))?;

    let payload = state.jwt_service.verify(&token).map_err(|e| {
        tracing::debug!("Token verification failed: {e}");
        ApiError::Unauthorized("Invalid or expired token".into())
    })?;

    let user = state
        .user_repo
        .find_by_id(&payload.user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "auth middleware user lookup failed");
            ApiError::Internal("Authentication service unavailable".into())
        })?
        .ok_or_else(|| ApiError::Unauthorized("Invalid authentication subject".into()))?;

    request.extensions_mut().insert(CurrentUser {
        id: user.id,
        username: user.username,
    });

    Ok(next.run(request).await)
}

/// Local-mode authentication middleware that skips JWT verification.
///
/// Injects a fixed `CurrentUser` with id and username `system_default_user`.
/// Used when the server runs as an embedded subprocess inside Electron.
pub async fn local_auth_middleware(mut request: Request, next: Next) -> Response {
    request.extensions_mut().insert(CurrentUser {
        id: "system_default_user".to_string(),
        username: "system_default_user".to_string(),
    });
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;

    async fn echo_user(request: Request<Body>) -> String {
        let user = request.extensions().get::<CurrentUser>().unwrap();
        format!("{}:{}", user.id, user.username)
    }

    #[tokio::test]
    async fn test_local_auth_middleware_injects_default_user() {
        let app = Router::new()
            .route("/test", get(echo_user))
            .route_layer(axum::middleware::from_fn(local_auth_middleware));

        let response = app
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "system_default_user:system_default_user"
        );
    }
}
