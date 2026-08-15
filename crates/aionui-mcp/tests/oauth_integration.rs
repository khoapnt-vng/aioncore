//! Integration tests for McpOAuthService with real SQLite.
//!
//! Tests from test-plan §4 (OAuth) at the service layer.
//! These tests exercise check_status, logout, get_authenticated_servers,
//! and get_token with a real DB. The full login flow (browser + callback)
//! cannot be tested end-to-end here; it requires a mock OAuth server.

use std::sync::Arc;

use aionui_db::{IOAuthTokenRepository, SqliteOAuthTokenRepository, UpsertOAuthTokenParams};
use aionui_mcp::McpOAuthService;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn make_service() -> (McpOAuthService, Arc<dyn IOAuthTokenRepository>) {
    let db = aionui_db::init_database_memory().await.unwrap();
    let repo: Arc<dyn IOAuthTokenRepository> = Arc::new(SqliteOAuthTokenRepository::new(db.pool().clone()));
    let svc = McpOAuthService::new(repo.clone(), reqwest::Client::new());
    // Keep db alive by leaking it (integration test only).
    std::mem::forget(db);
    (svc, repo)
}

async fn mount_oauth_metadata(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "authorization_endpoint": format!("{}/authorize", server.uri()),
            "token_endpoint": format!("{}/token", server.uri())
        })))
        .mount(server)
        .await;
}

// ---------------------------------------------------------------------------
// OA-1: Unauthenticated server returns false
// ---------------------------------------------------------------------------

#[tokio::test]
async fn check_status_unauthenticated_returns_false() {
    let (svc, _repo) = make_service().await;
    let status = svc.check_oauth_status("https://new-server.example.com").await.unwrap();
    assert!(!status.authenticated);
}

// ---------------------------------------------------------------------------
// OA-2: Authenticated server returns true
// ---------------------------------------------------------------------------

#[tokio::test]
async fn check_status_authenticated_returns_true() {
    let (svc, repo) = make_service().await;

    // Seed a valid token.
    repo.upsert(UpsertOAuthTokenParams {
        server_url: "https://mcp.example.com",
        access_token: "access_123",
        refresh_token: Some("refresh_456"),
        client_id: None,
        token_type: "bearer",
        // Expires in the far future.
        expires_at: Some(aionui_common::now_ms() + 3_600_000),
    })
    .await
    .unwrap();

    let status = svc.check_oauth_status("https://mcp.example.com").await.unwrap();
    assert!(status.authenticated);
}

// ---------------------------------------------------------------------------
// OA-2b: Expired token treated as unauthenticated
// ---------------------------------------------------------------------------

#[tokio::test]
async fn check_status_expired_token_returns_false() {
    let (svc, repo) = make_service().await;

    repo.upsert(UpsertOAuthTokenParams {
        server_url: "https://expired.example.com",
        access_token: "old_token",
        refresh_token: None,
        client_id: None,
        token_type: "bearer",
        // Already expired.
        expires_at: Some(1000),
    })
    .await
    .unwrap();

    let status = svc.check_oauth_status("https://expired.example.com").await.unwrap();
    assert!(!status.authenticated);
}

// ---------------------------------------------------------------------------
// OA-2c: Token with no expiry treated as valid
// ---------------------------------------------------------------------------

#[tokio::test]
async fn check_status_no_expiry_treated_as_valid() {
    let (svc, repo) = make_service().await;

    repo.upsert(UpsertOAuthTokenParams {
        server_url: "https://no-expiry.example.com",
        access_token: "no_exp_token",
        refresh_token: None,
        client_id: None,
        token_type: "bearer",
        expires_at: None,
    })
    .await
    .unwrap();

    let status = svc.check_oauth_status("https://no-expiry.example.com").await.unwrap();
    assert!(status.authenticated);
}

// ---------------------------------------------------------------------------
// OA-3: Get all authenticated URLs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_authenticated_servers_returns_all_urls() {
    let (svc, repo) = make_service().await;

    repo.upsert(UpsertOAuthTokenParams {
        server_url: "https://a.example.com",
        access_token: "tok_a",
        refresh_token: None,
        client_id: None,
        token_type: "bearer",
        expires_at: None,
    })
    .await
    .unwrap();

    repo.upsert(UpsertOAuthTokenParams {
        server_url: "https://b.example.com",
        access_token: "tok_b",
        refresh_token: None,
        client_id: None,
        token_type: "bearer",
        expires_at: None,
    })
    .await
    .unwrap();

    let urls = svc.get_authenticated_servers().await.unwrap();
    assert_eq!(urls.len(), 2);
    assert!(urls.contains(&"https://a.example.com".to_string()));
    assert!(urls.contains(&"https://b.example.com".to_string()));
}

#[tokio::test]
async fn get_authenticated_servers_empty_when_no_tokens() {
    let (svc, _repo) = make_service().await;
    let urls = svc.get_authenticated_servers().await.unwrap();
    assert!(urls.is_empty());
}

// ---------------------------------------------------------------------------
// OA-5: Login with invalid URL (no OAuth endpoints discoverable)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_invalid_url_returns_error() {
    let (svc, _repo) = make_service().await;
    // This URL won't have .well-known endpoints.
    let result = svc.login("https://127.0.0.1:1").await;
    // Discovery failure is surfaced as a structured `Ok { success: false, error }`
    // (not a bare `Err`/500) so the UI can show what went wrong.
    let resp = result.expect("login returns Ok with a structured failure payload");
    assert!(!resp.success);
    assert!(resp.error.is_some());
}

// ---------------------------------------------------------------------------
// OA-6: Logout deletes stored token
// ---------------------------------------------------------------------------

#[tokio::test]
async fn logout_deletes_stored_token() {
    let (svc, repo) = make_service().await;

    repo.upsert(UpsertOAuthTokenParams {
        server_url: "https://logout.example.com",
        access_token: "to_delete",
        refresh_token: None,
        client_id: None,
        token_type: "bearer",
        expires_at: None,
    })
    .await
    .unwrap();

    // Verify token exists.
    let status = svc.check_oauth_status("https://logout.example.com").await.unwrap();
    assert!(status.authenticated);

    // Logout.
    svc.logout("https://logout.example.com").await.unwrap();

    // Verify token is gone.
    let status = svc.check_oauth_status("https://logout.example.com").await.unwrap();
    assert!(!status.authenticated);
}

// ---------------------------------------------------------------------------
// OA-7: Logout is idempotent for non-authenticated URL
// ---------------------------------------------------------------------------

#[tokio::test]
async fn logout_idempotent_for_unauthenticated() {
    let (svc, _repo) = make_service().await;
    // Should not error.
    svc.logout("https://never-authed.example.com").await.unwrap();
}

// ---------------------------------------------------------------------------
// get_token tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_token_returns_none_for_unknown_url() {
    let (svc, _repo) = make_service().await;
    let token = svc.get_token("https://unknown.example.com").await.unwrap();
    assert!(token.is_none());
}

#[tokio::test]
async fn get_token_returns_access_token_when_valid() {
    let (svc, repo) = make_service().await;

    repo.upsert(UpsertOAuthTokenParams {
        server_url: "https://valid.example.com",
        access_token: "my_access_token",
        refresh_token: None,
        client_id: None,
        token_type: "bearer",
        expires_at: Some(aionui_common::now_ms() + 3_600_000),
    })
    .await
    .unwrap();

    let token = svc.get_token("https://valid.example.com").await.unwrap();
    assert_eq!(token.as_deref(), Some("my_access_token"));
}

#[tokio::test]
async fn expired_token_refresh_uses_persisted_dynamic_client_and_stores_new_grant() {
    let server = MockServer::start().await;
    mount_oauth_metadata(&server).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("refresh_token=old_refresh"))
        .and(body_string_contains("client_id=dynamic-client"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "new_access",
            "refresh_token": "new_refresh",
            "token_type": "bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;

    let (svc, repo) = make_service().await;
    let server_url = server.uri();
    repo.upsert(UpsertOAuthTokenParams {
        server_url: &server_url,
        access_token: "expired_access",
        refresh_token: Some("old_refresh"),
        client_id: Some("dynamic-client"),
        token_type: "bearer",
        expires_at: Some(1000),
    })
    .await
    .unwrap();

    let token = svc.get_token(&server_url).await.unwrap();
    assert_eq!(token.as_deref(), Some("new_access"));

    let stored = repo.get_by_url(&server_url).await.unwrap().unwrap();
    assert_eq!(stored.access_token, "new_access");
    assert_eq!(stored.refresh_token.as_deref(), Some("new_refresh"));
    assert_eq!(stored.client_id.as_deref(), Some("dynamic-client"));
    server.verify().await;
}

#[tokio::test]
async fn get_token_requires_reauthentication_when_expired_without_refresh_token() {
    let (svc, repo) = make_service().await;

    repo.upsert(UpsertOAuthTokenParams {
        server_url: "https://expired.example.com",
        access_token: "old_access",
        refresh_token: None,
        client_id: None,
        token_type: "bearer",
        expires_at: Some(1000),
    })
    .await
    .unwrap();

    let token = svc.get_token("https://expired.example.com").await.unwrap();
    assert_eq!(token, None);
}

#[tokio::test]
async fn expired_legacy_token_without_client_id_requires_reauthentication_without_refresh_request() {
    let server = MockServer::start().await;
    mount_oauth_metadata(&server).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "must_not_be_used",
            "token_type": "bearer"
        })))
        .expect(0)
        .mount(&server)
        .await;

    let (svc, repo) = make_service().await;
    let server_url = server.uri();
    repo.upsert(UpsertOAuthTokenParams {
        server_url: &server_url,
        access_token: "legacy_expired_access",
        refresh_token: Some("legacy_refresh"),
        client_id: None,
        token_type: "bearer",
        expires_at: Some(1000),
    })
    .await
    .unwrap();

    let token = svc.get_token(&server_url).await.unwrap();
    assert_eq!(token, None);
    server.verify().await;
}

#[tokio::test]
async fn refresh_http_failure_requires_reauthentication_without_returning_stale_token() {
    let server = MockServer::start().await;
    mount_oauth_metadata(&server).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("client_id=dynamic-client"))
        .respond_with(ResponseTemplate::new(503).set_body_string("temporary outage"))
        .expect(1)
        .mount(&server)
        .await;

    let (svc, repo) = make_service().await;
    let server_url = server.uri();
    repo.upsert(UpsertOAuthTokenParams {
        server_url: &server_url,
        access_token: "stale_access_must_not_escape",
        refresh_token: Some("refresh-token"),
        client_id: Some("dynamic-client"),
        token_type: "bearer",
        expires_at: Some(1000),
    })
    .await
    .unwrap();

    let token = svc.get_token(&server_url).await.unwrap();
    assert_eq!(token, None);
    assert_eq!(
        repo.get_by_url(&server_url).await.unwrap().unwrap().access_token,
        "stale_access_must_not_escape"
    );
    server.verify().await;
}

#[tokio::test]
async fn malformed_refresh_response_requires_reauthentication_without_returning_stale_token() {
    let server = MockServer::start().await;
    mount_oauth_metadata(&server).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
        .expect(1)
        .mount(&server)
        .await;

    let (svc, repo) = make_service().await;
    let server_url = server.uri();
    repo.upsert(UpsertOAuthTokenParams {
        server_url: &server_url,
        access_token: "stale_access_must_not_escape",
        refresh_token: Some("refresh-token"),
        client_id: Some("dynamic-client"),
        token_type: "bearer",
        expires_at: Some(1000),
    })
    .await
    .unwrap();

    assert_eq!(svc.get_token(&server_url).await.unwrap(), None);
    server.verify().await;
}

#[tokio::test]
async fn successful_reauthentication_restores_bearer_injection() {
    let (svc, repo) = make_service().await;
    let server_url = "https://reauth.example.com";
    repo.upsert(UpsertOAuthTokenParams {
        server_url,
        access_token: "legacy_expired_access",
        refresh_token: Some("legacy_refresh"),
        client_id: None,
        token_type: "bearer",
        expires_at: Some(1000),
    })
    .await
    .unwrap();

    assert_eq!(svc.bearer_for(server_url).await, None);

    repo.upsert(UpsertOAuthTokenParams {
        server_url,
        access_token: "reauthorized_access",
        refresh_token: Some("reauthorized_refresh"),
        client_id: Some("new-dynamic-client"),
        token_type: "bearer",
        expires_at: Some(aionui_common::now_ms() + 3_600_000),
    })
    .await
    .unwrap();

    assert_eq!(
        svc.bearer_for(server_url).await.as_deref(),
        Some("Bearer reauthorized_access")
    );
    assert_eq!(
        repo.get_by_url(server_url).await.unwrap().unwrap().client_id.as_deref(),
        Some("new-dynamic-client")
    );
}

#[tokio::test]
async fn get_token_returns_no_expiry_token() {
    let (svc, repo) = make_service().await;

    repo.upsert(UpsertOAuthTokenParams {
        server_url: "https://noexp.example.com",
        access_token: "forever_token",
        refresh_token: None,
        client_id: None,
        token_type: "bearer",
        expires_at: None,
    })
    .await
    .unwrap();

    let token = svc.get_token("https://noexp.example.com").await.unwrap();
    assert_eq!(token.as_deref(), Some("forever_token"));
}
