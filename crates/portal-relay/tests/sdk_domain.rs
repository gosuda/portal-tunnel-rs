//! Integration tests for `GET /v1/sdk/domain`.
//!
//! Exercise the handler via `tower::ServiceExt::oneshot` against the
//! `build_sdk_router` output. Pins the four S4 acceptance criteria:
//!
//! 1. `GET /v1/sdk/domain` returns 200 with body
//!    `{"data":{"protocol_version":"<v>","release_version":"<v>"}}`
//!    where `<v>` = `env!("CARGO_PKG_VERSION")`.
//! 2. Response carries `Access-Control-Allow-Origin: *` per Go upstream
//!    (`portal-tunnel/portal/api_server.go:238`).
//! 3. Other methods (POST, DELETE) return 405 (axum default for an
//!    unmatched method on a matched path; no handler-side enforcement).
//! 4. Workspace gates clean (asserted via `cargo xtask ci` outside this
//!    file).

#![expect(
    clippy::expect_used,
    reason = "test-only setup; integration test crate"
)]

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use portal_relay::api::{SdkState, build_sdk_router};
use portal_relay::policy::{PolicyRuntime, ReputationEngine};
use portal_relay::state::LeaseRegistry;
use tower::ServiceExt as _;

/// Build a default `SdkState` with no ENS resolver — the
/// `/v1/sdk/domain` handler does not consult any field of `SdkState`,
/// so the cheapest valid construction is sufficient. A future handler
/// that DOES read state will need a richer fixture; that lands with
/// the consuming slice.
fn default_sdk_state() -> SdkState {
    SdkState {
        leases: LeaseRegistry::new(),
        policy: Arc::new(PolicyRuntime::new()),
        engine: ReputationEngine::new(),
        ens_resolver: None,
    }
}

/// Issue a request against the SDK router and return the
/// `(status, headers, body_bytes)` triple. Centralizing the oneshot
/// shape keeps each acceptance test focused on its assertion rather
/// than the boilerplate of `Router::oneshot`.
async fn request_domain(method: Method) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let router = build_sdk_router(default_sdk_state());
    let request = Request::builder()
        .method(method)
        .uri("/v1/sdk/domain")
        .body(Body::empty())
        .expect("request build");
    let response = router.oneshot(request).await.expect("oneshot service");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body collect")
        .to_vec();
    (status, headers, bytes)
}

/// Acceptance criterion 1: 200 + envelope shape.
///
/// `CARGO_PKG_VERSION` is read from the test crate's compile env;
/// integration tests share the parent crate's `Cargo.toml`, so the
/// version pin tracks the parent `portal-relay` crate without a hand-
/// edit on every version bump.
#[tokio::test]
async fn domain_endpoint_returns_200_with_version_envelope() {
    let (status, _headers, bytes) = request_domain(Method::GET).await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("response is JSON");
    assert_eq!(
        json,
        serde_json::json!({
            "data": {
                "protocol_version": env!("CARGO_PKG_VERSION"),
                "release_version": env!("CARGO_PKG_VERSION"),
            }
        }),
        "domain envelope must be \
         {{data: {{protocol_version, release_version}} = CARGO_PKG_VERSION}}",
    );
}

/// Acceptance criterion 2: CORS header on the success response.
///
/// Go upstream (`portal-tunnel/portal/api_server.go:238`) sets
/// `Access-Control-Allow-Origin: *` so the SDK can fetch the domain
/// surface from a browser context. The Rust port mirrors that header
/// exactly.
#[tokio::test]
async fn domain_endpoint_sets_cors_allow_origin_star() {
    let (status, headers, _bytes) = request_domain(Method::GET).await;

    assert_eq!(status, StatusCode::OK);
    let value = headers
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .expect("Access-Control-Allow-Origin header present");
    assert_eq!(
        value.to_str().expect("CORS header is ASCII"),
        "*",
        "CORS Allow-Origin must be `*` per Go upstream parity",
    );
}

/// Acceptance criterion 3a: non-GET methods (here, POST) hit axum's
/// default 405 path. The `/v1/sdk/domain` route is registered with
/// `get(...)` only, so a POST to the same path resolves the method-
/// router but no method handler matches.
#[tokio::test]
async fn domain_endpoint_rejects_post_with_method_not_allowed() {
    let (status, _headers, _bytes) = request_domain(Method::POST).await;
    assert_eq!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "POST /v1/sdk/domain must surface 405 from axum's default \
         method-not-allowed path; no handler-side enforcement",
    );
}

/// Acceptance criterion 3b: same as 3a, with DELETE. Pinning two
/// methods rather than one guards against a future regression where
/// the route accidentally registered as `any(...)` instead of
/// `get(...)` — a single-method test would not catch that.
#[tokio::test]
async fn domain_endpoint_rejects_delete_with_method_not_allowed() {
    let (status, _headers, _bytes) = request_domain(Method::DELETE).await;
    assert_eq!(
        status,
        StatusCode::METHOD_NOT_ALLOWED,
        "DELETE /v1/sdk/domain must surface 405 from axum's default \
         method-not-allowed path",
    );
}
