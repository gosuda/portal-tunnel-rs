//! Integration tests for `GET /v1/admin/health`.
//!
//! Exercise the handler via `tower::ServiceExt::oneshot` against the
//! `build_admin_router` output. Pin: 200 + body shape with crate
//! version, and the no-handle independence contract that distinguishes
//! `/health` from the iter-135 / iter-137 endpoints which DO route
//! through `AdminState.reload`.

#![expect(
    clippy::expect_used,
    reason = "test-only setup; integration test crate"
)]

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use portal_relay::api::{AdminState, build_admin_router};
use portal_relay::{ReloadHandle, RuntimeConfig};
use tower::ServiceExt as _;

mod common;
use common::{admin_state_with, baseline_bootstrap};

/// GET the health endpoint and return the `(status, body_bytes)` pair.
async fn get_health(state: AdminState) -> (StatusCode, Vec<u8>) {
    let router = build_admin_router(state);
    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/admin/health")
        .body(Body::empty())
        .expect("request build");
    let response = router.oneshot(request).await.expect("oneshot service");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body collect")
        .to_vec();
    (status, bytes)
}

/// Endpoint returns 200 with the `CARGO_PKG_VERSION` envelope. Pinned
/// against `env!("CARGO_PKG_VERSION")` from this test crate so the
/// expectation tracks future version bumps without a hand-edit; the
/// test crate's `CARGO_PKG_VERSION` matches the parent `portal-relay`
/// crate by virtue of sharing `Cargo.toml`.
///
/// State carries a real reload handle here so the body-shape assertion
/// is distinct from the no-handle independence contract pinned by
/// `health_endpoint_works_when_reload_handle_is_none`.
#[tokio::test]
async fn health_endpoint_returns_200_with_crate_version() {
    let handle = Arc::new(ReloadHandle::new(
        baseline_bootstrap(),
        RuntimeConfig::default(),
    ));
    let state = admin_state_with(Some(handle));
    let (status, bytes) = get_health(state).await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("response is JSON");
    assert_eq!(
        json,
        serde_json::json!({"data": {"version": env!("CARGO_PKG_VERSION")}}),
        "health envelope must be {{data: {{version: <CARGO_PKG_VERSION>}}}}",
    );
}

/// Explicit positive coverage of the no-handle path. The iter-135
/// reload endpoint and iter-137 current-config endpoint both surface
/// 503 `feature_unavailable` when `AdminState.reload` is `None`;
/// `/health` MUST NOT — the handler is stateless. A future refactor
/// that routed health through `AdminState.reload` would break this
/// test with a clear semantic message.
#[tokio::test]
async fn health_endpoint_works_when_reload_handle_is_none() {
    let state = admin_state_with(None);
    let (status, _bytes) = get_health(state).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "health must be 200, not 503; the endpoint is independent of AdminState.reload",
    );
}
