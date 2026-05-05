//! Integration test pinning the iter-135 + iter-136 + iter-137
//! chain end-to-end:
//!
//! `Server::with_components` → `Server::with_reload_handle` →
//! `Server::admin_state()` → `build_admin_router` → handler.
//!
//! The single-endpoint test files (`admin_reload_endpoint.rs`,
//! `admin_get_current_config_endpoint.rs`) exercise each handler
//! against a hand-rolled `AdminState`. This file exercises the
//! orchestrator-built `AdminState` so a future refactor that
//! breaks the `Server` → `AdminState` bridge cannot pass with the
//! per-endpoint tests still green.

#![expect(
    clippy::expect_used,
    reason = "test-only setup; integration test crate"
)]

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use portal_relay::api::build_admin_router;
use portal_relay::{ReloadHandle, RuntimeConfig, Server};
use tower::ServiceExt as _;

mod common;
use common::baseline_bootstrap;

/// Build a `Server` with a freshly-constructed reload handle attached
/// — the canonical chain the bin crate's `serve` flow walks when a
/// `RelayConfigBundle` is loaded.
fn server_with_handle() -> (Server, Arc<ReloadHandle>) {
    let handle = Arc::new(ReloadHandle::new(
        baseline_bootstrap(),
        RuntimeConfig::default(),
    ));
    let server = Server::new().with_reload_handle(Arc::clone(&handle));
    (server, handle)
}

#[tokio::test]
async fn admin_router_built_from_server_handles_reload_post() {
    let (server, handle) = server_with_handle();
    assert_eq!(handle.current().bps_per_identity, 0);

    let router = build_admin_router(server.admin_state());
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/admin/config/reload")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"bps_per_identity": 8192}"#))
        .expect("request build");
    let response = router.oneshot(request).await.expect("oneshot service");

    assert_eq!(response.status(), StatusCode::OK);

    // The swap must be observable via the same handle the orchestrator
    // attached — proves Server::admin_state() did NOT clone-detach the
    // reload field into a new ArcSwap.
    assert_eq!(handle.current().bps_per_identity, 8192);
}

#[tokio::test]
async fn admin_router_built_from_server_handles_current_get() {
    let (server, handle) = server_with_handle();
    handle
        .reload(&handle.bootstrap(), {
            let payload = r#"{"bps_per_identity": 1024}"#;
            serde_json::from_str::<RuntimeConfig>(payload).expect("RuntimeConfig from JSON")
        })
        .expect("reload swap");

    let router = build_admin_router(server.admin_state());
    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/admin/config/current")
        .body(Body::empty())
        .expect("request build");
    let response = router.oneshot(request).await.expect("oneshot service");

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body collect");
    let body: serde_json::Value =
        serde_json::from_slice(&bytes).expect("response is JSON envelope");
    assert_eq!(
        body,
        serde_json::json!({"data": {"bps_per_identity": 1024, "ip_ban_list": []}}),
        "GET via Server::admin_state() must surface the swapped runtime",
    );
}

#[tokio::test]
async fn admin_router_built_from_default_server_returns_503_for_reload() {
    // Server::new() leaves reload as None — the orchestrator-level
    // contract for "bundle was not loaded". The admin router must then
    // surface 503 FeatureUnavailable on every endpoint that needs the
    // handle. Pins the negative half of the chain so a future change
    // that silently injects a default handle into Server::new() cannot
    // pass the chain tests.
    let server = Server::new();
    let router = build_admin_router(server.admin_state());
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/admin/config/reload")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"bps_per_identity": 1}"#))
        .expect("request build");
    let response = router.oneshot(request).await.expect("oneshot service");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}
