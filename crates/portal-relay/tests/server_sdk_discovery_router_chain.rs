//! Integration test pinning the orchestrator-to-handler chain for
//! the SDK trust-boundary router.
//!
//! `Server::with_components` → `Server::with_relay_protocol_key` →
//! `Server::sdk_router()` → handler.
//!
//! This test exercises the canonical orchestrator-to-router bridge
//! so a future refactor that breaks the `Server` → router bridge
//! cannot pass with the per-endpoint tests still green.
//!
//! The discovery router bridge is not tested here because v0.1
//! discovery has no routes; a meaningful integration test lands
//! alongside the first discovery handler.

#![expect(
    clippy::expect_used,
    reason = "test-only setup; integration test crate"
)]

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use portal_relay::Server;
use tower::ServiceExt as _;

/// Build a `Server` with the relay protocol key attached — the
/// canonical chain the bin crate's `serve` flow walks.
fn server_with_protocol_key() -> Server {
    let key = portal_crypto::ed25519_from_seed_for_test([0x22u8; 32]);
    Server::new()
        .with_reputation_engine(portal_relay::policy::ReputationEngine::new())
        .with_relay_protocol_key(key)
}

#[tokio::test]
async fn sdk_router_built_from_server_returns_domain_info() {
    let server = server_with_protocol_key();
    let router = server.sdk_router();
    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/sdk/domain")
        .body(Body::empty())
        .expect("request build");
    let response = router.oneshot(request).await.expect("oneshot service");

    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("response is JSON");
    assert!(
        json["data"]["protocol_version"].as_str().is_some(),
        "domain response must carry protocol_version"
    );
}
