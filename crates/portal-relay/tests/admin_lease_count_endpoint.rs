//! Integration tests for `GET /v1/admin/lease/count`.
//!
//! Pin: lock-free lease count via `LeaseRegistry::lease_count`.
//! Empty registry → `count: 0`; populated registry → matching
//! count. Returns 200 OK regardless of reload-handle attachment —
//! the lease registry is independent of the runtime config surface.

#![expect(
    clippy::expect_used,
    reason = "test-only setup; integration test crate"
)]

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use jiff::Timestamp;
use portal_relay::api::{AdminState, build_admin_router};
use portal_relay::policy::PolicyRuntime;
use portal_relay::state::{IdentityKey, LeaseRecord, LeaseRegistry};
use tower::ServiceExt as _;

mod common;

/// GET the lease-count endpoint and return the
/// `(status, body_bytes)` pair.
async fn get_lease_count(state: AdminState) -> (StatusCode, Vec<u8>) {
    let router = build_admin_router(state);
    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/admin/lease/count")
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

fn admin_state_with_leases(leases: LeaseRegistry) -> AdminState {
    AdminState {
        leases,
        policy: Arc::new(PolicyRuntime::new()),
        reload: None,
    }
}

#[tokio::test]
async fn lease_count_returns_zero_for_empty_registry() {
    let state = admin_state_with_leases(LeaseRegistry::new());
    let (status, bytes) = get_lease_count(state).await;
    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("response is JSON");
    assert_eq!(
        json,
        serde_json::json!({"data": {"count": 0}}),
        "empty registry must surface count: 0",
    );
}

#[tokio::test]
async fn lease_count_returns_registered_count() {
    let leases = LeaseRegistry::new();
    let now = Timestamp::now();
    let later = now
        .saturating_add(jiff::SignedDuration::from_secs(3600))
        .unwrap_or(Timestamp::MAX);
    let rec = LeaseRecord::new(
        IdentityKey([7u8; 32]),
        "test.example.relay".into(),
        Vec::new(),
        later,
        now,
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    );
    leases.register(rec).await.expect("register lease");
    let state = admin_state_with_leases(leases);
    let (status, bytes) = get_lease_count(state).await;
    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("response is JSON");
    assert_eq!(
        json,
        serde_json::json!({"data": {"count": 1}}),
        "single registered lease must surface count: 1",
    );
}
