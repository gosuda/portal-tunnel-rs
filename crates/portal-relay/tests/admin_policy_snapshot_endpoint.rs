//! Integration tests for `GET /v1/admin/policy/snapshot`.
//!
//! Pin: derived-policy observability via the
//! `PolicyRuntime::bps_cap_per_identity` + `ip_ban_count` getters.
//! No-handle path returns sentinel values (None / 0); attached-
//! handle path reflects the runtime snapshot.

#![expect(
    clippy::expect_used,
    reason = "test-only setup; integration test crate"
)]

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use portal_relay::api::{AdminState, build_admin_router};
use portal_relay::policy::PolicyRuntime;
use portal_relay::state::LeaseRegistry;
use portal_relay::{ReloadHandle, RuntimeConfig};
use tower::ServiceExt as _;

mod common;
use common::baseline_bootstrap;

/// GET the policy-snapshot endpoint and return the
/// `(status, body_bytes)` pair.
async fn get_policy_snapshot(state: AdminState) -> (StatusCode, Vec<u8>) {
    let router = build_admin_router(state);
    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/admin/policy/snapshot")
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

/// Build an `AdminState` with the supplied policy and no reload
/// handle on the `AdminState` itself (only via the policy's attached
/// handle if present). The endpoint reads through `state.policy`,
/// not `state.reload`, so this isolates the policy-getter path from
/// the reload-handle path that other admin endpoints exercise.
fn admin_state_with_policy(policy: PolicyRuntime) -> AdminState {
    AdminState {
        leases: LeaseRegistry::new(),
        policy: Arc::new(policy),
        reload: None,
    }
}

/// Sentinel-value path: a brand-new `PolicyRuntime` with no
/// attached reload handle yields `bps_cap_per_identity: null` and
/// `ip_ban_count: 0`. The endpoint returns 200 OK regardless —
/// liveness for the policy-snapshot surface mirrors the health
/// endpoint's contract: 200 always.
#[tokio::test]
async fn policy_snapshot_returns_sentinels_without_reload_handle() {
    let policy = PolicyRuntime::new();
    let state = admin_state_with_policy(policy);
    let (status, bytes) = get_policy_snapshot(state).await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("response is JSON");
    assert_eq!(
        json,
        serde_json::json!({
            "data": {
                "bps_cap_per_identity": null,
                "ip_ban_count": 0,
            }
        }),
        "no-handle path must surface sentinel values, not 503",
    );
}

/// Attached-handle path: a `PolicyRuntime` with a reload handle
/// carrying a populated runtime config surfaces the cap + ban-list
/// length through the snapshot envelope.
#[tokio::test]
async fn policy_snapshot_reflects_attached_runtime() {
    let payload = r#"{"bps_per_identity": 2048, "ip_ban_list": ["10.0.0.1", "fe80::1"]}"#;
    let runtime: RuntimeConfig = serde_json::from_str(payload).expect("RuntimeConfig from JSON");
    let handle = Arc::new(ReloadHandle::new(baseline_bootstrap(), runtime));
    let policy = PolicyRuntime::new().with_reload_handle(Arc::clone(&handle));
    let state = admin_state_with_policy(policy);
    let (status, bytes) = get_policy_snapshot(state).await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("response is JSON");
    assert_eq!(
        json,
        serde_json::json!({
            "data": {
                "bps_cap_per_identity": 2048,
                "ip_ban_count": 2,
            }
        }),
        "attached-handle path must reflect both reload-snapshot fields",
    );
}
