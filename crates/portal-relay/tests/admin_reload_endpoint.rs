//! Integration tests for `POST /v1/admin/config/reload`.
//!
//! Exercise the handler via `tower::ServiceExt::oneshot` against the
//! `build_admin_router` output. Pin: happy path, missing-handle,
//! bad-JSON, unknown-field-rejection.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only setup; integration test crate"
)]

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use portal_relay::api::{AdminState, build_admin_router};
use portal_relay::{ReloadHandle, RuntimeConfig};
use tower::ServiceExt as _;

mod common;
use common::{admin_state_with, baseline_bootstrap};

/// Assert the entire runtime snapshot is byte-for-byte identical to
/// the supplied baseline. Names the invariant the reject paths rely
/// on: a 4xx response must not mutate ANY field of the runtime
/// snapshot, not just the most obvious one (`bps_per_identity`). The
/// full-struct comparison is load-bearing — a per-field check would
/// silently miss a future field added to `RuntimeConfig`.
fn assert_runtime_unchanged(handle: &ReloadHandle, baseline: &RuntimeConfig) {
    let snap = handle.current();
    assert_eq!(
        &*snap, baseline,
        "runtime snapshot must remain byte-identical to the captured baseline after a rejected request",
    );
}

/// POST a JSON body to the reload endpoint and return the
/// `(status, body_bytes)` pair.
async fn post_reload(state: AdminState, body: &'static str) -> (StatusCode, Vec<u8>) {
    let router = build_admin_router(state);
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/admin/config/reload")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("request build");
    let response = router.oneshot(request).await.expect("oneshot service");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body collect")
        .to_vec();
    (status, bytes)
}

/// Happy path: 200 + the reload swap is observable on the handle.
#[tokio::test]
async fn reload_endpoint_swaps_runtime_when_handle_attached() {
    let handle = Arc::new(ReloadHandle::new(
        baseline_bootstrap(),
        RuntimeConfig::default(),
    ));
    assert_eq!(handle.current().bps_per_identity, 0);

    let state = admin_state_with(Some(Arc::clone(&handle)));
    let (status, bytes) = post_reload(
        state,
        r#"{"bps_per_identity": 4096, "ip_ban_list": ["10.0.0.1"]}"#,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("response is JSON");
    assert_eq!(
        json,
        serde_json::json!({"data": {"accepted": true}}),
        "success envelope must be {{data: {{accepted: true}}}}",
    );

    let snap = handle.current();
    assert_eq!(snap.bps_per_identity, 4096);
    assert_eq!(snap.ip_ban_list.len(), 1);
    assert_eq!(
        snap.ip_ban_list[0],
        "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
}

/// `AdminState` carries `reload: None` → the handler must surface
/// `feature_unavailable` (503) without attempting any reload.
#[tokio::test]
async fn reload_endpoint_returns_feature_unavailable_when_no_handle() {
    let state = admin_state_with(None);
    let (status, bytes) = post_reload(state, r#"{"bps_per_identity": 1024}"#).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("response is JSON");
    assert_eq!(
        json["error"]["code"], "feature_unavailable",
        "missing-handle must surface feature_unavailable",
    );
}

/// Malformed JSON → 400 `invalid_request` via the custom rejection
/// handler. The body never reaches the reload handle.
#[tokio::test]
async fn reload_endpoint_returns_invalid_request_for_bad_json() {
    let baseline = RuntimeConfig::default();
    let handle = Arc::new(ReloadHandle::new(baseline_bootstrap(), baseline.clone()));
    let state = admin_state_with(Some(Arc::clone(&handle)));

    let (status, bytes) = post_reload(state, "{ malformed json").await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("response is JSON");
    assert_eq!(
        json["error"]["code"], "invalid_request",
        "bad JSON must surface invalid_request",
    );

    assert_runtime_unchanged(&handle, &baseline);
}

/// Unknown field → 400 `invalid_request` (per iter-124's
/// `deny_unknown_fields`). Confirms the deny path runs through the
/// handler's `JsonRejection` mapping.
#[tokio::test]
async fn reload_endpoint_returns_invalid_request_for_unknown_field() {
    let baseline = RuntimeConfig::default();
    let handle = Arc::new(ReloadHandle::new(baseline_bootstrap(), baseline.clone()));
    let state = admin_state_with(Some(Arc::clone(&handle)));

    let (status, bytes) = post_reload(state, r#"{"bps_per_idenity": 4096}"#).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("response is JSON");
    assert_eq!(
        json["error"]["code"], "invalid_request",
        "unknown-field payload must surface invalid_request",
    );

    assert_runtime_unchanged(&handle, &baseline);
}
