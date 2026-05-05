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

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use compact_str::CompactString;
use portal_relay::api::{AdminState, build_admin_router};
use portal_relay::policy::PolicyRuntime;
use portal_relay::state::LeaseRegistry;
use portal_relay::{RelayServerConfig, ReloadHandle, RuntimeConfig};
use tower::ServiceExt as _;

/// Build a deterministic bootstrap config for the handle.
fn baseline_bootstrap() -> RelayServerConfig {
    RelayServerConfig::new(
        CompactString::const_new("test-relay"),
        PathBuf::from("/var/lib/portal/relay"),
        PathBuf::from("/etc/portal/api.key"),
        PathBuf::from("/etc/portal/keyless.key"),
        PathBuf::from("/etc/portal/quic.key"),
    )
}

/// Build an `AdminState` carrying the supplied (optional) reload handle.
fn admin_state_with(reload: Option<Arc<ReloadHandle>>) -> AdminState {
    AdminState {
        leases: LeaseRegistry::new(),
        policy: Arc::new(PolicyRuntime::new()),
        reload,
    }
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
    let handle = Arc::new(ReloadHandle::new(
        baseline_bootstrap(),
        RuntimeConfig::default(),
    ));
    let state = admin_state_with(Some(Arc::clone(&handle)));

    let (status, bytes) = post_reload(state, "{ malformed json").await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("response is JSON");
    assert_eq!(
        json["error"]["code"], "invalid_request",
        "bad JSON must surface invalid_request",
    );

    // Sanity: the runtime config must not have been touched.
    assert_eq!(handle.current().bps_per_identity, 0);
}

/// Unknown field → 400 `invalid_request` (per iter-124's
/// `deny_unknown_fields`). Confirms the deny path runs through the
/// handler's `JsonRejection` mapping.
#[tokio::test]
async fn reload_endpoint_returns_invalid_request_for_unknown_field() {
    let handle = Arc::new(ReloadHandle::new(
        baseline_bootstrap(),
        RuntimeConfig::default(),
    ));
    let state = admin_state_with(Some(Arc::clone(&handle)));

    let (status, bytes) = post_reload(state, r#"{"bps_per_idenity": 4096}"#).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("response is JSON");
    assert_eq!(
        json["error"]["code"], "invalid_request",
        "unknown-field payload must surface invalid_request",
    );

    // Sanity: the runtime config must not have been touched.
    assert_eq!(handle.current().bps_per_identity, 0);
}
