//! Integration tests for `GET /v1/admin/config/current`.
//!
//! Exercise the handler via `tower::ServiceExt::oneshot` against the
//! `build_admin_router` output. Pin: bootstrap-default snapshot,
//! post-swap snapshot, missing-handle.

#![expect(
    clippy::expect_used,
    reason = "test-only setup; integration test crate"
)]

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
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

/// GET the current-config endpoint and return the `(status, body_bytes)` pair.
async fn get_current(state: AdminState) -> (StatusCode, Vec<u8>) {
    let router = build_admin_router(state);
    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/admin/config/current")
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

/// Default `RuntimeConfig` is observable through the endpoint when no
/// swap has occurred yet — confirms the handler reads
/// `handle.current()` rather than a constructor-time captured value.
#[tokio::test]
async fn get_current_config_returns_bootstrap_default_when_no_swap_yet() {
    let handle = Arc::new(ReloadHandle::new(
        baseline_bootstrap(),
        RuntimeConfig::default(),
    ));
    let state = admin_state_with(Some(Arc::clone(&handle)));

    let (status, bytes) = get_current(state).await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("response is JSON");
    assert_eq!(
        json,
        serde_json::json!({"data": {"bps_per_identity": 0, "ip_ban_list": []}}),
        "default snapshot envelope must be {{data: {{bps_per_identity: 0, ip_ban_list: []}}}}",
    );
}

/// After a successful `handle.reload(...)`, the endpoint surfaces the
/// new snapshot — confirms the handler always loads the live
/// `arc_swap` pointer rather than a stale clone.
#[tokio::test]
async fn get_current_config_returns_post_swap_runtime() {
    let handle = Arc::new(ReloadHandle::new(
        baseline_bootstrap(),
        RuntimeConfig::default(),
    ));
    let bootstrap = handle.bootstrap();
    // `RuntimeConfig` is `#[non_exhaustive]` from this test crate's
    // perspective, so build the swap candidate via the deserialize
    // path operators use anyway.
    let swap: RuntimeConfig =
        serde_json::from_str(r#"{"bps_per_identity": 2048, "ip_ban_list": ["10.0.0.1"]}"#)
            .expect("runtime JSON parses");
    handle.reload(&bootstrap, swap).expect("reload accepted");

    let state = admin_state_with(Some(Arc::clone(&handle)));
    let (status, bytes) = get_current(state).await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("response is JSON");
    assert_eq!(
        json,
        serde_json::json!({"data": {"bps_per_identity": 2048, "ip_ban_list": ["10.0.0.1"]}}),
        "post-swap envelope must reflect the swapped runtime fields",
    );
}

/// `AdminState` carries `reload: None` → the handler must surface
/// `feature_unavailable` (503) without attempting any read.
#[tokio::test]
async fn get_current_config_returns_feature_unavailable_when_no_handle() {
    let state = admin_state_with(None);
    let (status, bytes) = get_current(state).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("response is JSON");
    assert_eq!(
        json["error"]["code"], "feature_unavailable",
        "missing-handle must surface feature_unavailable",
    );
}
