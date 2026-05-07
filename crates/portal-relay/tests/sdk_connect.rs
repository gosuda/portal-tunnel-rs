//! Integration tests for `POST /v1/sdk/connect` (Phase 5 SDK-API S8).
//!
//! The handler verifies a lease access token from the
//! `X-Portal-Access-Token` header, checks registry state, rejects
//! HTTP/2+ before hijack, and starts the HTTP/1.1 upgrade contract. The
//! positive-path test intentionally stops at the reachable Axum
//! `oneshot` boundary: `oneshot` does not provide a real underlying TCP
//! stream to complete `hyper::upgrade::on`, so the test asserts the
//! admission response and avoids pretending to exercise the future
//! bridge.
//!
//! Plan drift: the slice text mentions 403 for unauthorized in one
//! place. The crate-wide envelope maps `ApiErrorCode::Unauthorized` to
//! 401, matching S7 and lease-token error semantics; these tests pin
//! the existing 401 behavior.

#![expect(
    clippy::expect_used,
    reason = "test-only setup; integration test crate"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request, StatusCode, Version, header};
use jiff::{SignedDuration, Timestamp};
use portal_crypto::{Ed25519Signer, Ed25519Verifier, ed25519_from_seed_for_test, verifying_key};
use portal_relay::api::{SdkState, build_sdk_router};
use portal_relay::policy::{PolicyRuntime, ReputationEngine};
use portal_relay::state::LeaseRegistry;
use portal_relay::state::lease_registry::{IdentityKey, LeaseRecord};
use portal_relay::state::lease_token;
use tower::ServiceExt as _;

const TEST_PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 50000);
const HOSTNAME: &str = "tenant-connect.portal.test";
const TOKEN_KEY_SEED: [u8; 32] = [0x88u8; 32];

fn token_keys() -> (
    Arc<secrecy::SecretBox<portal_crypto::RelayEd25519Key>>,
    Arc<Ed25519Verifier>,
) {
    let key = Arc::new(ed25519_from_seed_for_test(TOKEN_KEY_SEED));
    let verifier = Arc::new(Ed25519Verifier::new(verifying_key(&key)));
    (key, verifier)
}

fn sdk_state(leases: LeaseRegistry) -> SdkState {
    let (signing_key, verifier) = token_keys();
    SdkState {
        leases,
        policy: Arc::new(PolicyRuntime::new()),
        engine: ReputationEngine::new(),
        ens_resolver: None,
        lease_token_signing_key: signing_key,
        lease_token_verifier: verifier,
    }
}

fn build_router(state: SdkState) -> Router {
    build_sdk_router(state).layer(MockConnectInfo(TEST_PEER))
}

const fn fixture_identity() -> IdentityKey {
    IdentityKey([0xC7u8; 32])
}

async fn register_fixture_lease(leases: &LeaseRegistry, identity: IdentityKey) -> Timestamp {
    let now = Timestamp::now();
    let expires_at = now
        .checked_add(SignedDuration::from_hours(24))
        .unwrap_or(Timestamp::MAX);
    let record = LeaseRecord::new(
        identity,
        HOSTNAME.into(),
        Vec::new(),
        expires_at,
        now,
        TEST_PEER.ip(),
    );
    leases
        .register(record)
        .await
        .expect("register fixture lease");
    expires_at
}

fn issue_token(identity: IdentityKey, expires_at: Timestamp) -> compact_str::CompactString {
    let key = ed25519_from_seed_for_test(TOKEN_KEY_SEED);
    let signer = Ed25519Signer::new(&key);
    lease_token::issue(identity, expires_at, &signer).expect("issue access token")
}

async fn send_connect(
    router: Router,
    token: Option<&str>,
    version: Version,
) -> (StatusCode, Option<String>, Vec<u8>) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/v1/sdk/connect")
        .version(version);
    if let Some(token) = token {
        builder = builder.header(lease_token::ACCESS_TOKEN_HEADER, token);
    }
    let request = builder.body(Body::empty()).expect("request build");
    let response = router.oneshot(request).await.expect("oneshot service");
    let status = response.status();
    let connection = response
        .headers()
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body collect")
        .to_vec();
    (status, connection, body)
}

fn error_code(body: &[u8]) -> String {
    let json: serde_json::Value = serde_json::from_slice(body).expect("response is JSON");
    json.pointer("/error/code")
        .and_then(|v| v.as_str())
        .expect("error.code present")
        .to_owned()
}

async fn post_hop(method: Method) -> StatusCode {
    let router = build_router(sdk_state(LeaseRegistry::new()));
    let request = Request::builder()
        .method(method)
        .uri("/v1/sdk/hop")
        .body(Body::empty())
        .expect("request build");
    router
        .oneshot(request)
        .await
        .expect("oneshot service")
        .status()
}

#[tokio::test]
async fn connect_missing_access_token_returns_401() {
    let router = build_router(sdk_state(LeaseRegistry::new()));

    let (status, _, body) = send_connect(router, None, Version::HTTP_11).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body={body:?}");
    assert_eq!(error_code(&body), "unauthorized");
}

#[tokio::test]
async fn connect_invalid_access_token_returns_401() {
    let router = build_router(sdk_state(LeaseRegistry::new()));

    let (status, _, body) = send_connect(router, Some("not-a-token"), Version::HTTP_11).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body={body:?}");
    assert_eq!(error_code(&body), "unauthorized");
}

#[tokio::test]
async fn connect_valid_token_unknown_lease_returns_404() {
    let identity = fixture_identity();
    let expires_at = Timestamp::now()
        .checked_add(SignedDuration::from_hours(1))
        .expect("future expiry");
    let token = issue_token(identity, expires_at);
    let router = build_router(sdk_state(LeaseRegistry::new()));

    let (status, _, body) = send_connect(router, Some(&token), Version::HTTP_11).await;

    assert_eq!(status, StatusCode::NOT_FOUND, "body={body:?}");
    assert_eq!(error_code(&body), "lease_not_found");
}

#[tokio::test]
async fn connect_http2_returns_400_http11_only() {
    let leases = LeaseRegistry::new();
    let identity = fixture_identity();
    let expires_at = register_fixture_lease(&leases, identity).await;
    let token = issue_token(identity, expires_at);
    let router = build_router(sdk_state(leases));

    let (status, _, body) = send_connect(router, Some(&token), Version::HTTP_2).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "body={body:?}");
    assert_eq!(error_code(&body), "http11_only");
}

#[tokio::test]
async fn connect_http11_valid_token_and_lease_reaches_hijack_boundary() {
    let leases = LeaseRegistry::new();
    let identity = fixture_identity();
    let expires_at = register_fixture_lease(&leases, identity).await;
    let token = issue_token(identity, expires_at);
    let router = build_router(sdk_state(leases));

    let (status, connection, body) = send_connect(router, Some(&token), Version::HTTP_11).await;

    assert_eq!(status, StatusCode::OK, "body={body:?}");
    assert_eq!(connection.as_deref(), Some("keep-alive"));
    assert!(
        body.is_empty(),
        "oneshot admission response has no body; raw prelude requires a real upgraded stream"
    );
}

#[tokio::test]
async fn sdk_hop_route_is_not_mounted() {
    assert_eq!(post_hop(Method::POST).await, StatusCode::NOT_FOUND);
    assert_eq!(post_hop(Method::DELETE).await, StatusCode::NOT_FOUND);
}
