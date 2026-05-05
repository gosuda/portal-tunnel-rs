//! Integration tests for `POST /v1/sdk/register-challenge` (Phase 5
//! SDK-API S5).
//!
//! Pin the five S5 acceptance criteria:
//!
//! 1. Happy path: valid body returns 201 with non-empty
//!    `challenge_id` (32-hex), `expires_at` ~120 s in the future,
//!    non-empty `siwe_message`.
//! 2. Banned source IP: 401 + `error.code = "ip_banned"`.
//! 3. Malformed JSON body: 400 + `error.code = "invalid_request"`.
//! 4. Per-IP cap: posting `REGISTER_CHALLENGE_PER_IP_CAP + 1` valid
//!    bodies from one source IP returns 429 +
//!    `error.code = "rate_limited"` on the last request.
//! 5. Transport conflict: `hop_token != ""` together with
//!    `udp_enabled = true` returns 503 + `error.code =
//!    "feature_unavailable"` (the v0.1 hop-unimplemented decision —
//!    documented in `register_challenge_handler` rustdoc).
//!
//! All tests share the `oneshot` pattern from `tests/sdk_domain.rs`,
//! adapted to inject a `ConnectInfo<SocketAddr>` via the
//! `MockConnectInfo` layer (axum's documented test path; see
//! `axum::extract::connect_info::MockConnectInfo` rustdoc).

#![expect(
    clippy::expect_used,
    reason = "test-only setup; integration test crate"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use portal_relay::api::{SdkState, build_sdk_router};
use portal_relay::policy::{PolicyRuntime, ReputationEngine};
use portal_relay::state::{LeaseRegistry, REGISTER_CHALLENGE_PER_IP_CAP};
use serde_json::json;
use tower::ServiceExt as _;

/// Default mock peer address for the connect-info layer.
const TEST_PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 50000);

/// Build a default `SdkState` with the given policy runtime. The
/// other state fields use the same minimal-fixture pattern as
/// `tests/sdk_domain.rs::default_sdk_state`.
fn sdk_state_with_policy(policy: Arc<PolicyRuntime>) -> SdkState {
    let signing_key = Arc::new(portal_crypto::ed25519_from_seed_for_test([0x77u8; 32]));
    let verifier = Arc::new(portal_crypto::Ed25519Verifier::new(
        portal_crypto::verifying_key(&signing_key),
    ));
    SdkState {
        leases: LeaseRegistry::new(),
        policy,
        engine: ReputationEngine::new(),
        ens_resolver: None,
        lease_token_signing_key: signing_key,
        lease_token_verifier: verifier,
    }
}

/// Build the SDK router with `MockConnectInfo(TEST_PEER)` injected so
/// the `ConnectInfo<SocketAddr>` extractor inside
/// `register_challenge_handler` resolves under `oneshot`.
fn build_router(state: SdkState) -> Router {
    build_sdk_router(state).layer(MockConnectInfo(TEST_PEER))
}

/// Construct the canonical happy-path JSON wire body. Encoding choices
/// match `RegisterChallengeBody` field documentation:
/// `eth_address` is `0x` + 40 lowercase hex; `ed25519_pk` is 32-byte
/// base64.
fn happy_body() -> serde_json::Value {
    let eth = "0x00112233445566778899aabbccddeeff00112233";
    let pk = BASE64_STANDARD.encode([0x11u8; 32]);
    json!({
        "eth_address": eth,
        "ed25519_pk": pk,
        "udp_enabled": true,
        "tcp_enabled": false,
        "hop_token": "",
        "hostname": "tenant-a",
        "metadata": "",
        "ttl": 600u32,
    })
}

/// Issue a POST against `/v1/sdk/register-challenge` and return
/// `(status, body_json)`.
async fn post_register_challenge(
    router: Router,
    body: Vec<u8>,
    host: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri("/v1/sdk/register-challenge")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(h) = host {
        builder = builder.header(header::HOST, h);
    }
    let request = builder.body(Body::from(body)).expect("request build");
    let response = router.oneshot(request).await.expect("oneshot service");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body collect")
        .to_vec();
    let json: serde_json::Value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("response is JSON")
    };
    (status, json)
}

/// Acceptance criterion 1: happy path returns 201 with a 32-hex
/// `challenge_id`, an `expires_at` ~120 s in the future, and a
/// non-empty `siwe_message`.
#[tokio::test]
async fn happy_path_returns_201_with_challenge_envelope() {
    let policy = Arc::new(PolicyRuntime::new());
    let router = build_router(sdk_state_with_policy(policy));
    let body = serde_json::to_vec(&happy_body()).expect("encode");

    let (status, json) = post_register_challenge(router, body, Some("example.com")).await;
    assert_eq!(status, StatusCode::CREATED, "happy path status");

    let data = json.get("data").expect("envelope has data");
    let id = data
        .get("challenge_id")
        .and_then(|v| v.as_str())
        .expect("challenge_id present");
    assert_eq!(id.len(), 32, "challenge_id is 32 hex chars (uuid simple)");
    assert!(
        id.chars().all(|c| c.is_ascii_hexdigit()),
        "challenge_id is hex: {id}",
    );
    let siwe = data
        .get("siwe_message")
        .and_then(|v| v.as_str())
        .expect("siwe_message present");
    assert!(!siwe.is_empty(), "siwe_message non-empty");
    // The Host header is the SIWE domain — the message text should
    // mention it. This pins the Path A resolution: the relay built
    // `domain` from the request's Host (Path A) rather than from a
    // relay-identity field (Path B), exactly as the slice plan's v0.1
    // trade-off authorizes.
    assert!(
        siwe.contains("example.com"),
        "siwe_message uses Host as domain: {siwe}",
    );

    // expires_at is RFC 3339; the relay's TTL constant is 120 s.
    // We only assert the field is present + parseable as a timestamp;
    // the upstream registry test (`state::lease_registry`) pins the
    // exact 120 s window.
    let expires_at = data
        .get("expires_at")
        .and_then(|v| v.as_str())
        .expect("expires_at present");
    let parsed = expires_at
        .parse::<jiff::Timestamp>()
        .expect("expires_at parses as jiff::Timestamp");
    let now = jiff::Timestamp::now();
    // Signed delta — a timestamp in the past must NOT pass. The
    // future-expiry contract is `parsed > now`; we allow a small
    // band around the 120 s TTL constant inside
    // `LeaseRegistry::issue_register_challenge` for clock-skew /
    // serialisation drift.
    let delta = parsed.as_second() - now.as_second();
    assert!(
        (90..=130).contains(&delta),
        "expires_at must be ~120s in the future: now={now}, expires_at={parsed}, delta={delta}s",
    );
}

/// Acceptance criterion 2: banned source IP returns 401 with
/// `error.code = "ip_banned"`.
#[tokio::test]
async fn banned_source_ip_returns_401_ip_banned() {
    let policy = Arc::new(PolicyRuntime::new());
    policy.ip_filter.ban(TEST_PEER.ip());
    let router = build_router(sdk_state_with_policy(policy));
    let body = serde_json::to_vec(&happy_body()).expect("encode");

    let (status, json) = post_register_challenge(router, body, Some("example.com")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "banned IP returns 401");
    let code = json
        .pointer("/error/code")
        .and_then(|v| v.as_str())
        .expect("error.code present");
    assert_eq!(code, "ip_banned");
}

/// Acceptance criterion 3: malformed JSON body returns 400 with
/// `error.code = "invalid_request"`.
#[tokio::test]
async fn malformed_json_returns_400_invalid_request() {
    let policy = Arc::new(PolicyRuntime::new());
    let router = build_router(sdk_state_with_policy(policy));

    let (status, json) =
        post_register_challenge(router, b"{invalid".to_vec(), Some("example.com")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "malformed body 400");
    let code = json
        .pointer("/error/code")
        .and_then(|v| v.as_str())
        .expect("error.code present");
    assert_eq!(code, "invalid_request");
}

/// Acceptance criterion 4: per-IP outstanding-challenge cap.
///
/// The handler shares the lease registry across the call site, so
/// posting `REGISTER_CHALLENGE_PER_IP_CAP + 1` valid bodies from the
/// same source IP exercises the cap enforced inside
/// `LeaseRegistry::issue_register_challenge`. Cloning the router
/// per-iteration keeps `oneshot` from consuming the underlying
/// service after the first call.
#[tokio::test]
async fn per_ip_cap_returns_429_rate_limited_at_threshold_plus_one() {
    let policy = Arc::new(PolicyRuntime::new());
    let state = sdk_state_with_policy(policy);
    let router = build_router(state);
    let body = serde_json::to_vec(&happy_body()).expect("encode");

    // Fire the first CAP requests — all must succeed.
    for i in 0..REGISTER_CHALLENGE_PER_IP_CAP {
        let (status, json) =
            post_register_challenge(router.clone(), body.clone(), Some("example.com")).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "request {i} of cap {REGISTER_CHALLENGE_PER_IP_CAP} expected 201; got {status}; \
             body={json}",
        );
    }

    // The (CAP+1)-th request must be rejected with 429 + rate_limited.
    let (status, json) = post_register_challenge(router, body, Some("example.com")).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "cap+1 request must surface 429"
    );
    let code = json
        .pointer("/error/code")
        .and_then(|v| v.as_str())
        .expect("error.code present");
    assert_eq!(code, "rate_limited");
}

/// Acceptance criterion 5: transport conflict.
///
/// `hop_token != ""` is rejected by the v0.1 hop-unimplemented gate
/// with 503 `feature_unavailable` (the documented decision in the
/// `register_challenge_handler` rustdoc). The reviewer-mandated
/// stricter shape (409 `transport_mismatch`) is the alternative
/// landing; this test pins the chosen shape so a future flip is
/// caught.
#[tokio::test]
async fn hop_token_with_udp_returns_503_feature_unavailable() {
    let policy = Arc::new(PolicyRuntime::new());
    let router = build_router(sdk_state_with_policy(policy));
    let mut body = happy_body();
    body["hop_token"] = json!("hop-tok-xyz");
    body["udp_enabled"] = json!(true);
    let bytes = serde_json::to_vec(&body).expect("encode");

    let (status, json) = post_register_challenge(router, bytes, Some("example.com")).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "hop_token+udp returns 503 feature_unavailable per v0.1 hop-unimplemented decision",
    );
    let code = json
        .pointer("/error/code")
        .and_then(|v| v.as_str())
        .expect("error.code present");
    assert_eq!(code, "feature_unavailable");
}

/// Bonus pin: no transport selected (no UDP, no TCP, no hop) returns
/// 409 `transport_mismatch`. Not in the slice's literal acceptance
/// list but a load-bearing acceptance criterion per the user task
/// (the "no transport selected" branch). Failure here would mean a
/// future refactor accidentally accepted a no-transport request.
#[tokio::test]
async fn no_transport_selected_returns_409_transport_mismatch() {
    let policy = Arc::new(PolicyRuntime::new());
    let router = build_router(sdk_state_with_policy(policy));
    let mut body = happy_body();
    body["udp_enabled"] = json!(false);
    body["tcp_enabled"] = json!(false);
    body["hop_token"] = json!("");
    let bytes = serde_json::to_vec(&body).expect("encode");

    let (status, json) = post_register_challenge(router, bytes, Some("example.com")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let code = json
        .pointer("/error/code")
        .and_then(|v| v.as_str())
        .expect("error.code present");
    assert_eq!(code, "transport_mismatch");
}

/// Bonus pin: missing Host header returns 400 `invalid_request`. The
/// Path A v0.1 trade-off documented in
/// `register_challenge_handler` requires a non-empty Host; absence
/// must surface as a malformed-request rather than a fall-back to
/// `relay_identity.name`.
#[tokio::test]
async fn missing_host_header_returns_400_invalid_request() {
    let policy = Arc::new(PolicyRuntime::new());
    let router = build_router(sdk_state_with_policy(policy));
    let body = serde_json::to_vec(&happy_body()).expect("encode");

    let (status, json) = post_register_challenge(router, body, None).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Path A v0.1: missing Host returns 400 invalid_request"
    );
    let code = json
        .pointer("/error/code")
        .and_then(|v| v.as_str())
        .expect("error.code present");
    assert_eq!(code, "invalid_request");
}
