//! Integration tests for `POST /v1/sdk/renew` and
//! `POST /v1/sdk/unregister` (Phase 5 SDK-API S7).
//!
//! Both endpoints share a single test crate because they consume the
//! same lease-access-token verification path; bundling the fixtures
//! avoids the same setup duplicated across two files. The renew tests
//! cluster first (AC1–AC4 below), then the unregister tests (AC5–AC7).
//!
//! Acceptance criteria pinned by the slice plan:
//! Note: the slice text's 403 for expired renew tokens is stale; the
//! crate-wide lease-token envelope maps `LeaseTokenError::Expired` to
//! 401 `unauthorized`, and S7 preserves that boundary.
//!
//! 1. **`renew` happy path** — registered lease + valid (non-expired)
//!    access token returns 200; the response carries a non-empty
//!    `access_token` that decodes via `lease_token::verify` to the
//!    same identity, and `expires_at` lands ~24h in the future
//!    (asserted within ±5s of `now + 24h`).
//! 2. **`renew` with expired access token** — token whose claims
//!    `expires_at = now - 1s` returns 401 `unauthorized`.
//! 3. **`renew` with valid token but lease unknown** — token verifies
//!    cryptographically but the identity is not in the registry
//!    returns 404 `lease_not_found`.
//! 4. **`renew` with malformed access token** — token whose framing
//!    fails returns 401 `unauthorized`.
//! 5. **`unregister` happy path** — registered lease + valid access
//!    token returns 200 `{"data": {}}`; the registry's
//!    `lookup_by_identity` returns `None` afterward.
//! 6. **`unregister` second call** — re-submitting the same token
//!    against the now-empty registry returns 404 `lease_not_found`.
//! 7. **`unregister` with malformed token** — returns 401
//!    `unauthorized`.

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
use jiff::{SignedDuration, Timestamp};
use portal_crypto::{Ed25519Signer, Ed25519Verifier, ed25519_from_seed_for_test, verifying_key};
use portal_relay::api::{SdkState, build_sdk_router};
use portal_relay::policy::{PolicyRuntime, ReputationEngine};
use portal_relay::state::LeaseRegistry;
use portal_relay::state::lease_registry::{IdentityKey, LeaseRecord};
use portal_relay::state::lease_token::{self, LeaseTokenClaims};
use secrecy::SecretBox;
use serde_json::json;
use tower::ServiceExt as _;

const TEST_PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 50000);
const HOSTNAME: &str = "tenant-renew.portal.test";
const TOKEN_KEY_SEED: [u8; 32] = [0x99u8; 32];

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Build a paired (`Arc<SecretBox<RelayEd25519Key>>`,
/// `Arc<Ed25519Verifier>`) under the same deterministic seed used by
/// every test in this file. The two halves MUST come from the same
/// scalar so `lease_token::issue` and `lease_token::verify` cooperate.
fn token_keys() -> (
    Arc<SecretBox<portal_crypto::RelayEd25519Key>>,
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

/// Deterministic identity for the registered-lease fixture.
const fn fixture_identity() -> IdentityKey {
    IdentityKey([0xA5u8; 32])
}

/// Register a lease for `identity` directly via [`LeaseRegistry::register`]
/// (bypassing the SIWE+ENS path) and return the lease's expiry. Using
/// the registry's own primitive — rather than driving the
/// register-challenge → register flow — keeps this test focused on
/// the renew/unregister contract without re-exercising S5/S6 setup.
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

/// Mint an access token under the same signing key the [`sdk_state`]
/// fixture wires into [`SdkState`] — the verifier/signer pairing
/// invariant requires the test-side issue path to use the same
/// scalar as the relay-side verify path.
fn issue_token(identity: IdentityKey, expires_at: Timestamp) -> compact_str::CompactString {
    let key = ed25519_from_seed_for_test(TOKEN_KEY_SEED);
    let signer = Ed25519Signer::new(&key);
    lease_token::issue(identity, expires_at, &signer).expect("issue access token")
}

async fn post_json(
    router: Router,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let bytes = serde_json::to_vec(&body).expect("encode body");
    let request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(bytes))
        .expect("request build");
    let response = router.oneshot(request).await.expect("oneshot service");
    let status = response.status();
    let body_bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body collect")
        .to_vec();
    let json = if body_bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body_bytes).expect("response is JSON")
    };
    (status, json)
}

// ---------------------------------------------------------------------------
// /v1/sdk/renew
// ---------------------------------------------------------------------------

/// AC1: registered lease + valid access token → 200 with rotated
/// `access_token` whose decoded identity matches and whose
/// `expires_at` lands within ±5s of `now + 24h`.
#[tokio::test]
async fn renew_happy_path_returns_200_with_rotated_token() {
    let leases = LeaseRegistry::new();
    let identity = fixture_identity();
    let original_expires = register_fixture_lease(&leases, identity).await;

    // The access token's `expires_at` must be in the future for verify
    // to accept it; reuse the lease's expiry as a convenient
    // 24h-in-the-future moment.
    let token = issue_token(identity, original_expires);
    let state = sdk_state(leases.clone());
    let verifier = Arc::clone(&state.lease_token_verifier);
    let router = build_router(state);

    let before = Timestamp::now();
    let (status, json) = post_json(router, "/v1/sdk/renew", json!({ "access_token": token })).await;
    let after = Timestamp::now();
    assert_eq!(status, StatusCode::OK, "renew happy path; body={json}");

    let data = json.get("data").expect("envelope has data");
    let new_token = data
        .get("access_token")
        .and_then(|v| v.as_str())
        .expect("access_token present");
    assert!(
        !new_token.is_empty(),
        "rotated access_token must not be empty"
    );

    let new_expires_str = data
        .get("expires_at")
        .and_then(|v| v.as_str())
        .expect("expires_at present");
    let new_expires: Timestamp = new_expires_str.parse().expect("expires_at is RFC 3339");

    // Decode the rotated token and assert the identity round-trips.
    let claims: LeaseTokenClaims =
        lease_token::verify(new_token, &verifier, Timestamp::now()).expect("verify rotated token");
    assert_eq!(claims.identity, identity.0);
    assert_eq!(claims.expires_at, new_expires.as_second());

    // The new expiry should be ~24h ahead of `now`. Bracket the
    // expected value on both sides of the handler call (`before` and
    // `after` capture wall time around the request) and assert the
    // actual `new_expires` falls inside the bracket ±5s tolerance.
    let lower = before
        .checked_add(SignedDuration::from_hours(24) - SignedDuration::from_secs(5))
        .expect("lower bound");
    let upper = after
        .checked_add(SignedDuration::from_hours(24) + SignedDuration::from_secs(5))
        .expect("upper bound");
    assert!(
        new_expires >= lower && new_expires <= upper,
        "new_expires={new_expires} not in [{lower}, {upper}]",
    );

    // Registry record should also reflect the bumped expiry.
    let updated = leases
        .lookup_by_identity(identity)
        .expect("lease still present after renew");
    assert_eq!(updated.expires_at, new_expires);
}

/// AC2: an access token whose claims expire in the past → 401
/// `unauthorized` (envelope mapping for `LeaseTokenError::Expired`).
#[tokio::test]
async fn renew_expired_access_token_returns_401() {
    let leases = LeaseRegistry::new();
    let identity = fixture_identity();
    let _ = register_fixture_lease(&leases, identity).await;

    // Mint a token whose `expires_at` is `now - 1s` — verify rejects
    // when `now >= expires_at`.
    let past = Timestamp::now()
        .checked_sub(SignedDuration::from_secs(1))
        .expect("past timestamp");
    let token = issue_token(identity, past);

    let router = build_router(sdk_state(leases));
    let (status, json) = post_json(router, "/v1/sdk/renew", json!({ "access_token": token })).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body={json}");
    let code = json
        .pointer("/error/code")
        .and_then(|v| v.as_str())
        .expect("error.code present");
    assert_eq!(code, "unauthorized");
}

/// AC3: a valid token whose identity was never registered (or has
/// since been swept) → 404 `lease_not_found`. Distinguishes the
/// crypto-credential branch (401) from the registry-state branch
/// (404).
#[tokio::test]
async fn renew_valid_token_unknown_lease_returns_404() {
    let leases = LeaseRegistry::new();

    // No lease registered — but mint a fresh token for some identity.
    let unknown_identity = IdentityKey([0x33u8; 32]);
    let future_expires = Timestamp::now()
        .checked_add(SignedDuration::from_secs(3600))
        .expect("future timestamp");
    let token = issue_token(unknown_identity, future_expires);

    let router = build_router(sdk_state(leases));
    let (status, json) = post_json(router, "/v1/sdk/renew", json!({ "access_token": token })).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "body={json}");
    let code = json
        .pointer("/error/code")
        .and_then(|v| v.as_str())
        .expect("error.code present");
    assert_eq!(code, "lease_not_found");
}

/// AC4: a malformed access token (no `.` separator) → 401
/// `unauthorized` per the `LeaseTokenError::MalformedFraming` →
/// `Unauthorized` envelope mapping.
#[tokio::test]
async fn renew_malformed_token_returns_401() {
    let leases = LeaseRegistry::new();
    let router = build_router(sdk_state(leases));

    let (status, json) = post_json(
        router,
        "/v1/sdk/renew",
        json!({ "access_token": "garbage" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body={json}");
    let code = json
        .pointer("/error/code")
        .and_then(|v| v.as_str())
        .expect("error.code present");
    assert_eq!(code, "unauthorized");
}

// ---------------------------------------------------------------------------
// /v1/sdk/unregister
// ---------------------------------------------------------------------------

/// AC5: registered lease + valid access token → 200 with empty data
/// envelope; subsequent `lookup_by_identity` returns `None`.
#[tokio::test]
async fn unregister_happy_path_returns_200_and_clears_lease() {
    let leases = LeaseRegistry::new();
    let identity = fixture_identity();
    let expires_at = register_fixture_lease(&leases, identity).await;
    let token = issue_token(identity, expires_at);

    let router = build_router(sdk_state(leases.clone()));
    let (status, json) = post_json(
        router,
        "/v1/sdk/unregister",
        json!({ "access_token": token }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "unregister happy; body={json}");

    // Wire shape: `{"data":{}}` — `data` is a non-null empty object.
    let data = json.get("data").expect("envelope has data");
    assert!(data.is_object(), "data must be object; got {data}");
    assert!(
        data.as_object().expect("object").is_empty(),
        "data must be empty object; got {data}",
    );

    // Side effect: lease gone.
    assert!(
        leases.lookup_by_identity(identity).is_none(),
        "lease must be absent after successful unregister",
    );
    assert_eq!(leases.lease_count(), 0);
}

/// AC6: a second `unregister` with the same token (lease already
/// gone) → 404 `lease_not_found`. The token is still valid
/// cryptographically; the lease is just absent.
#[tokio::test]
async fn unregister_second_call_returns_404() {
    let leases = LeaseRegistry::new();
    let identity = fixture_identity();
    let expires_at = register_fixture_lease(&leases, identity).await;
    let token = issue_token(identity, expires_at);

    let router = build_router(sdk_state(leases.clone()));

    // First call clears the lease.
    let (status1, _) = post_json(
        router.clone(),
        "/v1/sdk/unregister",
        json!({ "access_token": token.clone() }),
    )
    .await;
    assert_eq!(status1, StatusCode::OK);

    // Second call: token still verifies, but lease is gone.
    let (status2, json2) = post_json(
        router,
        "/v1/sdk/unregister",
        json!({ "access_token": token }),
    )
    .await;
    assert_eq!(status2, StatusCode::NOT_FOUND, "body={json2}");
    let code = json2
        .pointer("/error/code")
        .and_then(|v| v.as_str())
        .expect("error.code present");
    assert_eq!(code, "lease_not_found");
}

/// AC7: a malformed access token → 401 `unauthorized`. The
/// unregister handler does not reach the registry on this path.
#[tokio::test]
async fn unregister_malformed_token_returns_401() {
    let leases = LeaseRegistry::new();
    let router = build_router(sdk_state(leases));

    let (status, json) = post_json(
        router,
        "/v1/sdk/unregister",
        json!({ "access_token": "garbage" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body={json}");
    let code = json
        .pointer("/error/code")
        .and_then(|v| v.as_str())
        .expect("error.code present");
    assert_eq!(code, "unauthorized");
}
