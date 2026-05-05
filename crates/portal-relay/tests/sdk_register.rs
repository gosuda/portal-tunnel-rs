//! Integration tests for `POST /v1/sdk/register` (Phase 5 SDK-API S6).
//!
//! Pin the S6 acceptance criteria from the slice plan:
//!
//! 1. Happy path: issue + sign + register → 201 with valid
//!    `access_token` decodable via `state::lease_token::verify`.
//! 2. Bad SIWE signature: 401 `unauthorized`.
//! 3. Unknown `challenge_id`: 400 `invalid_request`.
//! 4. Hostname conflict (different identity holds same host) → 409
//!    `hostname_conflict`.
//! 5. Banned source IP: 401 `ip_banned`.
//! 6. ENS happy: stub returns `Some(name)` with forward-resolve match
//!    → `mark_ens_named` invoked.
//! 7. `ens_resolver = None`: 201, `is_ens_named` stays false.
//! 8. ENS transient error (`EnsError::Rpc`): 201 (request still
//!    succeeds), `is_ens_named` stays false.
//! 9. Replay: re-submit consumed `(challenge_id, signature)` → 400
//!    `invalid_request`.

#![expect(
    clippy::expect_used,
    reason = "test-only setup; integration test crate"
)]

use core::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use compact_str::CompactString;
use jiff::Timestamp;
use portal_crypto::{
    BoxedEnsResolver, Ed25519Verifier, EnsError, EnsResolver, EthAddress,
    ed25519_from_seed_for_test, evm_address_from_pubkey, secp256k1_from_bytes_for_test,
    sign_eip191_personal, tenant_public_key, verifying_key,
};
use portal_relay::api::{SdkState, build_sdk_router};
use portal_relay::policy::{IdentityKey, PolicyRuntime, ReputationEngine};
use portal_relay::state::LeaseRegistry;
use portal_relay::state::challenge::RegisterChallengeRequest as InnerRegisterChallengeRequest;
use portal_relay::state::lease_token::{self, LeaseTokenClaims};
use serde_json::json;
use tower::ServiceExt as _;

const TEST_PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 50000);
const SECP_SCALAR: [u8; 32] = [0x4cu8; 32];
const ED_SEED: [u8; 32] = [0x42u8; 32];
const HOSTNAME: &str = "tenant-a.portal.test";
const SIWE_DOMAIN: &str = "example.com";
const REGISTER_URI: &str = "https://example.com/v1/sdk/register";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn sdk_state(
    leases: LeaseRegistry,
    policy: Arc<PolicyRuntime>,
    engine: ReputationEngine,
    ens_resolver: Option<BoxedEnsResolver>,
) -> SdkState {
    let signing_key = Arc::new(ed25519_from_seed_for_test([0x77u8; 32]));
    let verifier = Arc::new(Ed25519Verifier::new(verifying_key(&signing_key)));
    SdkState {
        leases,
        policy,
        engine,
        ens_resolver,
        lease_token_signing_key: signing_key,
        lease_token_verifier: verifier,
    }
}

fn build_router(state: SdkState) -> Router {
    build_sdk_router(state).layer(MockConnectInfo(TEST_PEER))
}

/// Issue a register challenge directly via the registry, returning
/// `(challenge_id, siwe_message_text, eth_address, ed25519_pk_bytes)`.
async fn issue_challenge(
    leases: &LeaseRegistry,
    eth_address: [u8; 20],
    ed25519_pk: [u8; 32],
) -> (CompactString, String, EthAddress, [u8; 32]) {
    let inner = InnerRegisterChallengeRequest {
        eth_address,
        ed25519_pk,
        reported_ip: None,
    };
    let resp = leases
        .issue_register_challenge(
            &inner,
            SIWE_DOMAIN,
            REGISTER_URI,
            TEST_PEER.ip(),
            Timestamp::now(),
        )
        .await
        .expect("issue_register_challenge");
    (
        resp.challenge_id,
        resp.siwe_message_text,
        EthAddress::new(eth_address),
        ed25519_pk,
    )
}

/// Sign the SIWE message text with the deterministic test secp256k1
/// key, returning a 65-byte EIP-191 signature.
fn sign_siwe(msg: &str) -> [u8; 65] {
    let key = secp256k1_from_bytes_for_test(SECP_SCALAR);
    sign_eip191_personal(msg.as_bytes(), &key).expect("sign_eip191_personal")
}

fn deterministic_eth_address() -> [u8; 20] {
    let key = secp256k1_from_bytes_for_test(SECP_SCALAR);
    let pk = tenant_public_key(&key).expect("tenant_public_key");
    let addr = evm_address_from_pubkey(&pk);
    let mut raw = [0u8; 20];
    raw.copy_from_slice(addr.as_bytes());
    raw
}

fn deterministic_ed25519_pk() -> [u8; 32] {
    let key = ed25519_from_seed_for_test(ED_SEED);
    verifying_key(&key).to_bytes()
}

fn hex_lower(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn body_with_signature(
    challenge_id: &str,
    siwe_msg: &str,
    sig: &[u8; 65],
    hostname: &str,
) -> serde_json::Value {
    json!({
        "challenge_id": challenge_id,
        "siwe_message_text": siwe_msg,
        "siwe_signature": format!("0x{}", hex_lower(sig)),
        "hostname": hostname,
        "metadata": "",
    })
}

async fn post_register(router: Router, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let bytes = serde_json::to_vec(&body).expect("encode");
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/sdk/register")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::HOST, SIWE_DOMAIN)
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
// ENS resolver stubs
// ---------------------------------------------------------------------------

struct ForwardMatchResolver {
    name: String,
    eth: EthAddress,
}

impl EnsResolver for ForwardMatchResolver {
    #[expect(
        clippy::manual_async_fn,
        reason = "explicit impl Future + Send return required by trait"
    )]
    fn resolve<'a>(
        &'a self,
        name: &'a str,
    ) -> impl Future<Output = Result<EthAddress, EnsError>> + Send + 'a {
        async move {
            if name == self.name {
                Ok(self.eth)
            } else {
                Err(EnsError::NameNotFound(name.to_owned()))
            }
        }
    }

    #[expect(
        clippy::manual_async_fn,
        reason = "explicit impl Future + Send return required by trait"
    )]
    fn resolve_reverse(
        &self,
        addr: EthAddress,
    ) -> impl Future<Output = Result<Option<String>, EnsError>> + Send + '_ {
        async move {
            if addr == self.eth {
                Ok(Some(self.name.clone()))
            } else {
                Ok(None)
            }
        }
    }
}

struct TransientErrorResolver;

impl EnsResolver for TransientErrorResolver {
    #[expect(
        clippy::manual_async_fn,
        reason = "explicit impl Future + Send return required by trait"
    )]
    fn resolve<'a>(
        &'a self,
        _name: &'a str,
    ) -> impl Future<Output = Result<EthAddress, EnsError>> + Send + 'a {
        async move { Err(EnsError::Rpc("transient".to_owned())) }
    }

    #[expect(
        clippy::manual_async_fn,
        reason = "explicit impl Future + Send return required by trait"
    )]
    fn resolve_reverse(
        &self,
        _addr: EthAddress,
    ) -> impl Future<Output = Result<Option<String>, EnsError>> + Send + '_ {
        async move { Err(EnsError::Rpc("transient".to_owned())) }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// AC1: happy path returns 201 with an `access_token` that decodes
/// via `lease_token::verify` and whose `identity` claim matches the
/// registered ed25519 protocol pubkey.
#[tokio::test]
async fn happy_path_returns_201_with_decodable_access_token() {
    let leases = LeaseRegistry::new();
    let eth = deterministic_eth_address();
    let pk = deterministic_ed25519_pk();
    let (challenge_id, siwe_msg, _, _) = issue_challenge(&leases, eth, pk).await;
    let sig = sign_siwe(&siwe_msg);

    let policy = Arc::new(PolicyRuntime::new());
    let state = sdk_state(leases.clone(), policy, ReputationEngine::new(), None);
    let verifier = Arc::clone(&state.lease_token_verifier);
    let router = build_router(state);

    let (status, json) = post_register(
        router,
        body_with_signature(&challenge_id, &siwe_msg, &sig, HOSTNAME),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "happy path; body={json}");

    let data = json.get("data").expect("envelope has data");
    let identity_hex = data
        .get("identity")
        .and_then(|v| v.as_str())
        .expect("identity present");
    assert_eq!(identity_hex.len(), 64, "identity is 64-char hex");
    assert_eq!(identity_hex, hex_lower(&pk));

    let token = data
        .get("access_token")
        .and_then(|v| v.as_str())
        .expect("access_token present");
    let claims: LeaseTokenClaims =
        lease_token::verify(token, &verifier, Timestamp::now()).expect("verify access_token");
    assert_eq!(claims.identity, pk);

    // Lease is registered.
    assert_eq!(leases.lease_count(), 1);
}

/// AC2: flipping a bit in the signature → 401 `unauthorized` (Path A
/// envelope mapping for `ChallengeInvalidSignature`).
#[tokio::test]
async fn bad_siwe_signature_returns_401_unauthorized() {
    let leases = LeaseRegistry::new();
    let eth = deterministic_eth_address();
    let pk = deterministic_ed25519_pk();
    let (challenge_id, siwe_msg, _, _) = issue_challenge(&leases, eth, pk).await;
    let mut sig = sign_siwe(&siwe_msg);
    sig[3] ^= 0xff;

    let state = sdk_state(
        leases,
        Arc::new(PolicyRuntime::new()),
        ReputationEngine::new(),
        None,
    );
    let router = build_router(state);

    let (status, json) = post_register(
        router,
        body_with_signature(&challenge_id, &siwe_msg, &sig, HOSTNAME),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body={json}");
    let code = json
        .pointer("/error/code")
        .and_then(|v| v.as_str())
        .expect("error.code present");
    assert_eq!(code, "unauthorized");
}

/// AC3: unknown `challenge_id` → 400 `invalid_request`.
#[tokio::test]
async fn unknown_challenge_id_returns_400_invalid_request() {
    let leases = LeaseRegistry::new();
    let eth = deterministic_eth_address();
    let pk = deterministic_ed25519_pk();
    let (_, siwe_msg, _, _) = issue_challenge(&leases, eth, pk).await;
    let sig = sign_siwe(&siwe_msg);

    let state = sdk_state(
        leases,
        Arc::new(PolicyRuntime::new()),
        ReputationEngine::new(),
        None,
    );
    let router = build_router(state);

    // Replace the real challenge_id with a 32-hex value the registry
    // never issued.
    let bogus_id = "00000000000000000000000000000000";
    let (status, json) = post_register(
        router,
        body_with_signature(bogus_id, &siwe_msg, &sig, HOSTNAME),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body={json}");
    let code = json
        .pointer("/error/code")
        .and_then(|v| v.as_str())
        .expect("error.code present");
    assert_eq!(code, "invalid_request");
}

/// AC4: hostname conflict — register identity A on hostname H, then
/// register identity B (different ed25519 seed → different EOA via
/// the binding statement, but the SIWE recovery path here uses the
/// SAME EOA secp256k1 key; the binding mismatch is the second
/// identity's ed25519 pubkey, which is a separate `challenge_id` +
/// fresh SIWE message). Submitting hostname H again returns 409.
#[tokio::test]
async fn hostname_conflict_returns_409() {
    let leases = LeaseRegistry::new();

    // Register identity A on HOSTNAME.
    let eth = deterministic_eth_address();
    let pk_a = deterministic_ed25519_pk();
    let (cid_a, siwe_a, _, _) = issue_challenge(&leases, eth, pk_a).await;
    let sig_a = sign_siwe(&siwe_a);
    let state = sdk_state(
        leases.clone(),
        Arc::new(PolicyRuntime::new()),
        ReputationEngine::new(),
        None,
    );
    let router = build_router(state);
    let (status_a, _) = post_register(
        router,
        body_with_signature(&cid_a, &siwe_a, &sig_a, HOSTNAME),
    )
    .await;
    assert_eq!(status_a, StatusCode::CREATED);

    // Register identity B (different ed25519 key, same EOA) on the
    // SAME hostname → 409 hostname_conflict.
    let key_b = ed25519_from_seed_for_test([0x55u8; 32]);
    let pk_b = verifying_key(&key_b).to_bytes();
    let (cid_b, siwe_b, _, _) = issue_challenge(&leases, eth, pk_b).await;
    let sig_b = sign_siwe(&siwe_b);
    let state2 = sdk_state(
        leases,
        Arc::new(PolicyRuntime::new()),
        ReputationEngine::new(),
        None,
    );
    let router2 = build_router(state2);
    let (status_b, json_b) = post_register(
        router2,
        body_with_signature(&cid_b, &siwe_b, &sig_b, HOSTNAME),
    )
    .await;
    assert_eq!(status_b, StatusCode::CONFLICT, "body={json_b}");
    let code = json_b
        .pointer("/error/code")
        .and_then(|v| v.as_str())
        .expect("error.code present");
    assert_eq!(code, "hostname_conflict");
}

/// AC5: source IP banned → 401 `ip_banned`. Banned check fires
/// before the challenge consume.
#[tokio::test]
async fn banned_source_ip_returns_401_ip_banned() {
    let leases = LeaseRegistry::new();
    let eth = deterministic_eth_address();
    let pk = deterministic_ed25519_pk();
    let (challenge_id, siwe_msg, _, _) = issue_challenge(&leases, eth, pk).await;
    let sig = sign_siwe(&siwe_msg);

    let policy = Arc::new(PolicyRuntime::new());
    policy.ip_filter.ban(TEST_PEER.ip());
    let state = sdk_state(leases, policy, ReputationEngine::new(), None);
    let router = build_router(state);

    let (status, json) = post_register(
        router,
        body_with_signature(&challenge_id, &siwe_msg, &sig, HOSTNAME),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let code = json
        .pointer("/error/code")
        .and_then(|v| v.as_str())
        .expect("error.code present");
    assert_eq!(code, "ip_banned");
}

/// AC6: ENS resolver returns `Some(name)` whose forward-resolve
/// matches the registered EOA → `mark_ens_named` is called; the
/// engine reports the identity as ENS-named.
#[tokio::test]
async fn ens_happy_marks_identity_ens_named() {
    let leases = LeaseRegistry::new();
    let eth = deterministic_eth_address();
    let pk = deterministic_ed25519_pk();
    let (challenge_id, siwe_msg, eth_addr, _) = issue_challenge(&leases, eth, pk).await;
    let sig = sign_siwe(&siwe_msg);

    let resolver = BoxedEnsResolver::new(ForwardMatchResolver {
        name: "alice.eth".to_owned(),
        eth: eth_addr,
    });
    let engine = ReputationEngine::new();
    let state = sdk_state(
        leases,
        Arc::new(PolicyRuntime::new()),
        engine.clone(),
        Some(resolver),
    );
    let router = build_router(state);

    let (status, _) = post_register(
        router,
        body_with_signature(&challenge_id, &siwe_msg, &sig, HOSTNAME),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(engine.is_ens_named(IdentityKey(pk)));
}

/// AC7: `ens_resolver = None` → registration succeeds, identity is
/// NOT marked ENS-named.
#[tokio::test]
async fn ens_resolver_none_succeeds_without_marking() {
    let leases = LeaseRegistry::new();
    let eth = deterministic_eth_address();
    let pk = deterministic_ed25519_pk();
    let (challenge_id, siwe_msg, _, _) = issue_challenge(&leases, eth, pk).await;
    let sig = sign_siwe(&siwe_msg);

    let engine = ReputationEngine::new();
    let state = sdk_state(leases, Arc::new(PolicyRuntime::new()), engine.clone(), None);
    let router = build_router(state);

    let (status, _) = post_register(
        router,
        body_with_signature(&challenge_id, &siwe_msg, &sig, HOSTNAME),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(!engine.is_ens_named(IdentityKey(pk)));
}

/// AC8: ENS resolver returns transient error → registration STILL
/// succeeds (ENS-marking is bonus, not load-bearing for SIWE auth).
#[tokio::test]
async fn ens_transient_error_does_not_fail_registration() {
    let leases = LeaseRegistry::new();
    let eth = deterministic_eth_address();
    let pk = deterministic_ed25519_pk();
    let (challenge_id, siwe_msg, _, _) = issue_challenge(&leases, eth, pk).await;
    let sig = sign_siwe(&siwe_msg);

    let resolver = BoxedEnsResolver::new(TransientErrorResolver);
    let engine = ReputationEngine::new();
    let state = sdk_state(
        leases,
        Arc::new(PolicyRuntime::new()),
        engine.clone(),
        Some(resolver),
    );
    let router = build_router(state);

    let (status, _) = post_register(
        router,
        body_with_signature(&challenge_id, &siwe_msg, &sig, HOSTNAME),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(!engine.is_ens_named(IdentityKey(pk)));
}

/// AC9: replay — re-submitting the same `(challenge_id, signature)`
/// after a successful register returns 400 `invalid_request` because
/// the challenge was consumed single-use.
#[tokio::test]
async fn replay_after_successful_register_returns_400() {
    let leases = LeaseRegistry::new();
    let eth = deterministic_eth_address();
    let pk = deterministic_ed25519_pk();
    let (challenge_id, siwe_msg, _, _) = issue_challenge(&leases, eth, pk).await;
    let sig = sign_siwe(&siwe_msg);

    let state = sdk_state(
        leases.clone(),
        Arc::new(PolicyRuntime::new()),
        ReputationEngine::new(),
        None,
    );
    let router = build_router(state);
    let body = body_with_signature(&challenge_id, &siwe_msg, &sig, HOSTNAME);

    let (status1, _) = post_register(router.clone(), body.clone()).await;
    assert_eq!(status1, StatusCode::CREATED, "first register succeeds");

    // Second submission with the same challenge_id is rejected.
    let (status2, json2) = post_register(router, body).await;
    assert_eq!(
        status2,
        StatusCode::BAD_REQUEST,
        "replay rejected; body={json2}"
    );
    let code = json2
        .pointer("/error/code")
        .and_then(|v| v.as_str())
        .expect("error.code present");
    assert_eq!(code, "invalid_request");
}
