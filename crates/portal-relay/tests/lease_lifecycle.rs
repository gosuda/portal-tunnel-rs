//! Integration test for the SDK lease lifecycle gate (S9).
//!
//! Drives the public SDK router through Pending → Active → Active → Expired
//! without sleeping or mocking SIWE. The final expiry is forced by an explicit
//! `LeaseRegistry::cleanup_expired(now)` timestamp so the test remains fast and
//! deterministic.

#![expect(
    clippy::expect_used,
    reason = "test-only setup; integration test crate"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use jiff::{SignedDuration, Timestamp};
use portal_crypto::{
    Ed25519Verifier, ed25519_from_seed_for_test, evm_address_from_pubkey,
    secp256k1_from_bytes_for_test, sign_eip191_personal, tenant_public_key, verifying_key,
};
use portal_relay::api::{SdkState, build_sdk_router};
use portal_relay::policy::{PolicyRuntime, ReputationEngine};
use portal_relay::state::LeaseRegistry;
use serde_json::json;
use tower::ServiceExt as _;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::format::FmtSpan;

const TEST_PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 50000);
const SECP_SCALAR: [u8; 32] = [0x4cu8; 32];
const ED_SEED: [u8; 32] = [0x42u8; 32];
const TOKEN_KEY_SEED: [u8; 32] = [0x77u8; 32];
const HOSTNAME: &str = "tenant-lifecycle.portal.test";
const SIWE_DOMAIN: &str = "example.com";

#[derive(Clone, Default)]
struct CapturingWriter {
    sink: Arc<Mutex<Vec<u8>>>,
}

impl CapturingWriter {
    fn snapshot(&self) -> String {
        let buf = self.sink.lock().expect("capturing-writer mutex");
        String::from_utf8_lossy(&buf).into_owned()
    }
}

impl<'a> MakeWriter<'a> for CapturingWriter {
    type Writer = CapturingHandle;

    fn make_writer(&'a self) -> Self::Writer {
        CapturingHandle {
            sink: Arc::clone(&self.sink),
        }
    }
}

struct CapturingHandle {
    sink: Arc<Mutex<Vec<u8>>>,
}

impl std::io::Write for CapturingHandle {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        {
            let mut guard = self
                .sink
                .lock()
                .map_err(|_| std::io::Error::other("capturing-writer mutex poisoned"))?;
            guard.extend_from_slice(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn sdk_state(leases: LeaseRegistry) -> SdkState {
    let signing_key = Arc::new(ed25519_from_seed_for_test(TOKEN_KEY_SEED));
    let verifier = Arc::new(Ed25519Verifier::new(verifying_key(&signing_key)));
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

fn sign_siwe(msg: &str) -> [u8; 65] {
    let key = secp256k1_from_bytes_for_test(SECP_SCALAR);
    sign_eip191_personal(msg.as_bytes(), &key).expect("sign_eip191_personal")
}

fn register_challenge_body() -> serde_json::Value {
    json!({
        "eth_address": format!("0x{}", hex_lower(&deterministic_eth_address())),
        "ed25519_pk": BASE64_STANDARD.encode(deterministic_ed25519_pk()),
        "udp_enabled": true,
        "tcp_enabled": false,
        "hop_token": "",
        "hostname": HOSTNAME,
        "metadata": "",
        "ttl": 600u32,
    })
}

fn register_body(
    challenge_id: &str,
    siwe_message: &str,
    signature: &[u8; 65],
) -> serde_json::Value {
    json!({
        "challenge_id": challenge_id,
        "siwe_message_text": siwe_message,
        "siwe_signature": format!("0x{}", hex_lower(signature)),
        "hostname": HOSTNAME,
        "metadata": "",
    })
}

async fn post_json(
    router: Router,
    path: &str,
    body: serde_json::Value,
    host: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let bytes = serde_json::to_vec(&body).expect("encode body");
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(host) = host {
        builder = builder.header(header::HOST, host);
    }
    let request = builder.body(Body::from(bytes)).expect("request build");
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

fn data_str<'a>(json: &'a serde_json::Value, field: &str) -> &'a str {
    json.pointer(&format!("/data/{field}"))
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("/data/{field} string present; body={json}"))
}

fn error_code(json: &serde_json::Value) -> &str {
    json.pointer("/error/code")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("/error/code string present; body={json}"))
}

fn count_span_news(captured: &str, span_name: &str) -> usize {
    let needle = format!("{span_name}: new");
    captured
        .lines()
        .filter(|line| line.contains(&needle))
        .count()
}

#[tokio::test(flavor = "current_thread")]
async fn lease_lifecycle_register_renew_cleanup_then_stale_renew_404() {
    let writer = CapturingWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .with_target(false)
        .with_level(false)
        .without_time()
        .with_span_events(FmtSpan::NEW)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let leases = LeaseRegistry::new();
    let router = build_router(sdk_state(leases.clone()));

    // 1. Pending: issue a real SDK register challenge.
    let (challenge_status, challenge_json) = post_json(
        router.clone(),
        "/v1/sdk/register-challenge",
        register_challenge_body(),
        Some(SIWE_DOMAIN),
    )
    .await;
    assert_eq!(
        challenge_status,
        StatusCode::CREATED,
        "register-challenge body={challenge_json}",
    );
    let challenge_id = data_str(&challenge_json, "challenge_id").to_owned();
    let siwe_message = data_str(&challenge_json, "siwe_message").to_owned();

    // 2. Sign the SIWE text with the deterministic secp256k1 test key.
    let siwe_signature = sign_siwe(&siwe_message);

    // 3. Active: consume the challenge through the SDK register route.
    let (register_status, register_json) = post_json(
        router.clone(),
        "/v1/sdk/register",
        register_body(&challenge_id, &siwe_message, &siwe_signature),
        None,
    )
    .await;
    assert_eq!(
        register_status,
        StatusCode::CREATED,
        "register body={register_json}",
    );
    let original_token = data_str(&register_json, "access_token").to_owned();
    assert_eq!(leases.lease_count(), 1, "register creates one active lease");

    // 4. Active again: renew through the SDK route and capture the next token.
    let (renew_status, renew_json) = post_json(
        router.clone(),
        "/v1/sdk/renew",
        json!({ "access_token": original_token }),
        None,
    )
    .await;
    assert_eq!(renew_status, StatusCode::OK, "renew body={renew_json}");
    let renewed_token = data_str(&renew_json, "access_token").to_owned();
    let renewed_expires_at: Timestamp = data_str(&renew_json, "expires_at")
        .parse()
        .expect("renew expires_at parses as timestamp");
    assert!(
        !renewed_token.is_empty(),
        "renew returns the next access token"
    );

    // 5–6. Expired: explicitly sweep just past the renewed lease expiry.
    let future_now = renewed_expires_at
        .checked_add(SignedDuration::from_secs(1))
        .expect("future timestamp past renewed expiry");
    let cleanup = leases.cleanup_expired(future_now).await;
    assert_eq!(cleanup.dropped_leases.len(), 1, "one lease swept");
    assert_eq!(cleanup.dropped_challenges, 0, "challenge was consumed");
    assert_eq!(leases.lease_count(), 0, "registry empty after sweep");

    // 7. The renewed token is still cryptographically fresh according to the
    // handler's real wall clock, but its registry lease was swept.
    let (stale_status, stale_json) = post_json(
        router,
        "/v1/sdk/renew",
        json!({ "access_token": renewed_token }),
        None,
    )
    .await;
    assert_eq!(
        stale_status,
        StatusCode::NOT_FOUND,
        "stale renew body={stale_json}",
    );
    assert_eq!(error_code(&stale_json), "lease_not_found");

    // 8. Span smoke gate: current handlers expose instrumented spans for the
    // SDK-router state-changing calls. Expiry itself is a direct registry sweep,
    // so there is no SDK span to assert for cleanup without adding production
    // instrumentation solely for this test.
    let captured = writer.snapshot();
    assert_eq!(
        count_span_news(&captured, "sdk.register_challenge"),
        1,
        "one register-challenge span; captured={captured:?}",
    );
    assert_eq!(
        count_span_news(&captured, "sdk.register"),
        1,
        "one register span; captured={captured:?}",
    );
    assert_eq!(
        count_span_news(&captured, "sdk.renew"),
        2,
        "two renew spans: successful rotation plus stale-token 404; captured={captured:?}",
    );
}
