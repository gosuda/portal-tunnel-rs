//! Integration tests for `GET /v1/sdk/connect` (Phase 5 SDK-API S8).
//!
//! The handler verifies a lease access token from the
//! `X-Portal-Access-Token` header, checks registry state, rejects
//! HTTP/2+ before hijack, and starts the HTTP/1.1 upgrade contract. The
//! oneshot positive-path test pins the Axum admission response; the real
//! TCP positive-path test sends an HTTP/1.1 upgrade request through
//! hyper and observes the raw hijack prelude on the upgraded stream.
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
use portal_relay::policy::{IpFilter, PolicyRuntime, ProxyTrust, ReputationEngine};
use portal_relay::state::LeaseRegistry;
use portal_relay::state::lease_registry::{IdentityKey, LeaseRecord};
use portal_relay::state::lease_token;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
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
    sdk_state_with_policy(leases, PolicyRuntime::new())
}

fn sdk_state_with_policy(leases: LeaseRegistry, policy: PolicyRuntime) -> SdkState {
    let (signing_key, verifier) = token_keys();
    SdkState {
        leases,
        policy: Arc::new(policy),
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
    send_connect_with_xff(router, token, version, None).await
}

async fn send_connect_with_xff(
    router: Router,
    token: Option<&str>,
    version: Version,
    xff: Option<&str>,
) -> (StatusCode, Option<String>, Vec<u8>) {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri("/v1/sdk/connect")
        .version(version)
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, "portal-tunnel");
    if let Some(token) = token {
        builder = builder.header(lease_token::ACCESS_TOKEN_HEADER, token);
    }
    if let Some(xff) = xff {
        builder = builder.header("x-forwarded-for", xff);
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

async fn read_admission_headers(stream: &mut TcpStream) -> (Vec<u8>, Vec<u8>) {
    let mut response = Vec::new();
    let mut buf = [0u8; 128];
    loop {
        let n = stream.read(&mut buf).await.expect("read response");
        assert_ne!(n, 0, "connection closed before admission headers");
        response.extend_from_slice(&buf[..n]);
        if let Some(pos) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            let split = pos + 4;
            let remainder = response.split_off(split);
            return (response, remainder);
        }
    }
}

async fn read_raw_prelude(stream: &mut TcpStream, mut buffered: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let expected = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
    assert!(
        expected.starts_with(&buffered) || buffered.starts_with(expected),
        "bytes after admission headers did not start the raw prelude: {buffered:?}"
    );
    if buffered.len() < expected.len() {
        let already_buffered = buffered.len();
        buffered.resize(expected.len(), 0);
        stream
            .read_exact(&mut buffered[already_buffered..])
            .await
            .expect("read raw hijack prelude");
    }
    let tail = buffered.split_off(expected.len());
    assert_eq!(buffered, expected);
    (buffered, tail)
}

async fn post_connect_status() -> StatusCode {
    let router = build_router(sdk_state(LeaseRegistry::new()));
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/sdk/connect")
        .body(Body::empty())
        .expect("request build");
    router
        .oneshot(request)
        .await
        .expect("oneshot service")
        .status()
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

    assert_eq!(status, StatusCode::SWITCHING_PROTOCOLS, "body={body:?}");
    assert_eq!(connection.as_deref(), Some("upgrade"));
    assert!(
        body.is_empty(),
        "oneshot admission response has no body; raw prelude requires a real upgraded stream"
    );
}

#[tokio::test]
async fn connect_http11_real_tcp_upgrade_writes_raw_prelude() {
    let leases = LeaseRegistry::new();
    let identity = fixture_identity();
    let expires_at = register_fixture_lease(&leases, identity).await;
    let token = issue_token(identity, expires_at);
    let router = build_sdk_router(sdk_state(leases));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("listener local addr");

    let mut server = JoinSet::new();
    server.spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("serve sdk router");
    });

    let mut stream = TcpStream::connect(addr)
        .await
        .expect("connect to test server");
    let request = format!(
        "GET /v1/sdk/connect HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Connection: upgrade\r\n\
         Upgrade: portal-tunnel\r\n\
         {}: {token}\r\n\
         \r\n",
        lease_token::ACCESS_TOKEN_HEADER,
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write sdk connect request");

    let (admission, buffered) = read_admission_headers(&mut stream).await;
    let admission = String::from_utf8(admission).expect("admission response utf8");
    assert!(
        admission.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
        "admission response was {admission:?}"
    );
    assert!(
        admission
            .to_ascii_lowercase()
            .contains("connection: upgrade\r\n"),
        "admission response was {admission:?}"
    );
    assert!(
        admission
            .to_ascii_lowercase()
            .contains("upgrade: portal-tunnel\r\n"),
        "admission response was {admission:?}"
    );

    let (prelude, tail) = read_raw_prelude(&mut stream, buffered).await;
    assert_eq!(
        prelude,
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
    );
    assert!(tail.is_empty(), "no bridge bytes are emitted in S8");

    server.abort_all();
}

#[tokio::test]
async fn connect_trusted_proxy_xff_banned_client_returns_401_ip_banned() {
    let banned_client: IpAddr = "203.0.113.10".parse().expect("banned client ip");
    let filter = IpFilter::new();
    filter.ban(banned_client);
    let policy = PolicyRuntime::new()
        .with_ip_filter(filter)
        .with_proxy_trust(ProxyTrust::from_trusted_ips(vec![TEST_PEER.ip()]));
    let leases = LeaseRegistry::new();
    let identity = fixture_identity();
    let expires_at = register_fixture_lease(&leases, identity).await;
    let token = issue_token(identity, expires_at);
    let router = build_router(sdk_state_with_policy(leases, policy));

    let (status, _, body) =
        send_connect_with_xff(router, Some(&token), Version::HTTP_11, Some("203.0.113.10")).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body={body:?}");
    assert_eq!(error_code(&body), "ip_banned");
}

#[tokio::test]
async fn connect_untrusted_proxy_spoofed_xff_ban_uses_remote_ip_only() {
    let banned_client: IpAddr = "203.0.113.10".parse().expect("banned client ip");
    let filter = IpFilter::new();
    filter.ban(banned_client);
    let leases = LeaseRegistry::new();
    let identity = fixture_identity();
    let expires_at = register_fixture_lease(&leases, identity).await;
    let token = issue_token(identity, expires_at);
    let router = build_router(sdk_state_with_policy(
        leases,
        PolicyRuntime::new().with_ip_filter(filter),
    ));

    let (status, connection, body) =
        send_connect_with_xff(router, Some(&token), Version::HTTP_11, Some("203.0.113.10")).await;

    assert_eq!(status, StatusCode::SWITCHING_PROTOCOLS, "body={body:?}");
    assert_eq!(connection.as_deref(), Some("upgrade"));
    assert!(body.is_empty());

    let filter = IpFilter::new();
    filter.ban(TEST_PEER.ip());
    let leases = LeaseRegistry::new();
    let expires_at = register_fixture_lease(&leases, identity).await;
    let token = issue_token(identity, expires_at);
    let router = build_router(sdk_state_with_policy(
        leases,
        PolicyRuntime::new().with_ip_filter(filter),
    ));

    let (status, _, body) =
        send_connect_with_xff(router, Some(&token), Version::HTTP_11, Some("203.0.113.10")).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body={body:?}");
    assert_eq!(error_code(&body), "ip_banned");
}

#[tokio::test]
async fn connect_post_method_is_not_supported() {
    assert_eq!(post_connect_status().await, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn sdk_hop_route_is_not_mounted() {
    assert_eq!(post_hop(Method::POST).await, StatusCode::NOT_FOUND);
    assert_eq!(post_hop(Method::DELETE).await, StatusCode::NOT_FOUND);
}
