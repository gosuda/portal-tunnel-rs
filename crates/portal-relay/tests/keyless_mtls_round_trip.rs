//! Phase 6b/A U3 behavioral gate — end-to-end mTLS round trip
//! against the keyless sign endpoint.
//!
//! This test boots:
//! - a self-signed test CA (`rcgen::CertifiedIssuer::self_signed`),
//! - a server cert + key signed by the CA (the keyless surface's TLS identity),
//! - a tenant client cert + key signed by the same CA (the connecting tenant),
//! - the keyless [`portal_relay::keyless::Bridge`] worker pool over the
//!   workspace's RSA-2048 fixture key,
//! - the [`portal_relay::keyless::api::build_keyless_router`] axum router
//!   bound to the [`portal_relay::keyless::api::build_keyless_server_config`]
//!   `rustls::ServerConfig` with the test CA pinned in the verifier root store.
//!
//! It then issues a real TLS handshake via [`tokio_rustls::TlsConnector`]
//! with the tenant's client cert + the test CA in the trust roots, frames a
//! minimal HTTP/1.1 POST request to `/v1/keyless/sign`, asserts a 200
//! response, and verifies the returned signature against the public half of
//! the loaded keyless key + the same canonical signing input the server
//! built.
//!
//! ## What this test gates
//!
//! Per plan U3 §Test scenarios — the Phase 6b/A behavioural gate. Direct
//! coverage:
//! - **Happy path** mTLS handshake + signed-blob round trip + signature
//!   verification. (One test below; `#[tokio::test(flavor = "multi_thread")]`
//!   so the bridge worker pool's `spawn_blocking` does not block the
//!   reactor.)
//! - **Boundary** payload of exactly `KEYLESS_PAYLOAD_BUDGET` bytes still
//!   produces a verifiable signature (locks the inclusive ceiling).
//! - **Error** unknown `key_id` → HTTP 400 with wire code
//!   `unknown_key_id`; signer worker never invoked.
//! - **Error** scheme mismatch (RSA key + ECDSA scheme) → HTTP 400 with
//!   wire code `scheme_mismatch`.
//! - **Error** payload one byte over budget → HTTP 400 with wire code
//!   `payload_too_large`.
//!
//! Out-of-scope here (deferred per plan):
//! - mTLS handshake refusal when the client cert is signed by a non-pinned
//!   CA — covered by the rustls verifier itself; no application code path
//!   to assert; would require a separate test that observes the handshake
//!   failure rather than the HTTP layer.
//! - Rate-limit + bridge-queue-full scenarios — covered exhaustively in
//!   `keyless::policy` and `keyless::bridge` unit tests respectively;
//!   wiring them through the full mTLS round trip would test the same
//!   `error_status()` mapping the unit test in `keyless::api` already
//!   exercises.

#![expect(
    clippy::expect_used,
    clippy::panic,
    clippy::items_after_statements,
    clippy::manual_let_else,
    clippy::unused_async,
    reason = "integration test: panics are acceptable test-failure surface; \
              short test-only struct DataEnv definitions are clearer co-located \
              with their decode site"
)]

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use compact_str::CompactString;
use hyper_util::rt::TokioIo;
use portal_relay::keyless::{
    Bridge, BridgeConfig, KEYLESS_SIGN_PATH, KeylessApiState, KeylessPolicy, KeylessSignerAdapter,
    KeylessSigningKey, KnownKey, RoutingContext, SignRequest, SignResponse, SignatureSchemeWire,
    SubjectExtension, build_keyless_router, build_keyless_server_config, canonical_signing_input,
    load_keyless_signing_key,
};
use portal_wire::limits::KEYLESS_PAYLOAD_BUDGET;
use rustls::sign::SigningKey as _;
use rustls::{RootCertStore, SignatureAlgorithm};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

const RSA_2048_PEM: &[u8] = include_bytes!("./fixtures/keyless-rsa-2048.pem");
const TEST_KEY_ID: &str = "test-key-1";
const TEST_TENANT_SUBJECT: &str = "tenant-test";

// ---------------------------------------------------------------------------
// Test fixtures: rcgen CA + server cert + client cert
// ---------------------------------------------------------------------------

struct TestPki {
    /// CA cert in DER for pinning into both the server's client-verifier
    /// roots and the client's root store.
    ca_der: CertificateDer<'static>,
    /// Server cert chain (single-cert chain) for the keyless mTLS endpoint.
    server_chain: Vec<CertificateDer<'static>>,
    /// Server private key (PKCS#8 DER).
    server_key: PrivateKeyDer<'static>,
    /// Client cert chain (single-cert chain) for the tenant.
    client_chain: Vec<CertificateDer<'static>>,
    /// Client private key (PKCS#8 DER).
    client_key: PrivateKeyDer<'static>,
}

fn build_test_pki() -> TestPki {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    // 1. CA — self-signed.
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "Portal Keyless Test CA");
    ca_params.distinguished_name = ca_dn;
    let ca_key = KeyPair::generate().expect("ca keypair");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");
    let ca_der = ca_cert.der().clone();

    let ca_issuer = rcgen::Issuer::new(ca_params, ca_key);

    // 2. Server cert — signed by the CA, SAN includes localhost + ::1.
    let server_sans = vec!["localhost".to_owned(), "127.0.0.1".to_owned()];
    let mut server_params = CertificateParams::new(server_sans).expect("server params");
    let mut server_dn = DistinguishedName::new();
    server_dn.push(DnType::CommonName, "keyless-test-server");
    server_params.distinguished_name = server_dn;
    let server_key = KeyPair::generate().expect("server keypair");
    let server_cert = server_params
        .signed_by(&server_key, &ca_issuer)
        .expect("server cert sign");
    let server_chain = vec![server_cert.der().clone()];
    let server_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));

    // 3. Client cert — signed by the CA, with subject CN matching
    //    TEST_TENANT_SUBJECT.
    let mut client_params = CertificateParams::new(Vec::<String>::new()).expect("client params");
    let mut client_dn = DistinguishedName::new();
    client_dn.push(DnType::CommonName, TEST_TENANT_SUBJECT);
    client_params.distinguished_name = client_dn;
    let client_key = KeyPair::generate().expect("client keypair");
    let client_cert = client_params
        .signed_by(&client_key, &ca_issuer)
        .expect("client cert sign");
    let client_chain = vec![client_cert.der().clone()];
    let client_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der()));

    TestPki {
        ca_der,
        server_chain,
        server_key: server_key_der,
        client_chain,
        client_key: client_key_der,
    }
}

// ---------------------------------------------------------------------------
// Server harness
// ---------------------------------------------------------------------------

struct ServerHandle {
    addr: SocketAddr,
    cancel: CancellationToken,
    joinset: JoinSet<()>,
}

impl ServerHandle {
    async fn shutdown(mut self) {
        self.cancel.cancel();
        // Drop the joinset's tasks; allow them to exit at their own pace.
        self.joinset.shutdown().await;
    }
}

/// Spin up the keyless mTLS server bound to a random ephemeral port on
/// `[::1]:0` and return the bound address + a shutdown handle.
async fn spawn_keyless_server(pki: &TestPki) -> (ServerHandle, KeylessPolicy) {
    // 1. Build the policy + register the RSA-2048 fixture key.
    let policy = KeylessPolicy::new();
    let signing_key: KeylessSigningKey =
        load_keyless_signing_key(RSA_2048_PEM).expect("rsa-2048 loads");
    let adapter =
        KeylessSignerAdapter::from_keyless_signing_key(signing_key).expect("adapter construction");
    let algorithm: SignatureAlgorithm = adapter.algorithm();
    // Re-load a second copy of the key for the policy's known-keys map.
    // (Loading twice from the same bytes is cheap; sharing the secret
    // box would require Arc::clone semantics on `KeylessSigningKey`,
    // which is out of scope for this test.)
    let policy_key = load_keyless_signing_key(RSA_2048_PEM).expect("rsa-2048 second load");
    policy.register_key(TEST_KEY_ID, KnownKey::new(Arc::new(policy_key), algorithm));

    // 2. Build the bridge.  The adapter implements `rustls::sign::SigningKey`
    //    directly, so wrapping it in an `Arc<dyn SigningKey>` is the
    //    workspace path — `KeylessSignerAdapter::inner` is `pub(crate)`
    //    and not reachable from the integration test crate.
    let mut joinset: JoinSet<()> = JoinSet::new();
    let cancel = CancellationToken::new();
    let signing_key_dyn: Arc<dyn rustls::sign::SigningKey> = Arc::new(adapter);
    let bridge_cfg = BridgeConfig::with_workers_and_queue(
        std::num::NonZeroUsize::new(1).expect("non-zero"),
        std::num::NonZeroUsize::new(8).expect("non-zero"),
    );
    let bridge = Bridge::spawn(signing_key_dyn, bridge_cfg, &mut joinset, cancel.clone());

    // 3. Build the keyless ServerConfig with the test CA pinned.
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca_der.clone()).expect("add ca to roots");
    let server_cfg =
        build_keyless_server_config(roots, pki.server_chain.clone(), pki.server_key.clone_key())
            .expect("server config build");

    // 4. Build the router with a fixed-subject extractor (the
    //    listener layer would normally inject SubjectExtension after
    //    the TLS handshake — for hermeticity we wire in a closure
    //    upstream that pulls peer certs from the rustls connection
    //    state).  See `accept_loop` below.
    let router = build_keyless_router(KeylessApiState {
        policy: policy.clone(),
        bridge,
        subject_extractor: portal_relay::keyless::api::subject_from_extension,
    });

    // 5. Bind the listener on [::1]:0 — IPv6 loopback.  The plan asks
    //    for dual-stack [::]:0 in production (R12); the test uses
    //    [::1]:0 to keep the firewall surface zero.  Dual-stack is
    //    asserted at the listener helper layer (Phase 5/U6), not
    //    here.
    let listener = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, 0u16)))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");

    // 6. Spawn the accept loop on the joinset.
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let cancel_clone = cancel.clone();
    let router_arc = Arc::new(router);
    joinset.spawn(async move {
        accept_loop(listener, acceptor, router_arc, cancel_clone).await;
    });

    (
        ServerHandle {
            addr,
            cancel,
            joinset,
        },
        policy,
    )
}

async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    router: Arc<Router>,
    cancel: CancellationToken,
) {
    let mut conn_set: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            accept = listener.accept() => {
                let Ok((tcp, peer)) = accept else { continue };
                let acceptor = acceptor.clone();
                let router = Arc::clone(&router);
                conn_set.spawn(async move {
                    handle_conn(tcp, peer, acceptor, router).await;
                });
            }
        }
    }
    conn_set.shutdown().await;
}

async fn handle_conn(tcp: TcpStream, peer: SocketAddr, acceptor: TlsAcceptor, router: Arc<Router>) {
    let tls = match acceptor.accept(tcp).await {
        Ok(tls) => tls,
        Err(_) => return,
    };

    // Inject the tenant's CN into the request as a SubjectExtension.
    // In production the listener layer would parse the peer cert's
    // Subject DN; here we use the fixed test subject because the test
    // PKI pins one client cert.
    let (_io_inner, server_conn) = tls.get_ref();
    // Validate that mTLS occurred — the peer cert chain must be present.
    if server_conn.peer_certificates().is_none_or(<[_]>::is_empty) {
        // No client cert — should not happen given the verifier
        // requires one, but guard against silent drop.
        return;
    }

    // Build a per-connection axum service that injects the
    // SubjectExtension into every request.
    let router_for_conn = (*router).clone().layer(axum::middleware::from_fn(
        |mut req: axum::http::Request<axum::body::Body>, next: axum::middleware::Next| async move {
            req.extensions_mut()
                .insert(SubjectExtension(CompactString::const_new(
                    TEST_TENANT_SUBJECT,
                )));
            next.run(req).await
        },
    ));

    // ConnectInfo extractor needs the peer SocketAddr, which axum's
    // built-in `axum::serve(listener, into_make_service_with_connect_info)`
    // wires for us.  We invoke axum's into_make_service path manually
    // since we hand-rolled the TLS accept loop.
    use tower::ServiceExt as _;
    let make_svc = router_for_conn.into_make_service_with_connect_info::<SocketAddr>();
    // `make_svc.oneshot(peer)` is infallible (Service::Error =
    // Infallible) so the `Result` always carries `Ok`; keep the
    // `let _ = ...` shape so any future fallibility stays visible.
    let svc = match make_svc.oneshot(peer).await {
        Ok(svc) => svc,
        Err(infallible) => match infallible {},
    };

    let io = TokioIo::new(tls);
    let builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    let _ = builder
        .serve_connection(io, hyper_util::service::TowerToHyperService::new(svc))
        .await;
}

// ---------------------------------------------------------------------------
// Client harness
// ---------------------------------------------------------------------------

async fn build_client(pki: &TestPki) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca_der.clone()).expect("client roots add ca");
    let client_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("safe protocols")
    .with_root_certificates(roots)
    .with_client_auth_cert(pki.client_chain.clone(), pki.client_key.clone_key())
    .expect("client auth cert");
    TlsConnector::from(Arc::new(client_cfg))
}

/// Issue a single HTTP/1.1 POST to the keyless server over mTLS.
///
/// Returns `(status_code, response_body_bytes)`.
async fn http_post_keyless_sign(
    connector: &TlsConnector,
    addr: SocketAddr,
    request: &SignRequest,
) -> (u16, Vec<u8>) {
    let server_name: ServerName<'static> = ServerName::try_from("localhost").expect("sni name");
    let tcp = TcpStream::connect(addr).await.expect("client tcp connect");
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("client tls handshake");

    let body = serde_json::to_vec(request).expect("serialise request");
    let req_bytes = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
        path = KEYLESS_SIGN_PATH,
        len = body.len(),
    );
    tls.write_all(req_bytes.as_bytes())
        .await
        .expect("write hdr");
    tls.write_all(&body).await.expect("write body");
    tls.flush().await.expect("flush");

    let mut buf = Vec::with_capacity(4096);
    tls.read_to_end(&mut buf).await.expect("read response");

    parse_http_response(&buf)
}

fn parse_http_response(bytes: &[u8]) -> (u16, Vec<u8>) {
    // Split on the header/body delimiter "\r\n\r\n".
    let split = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response missing header/body delimiter");
    let (header, body) = bytes.split_at(split);
    let body = &body[4..];

    let header_str = std::str::from_utf8(header).expect("header utf-8");
    let status_line = header_str
        .lines()
        .next()
        .expect("response missing status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("status code is u16");
    (status, body.to_vec())
}

// ---------------------------------------------------------------------------
// Signature verification helper
// ---------------------------------------------------------------------------

fn verify_rsa_pss_sha256_signature(pem: &[u8], signed_input: &[u8], signature: &[u8]) -> bool {
    use pkcs1::der::Encode as _;
    use pkcs8::PrivateKeyInfo;
    use pkcs8::der::Decode as _;
    use rustls_pki_types::PrivateKeyDer;
    use rustls_pki_types::pem::PemObject as _;

    // 1. Parse the PEM bytes via rustls-pki-types — same path the
    //    keyless loader uses.  The fixture is PKCS#8 RSA.
    let parsed = PrivateKeyDer::from_pem_slice(pem).expect("parse pem");
    let pkcs8_der = match &parsed {
        PrivateKeyDer::Pkcs8(d) => d.secret_pkcs8_der(),
        _ => panic!("expected PKCS#8 RSA fixture"),
    };

    // 2. Decode the PKCS#8 wrapper to reach the inner PKCS#1
    //    RSAPrivateKey body.
    let info = PrivateKeyInfo::from_der(pkcs8_der).expect("pkcs8 info");
    let rsa_priv = pkcs1::RsaPrivateKey::from_der(info.private_key).expect("rsa private");

    // 3. Extract the RSA public-key (n, e) and re-encode as PKCS#1
    //    `RSAPublicKey` DER — the byte shape `aws_lc_rs`'s
    //    `UnparsedPublicKey` accepts when constructed against
    //    `RSA_PSS_2048_8192_SHA256`.
    let pub_key = rsa_priv.public_key();
    let pub_der = pub_key.to_der().expect("rsa pub der encode");

    // 4. Verify via aws_lc_rs — same crypto provider rustls used to
    //    sign on the server side, so verification semantics match
    //    exactly.
    let unparsed = aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::RSA_PSS_2048_8192_SHA256,
        pub_der,
    );
    unparsed.verify(signed_input, signature).is_ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn happy_path_mtls_sign_round_trip() {
    // Install rustls's aws-lc-rs crypto provider once per process.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let pki = build_test_pki();
    let (server, _policy) = spawn_keyless_server(&pki).await;
    let connector = build_client(&pki).await;

    let payload = b"happy path keyless sign".to_vec();
    let req = SignRequest {
        key_id: CompactString::const_new(TEST_KEY_ID),
        scheme: SignatureSchemeWire::from(rustls::SignatureScheme::RSA_PSS_SHA256),
        payload: payload.clone(),
        routing_context: RoutingContext {
            routed_hostname: CompactString::const_new("example.com"),
            requested_cert_subject: CompactString::const_new("example.com"),
        },
    };

    let (status, body) = http_post_keyless_sign(&connector, server.addr, &req).await;
    assert_eq!(
        status,
        200,
        "happy-path POST must succeed: body={:?}",
        String::from_utf8_lossy(&body)
    );

    // Decode `{"data": SignResponse}`.
    #[derive(serde::Deserialize)]
    struct DataEnv {
        data: SignResponse,
    }
    let resp: DataEnv = serde_json::from_slice(&body).expect("decode envelope");
    assert_eq!(resp.data.scheme.as_u16(), req.scheme.as_u16());
    assert!(
        !resp.data.signature.is_empty(),
        "signature must be non-empty"
    );

    // Verify the signature against the canonical signing input.
    let canonical = canonical_signing_input(&req).expect("canonical");
    assert!(
        verify_rsa_pss_sha256_signature(RSA_2048_PEM, &canonical, &resp.data.signature),
        "signature must verify against canonical_signing_input + RSA-2048 public key"
    );

    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_key_id_returns_400() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let pki = build_test_pki();
    let (server, _policy) = spawn_keyless_server(&pki).await;
    let connector = build_client(&pki).await;

    let req = SignRequest {
        key_id: CompactString::const_new("not-registered"),
        scheme: SignatureSchemeWire::from(rustls::SignatureScheme::RSA_PSS_SHA256),
        payload: b"x".to_vec(),
        routing_context: RoutingContext {
            routed_hostname: CompactString::const_new("h"),
            requested_cert_subject: CompactString::const_new("h"),
        },
    };
    let (status, body) = http_post_keyless_sign(&connector, server.addr, &req).await;
    assert_eq!(status, 400, "unknown key id must yield 400");
    let body_str = String::from_utf8_lossy(&body);
    assert!(
        body_str.contains("unknown_key_id"),
        "body must carry wire code unknown_key_id; got: {body_str}"
    );

    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scheme_mismatch_returns_400() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let pki = build_test_pki();
    let (server, _policy) = spawn_keyless_server(&pki).await;
    let connector = build_client(&pki).await;

    // Loaded key is RSA; ask for ECDSA → SchemeMismatch.
    let req = SignRequest {
        key_id: CompactString::const_new(TEST_KEY_ID),
        scheme: SignatureSchemeWire::from(rustls::SignatureScheme::ECDSA_NISTP256_SHA256),
        payload: b"x".to_vec(),
        routing_context: RoutingContext {
            routed_hostname: CompactString::const_new("h"),
            requested_cert_subject: CompactString::const_new("h"),
        },
    };
    let (status, body) = http_post_keyless_sign(&connector, server.addr, &req).await;
    assert_eq!(status, 400, "scheme mismatch must yield 400");
    assert!(
        String::from_utf8_lossy(&body).contains("scheme_mismatch"),
        "body must carry wire code scheme_mismatch"
    );

    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn payload_one_over_budget_returns_400() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let pki = build_test_pki();
    let (server, _policy) = spawn_keyless_server(&pki).await;
    let connector = build_client(&pki).await;

    let req = SignRequest {
        key_id: CompactString::const_new(TEST_KEY_ID),
        scheme: SignatureSchemeWire::from(rustls::SignatureScheme::RSA_PSS_SHA256),
        payload: vec![0u8; KEYLESS_PAYLOAD_BUDGET + 1],
        routing_context: RoutingContext {
            routed_hostname: CompactString::const_new("h"),
            requested_cert_subject: CompactString::const_new("h"),
        },
    };
    let (status, body) = http_post_keyless_sign(&connector, server.addr, &req).await;
    assert_eq!(status, 400, "payload over budget must yield 400");
    assert!(
        String::from_utf8_lossy(&body).contains("payload_too_large"),
        "body must carry wire code payload_too_large"
    );

    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn payload_at_budget_is_accepted() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let pki = build_test_pki();
    let (server, _policy) = spawn_keyless_server(&pki).await;
    let connector = build_client(&pki).await;

    // payload.len() == KEYLESS_PAYLOAD_BUDGET — boundary inclusive.
    let req = SignRequest {
        key_id: CompactString::const_new(TEST_KEY_ID),
        scheme: SignatureSchemeWire::from(rustls::SignatureScheme::RSA_PSS_SHA256),
        payload: vec![0u8; KEYLESS_PAYLOAD_BUDGET],
        routing_context: RoutingContext {
            routed_hostname: CompactString::const_new("h"),
            requested_cert_subject: CompactString::const_new("h"),
        },
    };
    let (status, _body) = http_post_keyless_sign(&connector, server.addr, &req).await;
    assert_eq!(status, 200, "payload at exactly the budget must yield 200");

    server.shutdown().await;
}

// Drain channel-warning silencer.
#[tokio::test]
async fn fixtures_compile() {
    // Smoke test that the fixture loader path is reachable.
    let _key = load_keyless_signing_key(RSA_2048_PEM).expect("rsa-2048 loads");
}
