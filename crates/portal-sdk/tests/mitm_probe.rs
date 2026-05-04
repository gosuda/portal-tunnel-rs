//! Behavioral gate for the RFC 5705 MITM-probe EKM derivation.
//!
//! These tests drive a full rustls handshake entirely in memory (no
//! sockets, no async runtime) using the standard pump pattern, then
//! assert the bilateral-agreement contract: client and server must
//! derive identical 32-byte EKM bytes from the canonical
//! `portal-tunnel/mitm-probe/v2` label.
//!
//! They also pin the failure mode that callers depend on for
//! ordering: deriving before the handshake completes returns
//! [`portal_sdk::MitmError::ExporterFailed`] rather than silently
//! producing zeros or a partial transcript.

#![expect(
    clippy::expect_used,
    reason = "behavioral gate — test-only constructors"
)]

use std::sync::Arc;

use portal_sdk::{MitmError, PROBE_EKM_LEN, derive_probe_ekm};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, ServerConfig,
    ServerConnection, SignatureScheme,
};

/// `ServerCertVerifier` used only in this test that accepts any peer
/// certificate. The probe contract is independent of certificate
/// trust — handshake completion is what gates exporter access — so a
/// noop verifier keeps the in-memory pump self-contained.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn build_server_config() -> Arc<ServerConfig> {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("rcgen self-signed cert");
    let cert_der = CertificateDer::from(issued.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(issued.signing_key.serialize_der().into());

    let cfg = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("server protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("single cert");
    Arc::new(cfg)
}

fn build_client_config() -> Arc<ClientConfig> {
    let cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    Arc::new(cfg)
}

/// Drive the in-memory pump until both sides report `is_handshaking()
/// == false`, with a hard cap to fail loudly instead of spinning if a
/// future rustls version changes the state machine.
fn complete_handshake(client: &mut ClientConnection, server: &mut ServerConnection) {
    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            return;
        }

        if client.wants_write() {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).expect("client write_tls");
            let mut cursor = buf.as_slice();
            while !cursor.is_empty() {
                server.read_tls(&mut cursor).expect("server read_tls");
            }
            server
                .process_new_packets()
                .expect("server process_new_packets");
        }

        if server.wants_write() {
            let mut buf = Vec::new();
            server.write_tls(&mut buf).expect("server write_tls");
            let mut cursor = buf.as_slice();
            while !cursor.is_empty() {
                client.read_tls(&mut cursor).expect("client read_tls");
            }
            client
                .process_new_packets()
                .expect("client process_new_packets");
        }
    }

    assert!(
        !client.is_handshaking() && !server.is_handshaking(),
        "handshake did not converge in 16 pump iterations",
    );
}

#[test]
fn bilateral_ekm_agreement() {
    // Both configs are built via `builder_with_provider(provider())`
    // — we never touch the rustls process-global default provider, so
    // these tests don't leak ordering-dependent state into the rest
    // of the suite.
    let server_cfg = build_server_config();
    let client_cfg = build_client_config();

    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut client = ClientConnection::new(client_cfg, server_name).expect("client conn");
    let mut server = ServerConnection::new(server_cfg).expect("server conn");

    complete_handshake(&mut client, &mut server);

    let client_ekm = derive_probe_ekm(&client).expect("client EKM after handshake");
    let server_ekm = derive_probe_ekm(&server).expect("server EKM after handshake");

    assert_eq!(client_ekm.len(), PROBE_EKM_LEN);
    assert_eq!(
        client_ekm, server_ekm,
        "client and server must derive identical EKM bytes",
    );
    // Sanity: the exporter must not return all-zero bytes for a
    // healthy handshake.
    assert!(client_ekm.iter().any(|b| *b != 0), "EKM is all zeros");
}

#[test]
fn derive_before_handshake_fails() {
    // `ClientConfig` with an empty root store is fine here — we never
    // pump packets, so the verifier is never called. We also stay off
    // the process-global crypto provider for ordering safety.
    let cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let server_name = ServerName::try_from("localhost").expect("server name");
    let client = ClientConnection::new(Arc::new(cfg), server_name).expect("client conn");

    assert!(
        client.is_handshaking(),
        "fresh ClientConnection must report is_handshaking=true"
    );

    let err = derive_probe_ekm(&client).expect_err("EKM must fail pre-handshake");
    assert!(matches!(err, MitmError::ExporterFailed(_)));
}
