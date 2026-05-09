//! Async HTTPS listener accept loop helper.
//!
//! Binds a [`tokio::net::TcpListener`], performs TLS handshake via
//! [`tokio_rustls::TlsAcceptor`], and serves an [`axum::Router`] over
//! HTTP/1 or HTTP/2 using [`hyper_util::server::conn::auto::Builder`].

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use compact_str::CompactString;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing;
use x509_cert::der::Decode;

use crate::keyless::SubjectExtension;

/// Errors emitted by the HTTPS listener accept loop.
#[derive(Debug, thiserror::Error)]
pub enum ListenerError {
    /// Underlying IO error (bind, accept, or `local_addr`).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Shared per-connection serving logic
// ---------------------------------------------------------------------------

/// Serve a single TLS connection to completion.
///
/// `service` is the per-connection axum service (either plain or wrapped with
/// `InjectExtension`).  `handshake_label` is the tracing label used for the
/// handshake-failure log (e.g. `"TLS"` or `"mTLS"`).
async fn serve_connection<S>(
    tls_stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    peer_addr: SocketAddr,
    service: S,
    handshake_label: &'static str,
) where
    S: tower::Service<
            http::Request<hyper::body::Incoming>,
            Response = http::Response<axum::body::Body>,
        > + Clone
        + Send
        + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    S::Future: Send + 'static,
{
    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let builder = ConnBuilder::new(TokioExecutor::new());
    if let Err(e) = builder
        .serve_connection_with_upgrades(io, TowerToHyperService::new(service))
        .await
    {
        tracing::debug!(error = %e, peer = %peer_addr, "{handshake_label} connection error");
    } else {
        tracing::debug!(peer = %peer_addr, "connection closed");
    }
}

/// Accept TLS connections on `listener` and serve `router` until `cancel`
/// is triggered.
///
/// # Errors
///
/// Returns [`ListenerError::Io`] if the bound address cannot be read.
pub async fn serve_tls_router(
    listener: TcpListener,
    tls_cfg: rustls::ServerConfig,
    router: Router,
    cancel: CancellationToken,
) -> Result<(), ListenerError> {
    tracing::info!(addr = %listener.local_addr()?, "HTTPS listener ready");

    let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((tcp_stream, peer_addr)) => {
                        let acceptor = acceptor.clone();
                        let router = router.clone();
                        #[expect(clippy::disallowed_methods, reason = "HTTPS listener accept loop spawns per-connection handler tasks")]
                        tokio::spawn(async move {
                            let tls_stream = match acceptor.accept(tcp_stream).await {
                                Ok(tls) => tls,
                                Err(e) => {
                                    tracing::debug!(error = %e, peer = %peer_addr, "TLS handshake failed");
                                    return;
                                }
                            };

                            let mut make_service = router.into_make_service_with_connect_info::<SocketAddr>();
                            let service = match tower::ServiceExt::oneshot(&mut make_service, peer_addr).await {
                                Ok(svc) => svc,
                                Err(infallible) => match infallible {},
                            };
                            serve_connection(tls_stream, peer_addr, service, "TLS").await;
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "accept error");
                    }
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// serve_mtls_router — mTLS with client-cert subject extraction
// ---------------------------------------------------------------------------

/// Tower service wrapper that injects a [`SubjectExtension`] into every
/// request before delegating to the inner service.
///
/// This is intentionally a local type — it only needs to exist inside the
/// per-connection accept task so the mTLS-validated subject DN reaches the
/// axum handler extensions.
#[derive(Clone, Debug)]
struct InjectExtension<S> {
    inner: S,
    subject: CompactString,
}

impl<S, ReqBody> tower::Service<http::Request<ReqBody>> for InjectExtension<S>
where
    S: tower::Service<http::Request<ReqBody>>,
    S::Error: std::fmt::Display,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<ReqBody>) -> Self::Future {
        req.extensions_mut()
            .insert(SubjectExtension(self.subject.clone()));
        self.inner.call(req)
    }
}

/// Accept **mTLS** connections on `listener`, extract the validated client
/// certificate's subject DN, and serve `router` with that subject injected
/// as a [`SubjectExtension`] on every request.
///
/// The accept-loop structure, error handling, and tracing follow
/// [`serve_tls_router`] exactly.
///
/// # Errors
///
/// Returns [`ListenerError::Io`] if the bound address cannot be read.
pub async fn serve_mtls_router(
    listener: TcpListener,
    tls_cfg: rustls::ServerConfig,
    router: Router,
    cancel: CancellationToken,
) -> Result<(), ListenerError> {
    tracing::info!(addr = %listener.local_addr()?, "mTLS listener ready");

    let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((tcp_stream, peer_addr)) => {
                        let acceptor = acceptor.clone();
                        let router = router.clone();
                        #[expect(clippy::disallowed_methods, reason = "mTLS listener accept loop spawns per-connection handler tasks")]
                        tokio::spawn(async move {
                            let tls_stream = match acceptor.accept(tcp_stream).await {
                                Ok(tls) => tls,
                                Err(e) => {
                                    tracing::debug!(error = %e, peer = %peer_addr, "mTLS handshake failed");
                                    return;
                                }
                            };

                            // Extract peer certificate chain and parse the
                            // leaf subject DN.
                            let subject = {
                                let (_, conn) = tls_stream.get_ref();
                                let peer_certs = match conn.peer_certificates() {
                                    Some(certs) if !certs.is_empty() => certs,
                                    _ => {
                                        tracing::debug!(peer = %peer_addr, "no peer certificates after mTLS handshake");
                                        return;
                                    }
                                };
                                let leaf = &peer_certs[0];
                                match x509_cert::Certificate::from_der(leaf.as_ref()) {
                                    Ok(cert) => {
                                        let dn = cert.tbs_certificate.subject.to_string();
                                        CompactString::new(dn)
                                    }
                                    Err(e) => {
                                        tracing::debug!(error = %e, peer = %peer_addr, "failed to parse peer certificate");
                                        return;
                                    }
                                }
                            };

                            let mut make_service = router.into_make_service_with_connect_info::<SocketAddr>();
                            let inner_service = match tower::ServiceExt::oneshot(&mut make_service, peer_addr).await {
                                Ok(svc) => svc,
                                Err(infallible) => match infallible {},
                            };
                            let service = InjectExtension {
                                inner: inner_service,
                                subject,
                            };
                            serve_connection(tls_stream, peer_addr, service, "mTLS").await;
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "accept error");
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only setup")]
mod tests {
    use super::*;
    use axum::routing::get;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    async fn hello() -> &'static str {
        "hello"
    }

    fn generate_self_signed_server_config() -> (rustls::ServerConfig, CertificateDer<'static>) {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        (cfg, cert_der)
    }

    #[derive(Debug)]
    struct SkipServerVerification;

    impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }

    #[tokio::test]
    #[expect(
        clippy::disallowed_methods,
        reason = "test runtime: server task spawned for cancellation"
    )]
    async fn serves_request_over_tls() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let (server_cfg, _cert_der) = generate_self_signed_server_config();
        #[expect(clippy::disallowed_methods, reason = "test-only router construction")]
        let router = Router::new().route("/", get(hello));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();

        let server_task = tokio::spawn(serve_tls_router(
            listener,
            server_cfg,
            router,
            cancel.clone(),
        ));

        // Give the server a moment to start.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client_cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_cfg));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(server_name, tcp).await.unwrap();

        let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        tls.write_all(request).await.unwrap();
        tls.flush().await.unwrap();

        let mut buf = Vec::with_capacity(4096);
        tls.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(
            response.contains("200 OK"),
            "expected 200 OK, got: {response}"
        );
        assert!(
            response.contains("hello"),
            "expected body 'hello', got: {response}"
        );

        cancel.cancel();
        let _ = server_task.await;
    }

    // -----------------------------------------------------------------------
    // mTLS helpers + tests
    // -----------------------------------------------------------------------

    /// Generate a CA, a server cert signed by the CA, and a client cert
    /// signed by the CA.  Returns `(server_config, client_config, ca_cert)`.
    fn generate_mtls_configs() -> (
        rustls::ServerConfig,
        rustls::ClientConfig,
        CertificateDer<'static>,
    ) {
        use rcgen::{BasicConstraints, DistinguishedName, DnType, IsCa, KeyUsagePurpose};

        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;

        // CA
        let ca_key = KeyPair::generate_for(alg).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut ca_dn = DistinguishedName::new();
        ca_dn.push(DnType::CommonName, "test-ca");
        ca_params.distinguished_name = ca_dn;
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_issuer = rcgen::Issuer::new(ca_params, ca_key);

        // Server cert
        let server_key = KeyPair::generate_for(alg).unwrap();
        let mut server_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        let mut server_dn = DistinguishedName::new();
        server_dn.push(DnType::CommonName, "localhost");
        server_params.distinguished_name = server_dn;
        let server_cert = server_params.signed_by(&server_key, &ca_issuer).unwrap();

        // Client cert
        let client_key = KeyPair::generate_for(alg).unwrap();
        let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut client_dn = DistinguishedName::new();
        client_dn.push(DnType::CommonName, "test-client");
        client_params.distinguished_name = client_dn;
        let client_cert = client_params.signed_by(&client_key, &ca_issuer).unwrap();

        let ca_der = ca_cert.der().clone();

        // Server config — require client certs
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_der.clone()).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots.clone()),
            provider.clone(),
        )
        .build()
        .unwrap();

        let server_cert_der = CertificateDer::from(server_cert.der().as_ref().to_vec());
        let server_cfg = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server_cert_der],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )
            .unwrap();

        // Client config — trust CA, present client cert
        let mut client_roots = rustls::RootCertStore::empty();
        client_roots.add(ca_der.clone()).unwrap();
        let client_cert_der = CertificateDer::from(client_cert.der().as_ref().to_vec());
        let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(client_roots)
            .with_client_auth_cert(
                vec![client_cert_der],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der())),
            )
            .unwrap();

        (server_cfg, client_cfg, ca_der)
    }

    /// Handler that echoes the [`SubjectExtension`] back as the response body.
    async fn echo_subject(ext: Option<axum::Extension<SubjectExtension>>) -> String {
        match ext {
            Some(axum::Extension(subj)) => subj.0.to_string(),
            None => "missing-subject".to_owned(),
        }
    }

    #[tokio::test]
    #[expect(
        clippy::disallowed_methods,
        reason = "test runtime: server task spawned for cancellation"
    )]
    async fn serves_mtls_request_and_extracts_subject() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let (server_cfg, client_cfg, _ca_der) = generate_mtls_configs();
        #[expect(clippy::disallowed_methods, reason = "test-only router construction")]
        let router = Router::new().route("/", get(echo_subject));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();

        let server_task = tokio::spawn(serve_mtls_router(
            listener,
            server_cfg,
            router,
            cancel.clone(),
        ));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let connector = TlsConnector::from(Arc::new(client_cfg));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(server_name, tcp).await.unwrap();

        let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        tls.write_all(request).await.unwrap();
        tls.flush().await.unwrap();

        let mut buf = Vec::with_capacity(4096);
        tls.read_to_end(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf);

        assert!(
            response.contains("200 OK"),
            "expected 200 OK, got: {response}"
        );
        // The rcgen subject for "test-client" contains a CN component.
        assert!(
            response.contains("test-client"),
            "expected subject containing 'test-client', got: {response}"
        );

        cancel.cancel();
        let _ = server_task.await;
    }

    #[tokio::test]
    #[expect(
        clippy::disallowed_methods,
        reason = "test runtime: server task spawned for cancellation"
    )]
    async fn mtls_without_client_cert_is_rejected() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let (server_cfg, _client_cfg, _ca_der) = generate_mtls_configs();
        #[expect(clippy::disallowed_methods, reason = "test-only router construction")]
        let router = Router::new().route("/", get(hello));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();

        let server_task = tokio::spawn(serve_mtls_router(
            listener,
            server_cfg,
            router,
            cancel.clone(),
        ));

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Client that does NOT present a client cert.
        // We skip server verification so we don't need the CA cert here.
        let client_cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_cfg));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from("localhost").unwrap();

        // The TLS handshake should fail because the server requires a client cert.
        // In TLS 1.3 the server may complete the handshake and then abort on first
        // I/O when it discovers no client cert was presented.
        let Ok(mut tls) = connector.connect(server_name, tcp).await else {
            // Handshake failed directly — rejection verified.
            cancel.cancel();
            let _ = server_task.await;
            return;
        };

        // Handshake succeeded but server may reject on first I/O.
        let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        let _ = tls.write_all(request).await;
        let _ = tls.flush().await;
        let mut buf = Vec::with_capacity(4096);
        let read_result = tls.read_to_end(&mut buf).await;
        assert!(
            read_result.is_err() || buf.is_empty(),
            "expected TLS stream to close without response when no client cert is presented"
        );

        cancel.cancel();
        let _ = server_task.await;
    }
}
