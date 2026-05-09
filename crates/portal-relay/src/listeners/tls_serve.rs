//! Async HTTPS listener accept loop helper.
//!
//! Binds a [`tokio::net::TcpListener`], performs TLS handshake via
//! [`tokio_rustls::TlsAcceptor`], and serves an [`axum::Router`] over
//! HTTP/1 or HTTP/2 using [`hyper_util::server::conn::auto::Builder`].

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing;

/// Errors emitted by the HTTPS listener accept loop.
#[derive(Debug, thiserror::Error)]
pub enum ListenerError {
    /// Underlying IO error (bind, accept, or `local_addr`).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
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
                                Ok(svc) => TowerToHyperService::new(svc),
                                Err(infallible) => match infallible {},
                            };
                            let io = hyper_util::rt::TokioIo::new(tls_stream);
                            let builder = ConnBuilder::new(TokioExecutor::new());
                            if let Err(e) = builder.serve_connection_with_upgrades(io, service).await {
                                tracing::debug!(error = %e, peer = %peer_addr, "connection error");
                            } else {
                                tracing::debug!(peer = %peer_addr, "connection closed");
                            }
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
}
