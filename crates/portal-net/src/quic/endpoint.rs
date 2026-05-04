//! quinn `Endpoint` constructor with ALPN `portal/2` + dual-stack bind +
//! aws-lc-rs crypto + ed25519 self-signed cert per R2/R13.
//!
//! Two role-tagged constructors are exposed:
//!
//! - [`Endpoint::server`] — relay-side listener. Generates a self-signed X.509
//!   wrapping the supplied [`QuicIdentityKey`] (ed25519). Cert-chain validity
//!   is intentionally not what authenticates the peer; the SDK pins the
//!   32-byte ed25519 public key extracted from the leaf cert's
//!   `SubjectPublicKeyInfo` via [`SpkiPinVerifier`].
//! - [`Endpoint::client`] — SDK-side dialer. Installs an
//!   [`SpkiPinVerifier`] keyed on the relay's pinned ed25519 public key.
//!
//! Both endpoints run TLS 1.3 only, ALPN-restricted to `portal/2`, on a
//! dual-stack `IPV6_V6ONLY=false` UDP socket.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use portal_wire::constants::ALPN;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use secrecy::{ExposeSecret as _, SecretBox};

use crate::dual_stack::bind_dual_stack_udp;
use crate::error::NetError;
use crate::quic::identity::QuicIdentityKey;
use crate::quic::verifier::SpkiPinVerifier;

/// Mode of an [`Endpoint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointRole {
    /// Server-side endpoint (relay listener).
    Server,
    /// Client-side endpoint (SDK dialer).
    Client,
}

/// Owned QUIC endpoint with role-tagged transport configuration.
#[derive(Clone)]
pub struct Endpoint {
    inner: quinn::Endpoint,
    role: EndpointRole,
}

impl Endpoint {
    /// Construct a server-mode endpoint listening on `addr`. Consumes the
    /// `QuicIdentityKey` by move (R2 trust-boundary handoff).
    ///
    /// # Errors
    ///
    /// Returns [`NetError::Identity`] on cert/key encoding errors,
    /// [`NetError::Tls`] on rustls config errors, [`NetError::BindFailed`]
    /// or [`NetError::Io`] on socket bind errors.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "R2 trust-boundary: the SecretBox<QuicIdentityKey> is moved into \
                  the endpoint for the lifetime of the listener; passing by reference \
                  would invite caller misuse (re-using a key across endpoints)."
    )]
    pub fn server(addr: SocketAddr, key: SecretBox<QuicIdentityKey>) -> Result<Self, NetError> {
        let (cert_der, priv_der) = self_signed_cert(&key)?;
        let mut rustls_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| {
            NetError::Tls(rustls::Error::General(format!(
                "rustls protocol versions: {e}",
            )))
        })?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], priv_der)?;
        rustls_cfg.alpn_protocols = vec![ALPN.to_vec()];
        // Quinn requires the ServerConfig to be wrapped in `QuicServerConfig`
        // which validates that TLS 1.3 is enabled and an initial cipher suite
        // is available (AES-128-GCM-SHA256 is provided by aws-lc-rs).
        let quic_server_cfg = QuicServerConfig::try_from(rustls_cfg)
            .map_err(|e| NetError::Tls(rustls::Error::General(format!("quic server cfg: {e}"))))?;
        let mut quinn_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_server_cfg));
        quinn_cfg.transport_config(Arc::new(default_transport_config()));

        let socket = bind_dual_stack_udp(addr.ip(), addr.port(), false)?;
        let inner = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(quinn_cfg),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(NetError::Io)?;
        Ok(Self {
            inner,
            role: EndpointRole::Server,
        })
    }

    /// Construct a client-mode endpoint with an SPKI-pinning verifier.
    /// `pinned_relay_pubkey` is the ed25519 public key carried in the
    /// `RelayDescriptor` (greenfield identity pin per Architectural Pillars).
    /// Cert chain validity, hostname, and expiry are intentionally NOT
    /// checked — the verifier extracts the 32-byte ed25519 public key from
    /// the leaf cert's `SubjectPublicKeyInfo` and matches it against the pin.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::Tls`] on rustls config errors, [`NetError::BindFailed`]
    /// or [`NetError::Io`] on socket bind errors.
    pub fn client(
        bind_addr: SocketAddr,
        pinned_relay_pubkey: VerifyingKey,
    ) -> Result<Self, NetError> {
        let mut client_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| {
            NetError::Tls(rustls::Error::General(format!(
                "rustls protocol versions: {e}",
            )))
        })?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SpkiPinVerifier::new(pinned_relay_pubkey)))
        .with_no_client_auth();
        client_cfg.alpn_protocols = vec![ALPN.to_vec()];
        let quic_client_cfg = QuicClientConfig::try_from(client_cfg)
            .map_err(|e| NetError::Tls(rustls::Error::General(format!("quic client cfg: {e}"))))?;
        let mut quinn_cfg = quinn::ClientConfig::new(Arc::new(quic_client_cfg));
        quinn_cfg.transport_config(Arc::new(default_transport_config()));

        let socket = bind_dual_stack_udp(bind_addr.ip(), bind_addr.port(), false)?;
        let mut inner = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(NetError::Io)?;
        inner.set_default_client_config(quinn_cfg);
        Ok(Self {
            inner,
            role: EndpointRole::Client,
        })
    }

    /// The local socket the endpoint is bound to.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::Io`] if the underlying socket has been closed.
    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        self.inner.local_addr().map_err(NetError::Io)
    }

    /// Role discriminant set at construction.
    #[must_use]
    pub const fn role(&self) -> EndpointRole {
        self.role
    }

    /// Server-side accept. Returns the next `quinn::Incoming` to be `await`-ed
    /// into a connection.
    ///
    /// Returns `Ok(None)` if the endpoint has been closed; returns
    /// [`NetError::RoleMismatch`] if invoked on a [`EndpointRole::Client`]
    /// endpoint (the underlying quinn endpoint has no `ServerConfig` and
    /// would otherwise hang indefinitely).
    ///
    /// # Errors
    ///
    /// Returns [`NetError::RoleMismatch`] when the role is not `Server`.
    pub async fn accept(&self) -> Result<Option<quinn::Incoming>, NetError> {
        if self.role != EndpointRole::Server {
            return Err(NetError::RoleMismatch {
                method: "accept",
                found: "Client",
            });
        }
        Ok(self.inner.accept().await)
    }

    /// Client-side connect. `server_name` is purely cosmetic — the SPKI-pin
    /// verifier ignores hostname matching. Convention: pass the relay's
    /// identity-key hex.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::RoleMismatch`] if invoked on a
    /// [`EndpointRole::Server`] endpoint, or [`NetError::Connect`] on a
    /// connection-construction failure (invalid `server_name`, missing
    /// client config, transport-init error).
    pub fn connect(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<quinn::Connecting, NetError> {
        if self.role != EndpointRole::Client {
            return Err(NetError::RoleMismatch {
                method: "connect",
                found: "Server",
            });
        }
        self.inner
            .connect(addr, server_name)
            .map_err(|e| NetError::Connect(e.to_string()))
    }
}

/// Default transport config: 15s keep-alive, 60s idle timeout, 16 max bidi
/// streams, 64 KiB send/receive datagram buffers. Mirrors Go's
/// `quicBackhaulConfig` with explicit datagram buffer sizing.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "Duration::from_mins is unstable on 1.95; from_secs(60) is the \
              MSRV-compatible idiom."
)]
fn default_transport_config() -> quinn::TransportConfig {
    let mut cfg = quinn::TransportConfig::default();
    cfg.keep_alive_interval(Some(Duration::from_secs(15)));
    // 60s is well within the VarInt budget (max 2^62 - 1 ms per RFC 9000 §16.1).
    // Compile-time-invariant; the unreachable error path is silenced via expect.
    #[expect(
        clippy::expect_used,
        reason = "60s is compile-time-invariant within VarInt budget; the only \
                  way this could fire is a quinn API regression."
    )]
    let idle: quinn::IdleTimeout = Duration::from_secs(60)
        .try_into()
        .expect("60s fits in VarInt — RFC 9000 §16.1");
    cfg.max_idle_timeout(Some(idle));
    cfg.max_concurrent_bidi_streams(16u32.into());
    cfg.datagram_receive_buffer_size(Some(64 * 1024));
    cfg.datagram_send_buffer_size(64 * 1024);
    cfg
}

/// Generate a self-signed X.509 wrapping the ed25519 keypair from the
/// `QuicIdentityKey`. The cert subject CN is the identity-key hex (cosmetic
/// only — the SDK pins on SPKI bytes, not chain validity).
///
/// `pub(crate)` so the verifier's tests can reuse the same cert-generation
/// path that production traffic flows through.
pub(crate) fn self_signed_cert(
    key: &SecretBox<QuicIdentityKey>,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), NetError> {
    use ed25519_dalek::pkcs8::EncodePrivateKey as _;

    let sk = key.expose_secret().signing_key();
    let pkcs8_der = sk
        .to_pkcs8_der()
        .map_err(|e| NetError::Identity(format!("PKCS#8 encode for cert: {e}")))?;
    let key_pair = rcgen::KeyPair::try_from(pkcs8_der.as_bytes())
        .map_err(|e| NetError::Identity(format!("rcgen keypair from pkcs8: {e}")))?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .map_err(|e| NetError::Identity(format!("rcgen params: {e}")))?;
    let pub_hex_short =
        sk.verifying_key()
            .to_bytes()
            .iter()
            .take(8)
            .fold(String::new(), |mut acc, b| {
                use std::fmt::Write as _;
                // `write!` on `String` is infallible; the discarded result is the
                // documented contract on the `core::fmt::Write` impl.
                let _ = write!(acc, "{b:02x}");
                acc
            });
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("portal-relay-{pub_hex_short}"),
    );
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| NetError::Identity(format!("rcgen self-sign: {e}")))?;
    let cert_der = cert.der().clone();
    let priv_der = PrivateKeyDer::try_from(pkcs8_der.as_bytes().to_vec())
        .map_err(|e| NetError::Identity(format!("priv key der: {e}")))?
        .clone_key();
    Ok((cert_der, priv_der))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests use generate_quic_identity_key + tokio runtime"
)]
mod tests {
    use super::*;
    use crate::quic::identity::{generate_quic_identity_key, quic_identity_verifying_key};

    #[tokio::test]
    async fn server_endpoint_binds_dual_stack_v6() {
        let key = generate_quic_identity_key();
        let endpoint = Endpoint::server("[::]:0".parse().unwrap(), key).unwrap();
        let local = endpoint.local_addr().unwrap();
        // R12 contract observable at the endpoint layer: requesting `[::]:0`
        // MUST yield an IPv6 socket. The `IPV6_V6ONLY=false` invariant on the
        // socket itself is asserted by `dual_stack::tests::
        // bind_dual_stack_udp_default_is_dual_stack`, which exercises the
        // exact helper this constructor calls; quinn's `Endpoint` does not
        // expose its underlying socket, so the only endpoint-observable
        // invariant here is the bound address family.
        assert!(
            local.is_ipv6(),
            "Endpoint::server on `[::]:0` must bind v6, got: {local:?}",
        );
        assert_eq!(endpoint.role(), EndpointRole::Server);
    }

    #[tokio::test]
    async fn client_endpoint_with_pinned_pubkey() {
        let server_key = generate_quic_identity_key();
        let pinned = quic_identity_verifying_key(&server_key);
        let client = Endpoint::client("[::]:0".parse().unwrap(), pinned).unwrap();
        assert_eq!(client.role(), EndpointRole::Client);
        let _ = client.local_addr().unwrap();
    }

    #[tokio::test]
    async fn server_endpoint_rejects_already_in_use() {
        let key1 = generate_quic_identity_key();
        let endpoint = Endpoint::server("127.0.0.1:0".parse().unwrap(), key1).unwrap();
        let bound_port = endpoint.local_addr().unwrap().port();
        let key2 = generate_quic_identity_key();
        let result = Endpoint::server(format!("127.0.0.1:{bound_port}").parse().unwrap(), key2);
        assert!(matches!(
            result,
            Err(NetError::BindFailed(_) | NetError::Io(_)),
        ));
    }

    #[tokio::test]
    async fn server_alpn_is_portal_2_only() {
        // Indirect assertion: build the ServerConfig via the same path the
        // public Endpoint::server uses, read back alpn_protocols.
        let key = generate_quic_identity_key();
        let (cert_der, priv_der) = self_signed_cert(&key).unwrap();
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], priv_der)
        .unwrap();
        cfg.alpn_protocols = vec![ALPN.to_vec()];
        assert_eq!(cfg.alpn_protocols, vec![b"portal/2".to_vec()]);
        assert_eq!(
            ALPN, b"portal/2",
            "portal_wire::constants::ALPN must be the canonical greenfield ALPN",
        );
    }

    #[tokio::test]
    async fn connect_rejects_server_role() {
        let key = generate_quic_identity_key();
        let endpoint = Endpoint::server("127.0.0.1:0".parse().unwrap(), key).unwrap();
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let result = endpoint.connect(target, "ignored.invalid");
        assert!(
            matches!(
                result,
                Err(NetError::RoleMismatch {
                    method: "connect",
                    found: "Server",
                }),
            ),
            "connect on Server endpoint must return structured RoleMismatch: {result:?}",
        );
    }

    #[tokio::test]
    async fn accept_rejects_client_role() {
        let server_key = generate_quic_identity_key();
        let pinned = quic_identity_verifying_key(&server_key);
        let client = Endpoint::client("[::]:0".parse().unwrap(), pinned).unwrap();
        let result = client.accept().await;
        assert!(
            matches!(
                result,
                Err(NetError::RoleMismatch {
                    method: "accept",
                    found: "Client",
                }),
            ),
            "accept on Client endpoint must return structured RoleMismatch: {result:?}",
        );
    }
}
