//! SDK-side `ServerCertVerifier` that pins the relay's leaf cert on the
//! 32-byte ed25519 public key extracted from its `SubjectPublicKeyInfo`.
//!
//! Cert chain validity, hostname matching, and expiry are intentionally NOT
//! checked — this is a self-signed pinned-identity boundary.
//!
//! ## Why a custom verifier?
//!
//! The portal relay presents an ed25519 self-signed certificate generated at
//! runtime from its `QuicIdentityKey` (see [`crate::quic::endpoint`]). Cert
//! chain validation is meaningless against a self-signed leaf; what matters
//! is that the leaf's public key matches the value the SDK obtained out of
//! band (typically via the relay descriptor / lease envelope). This verifier
//! enforces exactly that invariant.

use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

/// `rustls` server-cert verifier that pins on a 32-byte ed25519 public key.
#[derive(Debug)]
pub struct SpkiPinVerifier {
    pinned: VerifyingKey,
    aws_lc_provider: Arc<rustls::crypto::CryptoProvider>,
}

impl SpkiPinVerifier {
    /// Construct a verifier that accepts only certificates whose
    /// `SubjectPublicKeyInfo` carries the supplied ed25519 public key bytes.
    #[must_use]
    pub fn new(pinned: VerifyingKey) -> Self {
        Self {
            pinned,
            aws_lc_provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        }
    }
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        use x509_cert::der::Decode as _;

        let cert = x509_cert::Certificate::from_der(end_entity.as_ref())
            .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        let spki_bytes = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or(TlsError::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ))?;

        if spki_bytes.len() != 32 {
            return Err(TlsError::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        let mut bytes_arr = [0u8; 32];
        bytes_arr.copy_from_slice(spki_bytes);
        if bytes_arr == self.pinned.to_bytes() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // Workspace baseline is TLS 1.3 only; the relay's `ServerConfig` is
        // built with `with_safe_default_protocol_versions()` over an
        // `aws-lc-rs` provider that negotiates TLS 1.3, and the QUIC layer
        // additionally rejects any non-1.3 handshake. Returning a peer-
        // incompatible error preserves the documented invariant if a
        // non-conforming server somehow reaches this code path.
        Err(TlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOfferedOrEnabled,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.aws_lc_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Although the relay's self-signed cert is ed25519, the TLS 1.3
        // CertificateVerify transcript signature is negotiated separately;
        // delegate to the configured `aws-lc-rs` provider so all schemes the
        // provider can verify are advertised.
        self.aws_lc_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests use cert generation + accept deterministic input"
)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use crate::quic::endpoint::self_signed_cert;
    use crate::quic::identity::{generate_quic_identity_key, quic_identity_verifying_key};

    fn now_unix() -> UnixTime {
        UnixTime::since_unix_epoch(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        )
    }

    #[test]
    fn verifier_accepts_matching_pinned_pubkey() {
        let key = generate_quic_identity_key();
        let pinned = quic_identity_verifying_key(&key);
        let (cert_der, _priv_der) = self_signed_cert(&key).unwrap();
        let verifier = SpkiPinVerifier::new(pinned);
        let server_name = ServerName::try_from("any-cosmetic-name.invalid").unwrap();
        let result =
            verifier.verify_server_cert(&cert_der, &[], &server_name, &[], now_unix());
        assert!(
            result.is_ok(),
            "verifier should accept matching pubkey: {result:?}",
        );
    }

    #[test]
    fn verifier_rejects_different_pubkey() {
        let server_key = generate_quic_identity_key();
        let other_key = generate_quic_identity_key();
        let pinned = quic_identity_verifying_key(&other_key);
        let (cert_der, _priv_der) = self_signed_cert(&server_key).unwrap();
        let verifier = SpkiPinVerifier::new(pinned);
        let server_name = ServerName::try_from("any.invalid").unwrap();
        let result =
            verifier.verify_server_cert(&cert_der, &[], &server_name, &[], now_unix());
        assert!(
            matches!(result, Err(TlsError::InvalidCertificate(_))),
            "verifier should reject mismatched pubkey: {result:?}",
        );
    }

    #[test]
    fn verifier_rejects_malformed_cert() {
        let key = generate_quic_identity_key();
        let pinned = quic_identity_verifying_key(&key);
        let verifier = SpkiPinVerifier::new(pinned);
        let server_name = ServerName::try_from("any.invalid").unwrap();
        let bogus = CertificateDer::from(vec![0u8, 1, 2, 3, 4]);
        let result = verifier.verify_server_cert(&bogus, &[], &server_name, &[], now_unix());
        assert!(
            matches!(
                result,
                Err(TlsError::InvalidCertificate(
                    rustls::CertificateError::BadEncoding,
                )),
            ),
            "verifier should reject malformed cert: {result:?}",
        );
    }

    #[test]
    fn verifier_supported_schemes_nonempty() {
        let key = generate_quic_identity_key();
        let pinned = quic_identity_verifying_key(&key);
        let verifier = SpkiPinVerifier::new(pinned);
        assert!(
            !verifier.supported_verify_schemes().is_empty(),
            "aws-lc-rs provider must advertise at least one signature scheme",
        );
    }
}
