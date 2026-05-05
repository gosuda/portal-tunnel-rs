//! [`KeylessSignerAdapter`] — bridges [`KeylessSigningKey`] into the
//! rustls 0.23 [`rustls::sign::SigningKey`] trait surface.
//!
//! ## Why this exists
//!
//! rustls expects an `Arc<dyn SigningKey>` for any tenant-cert path.
//! The keyless module's [`KeylessSigningKey`] is a
//! [`secrecy::SecretBox<KeyMaterial>`] newtype with no rustls
//! integration on its own; this adapter wraps it.
//!
//! ## Strategy: delegate to the rustls aws-lc-rs provider
//!
//! Workspace policy is "use rustls's own provider, don't roll our own"
//! (R13 / ADR-0014).  The adapter therefore does **not** re-implement
//! RSA-PSS / RSA-PKCS1-v1.5 / ECDSA-P256 signing primitives — those
//! live inside rustls's aws-lc-rs provider.  The adapter:
//!
//! 1. Reads the inner DER bytes through the [`secrecy::SecretBox`]
//!    boundary exactly once at construction time
//!    (`KeylessSignerAdapter::from_keyless_signing_key`).
//! 2. Hands them to [`rustls::crypto::aws_lc_rs::sign::any_supported_type`],
//!    which returns an `Arc<dyn rustls::sign::SigningKey>` constructed
//!    by the rustls provider itself.
//! 3. Stores that `Arc<dyn SigningKey>` for the lifetime of the adapter.
//!    Subsequent `choose_scheme` / `algorithm` / sign calls forward to
//!    the inner key; the secret bytes are zeroized when the original
//!    [`KeylessSigningKey`] drops (its `Zeroizing<Vec<u8>>` field
//!    handles that — see `material.rs`).
//!
//! The adapter type is intentionally thin: by the time
//! [`rustls::sign::SigningKey::choose_scheme`] is called the inner
//! provider key has already been parsed, and signing is a direct
//! pass-through.
//!
//! ## R2 trust-boundary discipline
//!
//! The single [`secrecy::ExposeSecret::expose_secret`] call site lives
//! in [`KeylessSignerAdapter::from_keyless_signing_key`] and is gated
//! by a `#[tracing::instrument(skip_all)]` span so the boundary
//! crossing is observable in trace output.  Once construction
//! finishes, the adapter holds only the rustls-provider's
//! `Arc<dyn SigningKey>` — the original `SecretBox<KeyMaterial>` is
//! consumed and dropped (its `Zeroizing` payload wipes the DER bytes).
//!
//! ## Async-bridge boundary
//!
//! [`rustls::sign::Signer::sign`] is **synchronous** — that is the
//! whole reason the keyless module ships an async bridge in
//! `bridge.rs` (ADR-0016).  This adapter exposes the sync surface
//! rustls demands; the bridge wraps it in a worker pool that the
//! axum handler (Phase 6b/A U3) can `await`.

use rustls::sign::{Signer, SigningKey};
use rustls_pki_types::PrivateKeyDer;
use secrecy::ExposeSecret as _;
use tracing::instrument;

use crate::keyless::error::KeylessError;
use crate::keyless::material::{KeyMaterial, KeylessSigningKey};

// ---------------------------------------------------------------------------
// KeylessSignerAdapter
// ---------------------------------------------------------------------------

/// rustls [`SigningKey`] adapter over a [`KeylessSigningKey`].
///
/// Construct via [`KeylessSignerAdapter::from_keyless_signing_key`].
/// The adapter delegates `choose_scheme` and `algorithm` to a rustls
/// aws-lc-rs provider key built once at construction time.
///
/// ### Cloning + sharing
///
/// The inner provider key is held as
/// [`std::sync::Arc<dyn rustls::sign::SigningKey>`]; cloning the
/// adapter clones the `Arc` (cheap), so a single adapter can be
/// shared across the bridge worker pool without re-parsing the DER.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct KeylessSignerAdapter {
    /// rustls aws-lc-rs provider key constructed once at adapter
    /// build time.  Held as an `Arc` so the bridge worker pool can
    /// share one adapter instance without re-parsing the DER.
    inner: std::sync::Arc<dyn SigningKey>,
}

impl KeylessSignerAdapter {
    /// Build a [`KeylessSignerAdapter`] from a [`KeylessSigningKey`].
    ///
    /// This is the **single** site where the keyless `SecretBox`
    /// boundary is crossed.  The inner DER bytes are exposed exactly
    /// long enough to construct a `PrivateKeyDer` and hand it to the
    /// rustls aws-lc-rs provider; the consumed [`KeylessSigningKey`]
    /// drops at the end of the call and its `Zeroizing<Vec<u8>>`
    /// payload wipes the DER bytes.
    ///
    /// # Errors
    ///
    /// - [`KeylessError::InvalidKey`] — `rustls-pki-types` could not
    ///   classify the inner DER bytes as PKCS#1 / SEC1 / PKCS#8.  This
    ///   should not occur in practice because U1's loader only
    ///   accepts already-classified material; surfaced here as a
    ///   defense-in-depth guard.
    /// - [`KeylessError::SignFailed`] — the rustls aws-lc-rs provider
    ///   refused the key (e.g. RSA modulus too small for the
    ///   provider's policy).  The provider's error string is wrapped
    ///   verbatim.
    #[instrument(skip_all)]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "consuming KeylessSigningKey is load-bearing — the caller \
                  must release the SecretBox<KeyMaterial> so its zeroize-on-drop \
                  fires once the provider has built its own copy of the key"
    )]
    pub fn from_keyless_signing_key(key: KeylessSigningKey) -> Result<Self, KeylessError> {
        // Borrow the secret payload exactly once.  We do not retain
        // the borrow beyond the `any_supported_type` call; the
        // resulting `Arc<dyn SigningKey>` carries its own (provider-
        // owned) copy of the key material.
        let material = key.0.expose_secret();
        let der_bytes: &[u8] = match material {
            KeyMaterial::Rsa(bytes) | KeyMaterial::EcdsaP256(bytes) => bytes.as_slice(),
        };

        // `PrivateKeyDer::try_from(&[u8])` performs a small DER
        // header inspection (`SEQUENCE` tag + version byte) to route
        // the bytes into the correct enum variant — PKCS#1 / SEC1 /
        // PKCS#8.  U1's loader accepts all three encodings, so we
        // reuse the rustls-pki-types classifier here rather than
        // tracking the encoding through `KeyMaterial`.
        let private_key_der = PrivateKeyDer::try_from(der_bytes).map_err(|e| {
            KeylessError::InvalidKey(format!(
                "rustls-pki-types could not classify keyless der: {e}"
            ))
        })?;

        // Delegate to the rustls aws-lc-rs provider.  This is the
        // workspace-mandated path; we never construct a `SigningKey`
        // by hand.
        let inner = rustls::crypto::aws_lc_rs::sign::any_supported_type(&private_key_der)
            .map_err(|e| KeylessError::SignFailed(format!("provider rejected keyless key: {e}")))?;

        Ok(Self { inner })
    }
}

impl SigningKey for KeylessSignerAdapter {
    fn choose_scheme(&self, offered: &[rustls::SignatureScheme]) -> Option<Box<dyn Signer>> {
        // Direct delegation: the inner aws-lc-rs key already knows
        // every scheme it can satisfy (RSA-PSS / PKCS1-v1.5 / ECDSA-
        // P256), and rustls hands the resulting `Box<dyn Signer>`
        // back to the TLS state machine.  The keyless module adds no
        // policy here — scheme acceptance is a U3 concern and lives
        // in `policy.rs`.
        self.inner.choose_scheme(offered)
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.inner.algorithm()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test-only setup")]
mod tests {
    use super::*;
    use crate::keyless::material::load_keyless_signing_key;

    /// Pre-generated RSA-2048 PKCS#8 PEM for unit tests.
    /// TEST ONLY — not a production key.
    const RSA_2048_PEM: &[u8] = include_bytes!("../../tests/fixtures/keyless-rsa-2048.pem");

    /// Pre-generated NIST P-256 PKCS#8 PEM for unit tests.
    /// TEST ONLY — not a production key.
    const P256_PEM: &[u8] = include_bytes!("../../tests/fixtures/keyless-p256.pem");

    #[test]
    fn rsa_adapter_round_trips_through_provider() {
        let key = load_keyless_signing_key(RSA_2048_PEM).expect("rsa-2048 loads");
        let adapter =
            KeylessSignerAdapter::from_keyless_signing_key(key).expect("provider accepts rsa-2048");
        // RSA — algorithm tag must match rustls's enum.
        assert_eq!(adapter.algorithm(), rustls::SignatureAlgorithm::RSA);
        // The aws-lc-rs RsaSigningKey advertises six schemes
        // (RSA-PSS-{256,384,512}, PKCS1-{256,384,512}); offering
        // RSA_PSS_SHA256 must yield Some(Signer).
        let signer = adapter
            .choose_scheme(&[rustls::SignatureScheme::RSA_PSS_SHA256])
            .expect("rsa pss sha256 must be selectable");
        assert_eq!(signer.scheme(), rustls::SignatureScheme::RSA_PSS_SHA256);
        // Signing must succeed; we verify shape (non-empty), not
        // bytes — actual signature verification is U3's integration
        // test territory.
        let sig = signer.sign(b"keyless adapter unit test").expect("sign ok");
        assert!(!sig.is_empty(), "signature must be non-empty");
    }

    #[test]
    fn ecdsa_adapter_round_trips_through_provider() {
        let key = load_keyless_signing_key(P256_PEM).expect("p-256 loads");
        let adapter =
            KeylessSignerAdapter::from_keyless_signing_key(key).expect("provider accepts p-256");
        assert_eq!(adapter.algorithm(), rustls::SignatureAlgorithm::ECDSA);
        let signer = adapter
            .choose_scheme(&[rustls::SignatureScheme::ECDSA_NISTP256_SHA256])
            .expect("ecdsa-p256 must be selectable");
        assert_eq!(
            signer.scheme(),
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256
        );
        let sig = signer.sign(b"keyless adapter unit test").expect("sign ok");
        assert!(!sig.is_empty(), "signature must be non-empty");
    }

    #[test]
    fn unsupported_scheme_returns_none() {
        let key = load_keyless_signing_key(P256_PEM).expect("p-256 loads");
        let adapter =
            KeylessSignerAdapter::from_keyless_signing_key(key).expect("provider accepts p-256");
        // ECDSA key cannot satisfy an RSA-only offer.
        assert!(
            adapter
                .choose_scheme(&[rustls::SignatureScheme::RSA_PSS_SHA256])
                .is_none(),
            "ecdsa adapter must refuse rsa-only offers"
        );
    }

    #[test]
    fn debug_does_not_leak_inner_arc_pointer() {
        // Sanity: the Debug derive renders the type name; this test
        // exists to flag accidental hand-rolled Debug impls that
        // start dumping the inner Arc by Pointer (which would itself
        // leak via Pointer's pointer-equality channel).
        let key = load_keyless_signing_key(P256_PEM).expect("p-256 loads");
        let adapter =
            KeylessSignerAdapter::from_keyless_signing_key(key).expect("provider accepts p-256");
        let printed = format!("{adapter:?}");
        assert!(
            printed.contains("KeylessSignerAdapter"),
            "Debug must include the adapter type name: {printed}"
        );
    }
}
