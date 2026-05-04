//! [`KeylessSigningKey`] — opaque keyless signing material + PEM loader.
//!
//! ## R2 trust-boundary discipline (ADR-0002)
//!
//! [`KeylessSigningKey`] is the relay-owned newtype for the keyless
//! key role and is a distinct [`secrecy::SecretBox<T>`] type from the
//! relay's other key roles, all of which live as separate fields on
//! [`crate::state::RelayIdentity`] (the relay's identity bundle).
//! The Rust type system rejects accidental cross-use at compile time.
//! The workspace clippy `disallowed_methods` rule on
//! `portal_crypto::load_all_keys` plus the multi-key-return regex CI
//! gate cover the bundle-loader bypass: every keyless load goes through
//! [`load_keyless_signing_key`], which returns exactly one key.
//!
//! ## Loader scope — algorithm classification + structural validation
//!
//! [`load_keyless_signing_key`] performs **two** levels of acceptance:
//!
//! 1. *Algorithm classification* — the PEM section label and (for
//!    PKCS#8) the inner `AlgorithmIdentifier` OID must place the key
//!    in one of the v0.1 allow-listed families below.  Anything else
//!    fails [`KeylessError::UnsupportedAlgorithm`].
//! 2. *Structural validation* — the inner DER body must parse as the
//!    declared structure (PKCS#1 `RSAPrivateKey`, SEC1 `ECPrivateKey`,
//!    or PKCS#8 `PrivateKeyInfo` whose inner `privateKey` octet
//!    string is itself a valid PKCS#1 / SEC1 body).  Truncated or
//!    malformed DER fails [`KeylessError::InvalidKey`] at load time
//!    so the (forthcoming U2) `KeylessSignerAdapter` never sees
//!    structurally-broken material.
//!
//! Cryptographic key-length / strength policy (e.g. RSA ≥ 2048 bits,
//! reject low-exponent keys, …) is **out of scope** for this loader —
//! that constraint binds to the signer-construction site in Phase 6b/A
//! U2 where the rustls `SigningKey` is built and the upstream provider
//! enforces its own minima.
//!
//! ### v0.1 allow-list
//!
//! - **RSA** (PKCS#1 `RSA PRIVATE KEY` and PKCS#8 `PRIVATE KEY` with
//!   `rsaEncryption` OID `1.2.840.113549.1.1.1`).  The Go reference
//!   uses RSA-2048 in the production keyless path; the loader accepts
//!   any RFC-8017-conformant RSA private key.  RSA-3072 follows
//!   transparently — there is no algorithm-level distinction.
//! - **ECDSA-P256** (SEC1 `EC PRIVATE KEY` with named-curve OID
//!   `1.2.840.10045.3.1.7`, or PKCS#8 `PRIVATE KEY` with `id-ecPublicKey`
//!   OID `1.2.840.10045.2.1` whose `parameters` carry the same P-256
//!   OID).
//!
//! Everything else (DSA, Ed25519, NIST P-384 / P-521, secp256k1, …) is
//! refused with [`KeylessError::UnsupportedAlgorithm`].
//!
//! ## Zeroization
//!
//! The DER body inside [`KeyMaterial`] is wrapped in
//! [`zeroize::Zeroizing<Vec<u8>>`] so the secret bytes are wiped when
//! the [`secrecy::SecretBox`] drops. [`KeyMaterial`]'s own
//! [`zeroize::Zeroize`] impl forwards to the inner `Zeroizing` field —
//! `SecretBox<T>` requires `T: Zeroize`.
//!
//! ## Debug redaction
//!
//! [`secrecy::SecretBox<T>`] formats as
//! `SecretBox<…KeyMaterial>([REDACTED])` regardless of `T`'s own Debug
//! impl.  The unit tests below assert that the debug print of a
//! [`KeylessSigningKey`] does NOT leak the DER body.

// `der` is not declared as a direct workspace dep; we route through the
// `pkcs8` re-export, which is API-compatible and avoids a parallel
// `der` declaration in the workspace.
use pkcs1::RsaPrivateKey;
use pkcs8::PrivateKeyInfo;
use pkcs8::der::Decode as _;
use pkcs8::der::asn1::ObjectIdentifier;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject as _;
use sec1::EcPrivateKey;
use secrecy::SecretBox;
use zeroize::{Zeroize, Zeroizing};

use crate::keyless::error::KeylessError;

// ---------------------------------------------------------------------------
// Algorithm OIDs (RFC 8017 / RFC 5480 / RFC 5915)
// ---------------------------------------------------------------------------

/// PKCS#1 `rsaEncryption` algorithm OID.
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// `id-ecPublicKey` algorithm OID — the `AlgorithmIdentifier` OID under
/// PKCS#8 for any ECDSA key; the curve is carried in the `parameters`
/// field as a named-curve OID.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// NIST P-256 named-curve OID (RFC 5480 §2.1.1.1, "secp256r1").
const OID_NIST_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

// ---------------------------------------------------------------------------
// KeyMaterial — private discriminated DER body
// ---------------------------------------------------------------------------

/// Opaque DER body of a keyless signing key, tagged by algorithm.
///
/// `pub(crate)` (rather than `pub`) on the variants because the
/// algorithm tag is an internal detail of the keyless module — callers
/// should never branch on it; the sole consumer is the (forthcoming
/// U2) `KeylessSignerAdapter` which selects the rustls `SigningKey`
/// constructor based on this tag.
///
/// `#[doc(hidden)]` keeps the type out of the rendered rustdoc surface
/// even though it has to be `pub(crate)` for the U2 signer to pattern-
/// match it.
#[doc(hidden)]
#[non_exhaustive]
pub(crate) enum KeyMaterial {
    /// PKCS#1 or PKCS#8 RSA private key DER body.
    Rsa(Zeroizing<Vec<u8>>),
    /// SEC1 or PKCS#8 ECDSA-P256 private key DER body.
    EcdsaP256(Zeroizing<Vec<u8>>),
}

impl Zeroize for KeyMaterial {
    fn zeroize(&mut self) {
        match self {
            Self::Rsa(bytes) | Self::EcdsaP256(bytes) => bytes.zeroize(),
        }
    }
}

impl Default for KeyMaterial {
    /// Required by [`secrecy::SecretBox::new`]'s zeroize-on-drop
    /// machinery, which writes a default value over the slot during
    /// drop.  An empty RSA-tagged buffer is the cheapest sentinel; the
    /// variant tag is meaningless after drop.
    fn default() -> Self {
        Self::Rsa(Zeroizing::new(Vec::new()))
    }
}

// ---------------------------------------------------------------------------
// KeylessSigningKey — public newtype around SecretBox<KeyMaterial>
// ---------------------------------------------------------------------------

/// Opaque keyless signing key.
///
/// Constructed exclusively by [`load_keyless_signing_key`] from PEM
/// bytes.  Internally a [`secrecy::SecretBox<KeyMaterial>`]; the
/// Debug impl on `SecretBox` redacts the body to `[REDACTED]`.
///
/// Phase 6b/A U2 lands the rustls `SigningKey` adapter that exposes
/// signing through this type; today the only public surface is
/// construction.
#[non_exhaustive]
pub struct KeylessSigningKey(pub(crate) SecretBox<KeyMaterial>);

impl core::fmt::Debug for KeylessSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Delegate to SecretBox's redacting Debug.
        f.debug_tuple("KeylessSigningKey").field(&self.0).finish()
    }
}

// ---------------------------------------------------------------------------
// PEM loader
// ---------------------------------------------------------------------------

/// Load a single keyless signing key from PEM-encoded bytes.
///
/// The PEM may carry one of three section labels:
///
/// - `RSA PRIVATE KEY` (PKCS#1) — accepted as RSA.
/// - `EC PRIVATE KEY` (SEC1) — accepted iff the named-curve OID is
///   P-256 (`1.2.840.10045.3.1.7`).
/// - `PRIVATE KEY` (PKCS#8) — the inner `AlgorithmIdentifier` OID is
///   inspected and routed to RSA or ECDSA-P256; ECDSA keys must carry
///   the P-256 named-curve OID in the `AlgorithmIdentifier` `parameters`.
///
/// All other section labels (`CERTIFICATE`, `PUBLIC KEY`, …) and all
/// other algorithms / curves are refused.
///
/// # Errors
///
/// - [`KeylessError::MalformedPem`] — the bytes contained no PEM
///   private-key section, or the section was syntactically invalid.
/// - [`KeylessError::UnsupportedAlgorithm`] — the section was
///   parseable but the algorithm or curve is not on the v0.1 allow-list.
/// - [`KeylessError::InvalidKey`] — the PKCS#8 / SEC1 DER body did not
///   parse as the declared structure (truncated, missing curve params,
///   etc.).
pub fn load_keyless_signing_key(pem: &[u8]) -> Result<KeylessSigningKey, KeylessError> {
    // 1. Parse the first PEM private-key section.  rustls-pki-types
    //    detects the section kind (RsaPrivateKey / EcPrivateKey /
    //    PrivateKey) and returns a typed variant; everything else
    //    (CERTIFICATE, PUBLIC KEY, …) yields NoItemsFound because
    //    PrivateKeyDer::from_pem rejects non-private sections.
    let parsed = PrivateKeyDer::from_pem_slice(pem).map_err(|e| match e {
        rustls_pki_types::pem::Error::NoItemsFound => {
            KeylessError::MalformedPem("no private-key PEM section".to_owned())
        }
        other => KeylessError::MalformedPem(other.to_string()),
    })?;

    // 2. Route on the parsed variant.  PKCS#1 and SEC1 sections carry
    //    the algorithm in the section label itself; PKCS#8 needs an
    //    AlgorithmIdentifier inspection.  Each branch additionally
    //    parses the inner DER body so a truncated / malformed key
    //    body surfaces `InvalidKey` here rather than deferring the
    //    failure to the (forthcoming U2) signer-construction site.
    let material = match parsed {
        PrivateKeyDer::Pkcs1(rsa) => {
            // PKCS#1 `RSA PRIVATE KEY` is RSA by section label.
            // Validate the body parses as RFC 8017 §A.1.2.
            let der = rsa.secret_pkcs1_der();
            validate_pkcs1_rsa(der)
                .map_err(|e| KeylessError::InvalidKey(format!("pkcs1 rsa private key: {e}")))?;
            KeyMaterial::Rsa(Zeroizing::new(der.to_vec()))
        }
        PrivateKeyDer::Sec1(ec) => {
            // SEC1 `EC PRIVATE KEY` is ECDSA; verify the named curve
            // and that the body parses as RFC 5915.
            classify_sec1_p256(ec.secret_sec1_der())?
        }
        PrivateKeyDer::Pkcs8(pkcs8_key) => classify_pkcs8(pkcs8_key.secret_pkcs8_der())?,
        // PrivateKeyDer is non-exhaustive; future variants must
        // explicitly opt in to the keyless allow-list.
        other => {
            return Err(KeylessError::UnsupportedAlgorithm(format!(
                "unrecognised private-key DER variant: {other:?}"
            )));
        }
    };

    Ok(KeylessSigningKey(SecretBox::new(Box::new(material))))
}

// ---------------------------------------------------------------------------
// Classifier + structural-validation helpers
// ---------------------------------------------------------------------------

/// Decode and discard a PKCS#1 [`RsaPrivateKey`] from `der` to confirm
/// it is structurally valid per RFC 8017 §A.1.2.  Returns `Ok(())` on
/// success; the caller stashes the original bytes (we do not retain
/// the typed view because the inner `UintRef`s borrow from `der`).
fn validate_pkcs1_rsa(der: &[u8]) -> Result<(), pkcs1::Error> {
    let _: RsaPrivateKey<'_> = RsaPrivateKey::from_der(der)?;
    Ok(())
}

/// Inspect a SEC1 `ECPrivateKey` DER body and return the matching
/// [`KeyMaterial::EcdsaP256`] iff the body parses cleanly AND the
/// named-curve OID is P-256.
fn classify_sec1_p256(der: &[u8]) -> Result<KeyMaterial, KeylessError> {
    let ec =
        EcPrivateKey::from_der(der).map_err(|e| KeylessError::InvalidKey(format!("sec1: {e}")))?;
    let params = ec.parameters.ok_or_else(|| {
        KeylessError::UnsupportedAlgorithm("sec1: missing curve parameters".to_owned())
    })?;
    let oid = params.named_curve().ok_or_else(|| {
        KeylessError::UnsupportedAlgorithm("sec1: non-named-curve ec parameters".to_owned())
    })?;
    if oid != OID_NIST_P256 {
        return Err(KeylessError::UnsupportedAlgorithm(format!(
            "sec1: ec curve {oid} is not P-256 (1.2.840.10045.3.1.7)"
        )));
    }
    Ok(KeyMaterial::EcdsaP256(Zeroizing::new(der.to_vec())))
}

/// Inspect a PKCS#8 `PrivateKeyInfo` DER body and return the matching
/// [`KeyMaterial`] variant.  Refuses any algorithm that is not RSA or
/// ECDSA-P256.  Additionally validates the inner `privateKey` octet
/// string parses as the algorithm-specific structure (PKCS#1
/// `RSAPrivateKey` or SEC1 `ECPrivateKey`) so a malformed inner body
/// surfaces here rather than at signer-construction time.
fn classify_pkcs8(der: &[u8]) -> Result<KeyMaterial, KeylessError> {
    let info = PrivateKeyInfo::from_der(der)
        .map_err(|e| KeylessError::InvalidKey(format!("pkcs8: {e}")))?;
    let alg_oid = info.algorithm.oid;

    if alg_oid == OID_RSA_ENCRYPTION {
        // RFC 5208/5958: the privateKey OCTET STRING wraps a PKCS#1
        // RSAPrivateKey (RFC 8017 §A.1.2).  Validate the inner body.
        validate_pkcs1_rsa(info.private_key)
            .map_err(|e| KeylessError::InvalidKey(format!("pkcs8 rsa inner private key: {e}")))?;
        return Ok(KeyMaterial::Rsa(Zeroizing::new(der.to_vec())));
    }

    if alg_oid == OID_EC_PUBLIC_KEY {
        // The curve OID lives in the AlgorithmIdentifier's
        // `parameters` field as a bare ObjectIdentifier per RFC 5480
        // §2.1.1.  `assert_parameters_oid(P-256)` returns Ok iff the
        // parameters are exactly that OID.
        info.algorithm
            .assert_parameters_oid(OID_NIST_P256)
            .map_err(|e| {
                KeylessError::UnsupportedAlgorithm(format!(
                    "pkcs8: ec curve is not P-256 (parameters: {e})"
                ))
            })?;
        // RFC 5915 / RFC 5958: the privateKey OCTET STRING wraps a
        // SEC1 ECPrivateKey.  Validate the inner body and, when the
        // inner `parameters [0]` is present, require it to be a
        // namedCurve OID that matches the outer P-256.  RFC 5915
        // says the inner parameters MAY be omitted in PKCS#8 (the
        // outer AlgorithmIdentifier already pins the curve); if
        // present they MUST be a namedCurve and MUST match.  RFC
        // 5480 §2.1.1 forbids `implicitCurve` and `specifiedCurve`
        // in PKIX, so we refuse any non-namedCurve choice.
        let inner = EcPrivateKey::from_der(info.private_key)
            .map_err(|e| KeylessError::InvalidKey(format!("pkcs8 ec inner private key: {e}")))?;
        if let Some(params) = inner.parameters {
            let inner_oid = params.named_curve().ok_or_else(|| {
                KeylessError::UnsupportedAlgorithm(
                    "pkcs8: inner ec parameters are non-namedCurve \
                     (implicitCurve / specifiedCurve are forbidden in PKIX \
                     per RFC 5480 §2.1.1)"
                        .to_owned(),
                )
            })?;
            if inner_oid != OID_NIST_P256 {
                return Err(KeylessError::UnsupportedAlgorithm(format!(
                    "pkcs8: inner ec curve {inner_oid} disagrees with outer \
                     P-256 (1.2.840.10045.3.1.7)"
                )));
            }
        }
        return Ok(KeyMaterial::EcdsaP256(Zeroizing::new(der.to_vec())));
    }

    Err(KeylessError::UnsupportedAlgorithm(format!(
        "pkcs8: algorithm OID {alg_oid} is not RSA or ECDSA-P256"
    )))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test-only setup")]
mod tests {
    use secrecy::ExposeSecret as _;

    use super::*;

    /// Pre-generated RSA-2048 PKCS#8 PEM for unit tests.
    /// TEST ONLY — not a production key.
    const RSA_2048_PEM: &[u8] = include_bytes!("../../tests/fixtures/keyless-rsa-2048.pem");

    /// Pre-generated NIST P-256 PKCS#8 PEM for unit tests.
    /// TEST ONLY — not a production key.
    const P256_PEM: &[u8] = include_bytes!("../../tests/fixtures/keyless-p256.pem");

    /// Pre-generated NIST P-384 PKCS#8 PEM for unit tests; used to
    /// exercise the curve-rejection path.
    /// TEST ONLY — not a production key.
    const P384_PEM: &[u8] = include_bytes!("../../tests/fixtures/keyless-p384.pem");

    #[test]
    fn loads_valid_rsa_2048_pem() {
        let key = load_keyless_signing_key(RSA_2048_PEM).expect("rsa-2048 loads");
        // Inspect via the crate-private newtype field: the fixture is
        // RSA, so the inner KeyMaterial must be the Rsa variant.
        match key.0.expose_secret() {
            KeyMaterial::Rsa(bytes) => assert!(!bytes.is_empty(), "rsa der must be non-empty"),
            KeyMaterial::EcdsaP256(_) => panic!("expected Rsa variant, got EcdsaP256"),
        }
    }

    #[test]
    fn loads_valid_p256_pem() {
        let key = load_keyless_signing_key(P256_PEM).expect("p-256 loads");
        match key.0.expose_secret() {
            KeyMaterial::EcdsaP256(bytes) => {
                assert!(!bytes.is_empty(), "p-256 der must be non-empty");
            }
            KeyMaterial::Rsa(_) => panic!("expected EcdsaP256 variant, got Rsa"),
        }
    }

    #[test]
    fn rejects_p384_with_unsupported_algorithm() {
        let err =
            load_keyless_signing_key(P384_PEM).expect_err("p-384 must be refused as out-of-scope");
        assert!(
            matches!(err, KeylessError::UnsupportedAlgorithm(_)),
            "expected UnsupportedAlgorithm, got: {err:?}"
        );
    }

    #[test]
    fn rejects_empty_pem() {
        let err = load_keyless_signing_key(b"").expect_err("empty bytes must be rejected");
        assert!(
            matches!(err, KeylessError::MalformedPem(_)),
            "expected MalformedPem, got: {err:?}"
        );
    }

    #[test]
    fn rejects_garbage_bytes() {
        let err = load_keyless_signing_key(b"not a pem at all\n")
            .expect_err("non-pem bytes must be rejected");
        assert!(
            matches!(err, KeylessError::MalformedPem(_)),
            "expected MalformedPem, got: {err:?}"
        );
    }

    #[test]
    fn rejects_certificate_pem_section() {
        // A CERTIFICATE PEM body has a recognisable section label but is
        // not a private key.  The loader must refuse, not panic.
        const CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        let err = load_keyless_signing_key(CERT_PEM)
            .expect_err("certificate pem must not be accepted as a key");
        assert!(
            matches!(err, KeylessError::MalformedPem(_)),
            "expected MalformedPem, got: {err:?}"
        );
    }

    #[test]
    fn debug_does_not_leak_material() {
        let key = load_keyless_signing_key(P256_PEM).expect("p-256 loads");
        let printed = format!("{key:?}");
        // SecretBox<T>::Debug renders `SecretBox<…>([REDACTED])`; the
        // string MUST NOT contain any of the DER bytes' base64 / hex
        // representation, and MUST contain the redaction sentinel.
        assert!(
            printed.contains("REDACTED"),
            "Debug output missing [REDACTED] sentinel: {printed}"
        );
        // Belt-and-suspenders: the stringified PEM body's first base64
        // chunk must not appear in the Debug output.  We use a short
        // prefix so the assertion is deterministic across formatters.
        let pem_str = core::str::from_utf8(P256_PEM).expect("test fixture is utf-8");
        let body_line = pem_str
            .lines()
            .find(|line| !line.starts_with("-----") && !line.is_empty())
            .expect("pem must have at least one body line");
        // First 16 chars of the base64 body — long enough to be
        // statistically distinct, short enough to avoid line-wrap
        // surprises.
        let probe: String = body_line.chars().take(16).collect();
        assert!(
            !printed.contains(&probe),
            "Debug output leaked PEM body prefix '{probe}': {printed}"
        );
    }

    #[test]
    fn key_material_default_is_empty_rsa() {
        // The `Default` impl is required by `SecretBox`'s drop-time
        // overwrite path.  Sanity-check it does not allocate or panic
        // and has the documented empty-RSA shape.
        let m = KeyMaterial::default();
        match m {
            KeyMaterial::Rsa(bytes) => assert!(bytes.is_empty()),
            KeyMaterial::EcdsaP256(_) => panic!("default must be the Rsa sentinel"),
        }
    }
}
