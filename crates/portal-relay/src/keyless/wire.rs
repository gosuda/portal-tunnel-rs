//! Greenfield wire types for the keyless mTLS sign endpoint.
//!
//! The wire shape is the Phase 6b/A rename of the Go reference
//! `signrpc::{SignRequest, SignResponse}` types:
//!
//! - [`SignRequest`] — caller-supplied key id + signature scheme +
//!   raw payload + routing context.
//! - [`SignResponse`] — server-emitted signature bytes + the scheme
//!   the server actually used (always equal to the request scheme on
//!   success — surfaced explicitly so the client never has to parrot
//!   its own request back).
//! - [`KeylessErrorBody`] — the `{"error": {code, message}}` shape
//!   the U3 handler emits for 4xx / 5xx responses; this type is the
//!   keyless-flavoured analogue of [`crate::api::ApiErrorBody`] but
//!   lives here because the keyless surface is a distinct trust
//!   boundary (R2) and ships its own wire codes.
//! - [`RoutingContext`] — the SEC-015 ECH/inner-SNI mismatch carrier.
//!   The *type* ships in U3; the *check* (`routed_hostname` vs
//!   `requested_cert_subject` matching) lives in U4.  Today
//!   [`crate::keyless::policy`] only validates key id / scheme /
//!   payload-budget / rate-limit; the routing-context fields are
//!   carried through to the canonical signing input verbatim so a
//!   later U4 commit can add the refuse-to-sign rule without
//!   re-shaping the wire.
//!
//! ## SEC-007 canonical signing input
//!
//! The signed bytes are
//!
//! ```text
//! domain_separator || canonical(request)
//! ```
//!
//! where the domain separator is
//! [`portal_wire::domain_separators::KEYLESS_REQUEST`] (the byte string
//! `b"portal-tunnel/keyless-request/v1"`) and `canonical(request)` is
//! the postcard encoding of the tuple
//!
//! ```text
//! (key_id, scheme_u16, payload_len_u32, payload,
//!  routed_hostname, requested_cert_subject)
//! ```
//!
//! `scheme` is reduced to its underlying TLS-IANA `u16` ordinal
//! (rustls's `SignatureScheme` is `non_exhaustive` and not directly
//! `serde::Serialize`able; the canonical wire is the IANA `u16`).
//! `payload_len_u32` is included explicitly so the canonical form is
//! self-describing and a length-extension on the payload would change
//! the canonical bytes — defense in depth on top of postcard's own
//! length-prefixing.
//!
//! [`canonical_signing_input`] is the single helper site that builds
//! these bytes.  Both the U3 handler and the future U4 routing-context
//! check share this function; nothing else in the codebase should
//! re-derive the domain-separator concatenation by hand.

use compact_str::CompactString;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SignRequest — wire shape consumed by the keyless POST handler
// ---------------------------------------------------------------------------

/// Wire shape of a single keyless sign request.
///
/// Posted by the tenant via mTLS to the keyless Router; deserialised
/// from JSON in the U3 axum handler.  The `scheme` is carried as a
/// rustls [`rustls::SignatureScheme`] in memory but serialised as its
/// underlying TLS-IANA `u16` over the wire — see
/// [`SignatureSchemeWire`] for the round-trip.
///
/// **Field stability.** This struct is the JSON wire shape; future
/// additive fields will land via a versioned wire
/// (`/v2/keyless/sign` and a parallel `SignRequestV2` type) rather
/// than via in-place additive evolution, so we deliberately do
/// **not** mark this `#[non_exhaustive]` — downstream test harnesses
/// and the in-tree integration test construct values directly via
/// the struct expression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    /// Operator-assigned identifier matching one entry in the relay's
    /// known-keys table.  The handler refuses unknown ids before any
    /// signing work happens.
    pub key_id: CompactString,

    /// TLS signature scheme (IANA ordinal carried as `u16` over the
    /// wire; `rustls::SignatureScheme` newtype in memory).  Validated
    /// against the loaded key's algorithm in [`crate::keyless::policy`].
    pub scheme: SignatureSchemeWire,

    /// Raw bytes the caller wants signed.  Bounded by
    /// [`portal_wire::limits::KEYLESS_PAYLOAD_BUDGET`] (8192).
    /// The handler prepends the SEC-007 domain separator + canonical
    /// envelope before reaching the bridge — see
    /// [`canonical_signing_input`].
    ///
    /// Carried as `Vec<u8>` over serde-json: serialises as a JSON
    /// array of byte ordinals.  At the 8 KiB cap the JSON expansion
    /// is bounded; if base64 framing becomes desirable we will add
    /// it via a workspace dep + per-field `#[serde(with = ...)]`
    /// rather than ship a one-off helper here.
    pub payload: Vec<u8>,

    /// SEC-015 carrier — populated by the upstream relay routing
    /// layer (`routed_hostname`) and the tenant (`requested_cert_subject`).
    /// U3 carries this through verbatim; U4 enforces the refuse-to-sign
    /// rule when the two disagree.
    pub routing_context: RoutingContext,
}

/// Wire shape of a successful sign response.
///
/// Field-stability follows [`SignRequest`] — additive evolution via
/// versioned endpoint, not in-place — so this is **not** marked
/// `#[non_exhaustive]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    /// Raw signature bytes produced by the inner rustls signer.  The
    /// shape is scheme-dependent (DER-encoded ECDSA `r||s`, raw RSA
    /// PSS / PKCS#1 v1.5 octet string, etc.).  Clients verify against
    /// the keyless key's public half + the same canonical signing
    /// input the server constructed.
    ///
    /// Same JSON shape as `SignRequest::payload` — see that field's
    /// rustdoc for the base64 deferral note.
    pub signature: Vec<u8>,

    /// Echoes the scheme the server actually used.  Always equal to
    /// `SignRequest::scheme` on success — surfaced explicitly so a
    /// future scheme-downgrade path (post-quantum migration?) can
    /// renegotiate without breaking the client's parser.
    pub scheme: SignatureSchemeWire,
}

/// Wire shape of a keyless-flavoured `{"error": {...}}` response.
///
/// The U3 handler emits this on 4xx / 5xx; the wire-code set is
/// distinct from the main API surface's [`crate::api::ApiErrorCode`]
/// because the keyless trust boundary is independent (R2).
///
/// Field-stability follows [`SignRequest`] — not `#[non_exhaustive]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeylessErrorBody {
    /// Stable wire code, e.g. `unknown_key_id`, `scheme_mismatch`,
    /// `payload_too_large`, `rate_limited`, `bridge_unavailable`,
    /// `internal`.
    pub code: CompactString,
    /// Human-readable message.  MUST NOT echo internal state or
    /// secret material — the handler-side mapping in
    /// [`crate::keyless::api`] uses a fixed message per code.
    pub message: String,
}

// ---------------------------------------------------------------------------
// RoutingContext — SEC-015 carrier (type only; check lands in U4)
// ---------------------------------------------------------------------------

/// SEC-015 ECH/inner-SNI mismatch carrier.
///
/// `routed_hostname` is supplied by the upstream relay routing layer
/// (the hostname the tenant TLS connection was actually routed to —
/// the SNI value that won routing).  `requested_cert_subject` is
/// supplied by the tenant (the CN/SAN the tenant intends the
/// signature to be valid for).
///
/// **U3 scope**: this type ships verbatim — the handler carries the
/// fields into [`canonical_signing_input`] so the signature commits
/// to them.  The check that refuses to sign when the two disagree is
/// **U4** territory (`policy::check_routing_context`).  The
/// carry-through-then-refuse split keeps the wire stable across
/// U3 → U4: U4 adds a refusal arm, not a new wire field.
///
/// Field-stability follows [`SignRequest`] — not `#[non_exhaustive]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingContext {
    /// Hostname the connection was actually routed to (the relay's
    /// view of the inner SNI / routed name).
    pub routed_hostname: CompactString,
    /// Cert subject the tenant intends the signature to be valid
    /// for (CN/SAN string).
    pub requested_cert_subject: CompactString,
}

// ---------------------------------------------------------------------------
// SignatureSchemeWire — serde-friendly wrapper for rustls::SignatureScheme
// ---------------------------------------------------------------------------

/// `serde`-able wrapper around [`rustls::SignatureScheme`].
///
/// rustls's enum is `#[non_exhaustive]` and does not implement
/// `serde::{Serialize, Deserialize}` directly.  We carry the
/// underlying TLS-IANA `u16` ordinal over the wire (per the IANA
/// "TLS `SignatureScheme`" registry) and convert at the boundary.
/// The macro-generated `From<u16>` round-trips unknown ordinals
/// through the `SignatureScheme::Unknown(u16)` variant, so the
/// conversion never loses information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignatureSchemeWire(pub u16);

impl From<rustls::SignatureScheme> for SignatureSchemeWire {
    fn from(scheme: rustls::SignatureScheme) -> Self {
        Self(u16::from(scheme))
    }
}

impl From<SignatureSchemeWire> for rustls::SignatureScheme {
    fn from(wire: SignatureSchemeWire) -> Self {
        Self::from(wire.0)
    }
}

impl SignatureSchemeWire {
    /// Borrow the wrapped IANA ordinal.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Convert to a [`rustls::SignatureScheme`].
    ///
    /// Convenience accessor for the `From<SignatureSchemeWire>` impl;
    /// chosen as a method so callers do not have to spell out the
    /// turbofish at every call site.
    #[must_use]
    pub fn to_rustls(self) -> rustls::SignatureScheme {
        rustls::SignatureScheme::from(self.0)
    }
}

// ---------------------------------------------------------------------------
// canonical_signing_input — SEC-007 domain-separated canonical bytes
// ---------------------------------------------------------------------------

/// Build the deterministic signing input for a [`SignRequest`].
///
/// Returns
///
/// ```text
/// portal_wire::domain_separators::KEYLESS_REQUEST
/// || postcard::to_stdvec((
///        key_id,
///        scheme_u16,
///        payload_len_u32,
///        payload,
///        routed_hostname,
///        requested_cert_subject,
///    ))
/// ```
///
/// The single source of truth for the canonical wire shape.  Both the
/// U3 handler (signs) and the U3 integration test (verifies) call
/// this — no other site in the codebase should re-derive the
/// concatenation.
///
/// # Errors
///
/// Returns [`postcard::Error`] only if postcard's `to_stdvec` fails;
/// in practice that means out-of-memory.  Bubble it up; the handler
/// maps it to `internal`.
pub fn canonical_signing_input(req: &SignRequest) -> Result<Vec<u8>, postcard::Error> {
    // Encode the canonical tuple.  Field order matches the rustdoc
    // above; any reorder is a wire break and MUST land via an
    // explicit migration commit.  `payload_len_u32` is carried even
    // though postcard already length-prefixes byte slices — it is a
    // belt-and-suspenders against any future encoding change that
    // might drop the inner length, and it pins the canonical bytes
    // against length-extension games on the payload.
    let payload_len_u32: u32 = u32::try_from(req.payload.len()).unwrap_or(u32::MAX);
    let body = postcard::to_stdvec(&(
        req.key_id.as_str(),
        req.scheme.as_u16(),
        payload_len_u32,
        req.payload.as_slice(),
        req.routing_context.routed_hostname.as_str(),
        req.routing_context.requested_cert_subject.as_str(),
    ))?;

    // Prepend the SEC-007 domain separator.  Done at this layer
    // (rather than letting the bridge add it) so the bridge's
    // `canonical_message: Vec<u8>` field stays a verbatim
    // sign-this-byte-string surface — one fewer cross-module
    // contract for the U4 routing-context check to honour later.
    let mut out =
        Vec::with_capacity(portal_wire::domain_separators::KEYLESS_REQUEST.len() + body.len());
    out.extend_from_slice(portal_wire::domain_separators::KEYLESS_REQUEST);
    out.extend_from_slice(&body);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test-only setup")]
mod tests {
    use super::*;

    fn fixture() -> SignRequest {
        SignRequest {
            key_id: CompactString::const_new("test-key-1"),
            scheme: rustls::SignatureScheme::RSA_PSS_SHA256.into(),
            payload: b"hello world".to_vec(),
            routing_context: RoutingContext {
                routed_hostname: CompactString::const_new("example.com"),
                requested_cert_subject: CompactString::const_new("example.com"),
            },
        }
    }

    #[test]
    fn canonical_signing_input_starts_with_domain_separator() {
        let req = fixture();
        let bytes = canonical_signing_input(&req).expect("canonical encoding");
        let sep = portal_wire::domain_separators::KEYLESS_REQUEST;
        assert!(
            bytes.starts_with(sep),
            "canonical bytes must start with the SEC-007 domain separator"
        );
        assert!(
            bytes.len() > sep.len(),
            "canonical bytes must include a non-empty body"
        );
    }

    #[test]
    fn canonical_signing_input_is_deterministic() {
        let req = fixture();
        let a = canonical_signing_input(&req).expect("a");
        let b = canonical_signing_input(&req).expect("b");
        assert_eq!(a, b, "canonical encoding must be byte-deterministic");
    }

    #[test]
    fn canonical_signing_input_changes_when_payload_changes() {
        let mut req = fixture();
        let a = canonical_signing_input(&req).expect("a");
        req.payload.push(0xFF);
        let b = canonical_signing_input(&req).expect("b");
        assert_ne!(a, b, "appending a payload byte must change the canon");
    }

    #[test]
    fn canonical_signing_input_changes_when_routing_context_changes() {
        let mut req = fixture();
        let a = canonical_signing_input(&req).expect("a");
        req.routing_context.routed_hostname = CompactString::const_new("attacker.example.com");
        let b = canonical_signing_input(&req).expect("b");
        assert_ne!(
            a, b,
            "changing routed_hostname must change the canon (SEC-015 prep)"
        );
    }

    #[test]
    fn signature_scheme_wire_round_trip() {
        let scheme = rustls::SignatureScheme::ECDSA_NISTP256_SHA256;
        let wire: SignatureSchemeWire = scheme.into();
        assert_eq!(wire.as_u16(), 0x0403);
        let back: rustls::SignatureScheme = wire.into();
        assert_eq!(back, scheme);
    }

    #[test]
    fn signature_scheme_wire_unknown_round_trips() {
        // Unknown ordinals carry through via SignatureScheme::Unknown(u16).
        let wire = SignatureSchemeWire(0xBEEF);
        let scheme = wire.to_rustls();
        let back: SignatureSchemeWire = scheme.into();
        assert_eq!(back.as_u16(), 0xBEEF);
    }

    #[test]
    fn sign_request_json_round_trip() {
        let req = fixture();
        let s = serde_json::to_string(&req).expect("serialise");
        let back: SignRequest = serde_json::from_str(&s).expect("deserialise");
        // Compare via canonical encoding to side-step PartialEq absence.
        let a = canonical_signing_input(&req).expect("a");
        let b = canonical_signing_input(&back).expect("b");
        assert_eq!(a, b, "JSON round-trip must preserve canonical encoding");
    }

    #[test]
    fn sign_response_json_round_trip() {
        let resp = SignResponse {
            signature: vec![0xAA, 0xBB, 0xCC],
            scheme: rustls::SignatureScheme::RSA_PSS_SHA256.into(),
        };
        let s = serde_json::to_string(&resp).expect("serialise");
        let back: SignResponse = serde_json::from_str(&s).expect("deserialise");
        assert_eq!(back.signature, resp.signature);
        assert_eq!(back.scheme.as_u16(), resp.scheme.as_u16());
    }

    /// Lock the JSON wire shape: `payload` and `signature` MUST
    /// serialise as JSON arrays of byte ordinals (the serde-default
    /// for `Vec<u8>`).  Regression guard against an accidental
    /// re-introduction of a `#[serde(with = ...)]` helper that
    /// would silently flip the wire to base64 or hex.
    #[test]
    fn sign_request_payload_serialises_as_json_byte_array() {
        let req = SignRequest {
            key_id: CompactString::const_new("k"),
            scheme: rustls::SignatureScheme::RSA_PSS_SHA256.into(),
            payload: vec![1u8, 2, 255],
            routing_context: RoutingContext {
                routed_hostname: CompactString::const_new("h"),
                requested_cert_subject: CompactString::const_new("h"),
            },
        };
        let json: serde_json::Value =
            serde_json::to_value(&req).expect("serde_json::to_value must succeed");
        let payload = json
            .get("payload")
            .expect("payload field must be present")
            .as_array()
            .expect("payload must serialise as a JSON array");
        let observed: Vec<u8> = payload
            .iter()
            .map(|v| u8::try_from(v.as_u64().expect("byte")).expect("u8"))
            .collect();
        assert_eq!(observed, vec![1u8, 2, 255]);
    }

    #[test]
    fn sign_response_signature_serialises_as_json_byte_array() {
        let resp = SignResponse {
            signature: vec![0xAA, 0x00, 0xFF],
            scheme: rustls::SignatureScheme::RSA_PSS_SHA256.into(),
        };
        let json: serde_json::Value =
            serde_json::to_value(&resp).expect("serde_json::to_value must succeed");
        let sig = json
            .get("signature")
            .expect("signature field must be present")
            .as_array()
            .expect("signature must serialise as a JSON array");
        let observed: Vec<u8> = sig
            .iter()
            .map(|v| u8::try_from(v.as_u64().expect("byte")).expect("u8"))
            .collect();
        assert_eq!(observed, vec![0xAAu8, 0x00, 0xFF]);
    }
}
