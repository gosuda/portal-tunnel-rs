//! Error type for the keyless PEM loader, signer adapter, async
//! bridge, and U3 axum handler / policy.
//!
//! Phase 6b/A Batch 1 first half (U1) shipped the loader-side
//! variants: `MalformedPem`, `UnsupportedAlgorithm`, `InvalidKey`.
//! Batch 1 second half (U2) adds the signer + async-bridge variants:
//! `SignFailed`, `WorkerPanic`, `BridgeClosed`, `QueueFull`.
//! Batch 2 first half (U3) adds the handler / policy variants:
//! `UnknownKeyId`, `SchemeMismatch`, `PayloadTooLarge`, `RateLimited`.
//!
//! The variant set is `#[non_exhaustive]` so adding U4+ arms (SEC-015
//! routing-context refusal) is not a breaking change.

use thiserror::Error;

/// Errors produced by the keyless PEM loader, signer adapter, and
/// async-bridge worker pool.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum KeylessError {
    /// The supplied PEM bytes were syntactically invalid (no recognised
    /// section, base64 decode failure, missing END marker, etc.).
    #[error("malformed pem: {0}")]
    MalformedPem(String),

    /// The PEM was parseable, but the embedded private-key algorithm or
    /// curve is not on the v0.1 keyless allow-list.
    ///
    /// v0.1 accepts:
    /// - PKCS#1 / PKCS#8 RSA (RSA-2048; RSA-3072 lands when an operator
    ///   surfaces a need — see `material.rs` rustdoc).
    /// - PKCS#8 / SEC1 ECDSA on the NIST P-256 curve.
    ///
    /// Everything else (DSA, Ed25519, P-384, P-521, secp256k1, …) is
    /// refused at load time so we cannot accidentally hand a
    /// non-allow-listed algorithm to the
    /// [`super::signer::KeylessSignerAdapter`] (the rustls
    /// `SigningKey` shim).
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// The PEM's algorithm was on the allow-list but the inner DER body
    /// failed to parse (truncated PKCS#8, malformed SEC1 sequence,
    /// missing curve parameters, etc.).
    #[error("invalid key body: {0}")]
    InvalidKey(String),

    /// The signer's `sign(...)` call failed.  Wraps the rustls / aws-lc-rs
    /// error string so the failure is visible at the bridge boundary
    /// without leaking the underlying provider's typed error into our
    /// public surface.
    ///
    /// Phase 6b/A U2 — surfaced when a worker observes a signing-time
    /// error from the inner `rustls::sign::Signer::sign` call.
    #[error("sign failed: {0}")]
    SignFailed(String),

    /// A worker task ended without delivering a reply (the
    /// `oneshot::Sender` was dropped before sending).  The most likely
    /// cause is a worker panic — `JoinSet`-tracked workers surface their
    /// panic to the caller via this variant rather than silently
    /// hanging.
    ///
    /// Phase 6b/A U2 — emitted by `Bridge::sign` when the reply channel
    /// closes without producing a value.
    #[error("worker panicked or exited without reply")]
    WorkerPanic,

    /// The bridge's request channel was already closed (all workers
    /// have exited; cancellation has already drained the pool).  No
    /// further sign requests can be served on this `Bridge` instance.
    ///
    /// Phase 6b/A U2 — emitted by `Bridge::sign` when
    /// `mpsc::Sender::try_send` returns `TrySendError::Closed`.
    #[error("bridge channel closed")]
    BridgeClosed,

    /// The bridge's request queue is at capacity and the caller did
    /// not block.  At U3 the axum handler maps this to HTTP `503
    /// Service Unavailable` so backpressure is observable at the wire
    /// (see ADR-0016 §Decision).
    ///
    /// Phase 6b/A U2 — emitted by `Bridge::sign` when
    /// `mpsc::Sender::try_send` returns `TrySendError::Full`.
    #[error("bridge queue full")]
    QueueFull,

    /// The request's `key_id` is not registered in the relay's known
    /// keys map.  Surfaced by [`crate::keyless::policy`] before the
    /// bridge ever sees the request — the signer worker pool is NOT
    /// invoked for unknown key ids.
    ///
    /// Phase 6b/A U3 — handler maps this to HTTP `400 Bad Request`
    /// with wire code `unknown_key_id`.
    #[error("unknown key id: {0}")]
    UnknownKeyId(String),

    /// The request's `scheme` does not match the loaded key's
    /// algorithm (e.g. an RSA key was asked to produce an ECDSA
    /// signature, or vice versa).  Refusal happens in the policy
    /// layer; the worker pool never observes this request.
    ///
    /// Phase 6b/A U3 — handler maps this to HTTP `400 Bad Request`
    /// with wire code `scheme_mismatch`.
    #[error("scheme mismatch: {0}")]
    SchemeMismatch(String),

    /// The request's `payload` exceeds the SEC-014 keyless payload
    /// budget (`portal_wire::limits::KEYLESS_PAYLOAD_BUDGET`).
    ///
    /// Phase 6b/A U3 — handler maps this to HTTP `400 Bad Request`
    /// with wire code `payload_too_large`.
    #[error("payload too large: {observed} > {budget}")]
    PayloadTooLarge {
        /// Observed payload length in bytes.
        observed: usize,
        /// Configured budget in bytes (the inclusive ceiling).
        budget: usize,
    },

    /// The per-tenant governor rate limiter rejected this request.
    /// The handler maps this to HTTP `429 Too Many Requests`.
    ///
    /// Phase 6b/A U3 — emitted by [`crate::keyless::policy`]'s
    /// per-subject rate limit guard when the configured quota is
    /// exhausted for the connecting client cert's subject.
    #[error("rate limited")]
    RateLimited,

    /// SEC-015 ECH/inner-SNI mismatch: the request's
    /// `routing_context.routed_hostname` (set by the upstream relay
    /// routing layer) does not authorise the
    /// `routing_context.requested_cert_subject` the tenant declared.
    ///
    /// This refusal closes the MITM primitive enumerated in roadmap
    /// SEC-015 — a tenant terminating an inner SNI for `victim.com`
    /// cannot ask the keyless oracle to sign for a cert subject that
    /// does not authorise that hostname.  The handler maps this to
    /// HTTP `403 Forbidden` (NOT 400) so the wire signals an explicit
    /// security-policy refusal rather than an input-shape complaint.
    ///
    /// Phase 6b/A U4 — emitted by [`crate::keyless::policy::check_routing_context`].
    #[error("routing context mismatch: {0}")]
    RoutingContextMismatch(String),
}
