//! Error type for the keyless PEM loader, signer adapter, and
//! async bridge.
//!
//! Phase 6b/A Batch 1 first half (U1) shipped the loader-side
//! variants: `MalformedPem`, `UnsupportedAlgorithm`, `InvalidKey`.
//! Batch 1 second half (U2) adds the signer + async-bridge variants:
//! `SignFailed`, `WorkerPanic`, `BridgeClosed`, `QueueFull`.
//!
//! The variant set is `#[non_exhaustive]` so adding U3+ arms (axum
//! handler / policy / SEC-015) is not a breaking change.

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
    /// non-allow-listed algorithm to the (forthcoming U2) rustls
    /// `SigningKey` adapter.
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
}
