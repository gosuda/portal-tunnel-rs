//! Crate-level error type for `portal-relay`.
//!
//! Phase 5 Batch 1 shipped a minimal variant set covering the
//! pass-throughs the skeleton itself exercises. Phase 5 Batch 2 adds
//! the `Net(#[from] portal_net::NetError)` arm now that U3 listeners
//! + U4 identity loader pull `portal-net` into the dep graph.
//!
//! The `portal-acme` (`AcmeError`) pass-through arm remains deferred
//! until its owning unit lands (the unit that first consumes it adds
//! the dep and the variant in the same commit).

use thiserror::Error;

use crate::state::LeaseTokenError;

/// Top-level error type.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum RelayError {
    /// Configuration was rejected at construction time.
    #[error("config: {0}")]
    Config(String),

    /// I/O failure (filesystem or socket).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// portal-net error pass-through (key load, listener bind, etc.).
    #[error("net: {0}")]
    Net(#[from] portal_net::NetError),

    /// portal-crypto error pass-through (string form until the unit
    /// that first consumes a typed variant lands).
    #[error("crypto: {0}")]
    Crypto(String),

    /// portal-wire decode/encode failure.
    #[error("wire: {0}")]
    Wire(String),

    /// Keyless module failure (PEM parse, unsupported algorithm,
    /// malformed key body). Phase 6b/A U1.
    #[error("keyless: {0}")]
    Keyless(#[from] crate::keyless::KeylessError),

    /// Overlay subsystem failure (`WgDevice` adapter init, peer
    /// config validation, packet I/O). Phase 6b/B U6.
    #[error("overlay: {0}")]
    Overlay(#[from] crate::overlay::OverlayError),

    /// Lease-access-token issue/verify failure. Phase 5 SDK-API S1.
    #[error(transparent)]
    LeaseToken(#[from] LeaseTokenError),

    /// The client IP already has the per-IP cap (32) of outstanding
    /// pending register challenges. Phase 5 SDK-API S3.
    #[error("challenge: per-IP pending cap exceeded")]
    ChallengePendingCap,

    /// `consume_register_challenge` saw a `challenge_id` that does
    /// not exist in the pending table — either it was never issued,
    /// it was already consumed (single-use), or the janitor swept
    /// it past TTL. Phase 5 SDK-API S3.
    #[error("challenge: not found")]
    ChallengeNotFound,

    /// The pending challenge resolved by `challenge_id` has aged
    /// past its `expires_at`. Surfaced when a `consume_register_challenge`
    /// caller sneaks in between janitor ticks. Phase 5 SDK-API S3.
    #[error("challenge: expired")]
    ChallengeExpired,

    /// SIWE / ed25519 binding verification failed in
    /// `consume_register_challenge`. Wraps the `portal-crypto`
    /// failure as a string per the surrounding `Crypto` arm pattern
    /// (the typed pass-through lands later when `portal-crypto`
    /// exposes a stable Binding/Siwe error split). Phase 5 SDK-API S3.
    #[error("challenge: invalid signature: {0}")]
    ChallengeInvalidSignature(String),
}

/// Crate-wide `Result<T, RelayError>`.
pub type RelayResult<T> = Result<T, RelayError>;
