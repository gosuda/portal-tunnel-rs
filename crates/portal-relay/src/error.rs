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
}

/// Crate-wide `Result<T, RelayError>`.
pub type RelayResult<T> = Result<T, RelayError>;
