//! Crate-level error type for `portal-relay`.
//!
//! Phase 5 Batch 1 ships a minimal variant set covering the
//! pass-throughs the skeleton itself exercises. The `portal-net`
//! (`NetError`) and `portal-acme` (`AcmeError`) pass-through arms are
//! deferred until their owning workspace deps land in `[workspace.
//! dependencies]` (the unit that first consumes them adds the dep
//! and the variant in the same commit).

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

    /// portal-crypto error pass-through (string form until the unit
    /// that first consumes a typed variant lands).
    #[error("crypto: {0}")]
    Crypto(String),

    /// portal-wire decode/encode failure.
    #[error("wire: {0}")]
    Wire(String),
}

/// Crate-wide `Result<T, RelayError>`.
pub type RelayResult<T> = Result<T, RelayError>;
