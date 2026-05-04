//! `AcmeError` + `AcmeResult` — typed error enum for the crate.

use thiserror::Error;

/// Top-level error type for `portal-acme`.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum AcmeError {
    /// Configuration was rejected at construction time.
    #[error("config: {0}")]
    Config(String),

    /// Filesystem operation (read/write/atomic-rename) failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// `instant-acme` returned an RFC 8555 error.
    #[error("acme: {0}")]
    Acme(String),

    /// DNS provider operation (upsert/delete/sync) failed.
    #[error("dns: {0}")]
    Dns(String),

    /// Cert generation (rcgen / `instant-acme` finalize) failed.
    #[error("cert: {0}")]
    Cert(String),

    /// JSON encode/decode for account/registration persistence.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// Crate-wide `Result<T, AcmeError>`.
pub type AcmeResult<T> = Result<T, AcmeError>;
