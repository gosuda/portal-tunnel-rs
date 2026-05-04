//! Crate-level error type for `portal-sdk`.

use thiserror::Error;

/// Top-level error type for SDK operations.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum SdkError {
    /// Configuration was rejected at construction time (e.g.,
    /// missing relay descriptors, malformed identity path).
    #[error("config: {0}")]
    Config(String),

    /// I/O failure (filesystem or socket).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// portal-net error pass-through (transport-layer fault).
    #[error("net: {0}")]
    Net(#[from] portal_net::NetError),

    /// portal-crypto error pass-through (key load, signature, etc.).
    #[error("crypto: {0}")]
    Crypto(String),

    /// Wire decode failure (`RelayDescriptor` parsing, envelope decode).
    #[error("wire: {0}")]
    Wire(String),

    /// MITM probe rejected the connection — exporter label
    /// mismatch or value disagreement.
    #[error("mitm: {0}")]
    Mitm(String),

    /// Relay-set picker rejected the supplied descriptors due to
    /// insufficient ASN / operator diversity (eclipse defense).
    #[error("eclipse: {0}")]
    Eclipse(String),

    /// Lease-related failure (registration, renewal, expiry).
    #[error("lease: {0}")]
    Lease(String),
}

/// Crate-wide `Result<T, SdkError>`.
pub type SdkResult<T> = Result<T, SdkError>;
