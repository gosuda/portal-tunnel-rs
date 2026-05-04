//! Crate-level error type for `portal-net`.

use thiserror::Error;

/// Top-level error for all `portal-net` operations.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum NetError {
    /// I/O error (file or socket).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// TLS handshake or configuration failure.
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),

    /// QUIC runtime error from the underlying quinn endpoint (connection,
    /// migration, transport-level fault). Reserved for genuine quinn-emitted
    /// failures; programmer errors (role misuse) and connect-time failures
    /// have their own variants for caller discrimination.
    #[error("quic: {0}")]
    Quic(String),

    /// QUIC connect-time failure surfaced by [`quinn::Endpoint::connect`]
    /// (e.g., invalid `server_name`, no client config, transport-init error).
    /// Distinct from [`NetError::Quic`] so SDK-side retry policy can match a
    /// connect failure without absorbing every QUIC-adjacent error.
    #[error("connect: {0}")]
    Connect(String),

    /// Programmer error: an [`crate::quic::Endpoint`] method was called on a
    /// role that does not support it (e.g., `accept()` on a Client endpoint,
    /// `connect()` on a Server endpoint). Carries the method name and the
    /// role found so callers and tests can match on a structured variant
    /// rather than substring-matching an error message.
    #[error("role mismatch: {method}() not valid on {found} endpoint")]
    RoleMismatch {
        /// The method that was invoked.
        method: &'static str,
        /// The role of the endpoint at call time.
        found: &'static str,
    },

    /// Wire codec decode failure (from portal-wire).
    #[error("wire-decode: {0}")]
    WireDecode(String),

    /// ed25519 identity-key fault. Covers both PKCS#8 *load* failures
    /// (read-from-disk, decode) and *save* failures (encode, atomic-write).
    /// A single variant keeps the trust-boundary surface narrow per R2 (one
    /// error class for the QUIC identity key, regardless of direction).
    #[error("identity: {0}")]
    Identity(String),

    /// Listener bind failure.
    #[error("bind-failed: {0}")]
    BindFailed(String),

    /// Backhaul control-channel handshake failure.
    #[error("backhaul-handshake: {0}")]
    BackhaulHandshake(String),

    /// `PortAllocator` exhausted.
    #[error("port-exhausted")]
    PortExhausted,
}

const _: fn() = || {
    const fn assert_send_sync<T: Send + Sync + 'static>() {}
    assert_send_sync::<NetError>();
};
