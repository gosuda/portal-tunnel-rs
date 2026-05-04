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

    /// QUIC error (connection or endpoint).
    #[error("quic: {0}")]
    Quic(String),

    /// Wire codec decode failure (from portal-wire).
    #[error("wire-decode: {0}")]
    WireDecode(String),

    /// ed25519 PKCS#8 key load or parse failure.
    #[error("identity-load: {0}")]
    IdentityLoad(String),

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
