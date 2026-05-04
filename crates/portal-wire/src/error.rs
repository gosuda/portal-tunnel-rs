//! Wire-layer errors.

use thiserror::Error;

/// Decode / encode / policy violations at the wire layer.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Go marker `0x00` must never appear on greenfield streams.
    #[error("legacy keepalive byte 0x00 (go wire drift)")]
    LegacyKeepaliveByte,
    /// Unknown [`crate::channel::Channel`](Channel) discriminant.
    #[error("unknown channel tag: {0}")]
    UnknownChannelTag(u8),
    /// Unknown [`crate::channel::TcpProxyKind`](crate::channel::TcpProxyKind)
    /// sub-discriminant byte (the byte following a `Channel::TcpProxy` tag).
    #[error("unknown tcp-proxy kind: {0}")]
    UnknownTcpProxyKind(u8),
    /// Payload exceeds the per-channel SEC-014 cap.
    #[error("frame exceeds limit for channel")]
    FrameTooLarge,
    /// Postcard serialization failure.
    #[error("postcard encode: {0}")]
    PostcardEncode(#[from] postcard::Error),
    /// Postcard deserialization failure.
    #[error("postcard decode: {0}")]
    PostcardDecode(postcard::Error),
    /// I/O while framing (codec buffer).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
