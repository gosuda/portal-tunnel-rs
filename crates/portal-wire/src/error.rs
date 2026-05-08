//! Wire-layer errors.

use thiserror::Error;

/// Decode / encode / policy violations at the wire layer.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Go marker `0x00` must never appear on greenfield streams.
    #[error("legacy keepalive byte 0x00 (go wire drift)")]
    LegacyKeepaliveByte,
    /// Unknown [`crate::channel::Channel`] discriminant.
    #[error("unknown channel tag: {0}")]
    UnknownChannelTag(u8),
    /// Unknown [`crate::channel::TcpProxyKind`]
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
    /// Requested resource was not found.
    #[error("not found")]
    NotFound,
    /// TCP port pool is exhausted.
    #[error("tcp port exhausted")]
    TcpPortExhausted,
    /// TCP proxy surface is disabled by policy.
    #[error("tcp port disabled")]
    TcpPortDisabled,
    /// TCP capacity limit exceeded.
    #[error("tcp port capacity exceeded")]
    TcpPortCapacityExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages_are_non_empty() {
        let cases: Vec<(Error, &'static str)> = vec![
            (Error::LegacyKeepaliveByte, "legacy keepalive"),
            (Error::UnknownChannelTag(7), "unknown channel"),
            (Error::UnknownTcpProxyKind(3), "unknown tcp-proxy"),
            (Error::FrameTooLarge, "frame exceeds"),
            (Error::NotFound, "not found"),
            (Error::TcpPortExhausted, "tcp port exhausted"),
            (Error::TcpPortDisabled, "tcp port disabled"),
            (Error::TcpPortCapacityExceeded, "tcp port capacity exceeded"),
        ];
        for (err, expected_substring) in cases {
            let msg = err.to_string();
            assert!(
                !msg.is_empty(),
                "error variant must produce a non-empty display message"
            );
            assert!(
                msg.to_ascii_lowercase().contains(expected_substring),
                "display message '{msg}' should contain '{expected_substring}'"
            );
        }
    }
}
