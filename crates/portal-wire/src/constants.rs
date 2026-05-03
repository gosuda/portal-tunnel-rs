//! ALPN and HTTP header constants.

/// QUIC ALPN identifier (protocol generation 2).
pub const ALPN: &[u8] = b"portal/2";

/// Protocol generation byte mirrored in MITM label and docs.
pub const PROTOCOL_GENERATION: u8 = 2;

/// HTTP header carrying a signed binary [`crate::envelope::Envelope`].
pub const HEADER_ENVELOPE: &str = "X-Portal-Envelope";
