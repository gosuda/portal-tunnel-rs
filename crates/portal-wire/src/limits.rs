//! SEC-014 hard caps (amplification defense).

/// Max `Control` channel payload bytes (inclusive).
pub const CONTROL_MAX: usize = 8192;
/// Max `HopRoute` payload bytes.
pub const HOP_ROUTE_MAX: usize = 4096;
/// Max single UDP datagram payload bytes.
pub const UDP_DATAGRAM_MAX: usize = 65536;
/// Max `TcpProxy` frame payload bytes.
pub const TCP_PROXY_MAX: usize = 16384;
/// Max postcard-encoded `ReputationDelta`.
pub const REPUTATION_DELTA_MAX: usize = 1024;
/// Max postcard-encoded `LeaseToken`.
pub const LEASE_TOKEN_MAX: usize = 512;
/// Max canonical `RelayDescriptor` encoding.
pub const RELAY_DESCRIPTOR_CANON_MAX: usize = 4096;
/// Max keyless-request payload bytes (Phase 6b/A SEC-004 / SEC-014).
///
/// The keyless oracle signs TLS handshake transcript fragments — typically
/// the post-`CertificateVerify` handshake hash (≤ 64 bytes for SHA-512) or a
/// PSK binder message body. A conservative ceiling at 8 KiB (matching
/// [`CONTROL_MAX`]) leaves orders-of-magnitude headroom over any legitimate
/// TLS sign-input while bounding amplification: a malicious tenant cannot
/// coerce a 1 MiB signature input out of a single mTLS request.
pub const KEYLESS_PAYLOAD_BUDGET: usize = 8192;
