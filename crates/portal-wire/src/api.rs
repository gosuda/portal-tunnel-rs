//! JSON DTOs for HTTP API bodies (utoipa-friendly).

use compact_str::CompactString;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// SIWE binding attestation field (SEC-002) — verification in `portal-crypto`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiweAttestation {
    /// Bound ed25519 protocol key (raw).
    pub ed25519_pubkey: [u8; 32],
    /// EIP-4361 message bytes (UTF-8).
    pub siwe_message: String,
    /// secp256k1 / EIP-191 signature hex or raw (Phase 2 normalizes).
    pub siwe_signature: String,
}

/// Wire request body for `POST /v1/sdk/register-challenge`.
///
/// Mirrors Go v2.2.1 `types.RegisterChallengeRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterChallengeRequest {
    /// 20-byte EVM address as `"0x" + 40 hex` (case-insensitive).
    pub eth_address: String,
    /// 32-byte raw ed25519 protocol pubkey, standard-base64 encoded.
    pub ed25519_pk: String,
    /// Optional SDK-self-reported IP (carried into the eventual
    /// lease's R10 reputation signals). `None` / `""` = decline to
    /// report; the relay falls back to the transport-observed IP.
    #[serde(default)]
    pub reported_ip: Option<String>,
    /// Whether the SDK is requesting the UDP datagram surface. Mutually
    /// exclusive with a non-empty `hop_token`.
    #[serde(default)]
    pub udp_enabled: bool,
    /// Whether the SDK is requesting the TCP port surface. Mutually
    /// exclusive with a non-empty `hop_token`.
    #[serde(default)]
    pub tcp_enabled: bool,
    /// Optional multi-hop forwarding token. v0.1 does NOT implement
    /// hop routing; a non-empty token returns 503 `feature_unavailable`.
    #[serde(default)]
    pub hop_token: String,
    /// Hostname the SDK wants to register. Pinned at challenge-issue
    /// for traceability but not validated until the consume step (S6).
    #[serde(default)]
    pub hostname: String,
    /// Free-form per-lease metadata blob (base64 of postcard-encoded
    /// bytes; opaque to the relay).
    #[serde(default)]
    pub metadata: String,
    /// Requested lease TTL in seconds. v0.1 does NOT honor this on
    /// the challenge-issue path — the challenge TTL is a fixed
    /// 2-minute constant — but the field is captured here so the
    /// consume step (S6) can apply it to the eventual `LeaseRecord`.
    #[serde(default)]
    pub ttl: u32,
    /// Optional routed hostname (SNI target or override). Empty when
    /// omitted for backward compatibility.
    #[serde(default)]
    pub route_hostname: CompactString,
    /// Hostname hash used for deterministic routing / shard selection.
    /// Empty when omitted for backward compatibility.
    #[serde(default)]
    pub hostname_hash: String,
}

/// Wire response body for `POST /v1/sdk/register-challenge` 201.
///
/// Mirrors Go v2.2.1 `types.RegisterChallengeResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RegisterChallengeResponse {
    /// `UUIDv4` (32 lowercase-hex chars, no hyphens) — primary key
    /// into the relay's pending-challenge table.
    pub challenge_id: CompactString,
    /// Absolute expiry as RFC 3339 timestamp.
    pub expires_at: Timestamp,
    /// The EIP-4361 SIWE message text the SDK signs with its
    /// secp256k1 EOA key (EIP-191 personal-sign).
    pub siwe_message: String,
}

impl RegisterChallengeResponse {
    /// Constructor for downstream crates blocked by `#[non_exhaustive]`.
    #[must_use]
    #[expect(clippy::missing_const_for_fn, reason = "CompactString::new is not stable const")]
    pub fn new(challenge_id: CompactString, expires_at: Timestamp, siwe_message: String) -> Self {
        Self {
            challenge_id,
            expires_at,
            siwe_message,
        }
    }
}

/// Wire request body for `POST /v1/sdk/register`.
///
/// Mirrors Go v2.2.1 `types.RegisterRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Echoes the issued challenge id (32 lowercase-hex chars, no
    /// hyphens — `UUIDv4::simple`).
    pub challenge_id: CompactString,
    /// EIP-4361 SIWE message text the SDK signed. The relay
    /// re-parses this and asserts it byte-equals the text it pinned
    /// at challenge issue.
    pub siwe_message_text: String,
    /// 65-byte EIP-191 secp256k1 signature as `"0x" + 130 hex`
    /// (case-insensitive).
    pub siwe_signature: String,
    /// Hostname the SDK wants to register.
    pub hostname: CompactString,
    /// Free-form per-lease metadata blob, standard-base64 of the
    /// postcard-encoded bytes. Empty string = zero-byte blob.
    #[serde(default)]
    pub metadata: String,
    /// Optional routed hostname (SNI target or override).
    #[serde(default)]
    pub route_hostname: CompactString,
    /// Hostname hash used for deterministic routing / shard selection.
    #[serde(default)]
    pub hostname_hash: String,
}

/// Wire response body for `POST /v1/sdk/register` 201.
///
/// Mirrors Go v2.2.1 `types.RegisterResponse`, extended with
/// `route_hostname`, `hostname_hash`, and a dummy `ech_config_list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RegisterResponse {
    /// 32-byte raw ed25519 protocol pubkey as 64-char lowercase hex
    /// (no `0x` prefix).
    pub identity: String,
    /// Hostname the lease holds.
    pub hostname: CompactString,
    /// Lease expiry timestamp (RFC 3339).
    pub expires_at: Timestamp,
    /// Lease access token (signed JWT-style compact string).
    pub access_token: CompactString,
    /// Wire-protocol version.
    pub protocol_version: String,
    /// Relay binary release version.
    pub release_version: String,
    /// Routed hostname echoed back (or empty if omitted at request).
    pub route_hostname: CompactString,
    /// Hostname hash echoed back (or empty if omitted at request).
    pub hostname_hash: String,
    /// ECH (Encrypted Client Hello) config list — dummy placeholder
    /// until ECH key rotation lands in a later phase.
    pub ech_config_list: Vec<u8>,
}

impl RegisterResponse {
    /// Constructor for downstream crates blocked by `#[non_exhaustive]`.
    #[must_use]
    #[expect(clippy::too_many_arguments, reason = "wire response mirrors struct fields")]
    #[expect(clippy::missing_const_for_fn, reason = "String/CompactString not stable const")]
    pub fn new(
        identity: String,
        hostname: CompactString,
        expires_at: Timestamp,
        access_token: CompactString,
        protocol_version: String,
        release_version: String,
        route_hostname: CompactString,
        hostname_hash: String,
        ech_config_list: Vec<u8>,
    ) -> Self {
        Self {
            identity,
            hostname,
            expires_at,
            access_token,
            protocol_version,
            release_version,
            route_hostname,
            hostname_hash,
            ech_config_list,
        }
    }
}


#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test-only assertions")]

    use super::*;

    #[test]
    fn register_challenge_request_roundtrip() {
        let req = RegisterChallengeRequest {
            eth_address: "0x00112233445566778899aabbccddeeff00112233".to_owned(),
            ed25519_pk: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                [0xabu8; 32],
            ),
            reported_ip: Some("1.2.3.4".to_owned()),
            udp_enabled: true,
            tcp_enabled: false,
            hop_token: String::new(),
            hostname: "tenant-a".to_owned(),
            metadata: String::new(),
            ttl: 600,
            route_hostname: CompactString::new("route.example.com"),
            hostname_hash: "deadbeef".to_owned(),
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let back: RegisterChallengeRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(req, back);
    }

    #[test]
    fn register_request_roundtrip() {
        let req = RegisterRequest {
            challenge_id: CompactString::new("aabbccdd11223344556677889900aabb"),
            siwe_message_text: "example.com wants you to sign in...".to_owned(),
            siwe_signature: "0xabcd".to_owned(),
            hostname: CompactString::new("tenant-a"),
            metadata: String::new(),
            route_hostname: CompactString::new("route.example.com"),
            hostname_hash: "cafebabe".to_owned(),
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let back: RegisterRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(req, back);
    }

    #[test]
    fn register_response_roundtrip() {
        let resp = RegisterResponse {
            identity: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_owned(),
            hostname: CompactString::new("tenant-a"),
            expires_at: Timestamp::now(),
            access_token: CompactString::new("tok"),
            protocol_version: "0.1.0".to_owned(),
            release_version: "0.1.0".to_owned(),
            route_hostname: CompactString::new("route.example.com"),
            hostname_hash: "feedface".to_owned(),
            ech_config_list: vec![0x01, 0x02, 0x03],
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: RegisterResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(resp, back);
    }

    /// Backward-compatibility: old JSON without `route_hostname` / `hostname_hash`
    /// must deserialize successfully thanks to `#[serde(default)]`.
    #[test]
    fn register_challenge_request_missing_new_fields_defaults() {
        let json = r#"{
            "eth_address": "0x00112233445566778899aabbccddeeff00112233",
            "ed25519_pk": "abc123"
        }"#;
        let req: RegisterChallengeRequest = serde_json::from_str(json).expect("deserialize");
        assert_eq!(req.route_hostname, CompactString::default());
        assert_eq!(req.hostname_hash, String::new());
    }

    #[test]
    fn register_request_missing_new_fields_defaults() {
        let json = r#"{
            "challenge_id": "aabbccdd11223344556677889900aabb",
            "siwe_message_text": "msg",
            "siwe_signature": "0xab",
            "hostname": "tenant-a"
        }"#;
        let req: RegisterRequest = serde_json::from_str(json).expect("deserialize");
        assert_eq!(req.route_hostname, CompactString::default());
        assert_eq!(req.hostname_hash, String::new());
    }
}
