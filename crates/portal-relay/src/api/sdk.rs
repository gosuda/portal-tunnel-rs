//! SDK trust-boundary endpoint handlers.
//!
//! ## Endpoints
//!
//! - `GET /v1/sdk/domain` — bootstrap-time deployment-constant
//!   identity surface. Returns the relay's protocol/release version
//!   pair so the SDK can pin the wire surface it is talking to before
//!   it has any keys to authenticate. No state extraction; no rate
//!   limit; no authentication. CORS header
//!   `Access-Control-Allow-Origin: *` per Go upstream
//!   (`portal-tunnel/portal/api_server.go:238`).
//! - `POST /v1/sdk/register-challenge` — issue a one-shot SIWE
//!   register challenge. Decodes a [`RegisterChallengeBody`] wire
//!   request, extracts the canonicalized client IP via
//!   [`crate::policy::ProxyTrust::extract_client_ip`], asserts the
//!   IP is not banned, validates transport flags, then calls
//!   [`crate::state::LeaseRegistry::issue_register_challenge`]. The
//!   201 Created response carries [`RegisterChallengeResponseBody`]
//!   (`challenge_id`, `expires_at`, `siwe_message`).
//!
//! ## Trust boundary
//!
//! The SDK router is reachable from any client; handlers register
//! their own per-endpoint authentication policies. `GET /v1/sdk/domain`
//! is intentionally unauthenticated — it is the SDK's bootstrap
//! handshake before any lease, key, or signed material exists.
//! `POST /v1/sdk/register-challenge` is also unauthenticated by
//! design (pre-registration — the caller has not yet proved
//! possession of any key); abuse is bounded by the per-IP outstanding
//! cap enforced inside `LeaseRegistry::issue_register_challenge`.
//!
//! Subsequent handlers (`/v1/sdk/register`, `/v1/sdk/renew`,
//! `/v1/sdk/unregister`, `/v1/sdk/connect`) land in follow-up commits.

use std::net::{IpAddr, SocketAddr};

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use compact_str::CompactString;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::api::envelope::{ApiDataEnvelope, ApiError, ApiErrorCode, ok};
use crate::api::state::SdkState;
use crate::state::challenge::RegisterChallengeRequest as InnerRegisterChallengeRequest;

/// Wire body for `GET /v1/sdk/domain`.
///
/// Both fields are populated from `env!("CARGO_PKG_VERSION")` in v0.1
/// because the relay binary is the canonical version source. The
/// fields are kept as separate identifiers (rather than collapsed to a
/// single `version`) to mirror Go upstream's `types.DomainResponse`
/// shape — the discriminator is preserved for forward-compat so a
/// future relay can decouple wire-protocol version (`protocol_version`)
/// from binary build-tag (`release_version`) without a wire break.
///
/// `#[non_exhaustive]` blocks struct-literal construction from
/// downstream Rust crates; it does NOT guarantee JSON-wire
/// compatibility — a strict-decoder client that rejects unknown
/// keys would still break on a field addition.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct DomainBody {
    /// Wire-protocol version. v0.1 collapses to `CARGO_PKG_VERSION`;
    /// future releases may decouple from `release_version`.
    pub protocol_version: &'static str,
    /// Relay binary release version. v0.1 collapses to
    /// `CARGO_PKG_VERSION`; future releases may decouple from
    /// `protocol_version`.
    pub release_version: &'static str,
}

/// `GET /v1/sdk/domain` — deployment-constant relay identity.
///
/// Returns the relay's protocol/release version pair as a constant
/// JSON body wrapped in [`ApiDataEnvelope`]. The response carries an
/// `Access-Control-Allow-Origin: *` header so a browser-resident SDK
/// (origin-bound JS) can fetch the bootstrap surface before negotiating
/// any further authentication.
///
/// ## CORS approach
///
/// `tower-http` is not a workspace dependency in v0.1 (see
/// `crates/portal-relay/Cargo.toml`), so the header is set per-handler
/// via [`HeaderMap`] on a tuple-`IntoResponse` return shape. A
/// follow-up slice that needs broader CORS coverage (preflight, vary,
/// allow-methods) should adopt `tower_http::cors::CorsLayer` at the
/// router level rather than fan out per-handler header insertion.
///
/// # Errors
///
/// Infallible. The signature returns
/// `Result<…, ApiError>` for envelope uniformity with the rest of the
/// API surface; the `Err` arm is unreachable in v0.1.
#[tracing::instrument(name = "sdk.domain", skip_all)]
pub async fn domain_handler() -> Result<(HeaderMap, Json<ApiDataEnvelope<DomainBody>>), ApiError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    Ok((
        headers,
        ok(DomainBody {
            protocol_version: env!("CARGO_PKG_VERSION"),
            release_version: env!("CARGO_PKG_VERSION"),
        }),
    ))
}

/// Wire body for `POST /v1/sdk/register-challenge`.
///
/// The Rust port deviates from Go's literal `types.RegisterChallengeRequest`
/// shape in two ways:
///
/// 1. The two cross-signed key materials (`eth_address` + `ed25519_pk`)
///    are flat fields rather than nested under an `identity` object.
///    Rationale: Go's `Identity.PublicKey` is `json:"-"` and is plumbed
///    out-of-band; the Rust port's
///    [`portal_crypto::siwe::binding::canonical_statement`] requires
///    BOTH values at SIWE-build time. A flat shape avoids a redundant
///    nested object whose only `name` field is unused at the
///    challenge-issue step (S5 does not write to the lease record).
/// 2. `metadata` carries the SDK's opaque per-lease blob as a
///    base64-encoded byte string rather than a nested
///    `LeaseMetadata` struct. Rationale: the relay does not interpret
///    this blob; postcard-encoding by the SDK produces a tighter
///    representation than re-decoding the Go upstream's
///    `description / owner / tags` JSON object surface, and the byte
///    blob round-trips through the `consume_register_challenge` path
///    unchanged.
///
/// Encoding choices:
///
/// - `eth_address`: 20-byte EVM address as `"0x" + 40 lowercase hex`.
/// - `ed25519_pk`: 32-byte raw protocol pubkey as standard base64
///   (matches Go's `[]byte` JSON encoding default).
/// - `metadata`: standard-base64 of the postcard-encoded blob.
/// - `reported_ip`: optional self-reported IP (free-form string;
///   parsed via [`IpAddr::from_str`]).
///
/// `#[serde(deny_unknown_fields)]` is intentionally NOT applied:
/// downstream wire evolution (e.g., a future `attestation` field) must
/// be backward-compatible at the wire boundary even when older relays
/// see it.
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterChallengeBody {
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
}

/// Wire body for the `POST /v1/sdk/register-challenge` 201 response.
///
/// Mirrors Go's `types.RegisterChallengeResponse`. The wire field
/// `siwe_message` corresponds to the internal struct field
/// `siwe_message_text` — the rename is documented here so a reader
/// of either side can trace the wire boundary.
///
/// `#[non_exhaustive]` blocks struct-literal construction from
/// downstream Rust crates; it does NOT guarantee JSON-wire
/// compatibility — a strict-decoder client that rejects unknown
/// keys would still break on a field addition.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct RegisterChallengeResponseBody {
    /// `UUIDv4` (32 lowercase-hex chars, no hyphens) — primary key
    /// into the relay's pending-challenge table.
    pub challenge_id: CompactString,
    /// Absolute expiry as RFC 3339 timestamp.
    pub expires_at: Timestamp,
    /// The EIP-4361 SIWE message text the SDK signs with its
    /// secp256k1 EOA key (EIP-191 personal-sign). Renamed from
    /// the internal `siwe_message_text` for wire-shape parity with
    /// Go's `types.RegisterChallengeResponse.SIWEMessage`.
    pub siwe_message: String,
}

/// `POST /v1/sdk/register-challenge` — issue a one-shot SIWE
/// register challenge.
///
/// ## Path A: Host-header-required for `domain` resolution
///
/// The slice plan defines `domain = req.host_header || relay_identity.name`.
/// `SdkState` does not (yet) carry a `relay_name` field, so the v0.1
/// shape requires a non-empty `Host` header — missing/empty returns
/// 400 `invalid_request`. Rationale: per the slice's ≤5-files budget +
/// Carmack-Atomic preference, plumbing `relay_name` through `SdkState`
/// would touch every `SdkState` fixture across the test suite. SDK
/// clients in practice always send Host, so this trade-off is
/// invisible at the wire boundary.
///
/// ### Security trade-off — Host is attacker-controlled
///
/// `Host` is untrusted client input. A caller can therefore mint a
/// SIWE challenge whose `domain` field is any string — the relay does
/// NOT validate the Host against an allowlist in v0.1. The downstream
/// consume step (S6) re-binds the SIWE message under the same domain
/// the SDK echoes back, so a tampered Host does NOT let a caller
/// hijack a challenge for a different relay; the worst case is a
/// caller minting a challenge whose SIWE domain reads "evil.example"
/// in their own SDK logs. The bound material (eth address ↔ ed25519
/// pk) is unaffected. Operators who need strict domain binding
/// (e.g., to defeat phishing-style SDK-log spoofing) should fall back
/// to `relay_identity.name` — Path B. Tracked as a v0.1 follow-up.
/// Follow-up: extend `SdkState` with `relay_name: CompactString` and
/// either (a) reject Host values that don't match the relay name, or
/// (b) derive `domain` from `relay_name` unconditionally.
///
/// ## Hop-token handling
///
/// `hop_token != ""` is genuinely unimplemented in v0.1 (multi-hop is
/// v0.2 territory). A non-empty hop token returns 503
/// `feature_unavailable` regardless of UDP/TCP flag values. Rationale
/// over the alternative (409 `transport_mismatch` for a no-transport
/// selection): the operator-facing failure mode is "this feature
/// isn't built yet" rather than "the request is malformed".
///
/// ## Transport-disabled-by-policy gates
///
/// v0.1 [`crate::policy::PolicyRuntime`] does NOT carry per-listener
/// UDP/TCP enable bits — those gates land in a follow-up. The handler
/// therefore SKIPS the `udp_disabled` / `tcp_port_disabled` checks
/// and accepts UDP/TCP requests unconditionally (gated only by the
/// transport-mismatch rules). Follow-up: add
/// `PolicyRuntime::is_udp_enabled` / `is_tcp_enabled` getters and
/// re-introduce the 403 gate.
///
/// # Errors
///
/// - 400 `invalid_request` — malformed JSON body, malformed
///   `eth_address` / `ed25519_pk`, or empty `Host` header.
/// - 401 `ip_banned` — source IP is banned by either the in-memory
///   filter or the operator-managed snapshot.
/// - 409 `transport_mismatch` — `hop_token != ""` together with
///   `udp_enabled || tcp_enabled`, OR no transport selected.
/// - 429 `rate_limited` — per-IP outstanding-challenge cap
///   ([`crate::state::REGISTER_CHALLENGE_PER_IP_CAP`]) exceeded.
/// - 503 `feature_unavailable` — `hop_token != ""` (v0.1 hop is
///   genuinely unimplemented).
#[tracing::instrument(
    name = "sdk.register_challenge",
    skip_all,
    fields(client_ip = tracing::field::Empty),
)]
pub async fn register_challenge_handler(
    State(state): State<SdkState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<RegisterChallengeBody>, JsonRejection>,
) -> Result<
    (
        StatusCode,
        Json<ApiDataEnvelope<RegisterChallengeResponseBody>>,
    ),
    ApiError,
> {
    // 1. Decode the body. axum's `JsonRejection` covers malformed JSON,
    //    wrong content-type, and missing-required-field cases — surface
    //    them all as `invalid_request` per the slice's acceptance
    //    criterion 3.
    let Json(req) = body.map_err(|err| {
        ApiError::new(
            ApiErrorCode::InvalidRequest,
            format!("register-challenge body: {err}"),
        )
    })?;

    // 2. Extract the canonicalized client IP (R12) via the policy
    //    runtime's `ProxyTrust` chain. Only the legacy
    //    `X-Forwarded-For` and `X-Real-IP` headers are consulted —
    //    `ProxyTrust::extract_client_ip` does not parse the RFC 7239
    //    `Forwarded` header, and conflating the two formats here
    //    would smuggle an unparsed `Forwarded` value through a code
    //    path that expects XFF semantics. RFC 7239 support is a
    //    follow-up on `ProxyTrust`. Header lookups are
    //    case-insensitive (`HeaderMap::get`); empty values are
    //    treated as absent inside `extract_client_ip`.
    let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
    let real_ip = headers.get("x-real-ip").and_then(|v| v.to_str().ok());
    let client_ip: IpAddr = state
        .policy
        .proxy_trust
        .extract_client_ip(remote_addr, xff, real_ip);
    tracing::Span::current().record("client_ip", tracing::field::display(client_ip));

    // 3. Banned-IP check.
    if state.policy.is_ip_banned(client_ip) {
        return Err(ApiError::new(ApiErrorCode::IpBanned, "source ip is banned"));
    }

    // 4. Transport-flag validation.
    let hop_token = req.hop_token.trim();
    let has_hop = !hop_token.is_empty();
    if has_hop {
        // v0.1 hop is unimplemented; surface as 503 `feature_unavailable`.
        return Err(ApiError::new(
            ApiErrorCode::FeatureUnavailable,
            "hop routing not implemented in v0.1",
        ));
    }
    if !req.udp_enabled && !req.tcp_enabled {
        return Err(ApiError::new(
            ApiErrorCode::TransportMismatch,
            "no transport selected: at least one of udp_enabled / tcp_enabled must be true",
        ));
    }

    // 5. Domain resolution (Path A — Host header required).
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or_default();
    if host.is_empty() {
        return Err(ApiError::new(
            ApiErrorCode::InvalidRequest,
            "Host header required",
        ));
    }
    let register_uri = format!("https://{host}/v1/sdk/register");

    // 6. Decode the wire-shape bytes for the inner challenge request.
    let eth_address = decode_eth_address(&req.eth_address)?;
    let ed25519_pk = decode_ed25519_pk(&req.ed25519_pk)?;
    let reported_ip = match req.reported_ip.as_deref().map(str::trim) {
        Some("") | None => None,
        Some(s) => Some(s.parse::<IpAddr>().map_err(|err| {
            ApiError::new(
                ApiErrorCode::InvalidRequest,
                format!("reported_ip not a valid IP: {err}"),
            )
        })?),
    };
    let inner = InnerRegisterChallengeRequest {
        eth_address,
        ed25519_pk,
        reported_ip,
    };

    // 7. Issue the challenge.
    let resp = state
        .leases
        .issue_register_challenge(&inner, host, &register_uri, client_ip, Timestamp::now())
        .await?;

    Ok((
        StatusCode::CREATED,
        ok(RegisterChallengeResponseBody {
            challenge_id: resp.challenge_id,
            expires_at: resp.expires_at,
            siwe_message: resp.siwe_message_text,
        }),
    ))
}

/// Decode an `"0x" + 40 hex` EVM address into its 20-byte raw form.
/// Accepts mixed-case hex; rejects everything else as
/// `invalid_request`.
fn decode_eth_address(s: &str) -> Result<[u8; 20], ApiError> {
    let invalid =
        |msg: &str| ApiError::new(ApiErrorCode::InvalidRequest, format!("eth_address: {msg}"));
    let trimmed = s.trim();
    let hex_body = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .ok_or_else(|| invalid("expected `0x` prefix"))?;
    if hex_body.len() != 40 {
        return Err(invalid("expected 40 hex chars after `0x`"));
    }
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = decode_hex_nibble(hex_body.as_bytes()[i * 2])
            .ok_or_else(|| invalid("non-hex character"))?;
        let lo = decode_hex_nibble(hex_body.as_bytes()[i * 2 + 1])
            .ok_or_else(|| invalid("non-hex character"))?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

/// Decode a base64-encoded 32-byte ed25519 raw pubkey. Rejects any
/// other length / encoding as `invalid_request`.
fn decode_ed25519_pk(s: &str) -> Result<[u8; 32], ApiError> {
    let invalid =
        |msg: &str| ApiError::new(ApiErrorCode::InvalidRequest, format!("ed25519_pk: {msg}"));
    let raw = BASE64_STANDARD
        .decode(s.trim())
        .map_err(|err| invalid(&format!("not valid base64: {err}")))?;
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| invalid("expected 32 bytes after base64 decode"))?;
    Ok(arr)
}

/// Decode a single ASCII hex nibble (`0-9`, `a-f`, `A-F`). Returns
/// `None` on any other byte.
const fn decode_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test-only setup; integration paths exercise the same decoders end-to-end"
)]
mod tests {
    use core::fmt::Write as _;

    use super::*;

    #[test]
    fn decode_eth_address_round_trips_lowercase() {
        let raw: [u8; 20] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x01, 0x02, 0x03, 0x04,
        ];
        let mut s = String::from("0x");
        for b in raw {
            write!(s, "{b:02x}").expect("string write");
        }
        let got = decode_eth_address(&s).expect("decode");
        assert_eq!(got, raw);
    }

    #[test]
    fn decode_eth_address_accepts_mixed_case() {
        let s = "0xAaBbCcDdEeFf00112233445566778899AaBbCcDd";
        let got = decode_eth_address(s).expect("decode mixed-case");
        assert_eq!(got[0], 0xAA);
        assert_eq!(got[19], 0xDD);
    }

    #[test]
    fn decode_eth_address_rejects_missing_prefix() {
        let err = decode_eth_address("aabbccdd").expect_err("must reject missing 0x");
        assert_eq!(err.code, ApiErrorCode::InvalidRequest);
    }

    #[test]
    fn decode_eth_address_rejects_wrong_length() {
        let err = decode_eth_address("0xaa").expect_err("must reject short");
        assert_eq!(err.code, ApiErrorCode::InvalidRequest);
    }

    #[test]
    fn decode_ed25519_pk_round_trips() {
        let raw = [0x42u8; 32];
        let s = BASE64_STANDARD.encode(raw);
        let got = decode_ed25519_pk(&s).expect("decode");
        assert_eq!(got, raw);
    }

    #[test]
    fn decode_ed25519_pk_rejects_wrong_length() {
        let s = BASE64_STANDARD.encode([0u8; 16]);
        let err = decode_ed25519_pk(&s).expect_err("must reject 16 bytes");
        assert_eq!(err.code, ApiErrorCode::InvalidRequest);
    }
}
