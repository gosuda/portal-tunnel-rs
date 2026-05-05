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
//! - `POST /v1/sdk/register` — finalize the SIWE handshake; mint a
//!   lease and return [`RegisterResponseBody`] with a lease access
//!   token. See the handler rustdoc for full semantics.
//!
//! Subsequent handlers (`/v1/sdk/renew`, `/v1/sdk/unregister`,
//! `/v1/sdk/connect`) land in follow-up commits.

use std::net::{IpAddr, SocketAddr};

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, State};
use axum::http::uri::Authority;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use compact_str::CompactString;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::api::envelope::{ApiDataEnvelope, ApiError, ApiErrorCode, ok};
use crate::api::state::SdkState;
use crate::state::challenge::{
    RegisterChallengeRequest as InnerRegisterChallengeRequest,
    RegisterRequest as InnerRegisterRequest,
};
use crate::state::lease_registry::{IdentityKey, LeaseRecord};
use crate::state::lease_token;

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
/// ## Host parsing + port-stripping in SIWE `domain`
///
/// The Host header is parsed as an [`Authority`] before it is used in
/// any downstream string-formatting; a value that fails Authority
/// parse (e.g., embedded whitespace, leading colon, control bytes
/// that survive `to_str()`) returns 400 `invalid_request` rather
/// than leaking through `build_siwe_challenge` to a 401
/// `ChallengeInvalidSignature`. That separation matches the error
/// taxonomy: a malformed Host is request-shape, not credential.
///
/// The SIWE `domain` is set to `authority.host()` — i.e., the
/// host portion with the port stripped. The client must sign SIWE
/// messages with `domain = "<relay-host>"` regardless of whether the
/// relay listens on a non-standard port; this is forgiving across
/// reverse-proxy port mappings and matches how SDK clients commonly
/// think about "the relay's domain". The `register_uri` embedded in
/// the SIWE message uses `authority.as_str()` (port preserved) so
/// the URI accurately reflects how the SDK should reach
/// `/v1/sdk/register`.
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
///   `eth_address` / `ed25519_pk`, empty `Host` header, or a Host
///   value that fails [`Authority`] parse (e.g., embedded
///   whitespace, leading colon, control bytes).
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

    // 5. Domain resolution (Path A — Host header required). Validate
    //    as `Host = uri-host [":" port]` (no userinfo) before any
    //    string-formatting so a malformed Host returns 400.
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
    if host.contains('@') {
        return Err(ApiError::new(
            ApiErrorCode::InvalidRequest,
            "Host header malformed: userinfo not permitted",
        ));
    }
    let authority: Authority = host.parse().map_err(|err| {
        ApiError::new(
            ApiErrorCode::InvalidRequest,
            format!("Host header malformed: {err}"),
        )
    })?;
    let siwe_domain = authority.host();
    let register_uri = format!("https://{}/v1/sdk/register", authority.as_str());

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
        .issue_register_challenge(
            &inner,
            siwe_domain,
            &register_uri,
            client_ip,
            Timestamp::now(),
        )
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

/// Wire body for `POST /v1/sdk/register`.
///
/// Mirrors Go's `types.RegisterRequest` field set with one encoding
/// deviation: the 65-byte SIWE signature ships as `"0x" + 130 hex`
/// rather than via `serde-big-array` so the wire shape stays
/// human-inspectable and parallels [`RegisterChallengeBody`]'s
/// `eth_address` `0x`-hex convention. The `metadata` field carries
/// the SDK-side opaque per-lease blob as a standard-base64 string —
/// the same convention as `RegisterChallengeBody::metadata`. Empty
/// `metadata` (`""`) decodes as a zero-byte blob.
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterRequestBody {
    /// Echoes the issued challenge id (32 lowercase-hex chars, no
    /// hyphens — `UUIDv4::simple`).
    pub challenge_id: CompactString,
    /// EIP-4361 SIWE message text the SDK signed. The relay
    /// re-parses this and asserts it byte-equals the text it pinned
    /// at challenge issue.
    pub siwe_message_text: String,
    /// 65-byte EIP-191 secp256k1 signature as `"0x" + 130 hex`
    /// (case-insensitive). Decoded via [`decode_siwe_signature`].
    pub siwe_signature: String,
    /// Hostname the SDK wants to register.
    pub hostname: CompactString,
    /// Free-form per-lease metadata blob, standard-base64 of the
    /// postcard-encoded bytes. Empty string = zero-byte blob.
    #[serde(default)]
    pub metadata: String,
}

/// Wire body for the `POST /v1/sdk/register` 201 response.
///
/// Mirrors Go's `types.RegisterResponse` field set, minus the v0.2
/// transport-allocation fields (`udp_addr`, `tcp_addr`, `sni_port`,
/// `keyless_url`) and Go's nested `Identity { name, address }`
/// shape — Phase 5 v0.1 collapses identity to its 32-byte raw
/// ed25519 protocol pubkey rendered as 64-char lowercase hex, which
/// is the value the lease-access-token verifier matches on. The
/// `protocol_version` / `release_version` pair mirrors
/// [`DomainBody`] for SDK-side wire-version pinning across the
/// register call.
///
/// `#[non_exhaustive]` blocks struct-literal construction from
/// downstream Rust crates; it does NOT guarantee JSON-wire
/// compatibility — a strict-decoder client that rejects unknown
/// keys would still break on a field addition.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct RegisterResponseBody {
    /// 32-byte raw ed25519 protocol pubkey as 64-char lowercase hex
    /// (no `0x` prefix). Bound to the lease-access-token claims.
    pub identity: String,
    /// Hostname the lease holds.
    pub hostname: CompactString,
    /// Lease expiry timestamp (RFC 3339).
    pub expires_at: Timestamp,
    /// Lease access token (signed JWT-style compact string per
    /// [`crate::state::lease_token`]). The SDK echoes this on
    /// `/v1/sdk/renew` and `/v1/sdk/connect`.
    pub access_token: CompactString,
    /// Wire-protocol version. v0.1 collapses to `CARGO_PKG_VERSION`.
    pub protocol_version: &'static str,
    /// Relay binary release version. v0.1 collapses to
    /// `CARGO_PKG_VERSION`.
    pub release_version: &'static str,
}

/// `POST /v1/sdk/register` — finalize the SIWE handshake, mint a
/// lease, and return a lease access token.
///
/// ## Lease TTL
///
/// v0.1 hardcodes a 24h TTL ([`LEASE_DEFAULT_TTL`]) on the resulting
/// [`LeaseRecord`]. Honoring a per-request `ttl` override (Go
/// `RegisterRequest.TTL`) requires plumbing the field through
/// [`InnerRegisterChallengeRequest`] / [`PendingChallenge`] which is
/// out of scope for S6. The eventual `/v1/sdk/renew` handler is
/// where TTL bumps live.
///
/// ## Pre-authorized deviation: `consume_register_challenge` already
/// runs `verify_binding`
///
/// The slice plan calls for the handler to "extend
/// `consume_register_challenge` to call `verify_binding`". The S3
/// implementation already runs the SIWE+ed25519 binding verify
/// inside `consume_register_challenge` (see
/// `crates/portal-relay/src/state/lease_registry.rs:528-619`), so
/// the handler does NOT duplicate it. The plan was stale at the time
/// S6 landed; this rustdoc records the divergence so a reader of the
/// plan does not look for the missing verify.
///
/// ## Error envelope mapping for SIWE failures
///
/// `RelayError::ChallengeInvalidSignature(_)` maps to 401
/// `unauthorized` (matches the `LeaseTokenError::SignatureInvalid`
/// pattern). The slice plan suggested 403 in passing; the
/// envelope's existing 401 mapping is preserved for symmetry with
/// the lease-token credential path. Reviewer note: a future flip to
/// 403 would touch `envelope.rs::From<RelayError>` only and is a
/// one-line change.
///
/// ## Hostname conflict envelope
///
/// `LeaseRegistry::register` returns
/// [`RelayError::HostnameConflict`] on a hostname-vs-different-
/// identity collision; the envelope mapping renders 409
/// `hostname_conflict`. The typed error variant carries
/// `current_holder` for operator audit but the holder identity does
/// NOT surface on the wire (it would expose lease-graph topology to
/// a probing caller).
///
/// ## ENS round-trip
///
/// On success, if `state.ens_resolver.is_some()`, the handler
/// reverse-resolves the SIWE-recovered EOA, then forward-verifies
/// the returned name maps back to the same EOA. On round-trip match
/// the handler calls
/// [`crate::policy::ReputationEngine::mark_ens_named`]. ENS
/// failures (`Err(_)`) and bare `Ok(None)` / forward-resolve
/// mismatches are logged at `tracing::warn` and DO NOT fail the
/// request — registration is accepted on the strength of the SIWE
/// signature alone, ENS-marking is bonus.
///
/// # Errors
///
/// - 400 `invalid_request` — malformed JSON body, malformed
///   `siwe_signature` hex, malformed/unknown `challenge_id` (the
///   challenge was never issued, was already consumed single-use,
///   or was swept past TTL).
/// - 401 `ip_banned` — source IP banned by policy.
/// - 401 `unauthorized` — the SIWE signature failed
///   binding-verification, or the pinned challenge expired between
///   issue and consume.
/// - 409 `hostname_conflict` — a different identity already holds
///   the requested hostname.
/// - 500 `internal` — postcard / signer failures inside
///   [`crate::state::lease_token::issue`] (these are server-side
///   faults).
///
/// # Tracing fields & operator privacy
///
/// The `identity` field carries the 32-byte ed25519 pubkey hex (also
/// emitted on the wire in the response — not a secret). Combined with
/// `client_ip` in the same span, operators running verbose tracing
/// effectively log `(client_ip, identity)` pairs for every register
/// call. Operators MAY redact one or the other in their tracing
/// subscriber if log retention or privacy policy requires it.
#[tracing::instrument(
    name = "sdk.register",
    skip_all,
    fields(
        client_ip = tracing::field::Empty,
        identity = tracing::field::Empty,
        ens_named = tracing::field::Empty,
    ),
)]
pub async fn register_handler(
    State(state): State<SdkState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<RegisterRequestBody>, JsonRejection>,
) -> Result<(StatusCode, Json<ApiDataEnvelope<RegisterResponseBody>>), ApiError> {
    // 1. Decode the body.
    let Json(req) = body.map_err(|err| {
        ApiError::new(
            ApiErrorCode::InvalidRequest,
            format!("register body: {err}"),
        )
    })?;

    // 2. Canonicalize the client IP (R12).
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

    // 4. Decode the 65-byte SIWE signature from `0x`-hex.
    let siwe_signature = decode_siwe_signature(&req.siwe_signature)?;

    // 5. Decode the metadata blob from base64 (empty string → empty
    //    blob, mirroring the challenge body convention).
    let metadata = if req.metadata.is_empty() {
        Vec::new()
    } else {
        BASE64_STANDARD
            .decode(req.metadata.as_bytes())
            .map_err(|err| {
                ApiError::new(
                    ApiErrorCode::InvalidRequest,
                    format!("metadata: not valid base64: {err}"),
                )
            })?
    };

    // 6. Construct the inner consume request and consume the
    //    challenge. `consume_register_challenge` runs the
    //    SIWE+ed25519 binding verify internally; failures are
    //    typed via `RelayError` and map through the envelope.
    let inner = InnerRegisterRequest {
        challenge_id: req.challenge_id.clone(),
        siwe_message_text: req.siwe_message_text,
        siwe_signature,
        hostname: req.hostname.clone(),
        metadata,
    };
    let verified = state
        .leases
        .consume_register_challenge(&inner, Timestamp::now())
        .await?;

    // 7. Build the lease record. Identity = the binding-recovered
    //    ed25519 protocol pubkey.
    let identity = IdentityKey(verified.ed25519_pk.to_bytes());
    tracing::Span::current().record("identity", tracing::field::display(hex_lower(&identity.0)));
    let now = Timestamp::now();
    let expires_at = now.checked_add(LEASE_DEFAULT_TTL).unwrap_or(Timestamp::MAX);

    // 8. Mint the lease access token, THEN register the lease.
    //
    // Hoare invariant: token mint is in-process and has no external
    // side-effect on failure; registry insert (papaya tables) IS a
    // side-effect. Mint first so a token-mint fault aborts cleanly
    // without an orphaned lease holding the hostname slot.
    let signer = portal_crypto::Ed25519Signer::new(&state.lease_token_signing_key);
    let access_token = lease_token::issue(identity, expires_at, &signer)?;

    let mut record = LeaseRecord::new(
        identity,
        verified.hostname.clone(),
        verified.metadata.clone(),
        expires_at,
        now,
        verified.client_ip,
    );
    record.reported_ip = verified.register_request.reported_ip;

    // 9. Register the lease.
    state.leases.register(record).await?;

    // 10. ENS round-trip — best-effort, never fails the request.
    let mut ens_named = false;
    if let Some(resolver) = state.ens_resolver.as_ref() {
        match resolver.resolve_reverse(verified.eth_address).await {
            Ok(Some(name)) => match resolver.resolve(&name).await {
                Ok(addr) if addr == verified.eth_address => {
                    state.engine.mark_ens_named(identity);
                    ens_named = true;
                }
                Ok(_) => tracing::warn!(
                    "ENS reverse-resolution returned {name} but forward-resolve did not match"
                ),
                Err(err) => tracing::warn!(?err, "ENS forward-resolve failed; skipping mark"),
            },
            Ok(None) => {} // No reverse record — common case, not an error.
            Err(err) => tracing::warn!(?err, "ENS reverse-resolve failed; skipping mark"),
        }
    }
    tracing::Span::current().record("ens_named", ens_named);

    // 11. Respond.
    let body = RegisterResponseBody {
        identity: hex_lower(&identity.0),
        hostname: verified.hostname,
        expires_at,
        access_token,
        protocol_version: env!("CARGO_PKG_VERSION"),
        release_version: env!("CARGO_PKG_VERSION"),
    };
    Ok((StatusCode::CREATED, ok(body)))
}

/// Default lease TTL for v0.1 register flow (24 hours). Mirrors Go
/// `defaultLeaseTTL`. The SDK's per-request `ttl` override is not
/// honored at register time in v0.1 — it is consumed by `/v1/sdk/renew`.
const LEASE_DEFAULT_TTL: jiff::SignedDuration = jiff::SignedDuration::from_hours(24);

/// Render a 32-byte buffer as 64-char lowercase hex (no `0x` prefix).
/// Used to surface the registered identity on the wire.
fn hex_lower(bytes: &[u8; 32]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut s, byte| {
        let _ = write!(s, "{byte:02x}");
        s
    })
}

/// Decode a 65-byte SIWE signature from `"0x" + 130 hex` (mixed-case
/// accepted). Rejects any other shape as `invalid_request`. Mirrors
/// the [`decode_eth_address`] pattern.
fn decode_siwe_signature(s: &str) -> Result<[u8; 65], ApiError> {
    let invalid = |msg: &str| {
        ApiError::new(
            ApiErrorCode::InvalidRequest,
            format!("siwe_signature: {msg}"),
        )
    };
    let trimmed = s.trim();
    let hex_body = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .ok_or_else(|| invalid("expected `0x` prefix"))?;
    if hex_body.len() != 130 {
        return Err(invalid("expected 130 hex chars after `0x`"));
    }
    let mut out = [0u8; 65];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = decode_hex_nibble(hex_body.as_bytes()[i * 2])
            .ok_or_else(|| invalid("non-hex character"))?;
        let lo = decode_hex_nibble(hex_body.as_bytes()[i * 2 + 1])
            .ok_or_else(|| invalid("non-hex character"))?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
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
