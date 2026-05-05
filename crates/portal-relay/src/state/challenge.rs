//! Pending register-challenge bookkeeping types (Phase 5 SDK-API S3).
//!
//! These types describe the SDK ↔ relay register-challenge handshake:
//!
//! 1. Client POSTs a [`RegisterChallengeRequest`] (eth address +
//!    ed25519 protocol key + reported IP) to obtain a SIWE message
//!    text + a one-shot `challenge_id` ([`RegisterChallengeResponse`]).
//! 2. Client signs the SIWE message with its EOA secp256k1 key, then
//!    POSTs a [`RegisterRequest`] (`challenge_id` + signature) to
//!    finalize.
//! 3. The relay verifies the SIWE/ed25519 binding and yields a
//!    [`VerifiedChallenge`] which the register handler (S6) consumes
//!    to mint the lease.
//!
//! ## Why not `portal-wire`?
//!
//! `portal-wire::api::RegisterRequest` exists today as a Phase 1
//! placeholder (`name` + optional `siwe_attestation`) and does NOT
//! match the field set this slice needs. Per the slice plan's
//! pre-authorized deviation, the canonical Rust shape lives here in
//! `portal-relay::state::challenge`. A future portal-wire alignment
//! slice can lift these types up; until then this module is the
//! single source of truth for the challenge wire shapes.
//!
//! ## Pending registry table
//!
//! [`PendingChallenge`] is the value type stored in
//! [`crate::state::LeaseRegistry`]'s third papaya table
//! `by_challenge_id: HashMap<CompactString, PendingChallenge>`.
//! The fourth table `by_ip_pending_count: HashMap<IpAddr, u32>`
//! (mutex-serialised through the registry) enforces the per-IP cap
//! of 32 outstanding challenges (Go default
//! `defaultRegisterChallengeOutstandingPerIP`).
//!
//! ## Serde derives — deferred
//!
//! The wire-shape structs (`RegisterChallengeRequest`,
//! `RegisterChallengeResponse`, `RegisterRequest`) intentionally
//! ship without `Serialize` / `Deserialize` derives. The S5/S6
//! API handlers that wire these onto axum endpoints will add
//! whichever serde framing they need (and pull
//! `serde-big-array` for the 65-byte signature field). Defining
//! the derives here ahead of consumers would force a `serde-big-array`
//! dep and additional const-generic gymnastics with no current user.

use std::net::IpAddr;

use compact_str::CompactString;
use jiff::Timestamp;

use portal_crypto::EthAddress;

/// SDK request that initiates the SIWE register challenge handshake.
///
/// The `eth_address` is the EOA the client claims, the `ed25519_pk`
/// is the 32-byte raw protocol pubkey the SIWE message will bind to
/// (per `portal_crypto::siwe::binding::canonical_statement`), and
/// `reported_ip` is the SDK's self-reported IP (used by R10
/// reputation; the relay separately captures `client_ip` from the
/// transport layer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterChallengeRequest {
    /// 20-byte raw EVM address claimed by the SDK.
    pub eth_address: [u8; 20],
    /// 32-byte raw ed25519 protocol-key encoding the SDK will bind.
    pub ed25519_pk: [u8; 32],
    /// SDK self-reported IP (carried into the eventual `LeaseRecord`
    /// once the challenge consumes; nullable for SDKs that decline
    /// to report).
    pub reported_ip: Option<IpAddr>,
}

/// Relay reply to [`RegisterChallengeRequest`].
///
/// Carries the SIWE message text (the EIP-4361 string the client
/// signs) and the one-shot `challenge_id` the client must echo back
/// in [`RegisterRequest`]. The 2-min TTL is implicit in
/// `expires_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterChallengeResponse {
    /// `UUIDv4` stringified — the relay's primary key into the pending
    /// table.
    pub challenge_id: CompactString,
    /// EIP-4361 SIWE message text (rendered via `siwe::Message::to_string`).
    pub siwe_message_text: String,
    /// Absolute expiry; clients that are slow to sign past this
    /// timestamp will be rejected with [`crate::error::RelayError::ChallengeExpired`].
    pub expires_at: Timestamp,
}

/// SDK request that finalizes the handshake.
///
/// The relay re-parses `siwe_message_text` (the same text it minted
/// in [`RegisterChallengeResponse`], echoed back so the relay does
/// not have to keep the rendered string in memory across the TTL),
/// looks up the pending challenge by `challenge_id`, and verifies
/// the 65-byte EIP-191 signature under the bound ed25519 protocol
/// key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRequest {
    /// Echoes [`RegisterChallengeResponse::challenge_id`].
    pub challenge_id: CompactString,
    /// Echoes [`RegisterChallengeResponse::siwe_message_text`]; the
    /// relay re-parses it before verify. The pending-table entry
    /// also pins this string so a tampered echo cannot smuggle a
    /// different message under the original signature.
    pub siwe_message_text: String,
    /// 65-byte EIP-191 signature over `siwe_message_text` (the SDK's
    /// secp256k1 EOA signing path).
    pub siwe_signature: [u8; 65],
    /// Hostname the client wants to register (carried verbatim into
    /// the eventual lease record). The challenge layer does not
    /// validate hostname uniqueness; that is the register handler's
    /// (S6) responsibility.
    pub hostname: CompactString,
    /// Free-form per-lease metadata blob (postcard-encoded by the
    /// SDK, opaque to the relay).
    pub metadata: Vec<u8>,
}

/// Value stored in the pending-challenge table.
///
/// Cleared on `consume_register_challenge` (single-use) or on
/// `cleanup_expired(now)` (TTL sweep). The per-IP counter
/// (`by_ip_pending_count`) is decremented in the same atomic
/// transaction as the table removal so the cap cannot leak.
#[derive(Debug, Clone)]
pub struct PendingChallenge {
    /// Echoes [`RegisterChallengeResponse::challenge_id`] — the
    /// papaya table key. Stored on the value as well so callers can
    /// match a record to its key without a second lookup.
    pub challenge_id: CompactString,
    /// EOA the client claimed in the request; `consume_register_challenge`
    /// asserts the SIWE-recovered address matches this.
    pub expected_eth_address: EthAddress,
    /// ed25519 protocol key the SIWE message binds; the binding
    /// statement parser must recover the same pubkey.
    pub expected_ed25519_pk: ed25519_dalek::VerifyingKey,
    /// Rendered SIWE message text (preserved verbatim so the verify
    /// path does not have to re-render — and so a tampered echo in
    /// [`RegisterRequest::siwe_message_text`] is detectable).
    pub siwe_message_text: String,
    /// The original challenge request, retained so the consume path
    /// can plumb `reported_ip` into the resulting [`VerifiedChallenge`].
    pub register_request: RegisterChallengeRequest,
    /// Absolute expiry. `consume_register_challenge(req, now)` and
    /// `cleanup_expired(now)` reject / drop entries with `expires_at
    /// <= now`.
    pub expires_at: Timestamp,
    /// Transport-observed IP at issue time; bookkept against
    /// `by_ip_pending_count` so the per-IP cap survives challenges
    /// where the SDK lies about `reported_ip`.
    pub client_ip: IpAddr,
}

/// Output of `consume_register_challenge` — the trusted shape the
/// register handler (S6) consumes to mint the actual lease.
///
/// All fields are post-verification: `eth_address` is the
/// SIWE-recovered EOA (== `expected_eth_address` after the equality
/// check), `ed25519_pk` is the binding-recovered protocol pubkey
/// (== `expected_ed25519_pk`), and the carried `register_request` /
/// `client_ip` / `expires_at` are the same values the issue site
/// pinned (they survive the consume unchanged).
#[derive(Debug, Clone)]
pub struct VerifiedChallenge {
    /// SIWE-recovered Ethereum address.
    pub eth_address: EthAddress,
    /// Binding-recovered ed25519 protocol pubkey.
    pub ed25519_pk: ed25519_dalek::VerifyingKey,
    /// The hostname carried in the consume request (verbatim from
    /// the SDK; uniqueness check is the register handler's job).
    pub hostname: CompactString,
    /// Free-form per-lease metadata blob from the consume request.
    pub metadata: Vec<u8>,
    /// Original challenge request (carries `reported_ip`).
    pub register_request: RegisterChallengeRequest,
    /// Transport-observed IP at challenge issue time.
    pub client_ip: IpAddr,
}
