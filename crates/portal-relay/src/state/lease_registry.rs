//! `LeaseRegistry` — papaya-backed lease store + janitor.
//!
//! Replaces Go's `sync.RWMutex`-protected `[]*leaseRecord` with two
//! `papaya::HashMap` tables: a primary `IdentityKey → Arc<LeaseRecord>`
//! map and a hostname reverse index `CompactString → IdentityKey`.
//! Lookups stay lock-free; multi-step transactions (`register`,
//! `unregister`, `cleanup_expired`) take a single
//! `tokio::sync::Mutex` so concurrent writers serialise.
//!
//! ## Consistency model
//!
//! Writes are **serialised but not atomic from a reader's
//! perspective**. The mutex prevents two writers from racing each
//! other across the two tables, but lock-free readers
//! (`lookup_by_identity`, `lookup_by_hostname`, `lease_count`) do
//! NOT take the mutex and may observe transient mid-transaction
//! states. Specifically:
//!
//! - `lookup_by_hostname` may briefly return `None` for a
//!   newly-registered lease whose primary-table insert has landed
//!   but whose hostname-index insert has not — and vice versa
//!   during `unregister` / `cleanup_expired`.
//! - During hostname rotation on the same identity (re-register
//!   with a different hostname), readers may briefly see neither,
//!   one, or both hostnames resolve.
//!
//! This is intentional: the lock-free fast path is what makes
//! `papaya` worth using, and is a deliberate divergence from the
//! Go implementation (whose `sync.RWMutex` blocked all readers
//! during a `Lock`-held transaction). Callers that need a
//! consistent view across the two indexes must either retry on
//! `None` or fall back to identity-keyed lookups (the primary
//! table is single-source-of-truth).
//!
//! ## Phase 5 B4 scope
//!
//! This batch lands the minimum-viable surface that downstream
//! batches build on:
//!
//! - `LeaseRecord` value type (mirrors Go's `leaseRecord`).
//! - `LeaseRegistry::{register, renew, unregister, lookup_by_identity,
//!   lookup_by_hostname, cleanup_expired}`.
//! - `IdentityKey` newtype.
//!
//! Deferred to subsequent batches:
//! - `register_hop_route` / `delete_hop_route` (Phase 6b/B seam).
//! - `admit_lease_by_token` (depends on Phase 2 lease-token signing
//!   which is not yet on the portal-crypto surface).
//! - Transport-mismatch + capacity policy gates (depend on `policy::`
//!   landing in B5+).
//! - 5s janitor task driver — exposed as `cleanup_expired(now)` so
//!   the eventual server orchestrator (B9) can wire it into a
//!   `tokio::time::interval`.
//! - On-disk snapshot via `state::write_json_atomic` (B5+).

use std::net::IpAddr;
use std::sync::Arc;

use compact_str::CompactString;
use jiff::{SignedDuration, Timestamp};
use papaya::HashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::challenge::{
    PendingChallenge, RegisterChallengeRequest, RegisterChallengeResponse, RegisterRequest,
    VerifiedChallenge,
};
use crate::error::{RelayError, RelayResult};

// ---------------------------------------------------------------------------
// Pending-challenge constants (Phase 5 SDK-API S3)
// ---------------------------------------------------------------------------

/// Per-IP cap on outstanding pending register challenges. Mirrors
/// Go's `defaultRegisterChallengeOutstandingPerIP`. Hardcoded for
/// v0.1; hot-reloadable via `RuntimeConfig` is deferred to DEFER-8.
pub const REGISTER_CHALLENGE_PER_IP_CAP: u32 = 32;

/// Pending-challenge TTL. Mirrors Go's
/// `defaultRegisterChallengeTTL = 2 * time.Minute`.
const REGISTER_CHALLENGE_TTL: SignedDuration = SignedDuration::from_secs(120);

/// EIP-155 chain ID the SIWE message is bound to. v0.1 single-chain
/// (Ethereum mainnet); multi-chain support is a later concern.
const REGISTER_CHALLENGE_CHAIN_ID: u64 = 1;

/// Janitor sweep summary — what `cleanup_expired(now)` dropped.
///
/// Widens the previous `Vec<Arc<LeaseRecord>>` return so callers
/// can record both lease-expiration and challenge-expiration metrics
/// from a single janitor tick. The `dropped_challenges` counter is a
/// `usize` (not a `Vec<PendingChallenge>`) because there is no
/// downstream consumer of the dropped-challenge values themselves —
/// only the count matters for the audit log and per-IP-counter
/// arithmetic.
///
/// Lives in this module (not in `state::challenge`) because the
/// cleanup transaction is owned by the registry and the report
/// references `LeaseRecord` — placing it next to the records
/// avoids an awkward back-edge from `challenge.rs` into the registry's
/// value type.
#[derive(Debug, Clone, Default)]
pub struct CleanupReport {
    /// Lease records dropped by the sweep — preserved as `Arc` so
    /// downstream audit fan-out (e.g. `lease.expire` events) can
    /// inspect identity / hostname without re-acquiring the
    /// registry lock.
    pub dropped_leases: Vec<Arc<LeaseRecord>>,
    /// Number of pending challenges aged out by the sweep.
    pub dropped_challenges: usize,
}

/// Identity-key newtype: the 32-byte raw ed25519 public-key encoding.
///
/// Per RFC 8032 §5.1.2 these are the unwrapped point bytes — **not**
/// the DER-wrapped `SubjectPublicKeyInfo` blob. Callers that hold an
/// ed25519 `VerifyingKey` obtain these bytes via
/// `verifying_key.to_bytes()`. Hashable + serializable for use as map
/// keys + JSON snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityKey(pub [u8; 32]);

impl IdentityKey {
    /// Zero key (used as a sentinel in tests; production callers
    /// always plumb a real ed25519 verifying-key bytes pair).
    pub const ZERO: Self = Self([0u8; 32]);
}

/// Lease record. Mirrors Go's `leaseRecord` shape with the v0.1
/// scope subset; v0.2+ fields are explicitly omitted with module
/// rustdoc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRecord {
    /// Tenant identity key (raw 32-byte ed25519 public-key encoding;
    /// see [`IdentityKey`]).
    pub identity: IdentityKey,
    /// Tenant hostname (used for routing; case-insensitive lookup
    /// per Go semantics — callers normalize before storing).
    pub hostname: CompactString,
    /// Free-form per-lease metadata blob (postcard-encoded by the
    /// SDK, opaque to the relay).
    pub metadata: Vec<u8>,
    /// Lease expiry timestamp.
    pub expires_at: Timestamp,
    /// First-seen timestamp (for audit + reputation decay).
    pub first_seen_at: Timestamp,
    /// Last-seen timestamp (refreshed on `renew`).
    pub last_seen_at: Timestamp,
    /// Client IP at registration time (canonicalized via R12).
    pub client_ip: std::net::IpAddr,
    /// Self-reported IP from the SDK (used by R10 reputation; may
    /// differ from `client_ip` when the SDK is behind NAT).
    pub reported_ip: Option<std::net::IpAddr>,
}

impl LeaseRecord {
    /// Construct a fresh record with `first_seen_at == last_seen_at == now`.
    #[must_use]
    pub const fn new(
        identity: IdentityKey,
        hostname: CompactString,
        metadata: Vec<u8>,
        expires_at: Timestamp,
        now: Timestamp,
        client_ip: std::net::IpAddr,
    ) -> Self {
        Self {
            identity,
            hostname,
            metadata,
            expires_at,
            first_seen_at: now,
            last_seen_at: now,
            client_ip,
            reported_ip: None,
        }
    }
}

/// Lease registry. `Arc`-shareable; clone is cheap (single Arc bump).
#[derive(Clone)]
pub struct LeaseRegistry {
    inner: Arc<RegistryInner>,
}

struct RegistryInner {
    /// Primary: identity → record.
    by_identity: HashMap<IdentityKey, Arc<LeaseRecord>>,
    /// Reverse index: hostname → identity.
    by_hostname: HashMap<CompactString, IdentityKey>,
    /// Pending-challenge table (S3): `challenge_id` → pending entry.
    /// Cleared single-use on `consume_register_challenge` or by
    /// the janitor when `expires_at <= now`.
    by_challenge_id: HashMap<CompactString, PendingChallenge>,
    /// Per-IP outstanding-challenge counter (S3). Increment at
    /// `issue_register_challenge`, decrement at
    /// `consume_register_challenge` AND at `cleanup_expired` so the
    /// cap (`REGISTER_CHALLENGE_PER_IP_CAP`) cannot leak.
    ///
    /// **Concurrency contract:** all reads and writes happen under
    /// `mutate`. The counter is a plain `u32` (not `AtomicU32`) so
    /// there is no separately-mutable surface — cross-table
    /// atomicity with `by_challenge_id` is structural, not advisory.
    by_ip_pending_count: HashMap<IpAddr, u32>,
    /// Mutex serialising multi-step transactions (register /
    /// unregister / `cleanup_expired` / issue+consume challenge) so
    /// the cross-table updates stay atomic. Lookups don't take this
    /// lock.
    mutate: Mutex<()>,
}

impl Default for LeaseRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LeaseRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RegistryInner {
                by_identity: HashMap::new(),
                by_hostname: HashMap::new(),
                by_challenge_id: HashMap::new(),
                by_ip_pending_count: HashMap::new(),
                mutate: Mutex::new(()),
            }),
        }
    }

    /// Register a fresh lease. If `identity` already has a record,
    /// the prior record is replaced and its hostname index entry is
    /// removed if it no longer points at this identity.
    ///
    /// Hostname conflicts (a different identity already holds the
    /// hostname) surface as [`RelayError::Config`] with a
    /// "hostname conflict" payload — the eventual API layer maps
    /// this to HTTP 409.
    ///
    /// # Errors
    /// Returns [`RelayError::Config`] on hostname conflict.
    pub async fn register(&self, record: LeaseRecord) -> RelayResult<Arc<LeaseRecord>> {
        let _guard = self.inner.mutate.lock().await;

        // Hostname-conflict guard.
        let host_pin = self.inner.by_hostname.pin();
        if let Some(&existing_identity) = host_pin.get(&record.hostname)
            && existing_identity != record.identity
        {
            return Err(RelayError::Config(format!(
                "hostname '{}' is held by another identity",
                record.hostname,
            )));
        }
        // If THIS identity previously held a different hostname,
        // drop the old hostname index entry.
        let id_pin = self.inner.by_identity.pin();
        if let Some(prior) = id_pin.get(&record.identity)
            && prior.hostname != record.hostname
        {
            let _ = host_pin.remove(&prior.hostname);
        }

        let arc_record = Arc::new(record.clone());
        id_pin.insert(record.identity, Arc::clone(&arc_record));
        host_pin.insert(record.hostname.clone(), record.identity);
        Ok(arc_record)
    }

    /// Refresh `last_seen_at` and bump `expires_at` to `new_expires`.
    /// Returns the updated record on success; `None` if the identity
    /// is not registered.
    pub async fn renew(
        &self,
        identity: IdentityKey,
        new_expires: Timestamp,
        now: Timestamp,
    ) -> Option<Arc<LeaseRecord>> {
        let _guard = self.inner.mutate.lock().await;
        let id_pin = self.inner.by_identity.pin();
        let prior = id_pin.get(&identity)?;
        let mut next = (**prior).clone();
        next.last_seen_at = now;
        next.expires_at = new_expires;
        let arc_next = Arc::new(next);
        id_pin.insert(identity, Arc::clone(&arc_next));
        Some(arc_next)
    }

    /// Remove a lease. Returns the dropped record on success; `None`
    /// if the identity is not registered.
    pub async fn unregister(&self, identity: IdentityKey) -> Option<Arc<LeaseRecord>> {
        let _guard = self.inner.mutate.lock().await;
        let id_pin = self.inner.by_identity.pin();
        let dropped = id_pin.remove(&identity)?.clone();
        let host_pin = self.inner.by_hostname.pin();
        // Only drop the hostname index entry if it still names THIS
        // identity (don't trample a concurrent re-register of the
        // same hostname under a different identity).
        let _ = host_pin.remove_if(&dropped.hostname, |_, &v| v == identity);
        Some(dropped)
    }

    /// Look up a lease by identity. Lock-free.
    #[must_use]
    pub fn lookup_by_identity(&self, identity: IdentityKey) -> Option<Arc<LeaseRecord>> {
        self.inner.by_identity.pin().get(&identity).cloned()
    }

    /// Look up a lease by hostname. Lock-free.
    #[must_use]
    pub fn lookup_by_hostname(&self, hostname: &str) -> Option<Arc<LeaseRecord>> {
        let id = *self.inner.by_hostname.pin().get(hostname)?;
        self.inner.by_identity.pin().get(&id).cloned()
    }

    /// Drop every lease whose `expires_at <= now` AND every pending
    /// register-challenge whose `expires_at <= now`. Returns a
    /// [`CleanupReport`] summarising the sweep so the caller can fan
    /// out audit events and metrics.
    ///
    /// The two sweeps run under the same `mutate` lock so an
    /// expired-challenge drop atomically decrements its IP's
    /// `by_ip_pending_count` — this is the structural reason the
    /// per-IP cap cannot leak: there is no path that decrements a
    /// challenge from the table without also touching the IP
    /// counter, and there is no path that touches the IP counter
    /// outside this lock.
    ///
    /// Janitor scheduling (5s tick) is the server orchestrator's
    /// job (`Server::start`'s `JANITOR_INTERVAL` driver).
    pub async fn cleanup_expired(&self, now: Timestamp) -> CleanupReport {
        let _guard = self.inner.mutate.lock().await;

        // ---- Lease sweep ----
        let id_pin = self.inner.by_identity.pin();
        let host_pin = self.inner.by_hostname.pin();
        let mut dropped_leases: Vec<Arc<LeaseRecord>> = Vec::new();
        let to_drop: Vec<IdentityKey> = id_pin
            .iter()
            .filter(|(_, rec)| rec.expires_at <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in to_drop {
            if let Some(rec) = id_pin.remove(&id) {
                let _ = host_pin.remove_if(&rec.hostname, |_, &v| v == id);
                dropped_leases.push(rec.clone());
            }
        }

        // ---- Challenge sweep ----
        let chal_pin = self.inner.by_challenge_id.pin();
        let ip_count_pin = self.inner.by_ip_pending_count.pin();
        let expired_ids: Vec<(CompactString, IpAddr)> = chal_pin
            .iter()
            .filter(|(_, p)| p.expires_at <= now)
            .map(|(cid, p)| (cid.clone(), p.client_ip))
            .collect();
        let mut dropped_challenges: usize = 0;
        for (cid, ip) in expired_ids {
            if chal_pin.remove(&cid).is_some() {
                dropped_challenges = dropped_challenges.saturating_add(1);
                // Decrement (saturating, just in case), removing the
                // IP entry entirely once it hits zero so the table
                // does not bloat with one record per ever-seen IP.
                if let Some(&prev) = ip_count_pin.get(&ip) {
                    let next = prev.saturating_sub(1);
                    if next == 0 {
                        let _ = ip_count_pin.remove(&ip);
                    } else {
                        ip_count_pin.insert(ip, next);
                    }
                }
            }
        }

        CleanupReport {
            dropped_leases,
            dropped_challenges,
        }
    }

    /// Issue a fresh pending register challenge.
    ///
    /// Mints a `UUIDv4` `challenge_id`, constructs a SIWE message via
    /// [`portal_crypto::build_siwe_challenge`] (TTL = 2 min,
    /// `chain_id` = 1 — Ethereum mainnet), and stores a
    /// [`PendingChallenge`] keyed by `challenge_id`. Returns the
    /// rendered SIWE text + expiry as a
    /// [`RegisterChallengeResponse`].
    ///
    /// Per-IP cap is enforced under the same `mutate` lock that
    /// serialises the cross-table updates, so cap-check + insert +
    /// counter-bump are observed atomically by every other writer
    /// (cap cannot be raced over the threshold).
    ///
    /// # Errors
    ///
    /// - [`RelayError::ChallengePendingCap`] when `client_ip`
    ///   already holds [`REGISTER_CHALLENGE_PER_IP_CAP`] outstanding
    ///   pending challenges.
    /// - [`RelayError::ChallengeInvalidSignature`] (re-using the
    ///   crypto-pass-through string slot) if the request's
    ///   `ed25519_pk` is structurally invalid (not on-curve), or
    ///   the SIWE builder rejects the configured `domain` / `uri`.
    pub async fn issue_register_challenge(
        &self,
        req: &RegisterChallengeRequest,
        domain: &str,
        register_uri: &str,
        client_ip: IpAddr,
        now: Timestamp,
    ) -> RelayResult<RegisterChallengeResponse> {
        // Validate + decode + build the SIWE message OUTSIDE the
        // mutex. None of these steps touch the registry tables, and
        // they are the dominant cost of issue (ed25519 curve check
        // + iri-string parse + UUIDv4 mint + EIP-4361 render). Doing
        // them under the lock would serialise all lease/challenge
        // writers behind one challenge issue.
        let ed25519_pk = ed25519_dalek::VerifyingKey::from_bytes(&req.ed25519_pk)
            .map_err(|e| RelayError::ChallengeInvalidSignature(format!("ed25519 pk: {e}")))?;
        let eth_address = portal_crypto::EthAddress::new(req.eth_address);

        // Mint a UUIDv4 challenge_id (16 bytes of CSPRNG entropy via
        // the `getrandom` backend). Rendered via `Uuid::simple` as 32
        // lowercase-hex chars (no hyphens) so the value satisfies the
        // EIP-4361 §4.2 nonce charset rule (≥8 alphanumeric ASCII).
        let raw_uuid = uuid::Uuid::new_v4();
        let challenge_id = CompactString::from(raw_uuid.simple().to_string());

        // Build the SIWE message via portal-crypto's canonical
        // ed25519-binding template; renders to text via
        // `siwe::Message::to_string`.
        let builder = portal_crypto::ChallengeBuilder {
            domain: CompactString::from(domain),
            uri: CompactString::from(register_uri),
            chain_id: REGISTER_CHALLENGE_CHAIN_ID,
            ttl: REGISTER_CHALLENGE_TTL,
        };
        let challenge = portal_crypto::build_siwe_challenge(
            &builder,
            eth_address,
            ed25519_pk,
            challenge_id.as_str(),
            challenge_id.as_str(),
            now,
        )
        .map_err(|e| RelayError::ChallengeInvalidSignature(format!("siwe build: {e}")))?;
        let siwe_message_text = challenge.message.to_string();
        let expires_at = challenge.expires_at;

        let pending = PendingChallenge {
            challenge_id: challenge_id.clone(),
            expected_eth_address: eth_address,
            expected_ed25519_pk: ed25519_pk,
            siwe_message_text: siwe_message_text.clone(),
            register_request: req.clone(),
            expires_at,
            client_ip,
        };

        // Critical section: cap check + insert + counter bump.
        // Everything inside this block is O(1) papaya operations;
        // no I/O, no parsing, no crypto. Dropping `_guard` at the
        // end of the block (before the `Ok(...)`) keeps the
        // critical section minimal.
        {
            let _guard = self.inner.mutate.lock().await;
            let ip_count_pin = self.inner.by_ip_pending_count.pin();
            let current = ip_count_pin.get(&client_ip).copied().unwrap_or(0);
            if current >= REGISTER_CHALLENGE_PER_IP_CAP {
                return Err(RelayError::ChallengePendingCap);
            }
            let chal_pin = self.inner.by_challenge_id.pin();
            chal_pin.insert(challenge_id.clone(), pending);
            ip_count_pin.insert(client_ip, current.saturating_add(1));
        }

        Ok(RegisterChallengeResponse {
            challenge_id,
            siwe_message_text,
            expires_at,
        })
    }

    /// Consume a pending register challenge: verify the SIWE
    /// signature + ed25519 binding under the relay's pending entry,
    /// remove the entry single-use, and decrement the per-IP counter.
    ///
    /// The remove-then-verify ordering is deliberate: we remove the
    /// entry FIRST (so the single-use property holds even if the
    /// caller retries) then verify the signature against the
    /// just-removed entry's pinned `siwe_message_text`. If the verify
    /// fails the challenge is gone — the caller MUST request a fresh
    /// challenge. Concurrent calls with the same `challenge_id`:
    /// exactly one observes the `Some` from `chal_pin.remove`; the
    /// other observes `None` and returns
    /// [`RelayError::ChallengeNotFound`].
    ///
    /// # Single-use applies to ALL outcomes
    ///
    /// The pending entry is removed from the table at the START of
    /// this method, BEFORE the TTL check or the SIWE verify runs.
    /// That means any non-`Ok` outcome — `ChallengeExpired`,
    /// `ChallengeInvalidSignature`, etc. — ALSO consumes the slot.
    /// SDK authors MUST NOT ship "retry-with-corrected-echo" or
    /// "retry-after-clock-skew" loops keyed on the same
    /// `challenge_id`; on any failure the caller MUST request a
    /// fresh challenge via `issue_register_challenge`.
    ///
    /// # Errors
    ///
    /// - [`RelayError::ChallengeNotFound`] when no pending entry
    ///   matches `req.challenge_id` (never issued, already consumed,
    ///   or already swept).
    /// - [`RelayError::ChallengeExpired`] when the matching entry's
    ///   `expires_at <= now` at consume time. The entry is removed
    ///   regardless (see "Single-use applies to ALL outcomes" above).
    /// - [`RelayError::ChallengeInvalidSignature`] when the SIWE
    ///   re-parse, the binding-statement parse, the EIP-191 verify,
    ///   the domain/nonce equality, or the
    ///   echoed-`siwe_message_text` equality fails. The entry is
    ///   removed regardless (see "Single-use applies to ALL outcomes"
    ///   above).
    pub async fn consume_register_challenge(
        &self,
        req: &RegisterRequest,
        now: Timestamp,
    ) -> RelayResult<VerifiedChallenge> {
        // Critical section: atomic single-use remove + counter
        // decrement. Verification (SIWE parse + EIP-191 recovery +
        // binding-statement parse) is the dominant cost of consume
        // and runs on the OWNED `pending` value AFTER the lock is
        // released — so a slow verifier (or a hostile client crafting
        // a worst-case parse path) cannot stall lease/challenge
        // writers. Once the entry is removed it is exclusively owned
        // by this future; concurrent same-`challenge_id` callers
        // observe `None` and return `ChallengeNotFound`.
        let pending = {
            let _guard = self.inner.mutate.lock().await;
            let chal_pin = self.inner.by_challenge_id.pin();
            let p = chal_pin
                .remove(&req.challenge_id)
                .ok_or(RelayError::ChallengeNotFound)?
                .clone();
            let ip_count_pin = self.inner.by_ip_pending_count.pin();
            if let Some(&prev) = ip_count_pin.get(&p.client_ip) {
                let next = prev.saturating_sub(1);
                if next == 0 {
                    let _ = ip_count_pin.remove(&p.client_ip);
                } else {
                    ip_count_pin.insert(p.client_ip, next);
                }
            }
            p
        };

        // TTL gate (the janitor races against an under-the-wire
        // consume; reject if we missed the sweep). The entry is
        // already removed — there is no point retaining a stale
        // entry, the caller MUST request a fresh challenge.
        if pending.expires_at <= now {
            return Err(RelayError::ChallengeExpired);
        }

        // Anti-tamper: the echoed message text MUST match the
        // pinned text byte-for-byte. Without this, a malicious
        // client could swap in a different SIWE message under the
        // original signature (the EIP-191 verify recovers an
        // address from whatever bytes are presented).
        if req.siwe_message_text != pending.siwe_message_text {
            return Err(RelayError::ChallengeInvalidSignature(
                "echoed siwe_message_text does not match issued challenge".to_owned(),
            ));
        }

        // Re-parse the SIWE message and run the canonical
        // binding-verify path: domain + nonce + window + EIP-191
        // signature + ed25519-binding statement extraction.
        let parsed: ::siwe::Message = pending
            .siwe_message_text
            .parse()
            .map_err(|e| RelayError::ChallengeInvalidSignature(format!("siwe parse: {e}")))?;

        let attestation = portal_crypto::verify_binding(
            &parsed,
            &req.siwe_signature,
            // domain + nonce mirror what `issue_register_challenge`
            // pinned: nonce == challenge_id (UUIDv4 simple form).
            parsed.domain.as_str(),
            pending.challenge_id.as_str(),
            pending.expected_ed25519_pk,
            now,
        )
        .map_err(|e| RelayError::ChallengeInvalidSignature(format!("verify_binding: {e}")))?;

        // Belt-and-braces: the SIWE-recovered EOA must match what
        // the requester originally claimed. (Anti-rebind: a fresh
        // signature under a *different* EOA over the same message
        // would otherwise verify and silently rebind the protocol
        // pubkey to a different EOA.)
        if attestation.eth_address != pending.expected_eth_address {
            return Err(RelayError::ChallengeInvalidSignature(
                "siwe-recovered eth address does not match challenge issuer".to_owned(),
            ));
        }

        Ok(VerifiedChallenge {
            eth_address: attestation.eth_address,
            ed25519_pk: attestation.ed25519_pubkey,
            hostname: req.hostname.clone(),
            metadata: req.metadata.clone(),
            register_request: pending.register_request,
            client_ip: pending.client_ip,
        })
    }

    /// Snapshot the current pending-challenge count (for tests +
    /// metrics).
    #[must_use]
    pub fn pending_challenge_count(&self) -> usize {
        self.inner.by_challenge_id.pin().len()
    }

    /// Snapshot the per-IP outstanding-challenge count for `ip`,
    /// returning 0 if the IP has no entry. Lock-free read against the
    /// papaya table; the value may transiently differ from a
    /// concurrently-running issue/consume but converges once the
    /// `mutate` lock releases.
    #[must_use]
    pub fn pending_count_for_ip(&self, ip: IpAddr) -> u32 {
        self.inner
            .by_ip_pending_count
            .pin()
            .get(&ip)
            .copied()
            .unwrap_or(0)
    }

    /// Snapshot the current lease count (for tests + metrics).
    #[must_use]
    pub fn lease_count(&self) -> usize {
        self.inner.by_identity.pin().len()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only setup")]
mod tests {
    use super::*;

    fn fixed_now() -> Timestamp {
        Timestamp::from_second(1_778_155_200).unwrap() // 2026-05-04 12:00 UTC
    }

    fn ip_localhost() -> std::net::IpAddr {
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    }

    fn make_record(identity: IdentityKey, host: &str, expires: Timestamp) -> LeaseRecord {
        LeaseRecord::new(
            identity,
            CompactString::from(host),
            Vec::new(),
            expires,
            fixed_now(),
            ip_localhost(),
        )
    }

    fn ten_minutes_from_now() -> Timestamp {
        fixed_now()
            .saturating_add(jiff::SignedDuration::from_secs(600))
            .unwrap_or(Timestamp::MAX)
    }

    #[tokio::test]
    async fn register_then_lookup_by_identity_returns_record() {
        let reg = LeaseRegistry::new();
        let id = IdentityKey([0xau8; 32]);
        let rec = make_record(id, "alice.portal.test", ten_minutes_from_now());
        reg.register(rec).await.unwrap();
        assert_eq!(reg.lease_count(), 1);
        let got = reg.lookup_by_identity(id).unwrap();
        assert_eq!(got.hostname.as_str(), "alice.portal.test");
    }

    #[tokio::test]
    async fn register_populates_hostname_index() {
        let reg = LeaseRegistry::new();
        let id = IdentityKey([0xbu8; 32]);
        let rec = make_record(id, "bob.portal.test", ten_minutes_from_now());
        reg.register(rec).await.unwrap();
        let got = reg.lookup_by_hostname("bob.portal.test").unwrap();
        assert_eq!(got.identity, id);
    }

    #[tokio::test]
    async fn register_hostname_conflict_rejects() {
        let reg = LeaseRegistry::new();
        let id1 = IdentityKey([0x1u8; 32]);
        let id2 = IdentityKey([0x2u8; 32]);
        reg.register(make_record(
            id1,
            "shared.portal.test",
            ten_minutes_from_now(),
        ))
        .await
        .unwrap();
        let result = reg
            .register(make_record(
                id2,
                "shared.portal.test",
                ten_minutes_from_now(),
            ))
            .await;
        assert!(matches!(result, Err(RelayError::Config(_))));
    }

    #[tokio::test]
    async fn re_register_same_identity_different_hostname_drops_old_index() {
        let reg = LeaseRegistry::new();
        let id = IdentityKey([0xcu8; 32]);
        reg.register(make_record(id, "old.portal.test", ten_minutes_from_now()))
            .await
            .unwrap();
        reg.register(make_record(id, "new.portal.test", ten_minutes_from_now()))
            .await
            .unwrap();
        assert!(reg.lookup_by_hostname("old.portal.test").is_none());
        assert!(reg.lookup_by_hostname("new.portal.test").is_some());
    }

    #[tokio::test]
    async fn renew_extends_expires() {
        let reg = LeaseRegistry::new();
        let id = IdentityKey([0xdu8; 32]);
        let initial = fixed_now();
        let later = initial
            .saturating_add(jiff::SignedDuration::from_secs(120))
            .unwrap_or(Timestamp::MAX);
        reg.register(make_record(id, "renew.portal.test", initial))
            .await
            .unwrap();
        let renewed = reg.renew(id, later, initial).await.unwrap();
        assert_eq!(renewed.expires_at, later);
    }

    #[tokio::test]
    async fn renew_unknown_identity_returns_none() {
        let reg = LeaseRegistry::new();
        assert!(
            reg.renew(IdentityKey([0xeu8; 32]), fixed_now(), fixed_now())
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn unregister_drops_record_and_index() {
        let reg = LeaseRegistry::new();
        let id = IdentityKey([0xfu8; 32]);
        reg.register(make_record(id, "drop.portal.test", ten_minutes_from_now()))
            .await
            .unwrap();
        let dropped = reg.unregister(id).await.unwrap();
        assert_eq!(dropped.hostname.as_str(), "drop.portal.test");
        assert_eq!(reg.lease_count(), 0);
        assert!(reg.lookup_by_hostname("drop.portal.test").is_none());
    }

    #[tokio::test]
    async fn cleanup_expired_drops_only_expired() {
        let reg = LeaseRegistry::new();
        let now = fixed_now();
        let already_expired = now;
        let still_valid = now
            .saturating_add(jiff::SignedDuration::from_secs(600))
            .unwrap_or(Timestamp::MAX);

        let expired_id = IdentityKey([0x10u8; 32]);
        let live_id = IdentityKey([0x11u8; 32]);
        reg.register(make_record(expired_id, "exp.portal.test", already_expired))
            .await
            .unwrap();
        reg.register(make_record(live_id, "live.portal.test", still_valid))
            .await
            .unwrap();

        let report = reg
            .cleanup_expired(
                now.saturating_add(jiff::SignedDuration::from_secs(1))
                    .unwrap_or(Timestamp::MAX),
            )
            .await;
        assert_eq!(report.dropped_leases.len(), 1);
        assert_eq!(report.dropped_leases[0].identity, expired_id);
        assert_eq!(report.dropped_challenges, 0);
        assert_eq!(reg.lease_count(), 1);
        assert!(reg.lookup_by_hostname("live.portal.test").is_some());
        assert!(reg.lookup_by_hostname("exp.portal.test").is_none());
    }

    // ---------------------------------------------------------------
    // Phase 5 SDK-API S3 — pending register-challenge tests
    // ---------------------------------------------------------------

    use portal_crypto::{
        evm_address_from_pubkey, secp256k1_from_bytes_for_test, sign_eip191_personal,
        tenant_public_key,
    };

    /// Deterministic secp256k1 scalar — same constant the
    /// `portal-crypto::siwe::challenge` tests use, so tooling that
    /// inspects the matching EOA between crates lines up.
    const TEST_SECP_SCALAR: [u8; 32] = [
        0x4c, 0x08, 0x83, 0xa6, 0x91, 0x02, 0x93, 0x7d, 0x62, 0x31, 0x47, 0x1b, 0x5d, 0xbb, 0x62,
        0x04, 0xfe, 0x51, 0x29, 0x61, 0x70, 0x82, 0x79, 0x2a, 0xe4, 0x68, 0xd0, 0x1a, 0x3f, 0x36,
        0x23, 0x18,
    ];

    const TEST_DOMAIN: &str = "relay.portal.test";
    const TEST_REGISTER_URI: &str = "https://relay.portal.test/v1/register";

    fn make_challenge_request(ed25519_seed: [u8; 32]) -> RegisterChallengeRequest {
        let secp_key = secp256k1_from_bytes_for_test(TEST_SECP_SCALAR);
        let pk = tenant_public_key(&secp_key).unwrap();
        let eth_addr = evm_address_from_pubkey(&pk);
        let ed25519_signing = ed25519_dalek::SigningKey::from_bytes(&ed25519_seed);
        RegisterChallengeRequest {
            eth_address: *eth_addr.as_bytes(),
            ed25519_pk: ed25519_signing.verifying_key().to_bytes(),
            reported_ip: Some(ip_localhost()),
        }
    }

    fn sign_challenge(
        response: &RegisterChallengeResponse,
        hostname: &str,
        metadata: Vec<u8>,
    ) -> RegisterRequest {
        let secp_key = secp256k1_from_bytes_for_test(TEST_SECP_SCALAR);
        let sig = sign_eip191_personal(response.siwe_message_text.as_bytes(), &secp_key).unwrap();
        RegisterRequest {
            challenge_id: response.challenge_id.clone(),
            siwe_message_text: response.siwe_message_text.clone(),
            siwe_signature: sig,
            hostname: CompactString::from(hostname),
            metadata,
        }
    }

    /// `AC1`: `issue_register_challenge` returns a fresh UUID-derived
    /// `challenge_id`, the SIWE message text, and a 2-min expiry.
    #[tokio::test]
    async fn issue_register_challenge_returns_fresh_id_and_two_minute_expiry() {
        let reg = LeaseRegistry::new();
        let now = fixed_now();
        let req = make_challenge_request([0x11u8; 32]);

        let resp = reg
            .issue_register_challenge(&req, TEST_DOMAIN, TEST_REGISTER_URI, ip_localhost(), now)
            .await
            .unwrap();

        assert_eq!(resp.challenge_id.len(), 32, "uuid simple form is 32 chars");
        assert!(resp.siwe_message_text.contains(TEST_DOMAIN));
        let expected_expiry = now
            .checked_add(SignedDuration::from_secs(120))
            .unwrap_or(Timestamp::MAX);
        assert_eq!(resp.expires_at, expected_expiry);
        assert_eq!(reg.pending_challenge_count(), 1);
        assert_eq!(reg.pending_count_for_ip(ip_localhost()), 1);
    }

    /// `AC2`: 33rd outstanding pending challenge from one IP returns
    /// `RelayError::ChallengePendingCap`.
    #[tokio::test]
    async fn issue_thirty_third_pending_challenge_rejects_with_cap() {
        let reg = LeaseRegistry::new();
        let now = fixed_now();
        let ip = ip_localhost();

        for i in 0..REGISTER_CHALLENGE_PER_IP_CAP {
            // Each issue uses a distinct ed25519 seed to keep the
            // bound pubkey unique (the seed is opaque to the cap
            // logic, but distinct seeds make the test self-document).
            let seed_byte = u8::try_from(i & 0xff).unwrap_or(0);
            let req = make_challenge_request([seed_byte; 32]);
            reg.issue_register_challenge(&req, TEST_DOMAIN, TEST_REGISTER_URI, ip, now)
                .await
                .unwrap();
        }
        assert_eq!(reg.pending_count_for_ip(ip), REGISTER_CHALLENGE_PER_IP_CAP,);

        let req = make_challenge_request([0xffu8; 32]);
        let result = reg
            .issue_register_challenge(&req, TEST_DOMAIN, TEST_REGISTER_URI, ip, now)
            .await;
        assert!(matches!(result, Err(RelayError::ChallengePendingCap)));
    }

    /// `AC3a`: `consume_register_challenge` with valid SIWE returns
    /// `Ok(VerifiedChallenge)` and removes the entry single-use.
    #[tokio::test]
    async fn consume_register_challenge_happy_path_removes_entry() {
        let reg = LeaseRegistry::new();
        let now = fixed_now();
        let req = make_challenge_request([0x42u8; 32]);

        let resp = reg
            .issue_register_challenge(&req, TEST_DOMAIN, TEST_REGISTER_URI, ip_localhost(), now)
            .await
            .unwrap();

        let signed = sign_challenge(&resp, "host.portal.test", b"meta".to_vec());
        let verified = reg.consume_register_challenge(&signed, now).await.unwrap();

        assert_eq!(verified.hostname.as_str(), "host.portal.test");
        assert_eq!(verified.metadata, b"meta".to_vec());
        assert_eq!(verified.client_ip, ip_localhost());
        assert_eq!(verified.ed25519_pk.to_bytes(), req.ed25519_pk);
        assert_eq!(verified.eth_address.as_bytes(), &req.eth_address);

        // Single-use: a second consume with the same id MUST fail.
        let second = reg.consume_register_challenge(&signed, now).await;
        assert!(matches!(second, Err(RelayError::ChallengeNotFound)));
        assert_eq!(reg.pending_challenge_count(), 0);
        assert_eq!(reg.pending_count_for_ip(ip_localhost()), 0);
    }

    /// `AC3b`: concurrent `consume_register_challenge` calls with the
    /// same `challenge_id` — exactly one returns Ok, the rest return
    /// `ChallengeNotFound`.
    ///
    /// Uses a multi-threaded runtime + `RACE_TASK_COUNT = 16` so the
    /// scheduler interleaves the futures. A current-thread runtime
    /// with 2 tasks would also pass this test against a buggy
    /// grab-then-check-under-no-lock implementation; the wider race
    /// surface here amplifies scheduler-edge bugs that the structural
    /// `papaya::HashMap::remove` atomicity protects against.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_consume_yields_exactly_one_winner() {
        const RACE_TASK_COUNT: u32 = 16;

        let reg = LeaseRegistry::new();
        let now = fixed_now();
        let req = make_challenge_request([0x77u8; 32]);

        let resp = reg
            .issue_register_challenge(&req, TEST_DOMAIN, TEST_REGISTER_URI, ip_localhost(), now)
            .await
            .unwrap();
        let signed = sign_challenge(&resp, "race.portal.test", Vec::new());

        // R9: spawn into a caller-owned `JoinSet` rather than
        // bare `tokio::spawn` so the test cleanly joins all
        // futures at scope exit.
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..RACE_TASK_COUNT {
            let reg_clone = reg.clone();
            let signed_clone = signed.clone();
            set.spawn(async move {
                reg_clone
                    .consume_register_challenge(&signed_clone, now)
                    .await
            });
        }
        let mut oks = 0u32;
        let mut nf = 0u32;
        while let Some(joined) = set.join_next().await {
            match joined.unwrap() {
                Ok(_) => oks += 1,
                Err(RelayError::ChallengeNotFound) => nf += 1,
                other => panic!("unexpected result: {other:?}"),
            }
        }
        assert_eq!(oks, 1, "exactly one consume must win");
        assert_eq!(
            nf,
            RACE_TASK_COUNT - 1,
            "the rest must observe ChallengeNotFound",
        );
    }

    /// `AC4` / `AC5` — the LOAD-BEARING test:
    /// issue 32 challenges → 33rd rejects → advance `now` past
    /// challenge TTL → `cleanup_expired(now)` → 33rd attempt
    /// succeeds. Pins the per-IP cap counter against expiration
    /// leaks.
    #[tokio::test]
    async fn cleanup_expired_decrements_per_ip_cap_counter() {
        let reg = LeaseRegistry::new();
        let now = fixed_now();
        let ip = ip_localhost();

        for i in 0..REGISTER_CHALLENGE_PER_IP_CAP {
            let seed_byte = u8::try_from(i & 0xff).unwrap_or(0);
            let req = make_challenge_request([seed_byte; 32]);
            reg.issue_register_challenge(&req, TEST_DOMAIN, TEST_REGISTER_URI, ip, now)
                .await
                .unwrap();
        }
        assert_eq!(reg.pending_count_for_ip(ip), REGISTER_CHALLENGE_PER_IP_CAP,);

        // 33rd issue rejects — cap holds.
        let blocked_req = make_challenge_request([0xa1u8; 32]);
        let blocked = reg
            .issue_register_challenge(&blocked_req, TEST_DOMAIN, TEST_REGISTER_URI, ip, now)
            .await;
        assert!(matches!(blocked, Err(RelayError::ChallengePendingCap)));

        // Advance past TTL (2 min + 1 s) and sweep.
        let after_ttl = now
            .checked_add(SignedDuration::from_secs(121))
            .unwrap_or(Timestamp::MAX);
        let report = reg.cleanup_expired(after_ttl).await;
        assert_eq!(
            report.dropped_challenges,
            usize::try_from(REGISTER_CHALLENGE_PER_IP_CAP).unwrap_or(usize::MAX),
        );
        assert_eq!(report.dropped_leases.len(), 0);
        assert_eq!(
            reg.pending_count_for_ip(ip),
            0,
            "per-IP cap counter MUST be decremented to zero by the sweep",
        );

        // 33rd attempt now succeeds — cap counter freed.
        reg.issue_register_challenge(&blocked_req, TEST_DOMAIN, TEST_REGISTER_URI, ip, after_ttl)
            .await
            .unwrap();
        assert_eq!(reg.pending_count_for_ip(ip), 1);
    }

    /// `cleanup_expired` past TTL with no consume returns
    /// `ChallengeNotFound` on a subsequent consume of the swept id.
    #[tokio::test]
    async fn consume_swept_challenge_returns_not_found() {
        let reg = LeaseRegistry::new();
        let now = fixed_now();
        let req = make_challenge_request([0x09u8; 32]);

        let resp = reg
            .issue_register_challenge(&req, TEST_DOMAIN, TEST_REGISTER_URI, ip_localhost(), now)
            .await
            .unwrap();

        let after_ttl = now
            .checked_add(SignedDuration::from_secs(121))
            .unwrap_or(Timestamp::MAX);
        let report = reg.cleanup_expired(after_ttl).await;
        assert_eq!(report.dropped_challenges, 1);

        let signed = sign_challenge(&resp, "late.portal.test", Vec::new());
        let result = reg.consume_register_challenge(&signed, after_ttl).await;
        assert!(matches!(result, Err(RelayError::ChallengeNotFound)));
    }

    /// Tampered echo of `siwe_message_text` is rejected as
    /// `ChallengeInvalidSignature` before any crypto path runs.
    #[tokio::test]
    async fn consume_rejects_tampered_message_text_echo() {
        let reg = LeaseRegistry::new();
        let now = fixed_now();
        let req = make_challenge_request([0x05u8; 32]);

        let resp = reg
            .issue_register_challenge(&req, TEST_DOMAIN, TEST_REGISTER_URI, ip_localhost(), now)
            .await
            .unwrap();

        let mut signed = sign_challenge(&resp, "tamper.portal.test", Vec::new());
        signed.siwe_message_text.push_str("EXTRA");
        let result = reg.consume_register_challenge(&signed, now).await;
        assert!(matches!(
            result,
            Err(RelayError::ChallengeInvalidSignature(_))
        ));
        // Single-use still applies: a re-attempt with the correct
        // text fails because the entry was already removed.
        let correct = sign_challenge(&resp, "tamper.portal.test", Vec::new());
        let retry = reg.consume_register_challenge(&correct, now).await;
        assert!(matches!(retry, Err(RelayError::ChallengeNotFound)));
    }
}
