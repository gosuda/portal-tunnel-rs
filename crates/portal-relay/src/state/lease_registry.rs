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

use std::sync::Arc;

use compact_str::CompactString;
use jiff::Timestamp;
use papaya::HashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::error::{RelayError, RelayResult};

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
    /// Mutex serialising multi-step transactions (register /
    /// unregister) so the two-table updates stay atomic. Lookups
    /// don't take this lock.
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

    /// Drop every lease whose `expires_at <= now`. Returns the
    /// dropped records so the caller can fan out audit events.
    /// Janitor scheduling (5s tick) is the eventual server
    /// orchestrator's job (Phase 5 B9).
    pub async fn cleanup_expired(&self, now: Timestamp) -> Vec<Arc<LeaseRecord>> {
        let _guard = self.inner.mutate.lock().await;
        let id_pin = self.inner.by_identity.pin();
        let host_pin = self.inner.by_hostname.pin();
        let mut dropped: Vec<Arc<LeaseRecord>> = Vec::new();
        let to_drop: Vec<IdentityKey> = id_pin
            .iter()
            .filter(|(_, rec)| rec.expires_at <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in to_drop {
            if let Some(rec) = id_pin.remove(&id) {
                let _ = host_pin.remove_if(&rec.hostname, |_, &v| v == id);
                dropped.push(rec.clone());
            }
        }
        dropped
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

        let dropped = reg
            .cleanup_expired(
                now.saturating_add(jiff::SignedDuration::from_secs(1))
                    .unwrap_or(Timestamp::MAX),
            )
            .await;
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].identity, expired_id);
        assert_eq!(reg.lease_count(), 1);
        assert!(reg.lookup_by_hostname("live.portal.test").is_some());
        assert!(reg.lookup_by_hostname("exp.portal.test").is_none());
    }
}
