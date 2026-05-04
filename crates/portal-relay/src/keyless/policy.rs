//! SEC-004 keyless validation pipeline.
//!
//! [`KeylessPolicy`] is the single guard that gates every keyless
//! request before it reaches the [`crate::keyless::Bridge`].  The
//! pipeline order matters — cheap rejections happen first so a
//! malicious tenant cannot spend signer-pool capacity by floating
//! malformed requests:
//!
//! 1. **Known-key check**: `key_id ∈ known_keys`.  Unknown id ⇒
//!    [`KeylessError::UnknownKeyId`].  No allocation, no map mutation.
//! 2. **Scheme match**: the requested signature scheme's algorithm
//!    matches the loaded key's algorithm (RSA key cannot sign with an
//!    ECDSA scheme, and vice versa).  ⇒ [`KeylessError::SchemeMismatch`].
//! 3. **Payload budget**: `payload.len() <= KEYLESS_PAYLOAD_BUDGET`.
//!    ⇒ [`KeylessError::PayloadTooLarge`].  Inclusive ceiling — a
//!    payload of exactly the budget is accepted; the test fixture
//!    pins this boundary.
//! 4. **Per-tenant rate limit**: `governor::DefaultDirectRateLimiter`
//!    keyed by the connecting client cert's subject (compact string).
//!    Quota: [`KEYLESS_TENANT_BURST`] requests in the burst window,
//!    refilled at [`KEYLESS_TENANT_SUSTAINED`] tokens / second.
//!    Exhaustion ⇒ [`KeylessError::RateLimited`].
//!
//! ## SEC-015 deferred
//!
//! The `routing_context` field on `SignRequest` is intentionally NOT
//! checked here — that is U4 territory
//! (`policy::check_routing_context`).  U3 ships the wire field +
//! carries it through to the canonical signing input verbatim; U4
//! adds the refusal arm.  This module's rustdoc is the single
//! authority on the U3-vs-U4 split; do not add a routing-context
//! check here without flipping the U4 plan unit's status.
//!
//! ## papaya choice
//!
//! Both maps (`known_keys` and `tenant_limits`) are read-dominated:
//! every request reads, but writes are rare (operator-config reload
//! for `known_keys`; first-request-from-a-new-subject for
//! `tenant_limits`).  `papaya::HashMap` is a workspace-already-pulled
//! lock-free alternative that matches this access pattern; using
//! `std::sync::Mutex<HashMap<...>>` would serialise every request
//! through one global lock.
//!
//! ## `tenant_limits` cardinality cap (memory-DoS guard)
//!
//! Even with an mTLS-validated client cert, a tenant can rotate the
//! cert's subject string (long random CN, randomised SANs) and force
//! the per-subject limiter map to grow unboundedly; that turns the
//! rate-limit surface into a memory-amplification primitive.  We
//! defend with a hard cap [`MAX_TRACKED_SUBJECTS`] on the map's
//! cardinality.  When the map is full and a previously-unseen
//! subject arrives, the policy falls back to a single shared
//! "overflow" limiter dimensioned at the same per-tenant quota —
//! which means a flood of unique subjects competes for a single
//! limiter and gets `RateLimited` after the burst, exactly the
//! behaviour we want.  Operators size the cap via
//! [`KeylessPolicy::with_capacity`] when wiring the policy into the
//! relay; the workspace-default constructor uses the default cap.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use compact_str::CompactString;
use governor::{
    DefaultDirectRateLimiter, Quota,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
};
use papaya::HashMap as PapayaMap;
use portal_wire::limits::KEYLESS_PAYLOAD_BUDGET;
use rustls::{SignatureAlgorithm, SignatureScheme};

use crate::keyless::error::KeylessError;
use crate::keyless::material::KeylessSigningKey;
use crate::keyless::wire::{RoutingContext, SignRequest};

// ---------------------------------------------------------------------------
// Per-tenant rate-limit defaults
// ---------------------------------------------------------------------------

/// Burst capacity (concurrent / instantaneous) per tenant subject.
///
/// 100 requests is enough headroom for a CDN-style tenant doing
/// pipelined TLS handshakes during a traffic ramp; smaller than
/// that and bursty rekey storms would falsely trip the limiter.
/// Operator-tuneable at handler-build time when the keyless-config
/// surface lands.
pub const KEYLESS_TENANT_BURST: u32 = 100;

/// Sustained refill rate (requests per second) per tenant subject.
///
/// 50 RPS sustained is well above the ~1 RPS / handshake / minute
/// that a healthy CDN node sees.  The 2:1 burst-to-sustained ratio
/// matches the governor crate's recommended starting shape.
pub const KEYLESS_TENANT_SUSTAINED: u32 = 50;

/// Maximum number of distinct subjects tracked in the per-tenant
/// rate-limit map.  See the module rustdoc's "cardinality cap"
/// section for the memory-DoS rationale.
///
/// 4096 distinct subjects is a generous ceiling for v0.1 — a single
/// tenant cert is one entry; even a multi-tenant relay fronting
/// hundreds of CDN edge identities sits well below this.  Operators
/// who serve more independent identities can raise the cap via
/// [`KeylessPolicy::with_capacity`].
pub const MAX_TRACKED_SUBJECTS: usize = 4096;

// ---------------------------------------------------------------------------
// KnownKey — what the policy stores per registered key id
// ---------------------------------------------------------------------------

/// A keyless signing key registered against a stable `key_id`.
///
/// Stored value type for [`KeylessPolicy::known_keys`].  Carries:
///
/// - `algorithm`: the rustls `SignatureAlgorithm` advertised by the
///   loaded key (RSA / ECDSA / …).  Cached so the scheme-match
///   check is a cheap enum comparison instead of a re-parse of the
///   secret-box body.
/// - `signing_key`: the `KeylessSigningKey` itself.  Wrapped in
///   `Arc` so multiple handler clones share the same secret without
///   re-loading the PEM.
///
/// The struct is intentionally narrow: anything richer (operator
/// labels, expiry, rotation metadata, …) lives at the Phase 7
/// keyless-config surface, not in the per-request hot path.
#[non_exhaustive]
pub struct KnownKey {
    /// The loaded keyless signing key.
    pub signing_key: Arc<KeylessSigningKey>,
    /// Cached algorithm classifier.
    pub algorithm: SignatureAlgorithm,
}

impl KnownKey {
    /// Construct a [`KnownKey`].  The `algorithm` field is stored
    /// verbatim — callers obtain it from a built
    /// [`crate::keyless::KeylessSignerAdapter`]'s
    /// [`rustls::sign::SigningKey::algorithm`] before discarding the
    /// adapter (the bridge owns the live adapter; the policy only
    /// needs the algorithm tag).
    #[must_use]
    pub const fn new(signing_key: Arc<KeylessSigningKey>, algorithm: SignatureAlgorithm) -> Self {
        Self {
            signing_key,
            algorithm,
        }
    }
}

impl core::fmt::Debug for KnownKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Intentionally avoid printing the inner `KeylessSigningKey`
        // even though its `Debug` redacts: the algorithm tag is the
        // only useful detail at the policy layer.
        f.debug_struct("KnownKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// KeylessPolicy
// ---------------------------------------------------------------------------

/// Per-relay keyless validation state.
///
/// Cheap to clone (`Arc` of two papaya maps).  Held by the U3 axum
/// router state; one instance per relay.
#[derive(Clone)]
pub struct KeylessPolicy {
    inner: Arc<KeylessPolicyInner>,
}

struct KeylessPolicyInner {
    known_keys: PapayaMap<CompactString, Arc<KnownKey>>,
    tenant_limits: PapayaMap<CompactString, Arc<DefaultDirectRateLimiter>>,
    tenant_quota: Quota,
    /// Hard cap on `tenant_limits` cardinality — memory-DoS guard.
    /// See module rustdoc.
    max_tracked_subjects: usize,
    /// Atomic reservation counter for the per-subject map.  Each
    /// thread that wants to insert a new entry first claims a slot
    /// via `compare_exchange` — losers fall back to the overflow
    /// limiter, so the cap is enforced atomically rather than via
    /// a racy check-then-insert.  The counter is incremented BEFORE
    /// the `try_insert` and decremented if the insert loses to a
    /// concurrent winner under the same key (papaya `try_insert`
    /// reports `Err` with the existing entry).
    reserved_subjects: AtomicUsize,
    /// Shared limiter applied when the per-subject map is at
    /// capacity and a previously-unseen subject arrives.  Built once
    /// at policy construction so the overflow path does not
    /// allocate.
    overflow_limiter: Arc<DefaultDirectRateLimiter>,
}

impl core::fmt::Debug for KeylessPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeylessPolicy")
            .field("known_keys_len", &self.inner.known_keys.pin().len())
            .field("tenant_limits_len", &self.inner.tenant_limits.pin().len())
            .finish_non_exhaustive()
    }
}

impl KeylessPolicy {
    /// Build an empty policy with workspace-default rate-limit quota
    /// ([`KEYLESS_TENANT_BURST`] burst, [`KEYLESS_TENANT_SUSTAINED`]
    /// req/sec sustained refill).
    ///
    /// The `known_keys` map is empty; callers register keys via
    /// [`Self::register_key`] at startup.
    ///
    /// # Panics
    ///
    /// Never — the default constants are non-zero by construction
    /// and `Quota::per_second(NonZeroU32)` is total once a non-zero
    /// rate is supplied.  An expect is used to assert the const
    /// invariant at a single site so consumers do not have to handle
    /// a `Result` for what is plumbing.
    #[must_use]
    pub fn new() -> Self {
        Self::with_quota(default_tenant_quota())
    }

    /// Build with a caller-supplied [`Quota`].  Used by the keyless
    /// integration test to dial the limiter down to ~1 RPS so the
    /// rate-limit scenario completes inside a few seconds.
    #[must_use]
    pub fn with_quota(tenant_quota: Quota) -> Self {
        Self::with_capacity(tenant_quota, MAX_TRACKED_SUBJECTS)
    }

    /// Build with a caller-supplied [`Quota`] and an explicit
    /// cardinality cap on the per-subject limiter map.  See the
    /// module rustdoc's "cardinality cap" section for the memory-DoS
    /// rationale.
    ///
    /// `max_tracked_subjects == 0` is sanitised to 1 — a 0-cap map
    /// would always overflow and the surface would degrade silently.
    #[must_use]
    pub fn with_capacity(tenant_quota: Quota, max_tracked_subjects: usize) -> Self {
        let cap = usize::max(1, max_tracked_subjects);
        let overflow_limiter = Arc::new(DefaultDirectRateLimiter::direct(tenant_quota));
        Self {
            inner: Arc::new(KeylessPolicyInner {
                known_keys: PapayaMap::new(),
                tenant_limits: PapayaMap::new(),
                tenant_quota,
                max_tracked_subjects: cap,
                reserved_subjects: AtomicUsize::new(0),
                overflow_limiter,
            }),
        }
    }

    /// Register a known signing key under `key_id`.  Returns `true`
    /// if the entry was inserted; `false` if a key with that id was
    /// already present (the existing entry is left untouched — the
    /// caller is responsible for explicit rotation flows).
    pub fn register_key(&self, key_id: impl Into<CompactString>, known: KnownKey) -> bool {
        let id = key_id.into();
        let known = Arc::new(known);
        let pinned = self.inner.known_keys.pin();
        pinned.insert(id, known).is_none()
    }

    /// Borrow the registered [`KnownKey`] for `key_id`, if any.
    ///
    /// Cheap `Arc` clone — papaya's pinned guard returns a `&Arc<…>`
    /// which we clone before returning so the guard does not escape.
    #[must_use]
    pub fn known_key(&self, key_id: &str) -> Option<Arc<KnownKey>> {
        self.inner.known_keys.pin().get(key_id).cloned()
    }

    /// Run the four-step validation pipeline against `req` for a
    /// connection from the tenant identified by `subject`.
    ///
    /// On success returns the matched [`KnownKey`] — the handler
    /// uses the returned `Arc` to build its canonical signing input
    /// against the right key without re-doing the lookup.
    ///
    /// On failure returns the typed [`KeylessError`] variant; the
    /// handler maps each variant to its wire code + HTTP status.
    ///
    /// # Errors
    ///
    /// - [`KeylessError::RoutingContextMismatch`] — SEC-015: the
    ///   request's `routed_hostname` does not authorise the
    ///   `requested_cert_subject` (handler maps to HTTP 403).  Run
    ///   FIRST so the security-policy refusal short-circuits before
    ///   any allocation, lookup, or signer-pool capacity is spent.
    /// - [`KeylessError::UnknownKeyId`] — `key_id` not in `known_keys`.
    /// - [`KeylessError::SchemeMismatch`] — `scheme.algorithm()` does
    ///   not match the loaded key's `algorithm`.
    /// - [`KeylessError::PayloadTooLarge`] — `payload.len() >
    ///   KEYLESS_PAYLOAD_BUDGET`.
    /// - [`KeylessError::RateLimited`] — the per-subject governor
    ///   limiter rejected this request.
    pub fn validate(
        &self,
        subject: &str,
        req: &SignRequest,
    ) -> Result<Arc<KnownKey>, KeylessError> {
        // --- Step 0 (SEC-015): routing-context refuse-to-sign --------------
        // Runs BEFORE every other check.  A signing-policy refusal is the
        // strictest verdict the keyless oracle can render, so it short-
        // circuits ahead of input-shape validation and rate-limit
        // accounting.  Mismatch → 403 Forbidden at the handler.
        check_routing_context(&req.routing_context)?;

        // --- Step 1: known key id ------------------------------------------
        let known = self.known_key(req.key_id.as_str()).ok_or_else(|| {
            KeylessError::UnknownKeyId(format!("no key registered under id {:?}", req.key_id))
        })?;

        // --- Step 2: scheme matches the key's algorithm --------------------
        let scheme: SignatureScheme = req.scheme.to_rustls();
        let scheme_alg = signature_scheme_algorithm(scheme).ok_or_else(|| {
            KeylessError::SchemeMismatch(format!(
                "scheme ordinal 0x{:04x} is not on the v0.1 keyless allow-list",
                req.scheme.as_u16()
            ))
        })?;
        if scheme_alg != known.algorithm {
            return Err(KeylessError::SchemeMismatch(format!(
                "scheme algorithm {scheme_alg:?} does not match key algorithm {:?}",
                known.algorithm
            )));
        }

        // --- Step 3: payload budget ----------------------------------------
        if req.payload.len() > KEYLESS_PAYLOAD_BUDGET {
            return Err(KeylessError::PayloadTooLarge {
                observed: req.payload.len(),
                budget: KEYLESS_PAYLOAD_BUDGET,
            });
        }

        // --- Step 4: per-subject rate limit --------------------------------
        // Look up (or insert) the limiter for this subject.  Two-step
        // lookup keeps the common path (already-known subject) free
        // of allocation.
        let limiter = self.limiter_for_subject(subject);
        if limiter.check().is_err() {
            return Err(KeylessError::RateLimited);
        }

        Ok(known)
    }

    /// Return the rate-limiter for `subject`, inserting a fresh one
    /// keyed by the configured per-tenant quota if none exists yet.
    ///
    /// **Cardinality cap (memory-DoS guard, atomic).**  Insertion is
    /// gated by an [`AtomicUsize`] reservation counter
    /// (`reserved_subjects`).  Each thread wishing to insert a new
    /// entry first claims a slot via a `compare_exchange` loop; if
    /// the counter has reached `max_tracked_subjects`, the thread
    /// returns the shared `overflow_limiter` instead.  The counter
    /// is rolled back when the subsequent papaya `try_insert` loses
    /// to a concurrent winner under the same key, so the
    /// reservation count stays equal to the map's true cardinality.
    /// This makes the cap atomic across arbitrary insert
    /// concurrency — no two threads can simultaneously observe
    /// `count < cap` and both insert past the limit.
    ///
    /// Synchronisation contract:
    /// - `compare_exchange` uses `AcqRel` on success / `Acquire` on
    ///   failure; that pairs each reservation with the matching
    ///   roll-back release on the failure path.
    /// - `load(Acquire)` only synchronises with prior releases — it
    ///   reads the most recently-released value, not "the latest"
    ///   in a real-time sense; we use it for the fast-path early
    ///   exit and never rely on it as the cap-enforcement primitive.
    fn limiter_for_subject(&self, subject: &str) -> Arc<DefaultDirectRateLimiter> {
        // Fast path: the subject is already in the map.
        let pinned = self.inner.tenant_limits.pin();
        if let Some(existing) = pinned.get(subject) {
            return Arc::clone(existing);
        }

        // Reservation loop: atomically claim a slot iff the current
        // reservation count is below the cap.  Loser-arms (someone
        // else bumped the counter between the load and the CAS)
        // retry; cap-arms (counter is already at the cap) fall back
        // to the overflow limiter.
        let cap = self.inner.max_tracked_subjects;
        let counter = &self.inner.reserved_subjects;
        loop {
            let observed = counter.load(Ordering::Acquire);
            if observed >= cap {
                return Arc::clone(&self.inner.overflow_limiter);
            }
            if counter
                .compare_exchange_weak(observed, observed + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }

        // Reservation claimed.  Build the fresh limiter and try to
        // insert it.  On race-loss (another thread inserted the same
        // key first) we MUST roll back the reservation so the count
        // stays equal to the map's true cardinality.
        let new_limiter = Arc::new(DefaultDirectRateLimiter::direct(self.inner.tenant_quota));
        let key = CompactString::new(subject);
        match pinned.try_insert(key, Arc::clone(&new_limiter)) {
            Ok(_) => new_limiter,
            Err(occupied) => {
                // Roll back our reservation: another thread won the
                // insert race for this key, so the map cardinality
                // did not actually increase under our reservation.
                counter.fetch_sub(1, Ordering::AcqRel);
                Arc::clone(occupied.current)
            }
        }
    }

    /// Number of subjects currently held in the per-tenant limiter
    /// map.  Exposed for the cardinality-cap regression test +
    /// future Phase 7 admin observability.
    #[must_use]
    pub fn tracked_subjects(&self) -> usize {
        self.inner.tenant_limits.pin().len()
    }
}

impl Default for KeylessPolicy {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// SEC-015 routing-context refuse-to-sign check.
///
/// Returns `Ok(())` iff `ctx.routed_hostname` authorises
/// `ctx.requested_cert_subject` under the v0.1 matching rule:
///
/// - **Direct match.** `routed_hostname == requested_cert_subject`,
///   compared case-insensitively per RFC 6125 §6.4.
/// - **Single-label wildcard.** `requested_cert_subject = "*.<suffix>"`
///   matches `routed_hostname = "<label>.<suffix>"` iff
///   `<label>` is non-empty, contains no dot, and `<suffix>` itself
///   contains at least one dot.  This forbids degenerate patterns like
///   `*.com` (too broad) and limits wildcard coverage to a single
///   label — `*.example.com` covers `foo.example.com` but NOT
///   `example.com` (apex) and NOT `foo.bar.example.com` (sub-sub).
///
/// Anything else — embedded wildcards (`foo.*.com`), trailing dots
/// (`example.com.`), pure `*`, or arbitrary mismatches — is refused.
///
/// # Errors
///
/// Returns [`KeylessError::RoutingContextMismatch`] when the
/// authorisation rule above is not satisfied.  The handler maps this
/// to HTTP 403 (NOT 400) so the wire signals an explicit
/// security-policy refusal rather than an input-shape complaint.
pub fn check_routing_context(ctx: &RoutingContext) -> Result<(), KeylessError> {
    let routed = ctx.routed_hostname.as_str();
    let requested = ctx.requested_cert_subject.as_str();

    if hostname_authorises(routed, requested) {
        Ok(())
    } else {
        Err(KeylessError::RoutingContextMismatch(format!(
            "routed_hostname {routed:?} does not authorise requested_cert_subject {requested:?}"
        )))
    }
}

/// Pure helper for [`check_routing_context`].  Returns `true` iff
/// `routed` is authorised by the cert-subject pattern `requested`
/// under the v0.1 matching rule documented on the public function.
fn hostname_authorises(routed: &str, requested: &str) -> bool {
    if routed.is_empty() || requested.is_empty() {
        return false;
    }
    // Reject trailing-dot forms on either side; FQDN-with-dot is a
    // DNS-resolution detail, not part of the cert/SNI surface this
    // check evaluates.
    if routed.ends_with('.') || requested.ends_with('.') {
        return false;
    }

    // Wildcard pattern `*.<suffix>`: single-label prefix only.
    if let Some(suffix) = requested.strip_prefix("*.") {
        // `*.<suffix>` MUST have a meaningful suffix — `*.com` is
        // refused because the authorisation surface is "every site
        // under .com".
        if !suffix.contains('.') {
            return false;
        }
        // Suffix must not itself contain wildcards.
        if suffix.contains('*') {
            return false;
        }
        // routed = "<label>.<suffix>" where <label> has no dot.
        let Some(dot_idx) = routed.find('.') else {
            return false;
        };
        let label = &routed[..dot_idx];
        let routed_suffix = &routed[dot_idx + 1..];
        return !label.is_empty()
            && !label.contains('*')
            && routed_suffix.eq_ignore_ascii_case(suffix);
    }

    // Embedded or trailing wildcards in the pattern (anything other
    // than a leading `*.`) are refused.
    if requested.contains('*') {
        return false;
    }

    // Direct match, case-insensitive (RFC 6125 §6.4).
    routed.eq_ignore_ascii_case(requested)
}

/// Map a [`SignatureScheme`] to its [`SignatureAlgorithm`] under the
/// v0.1 keyless allow-list.
///
/// rustls's own `SignatureScheme::algorithm()` is `pub(crate)` (not
/// callable from outside the rustls crate); we re-implement the
/// table here.  Schemes outside the v0.1 allow-list — DSA, Ed25519,
/// Ed448, ML-DSA — return `None`, which the policy maps to
/// [`KeylessError::SchemeMismatch`] at the handler boundary.
const fn signature_scheme_algorithm(scheme: SignatureScheme) -> Option<SignatureAlgorithm> {
    match scheme {
        SignatureScheme::RSA_PKCS1_SHA1
        | SignatureScheme::RSA_PKCS1_SHA256
        | SignatureScheme::RSA_PKCS1_SHA384
        | SignatureScheme::RSA_PKCS1_SHA512
        | SignatureScheme::RSA_PSS_SHA256
        | SignatureScheme::RSA_PSS_SHA384
        | SignatureScheme::RSA_PSS_SHA512 => Some(SignatureAlgorithm::RSA),
        SignatureScheme::ECDSA_NISTP256_SHA256
        | SignatureScheme::ECDSA_NISTP384_SHA384
        | SignatureScheme::ECDSA_NISTP521_SHA512 => Some(SignatureAlgorithm::ECDSA),
        _ => None,
    }
}

/// `KEYLESS_TENANT_BURST` as a `NonZeroU32` — `const`-evaluated so
/// the panic-on-zero path is statically unreachable.
const KEYLESS_TENANT_BURST_NONZERO: core::num::NonZeroU32 =
    match core::num::NonZeroU32::new(KEYLESS_TENANT_BURST) {
        Some(v) => v,
        None => panic!("KEYLESS_TENANT_BURST const is non-zero by construction"),
    };

/// `KEYLESS_TENANT_SUSTAINED` as a `NonZeroU32` — `const`-evaluated.
const KEYLESS_TENANT_SUSTAINED_NONZERO: core::num::NonZeroU32 =
    match core::num::NonZeroU32::new(KEYLESS_TENANT_SUSTAINED) {
        Some(v) => v,
        None => panic!("KEYLESS_TENANT_SUSTAINED const is non-zero by construction"),
    };

/// Workspace-default per-tenant quota: [`KEYLESS_TENANT_BURST`] burst
/// + [`KEYLESS_TENANT_SUSTAINED`] req/sec sustained.
#[expect(
    clippy::missing_const_for_fn,
    reason = "governor 0.10's `Quota::per_second` / `allow_burst` are not \
              declared `const fn`, so this wrapper cannot be const either; \
              clippy mis-promotes because the bodies happen to satisfy \
              const-eval rules. Re-evaluate when the upstream marks them const."
)]
fn default_tenant_quota() -> Quota {
    Quota::per_second(KEYLESS_TENANT_SUSTAINED_NONZERO).allow_burst(KEYLESS_TENANT_BURST_NONZERO)
}

/// Spell out the unused governor type-state aliases so an accidental
/// future swap (`DefaultKeyedRateLimiter`? sharded?) still
/// type-checks.
///
/// Direct (un-keyed) limiter at `InMemoryState` + the workspace's
/// `DefaultClock`; matches `DefaultDirectRateLimiter`.
#[allow(dead_code)]
type _LimiterShape = governor::RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test-only setup")]
mod tests {
    use super::*;
    use crate::keyless::material::load_keyless_signing_key;
    use crate::keyless::wire::{RoutingContext, SignRequest, SignatureSchemeWire};

    /// RSA-2048 test fixture (same as material.rs / signer.rs).
    const RSA_2048_PEM: &[u8] = include_bytes!("../../tests/fixtures/keyless-rsa-2048.pem");

    fn rsa_known_key() -> KnownKey {
        let key = load_keyless_signing_key(RSA_2048_PEM).expect("rsa-2048 loads");
        KnownKey::new(Arc::new(key), SignatureAlgorithm::RSA)
    }

    fn fixture_request(payload_len: usize, scheme: SignatureScheme) -> SignRequest {
        SignRequest {
            key_id: CompactString::const_new("test-key-1"),
            scheme: SignatureSchemeWire::from(scheme),
            payload: vec![0u8; payload_len],
            routing_context: RoutingContext {
                routed_hostname: CompactString::const_new("h"),
                requested_cert_subject: CompactString::const_new("h"),
            },
        }
    }

    #[test]
    fn unknown_key_id_is_rejected_first() {
        let policy = KeylessPolicy::new();
        // No keys registered.
        let req = fixture_request(16, SignatureScheme::RSA_PSS_SHA256);
        let err = policy
            .validate("subject-a", &req)
            .expect_err("unknown id must be refused");
        assert!(
            matches!(err, KeylessError::UnknownKeyId(_)),
            "expected UnknownKeyId, got: {err:?}"
        );
    }

    #[test]
    fn known_id_with_matching_scheme_passes() {
        let policy = KeylessPolicy::new();
        assert!(policy.register_key("test-key-1", rsa_known_key()));
        let req = fixture_request(16, SignatureScheme::RSA_PSS_SHA256);
        let known = policy
            .validate("subject-a", &req)
            .expect("valid request must pass");
        assert_eq!(known.algorithm, SignatureAlgorithm::RSA);
    }

    #[test]
    fn rsa_key_with_ecdsa_scheme_is_scheme_mismatch() {
        let policy = KeylessPolicy::new();
        assert!(policy.register_key("test-key-1", rsa_known_key()));
        let req = fixture_request(16, SignatureScheme::ECDSA_NISTP256_SHA256);
        let err = policy
            .validate("subject-a", &req)
            .expect_err("rsa key cannot sign ecdsa scheme");
        assert!(
            matches!(err, KeylessError::SchemeMismatch(_)),
            "expected SchemeMismatch, got: {err:?}"
        );
    }

    #[test]
    fn payload_at_budget_is_accepted() {
        let policy = KeylessPolicy::new();
        assert!(policy.register_key("test-key-1", rsa_known_key()));
        let req = fixture_request(KEYLESS_PAYLOAD_BUDGET, SignatureScheme::RSA_PSS_SHA256);
        policy
            .validate("subject-a", &req)
            .expect("payload at exactly the budget must pass");
    }

    #[test]
    fn payload_one_over_budget_is_rejected() {
        let policy = KeylessPolicy::new();
        assert!(policy.register_key("test-key-1", rsa_known_key()));
        let req = fixture_request(KEYLESS_PAYLOAD_BUDGET + 1, SignatureScheme::RSA_PSS_SHA256);
        let err = policy
            .validate("subject-a", &req)
            .expect_err("payload over budget must be refused");
        assert!(
            matches!(
                err,
                KeylessError::PayloadTooLarge {
                    observed,
                    budget: KEYLESS_PAYLOAD_BUDGET,
                } if observed == KEYLESS_PAYLOAD_BUDGET + 1
            ),
            "expected PayloadTooLarge with observed = budget+1, got: {err:?}"
        );
    }

    #[test]
    fn unsupported_scheme_is_scheme_mismatch() {
        let policy = KeylessPolicy::new();
        assert!(policy.register_key("test-key-1", rsa_known_key()));
        // Ed25519 is not on the v0.1 keyless allow-list (RSA / ECDSA-P256
        // only); the scheme-algorithm classifier returns None and the
        // policy maps that to SchemeMismatch.
        let req = fixture_request(16, SignatureScheme::ED25519);
        let err = policy
            .validate("subject-a", &req)
            .expect_err("unsupported scheme must be refused");
        assert!(
            matches!(err, KeylessError::SchemeMismatch(_)),
            "expected SchemeMismatch for non-allowlisted scheme, got: {err:?}"
        );
    }

    #[test]
    fn rate_limit_eventually_rejects_when_burst_exhausted() {
        // Tight quota — 2 burst, 1 RPS sustained — so the test
        // exhausts the burst within a few iterations.
        let burst = core::num::NonZeroU32::new(2).expect("non-zero");
        let sustained = core::num::NonZeroU32::new(1).expect("non-zero");
        let quota = Quota::per_second(sustained).allow_burst(burst);
        let policy = KeylessPolicy::with_quota(quota);
        assert!(policy.register_key("test-key-1", rsa_known_key()));

        let req = fixture_request(16, SignatureScheme::RSA_PSS_SHA256);

        // Burst capacity == 2: first two go through, subsequent
        // requests inside the same second hit RateLimited.
        let mut rate_limited = false;
        for _ in 0..16u32 {
            match policy.validate("subject-rate-test", &req) {
                Ok(_) => {}
                Err(KeylessError::RateLimited) => {
                    rate_limited = true;
                    break;
                }
                Err(other) => panic!("unexpected error before rate-limit: {other:?}"),
            }
        }
        assert!(
            rate_limited,
            "burst of 2 + 16 immediate requests must produce a RateLimited"
        );
    }

    #[test]
    fn rate_limit_is_per_subject() {
        // Verify the limiter map keys on subject — exhausting one
        // subject's quota does not affect another.
        let burst = core::num::NonZeroU32::new(1).expect("non-zero");
        let sustained = core::num::NonZeroU32::new(1).expect("non-zero");
        let quota = Quota::per_second(sustained).allow_burst(burst);
        let policy = KeylessPolicy::with_quota(quota);
        assert!(policy.register_key("test-key-1", rsa_known_key()));

        let req = fixture_request(16, SignatureScheme::RSA_PSS_SHA256);

        // First subject: burst of 1, then RateLimited.
        policy.validate("subject-a", &req).expect("first ok");
        let err = policy
            .validate("subject-a", &req)
            .expect_err("second must be rate-limited");
        assert!(matches!(err, KeylessError::RateLimited));

        // Second subject: independent quota, must succeed.
        policy
            .validate("subject-b", &req)
            .expect("subject-b's quota is independent");
    }

    #[test]
    fn known_key_lookup_is_arc_cheap() {
        let policy = KeylessPolicy::new();
        assert!(policy.register_key("k1", rsa_known_key()));
        let a = policy.known_key("k1").expect("present");
        let b = policy.known_key("k1").expect("present");
        // Same Arc — papaya stores Arc<KnownKey> by value, lookup
        // returns clones.
        assert!(Arc::ptr_eq(&a, &b));
        assert!(policy.known_key("missing").is_none());
    }

    #[test]
    fn double_register_keeps_first_entry() {
        let policy = KeylessPolicy::new();
        assert!(policy.register_key("k1", rsa_known_key()));
        // Second registration with the same id reports false (was
        // already present); the existing entry is kept.
        assert!(!policy.register_key("k1", rsa_known_key()));
    }

    #[test]
    fn tenant_limit_map_is_capped_at_max_tracked_subjects() {
        // Memory-DoS guard: the per-subject limiter map MUST NOT
        // grow beyond `max_tracked_subjects`, even under repeated
        // distinct-subject requests.
        let burst = core::num::NonZeroU32::new(100).expect("non-zero");
        let sustained = core::num::NonZeroU32::new(50).expect("non-zero");
        let quota = Quota::per_second(sustained).allow_burst(burst);
        let cap: usize = 4;
        let policy = KeylessPolicy::with_capacity(quota, cap);
        assert!(policy.register_key("test-key-1", rsa_known_key()));

        let req = fixture_request(16, SignatureScheme::RSA_PSS_SHA256);

        // Submit 32 distinct subjects sequentially.  All should be
        // accepted (burst capacity well above 1) but the map MUST
        // cap at `cap` entries — the rest go through the overflow
        // limiter.
        for i in 0..32u32 {
            let subj = format!("subject-{i}");
            policy
                .validate(&subj, &req)
                .expect("each distinct subject within burst must validate");
        }

        let tracked = policy.tracked_subjects();
        assert!(
            tracked <= cap,
            "tenant_limits cardinality must stay at or below cap; tracked={tracked} cap={cap}"
        );
    }

    #[test]
    fn concurrent_inserts_respect_cardinality_cap() {
        // Stress-test the atomic reservation loop: many threads,
        // each contributing a unique subject, MUST collectively
        // produce a per-subject map sized at most `cap`.  Any
        // check-then-insert race in `limiter_for_subject` shows up
        // as `tracked > cap`.
        use std::sync::Barrier;
        use std::thread;

        let burst = core::num::NonZeroU32::new(1000).expect("non-zero");
        let sustained = core::num::NonZeroU32::new(500).expect("non-zero");
        let quota = Quota::per_second(sustained).allow_burst(burst);
        let cap: usize = 8;
        let policy = Arc::new(KeylessPolicy::with_capacity(quota, cap));
        assert!(policy.register_key("test-key-1", rsa_known_key()));

        let threads = 32usize;
        let per_thread = 16usize;
        let barrier = Arc::new(Barrier::new(threads));
        let mut handles = Vec::with_capacity(threads);
        for t in 0..threads {
            let policy = Arc::clone(&policy);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let req = fixture_request(16, SignatureScheme::RSA_PSS_SHA256);
                barrier.wait();
                for i in 0..per_thread {
                    let subj = format!("t{t}-s{i}");
                    let _ = policy.validate(&subj, &req);
                }
            }));
        }
        for h in handles {
            h.join().expect("thread join");
        }

        let tracked = policy.tracked_subjects();
        assert!(
            tracked <= cap,
            "atomic-reservation loop violated: tracked={tracked} > cap={cap}"
        );
    }

    // ---- SEC-015 routing-context matching matrix (U4) ---------------

    fn ctx(routed: &str, requested: &str) -> RoutingContext {
        RoutingContext {
            routed_hostname: CompactString::new(routed),
            requested_cert_subject: CompactString::new(requested),
        }
    }

    #[test]
    fn routing_direct_match_authorises() {
        check_routing_context(&ctx("victim.com", "victim.com")).expect("direct match");
    }

    #[test]
    fn routing_direct_match_is_case_insensitive() {
        check_routing_context(&ctx("Victim.COM", "victim.com")).expect("rfc 6125 §6.4 case-insens");
        check_routing_context(&ctx("victim.com", "VICTIM.COM")).expect("symmetric case-insens");
    }

    #[test]
    fn routing_wildcard_matches_single_label() {
        check_routing_context(&ctx("api.example.com", "*.example.com"))
            .expect("wildcard covers single-label prefix");
    }

    #[test]
    fn routing_wildcard_rejects_apex() {
        let err = check_routing_context(&ctx("example.com", "*.example.com"))
            .expect_err("wildcard does NOT cover apex");
        assert!(matches!(err, KeylessError::RoutingContextMismatch(_)));
    }

    #[test]
    fn routing_wildcard_rejects_subsubdomain() {
        let err = check_routing_context(&ctx("foo.bar.example.com", "*.example.com"))
            .expect_err("wildcard does NOT cover sub-subdomain");
        assert!(matches!(err, KeylessError::RoutingContextMismatch(_)));
    }

    #[test]
    fn routing_wildcard_rejects_too_broad_tld() {
        let err = check_routing_context(&ctx("foo.com", "*.com"))
            .expect_err("`*.com` is too broad and refused");
        assert!(matches!(err, KeylessError::RoutingContextMismatch(_)));
        let err = check_routing_context(&ctx("any.io", "*.io"))
            .expect_err("`*.io` is too broad and refused");
        assert!(matches!(err, KeylessError::RoutingContextMismatch(_)));
    }

    #[test]
    fn routing_rejects_mismatched_hostname() {
        let err = check_routing_context(&ctx("victim.com", "attacker.com"))
            .expect_err("plain mismatch must refuse");
        assert!(matches!(err, KeylessError::RoutingContextMismatch(_)));
    }

    #[test]
    fn routing_rejects_embedded_wildcard() {
        let err = check_routing_context(&ctx("foo.bar.com", "foo.*.com"))
            .expect_err("embedded wildcard not allowed (only leading *.)");
        assert!(matches!(err, KeylessError::RoutingContextMismatch(_)));
    }

    #[test]
    fn routing_rejects_bare_star() {
        let err =
            check_routing_context(&ctx("anything.com", "*")).expect_err("bare `*` refused");
        assert!(matches!(err, KeylessError::RoutingContextMismatch(_)));
    }

    #[test]
    fn routing_rejects_empty_strings() {
        assert!(matches!(
            check_routing_context(&ctx("", "victim.com")),
            Err(KeylessError::RoutingContextMismatch(_))
        ));
        assert!(matches!(
            check_routing_context(&ctx("victim.com", "")),
            Err(KeylessError::RoutingContextMismatch(_))
        ));
        assert!(matches!(
            check_routing_context(&ctx("", "")),
            Err(KeylessError::RoutingContextMismatch(_))
        ));
    }

    #[test]
    fn routing_rejects_trailing_dot_fqdn() {
        // Trailing-dot FQDN form is a DNS-resolution detail, not part
        // of the cert/SNI authorisation surface.
        let err = check_routing_context(&ctx("victim.com.", "victim.com"))
            .expect_err("routed trailing dot refused");
        assert!(matches!(err, KeylessError::RoutingContextMismatch(_)));
        let err = check_routing_context(&ctx("victim.com", "victim.com."))
            .expect_err("requested trailing dot refused");
        assert!(matches!(err, KeylessError::RoutingContextMismatch(_)));
    }

    #[test]
    fn validate_runs_routing_check_before_other_steps() {
        // Confirms Step 0 ordering: a request with a mismatching
        // routing context fails BEFORE the unknown-key check, so
        // the strictest verdict (security-policy refusal) short-
        // circuits ahead of input-shape validation.
        let policy = KeylessPolicy::new();
        // No keys registered AND routing mismatch — must surface as
        // RoutingContextMismatch (the SEC-015 verdict), not as
        // UnknownKeyId.
        let req = SignRequest {
            key_id: CompactString::const_new("nonexistent"),
            scheme: SignatureSchemeWire::from(SignatureScheme::RSA_PSS_SHA256),
            payload: vec![0u8; 16],
            routing_context: RoutingContext {
                routed_hostname: CompactString::const_new("victim.com"),
                requested_cert_subject: CompactString::const_new("attacker.com"),
            },
        };
        let err = policy.validate("subject", &req).expect_err("must refuse");
        assert!(
            matches!(err, KeylessError::RoutingContextMismatch(_)),
            "expected RoutingContextMismatch first; got {err:?}"
        );
    }
}
