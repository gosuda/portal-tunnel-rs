//! R10 v0.1 per-relay reputation engine — minimum viable surface.
//!
//! Phase 5 Batch 7 (narrowed) lands the **core** engine: a
//! [`governor`]-keyed adaptive rate limiter on the
//! `(identity, ip, lease)` triple plus a per-identity
//! exponential-decay reputation score. Decisions surface as
//! [`ReputationDecision`] (`Allow` / `Backpressure(Duration)` /
//! `Block(BlockReason)`), and signals (rate-limit hits, future
//! honeypot fingerprinting, blocked-request feedback) feed back
//! into the score via [`ReputationEngine::record_signal`].
//!
//! ## Decay math
//!
//! Each score carries the timestamp of its last update. On read,
//! the engine applies an exponential decay:
//!
//! ```text
//! score(now) = score(last_updated) * exp(-decay_constant * elapsed_seconds)
//! half-life  = ln(2) / decay_constant
//! ```
//!
//! The default [`REPUTATION_DECAY_CONSTANT`] yields a 24-hour
//! half-life — a tenant that earns N reputation points and then
//! goes quiet sees those points halve every 24h.
//!
//! ## Concurrency model
//!
//! Mirrors [`crate::keyless::policy::KeylessPolicy`]:
//! - [`papaya::HashMap`] backs the per-identity score table for
//!   lock-free reads + writes on the hot path.
//! - The struct holds an `Arc<Inner>` so handlers carry cheap
//!   clones without re-allocating the keyed limiter.
//! - The keyed governor limiter is `Sync` and consults its own
//!   internal [`std::collections::HashMap`] under a mutex (per the
//!   `governor 0.10` `DefaultKeyedStateStore` shape).
//!
//! ## What this module **does NOT** ship in this iteration
//!
//! Each deferral is annotated with a `TODO(R10-followup): …`
//! comment at the relevant call site so the next batch can wire
//! them in without re-discovering the contract:
//!
//! - **ENS Sybil-gating bypass.** Plan U12 step 4 carves out a
//!   "score >= `block_threshold` AND identity is not ENS-named"
//!   condition. The minimum-engine apex is "score >=
//!   `block_threshold` → Block" unconditionally; the bypass branch
//!   that consults `Arc<dyn EnsResolver>` lands with the U6
//!   admin/SDK API surface batch.
//! - **Honeypot path matcher.** `Arc<HoneypotMatcher>` (compile-
//!   time path glob set against `/.env`, `/wp-admin/*`, `/.git/*`)
//!   feeds [`SignalKind::HoneypotHit`] from the listener pipeline;
//!   the signal variant exists already so call sites can stub
//!   today.
//! - **Persistence.** `reputation.json` round-trip via U5
//!   [`crate::state::write_json_atomic`] (60s cadence) is plan U12
//!   step 6's persistence requirement; the engine is in-memory
//!   only this iteration.
//! - **ADR-0007.** Decay / threshold / weight defaults are set to
//!   reasonable v0.1 values and pinned as `pub const`; the formal
//!   ADR justifying those choices is a separate decision artifact
//!   commit.
//! - **Hot-reload.** `arc_swap::ArcSwap<ReputationConfig>` is U13
//!   territory. The engine takes an `Arc<ReputationConfig>` so the
//!   transition to `ArcSwap` is a single field swap.
//! - **Per-signal tracing.** Only [`ReputationEngine::decide`]
//!   carries `#[tracing::instrument]` this iteration; emitting a
//!   per-signal-kind audit span on every [`ReputationEngine::
//!   record_signal`] is U13 territory.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use compact_str::CompactString;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use jiff::{Timestamp, Unit};
use papaya::HashMap as PapayaMap;

pub use crate::state::lease_registry::IdentityKey;

// ---------------------------------------------------------------------------
// v0.1 defaults — provisional ADR-0007 values
// ---------------------------------------------------------------------------
//
// These are the operator-facing defaults used by
// [`ReputationConfig::default`]. They are pinned as `pub const` so
// the eventual ADR-0007 follow-up (which will justify each value
// against threat-model + load-test data) can amend them without
// breaking call sites.

/// Default decay half-life in seconds (24 hours).
///
/// A tenant that earns reputation points and then goes quiet sees
/// the score halve every 24 hours. Long enough that a single bad
/// actor cannot "wash out" by waiting overnight; short enough that
/// a now-reformed identity is not blocked forever.
pub const REPUTATION_DECAY_HALF_LIFE_SECS: f64 = 24.0 * 3600.0;

/// Default decay constant: `ln(2) / half_life_secs`.
///
/// Pinned as a `f64` constant so the engine does not recompute
/// `ln(2)` on every signal. `f64::ln` is not `const fn` yet; we
/// inline the canonical value from `f64::ln(2.0_f64)` (see the
/// unit test that asserts the round-trip).
pub const REPUTATION_DECAY_CONSTANT: f64 = 0.000_008_022_536_812_239_24; // ln(2) / 86_400.0

/// Default block threshold — score at or above this returns
/// [`ReputationDecision::Block`].
pub const REPUTATION_BLOCK_THRESHOLD: f64 = 100.0;

/// Default backpressure threshold — score at or above this (but
/// below [`REPUTATION_BLOCK_THRESHOLD`]) returns
/// [`ReputationDecision::Backpressure`].
pub const REPUTATION_BACKPRESSURE_THRESHOLD: f64 = 50.0;

/// Default backpressure yield duration.
///
/// A handler that observes `Backpressure(d)` sleeps `d` before
/// forwarding. Conservative 50ms — enough to feel adversarial-
/// noticeable jitter without stalling a single legitimate burst
/// behind a rate-limit hit.
pub const REPUTATION_BACKPRESSURE_YIELD: Duration = Duration::from_millis(50);

/// Default sustained refill rate (RPS) for the per-triple keyed rate limiter.
///
/// Matches [`crate::keyless::policy::KEYLESS_TENANT_SUSTAINED`] so
/// a single operator-tunable surface drives both keyless +
/// reputation rate budgets in v0.1.
pub const REPUTATION_QUOTA_SUSTAINED: u32 = 50;

/// Default burst capacity for the per-triple keyed rate limiter.
///
/// 2:1 burst:sustained ratio per `governor`'s recommended starting
/// shape.
pub const REPUTATION_QUOTA_BURST: u32 = 100;

// ---------------------------------------------------------------------------
// LeaseId — third leg of the keyed-limiter triple
// ---------------------------------------------------------------------------

/// Lease identifier — matches the lease registry's
/// [`compact_str::CompactString`] surface.
///
/// The R10 limiter keys on `(identity, ip, lease_id)` so a single
/// tenant identity that rotates leases (re-register flow) gets a
/// fresh budget per lease, while sustained churn under one lease
/// still trips the limiter.
pub type LeaseId = CompactString;

// ---------------------------------------------------------------------------
// SignalKind / BlockReason / ReputationDecision
// ---------------------------------------------------------------------------

/// Kinds of reputation-affecting signals.
///
/// `#[non_exhaustive]` so future signals (canary-token tripping,
/// SIWE replay attempts, …) can land without breaking call sites.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignalKind {
    /// The keyed governor limiter rejected a request — pure
    /// rate-limit feedback. Default weight per ADR-0007 follow-up;
    /// [`ReputationEngine::record_signal`] takes the weight as an
    /// argument so callers can override per call site.
    RateLimited,
    /// The request hit a configured honeypot path
    /// (`/.env`, `/wp-admin/*`, …). Reserved for the U6 admin/SDK
    /// API surface batch.
    ///
    /// TODO(R10-followup): wire `Arc<HoneypotMatcher>` so the
    /// listeners pipeline can call `record_signal(_, HoneypotHit, _)`
    /// when an inbound request URI matches the configured glob set.
    HoneypotHit,
    /// A request was blocked by the engine itself (downstream
    /// handler observed [`ReputationDecision::Block`]) — the
    /// engine keeps recording so a blocked tenant's score does not
    /// decay below threshold while they keep poking.
    BlockedRequest,
}

/// Reasons a request can be blocked.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// The per-identity reputation score crossed the configured
    /// [`ReputationConfig::block_threshold`].
    ReputationExceeded,
    /// The per-triple keyed rate limiter rejected the request.
    RateLimited,
}

impl core::fmt::Display for BlockReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let label = match self {
            Self::ReputationExceeded => "reputation_exceeded",
            Self::RateLimited => "rate_limited",
        };
        f.write_str(label)
    }
}

/// The engine's per-request verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationDecision {
    /// Forward the request to the handler immediately.
    Allow,
    /// Forward the request after sleeping the supplied duration
    /// — a soft, latency-only deterrent for tenants in the
    /// backpressure band.
    Backpressure(Duration),
    /// Refuse the request. Caller maps to HTTP 403 (reputation)
    /// or 429 (rate-limit) per the [`BlockReason`] variant.
    Block(BlockReason),
}

impl ReputationDecision {
    /// Compact label for tracing fields. Avoids `Debug`-style
    /// noise on audit spans.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Backpressure(_) => "backpressure",
            Self::Block(_) => "block",
        }
    }
}

// ---------------------------------------------------------------------------
// ReputationScore
// ---------------------------------------------------------------------------

/// Decay-tracked reputation score.
///
/// The engine applies decay on every read so the stored value is
/// always "as of `last_updated`" — the projected `now`-value is a
/// pure function of the stored pair and the configured
/// `decay_constant`.
#[derive(Debug, Clone, Copy)]
pub struct ReputationScore {
    /// The decayed-as-of-`last_updated` score.
    pub value: f64,
    /// Wall-clock instant of the most recent decay step.
    pub last_updated: Timestamp,
}

impl ReputationScore {
    /// Construct a fresh score at value 0 with `last_updated = now`.
    #[must_use]
    pub const fn fresh(now: Timestamp) -> Self {
        Self {
            value: 0.0,
            last_updated: now,
        }
    }

    /// Project this score forward to `now`, applying decay.
    /// Returns the projected value without mutating the stored
    /// pair (callers persist the new `(value, now)` via
    /// [`ReputationEngine::record_signal`] or the engine's
    /// internal store flow).
    #[must_use]
    pub fn projected(&self, now: Timestamp, decay_constant: f64) -> f64 {
        apply_decay(self.value, self.last_updated, now, decay_constant)
    }
}

/// Pure decay-projection helper. Exposed at the module level for
/// the unit test fixture and to keep [`ReputationScore::projected`]
/// trivially correct.
///
/// Guards against non-finite inputs: `NaN` / `±inf` would poison
/// every downstream threshold comparison (every `>=` and `<=`
/// against `NaN` is `false`, so a poisoned score silently routes
/// to [`ReputationDecision::Allow`]).  We coerce non-finite stored
/// values to 0.0 here — sanitising at the read site means a stale
/// poisoned entry from any path (e.g. a malformed
/// `reputation.json` snapshot in the U5 follow-up) cannot leak
/// past the engine boundary.
#[must_use]
pub fn apply_decay(
    score: f64,
    last_updated: Timestamp,
    now: Timestamp,
    decay_constant: f64,
) -> f64 {
    // Sanitise stored input. A non-finite stored value is the
    // result of an upstream bug + always routes to "no
    // accumulated reputation"; do NOT propagate it.
    if !score.is_finite() {
        return 0.0;
    }
    if score == 0.0 {
        return score;
    }
    // jiff `Timestamp - Timestamp = Span`; `Span::total(Unit::Second)` returns
    // `Result<f64, Error>` — the only failure modes are unit-mismatch / overflow,
    // neither of which can fire when the unit is `Second` and both inputs are
    // valid `Timestamp` values.  `unwrap_or(0.0)` is the safe degraded path
    // (no decay if the elapsed-seconds projection is unrepresentable as f64).
    let elapsed_seconds = (now - last_updated).total(Unit::Second).unwrap_or(0.0);
    if elapsed_seconds <= 0.0 {
        return score;
    }
    let projected = score * (-decay_constant * elapsed_seconds).exp();
    // The exp() factor is in [0, 1] for non-negative elapsed time,
    // so finite-in implies finite-out under normal conditions.
    // Defence-in-depth: if a pathological `decay_constant` (e.g.
    // negative, NaN) produces non-finite output, sanitise here
    // rather than propagating poison.
    if projected.is_finite() {
        projected
    } else {
        0.0
    }
}

// ---------------------------------------------------------------------------
// ReputationConfig
// ---------------------------------------------------------------------------

/// Per-engine tuning surface. Held behind an `Arc` so a future U13
/// `ArcSwap<ReputationConfig>` swap-in is a single-field rewire
/// from the engine's perspective.
#[derive(Debug, Clone)]
pub struct ReputationConfig {
    /// Decay constant `λ` such that `score(t1) = score(t0) *
    /// exp(-λ * (t1 - t0))`. Default: [`REPUTATION_DECAY_CONSTANT`]
    /// (24-hour half-life).
    pub decay_constant: f64,
    /// Score at-or-above which [`ReputationEngine::decide`] returns
    /// [`ReputationDecision::Block`]. Default:
    /// [`REPUTATION_BLOCK_THRESHOLD`].
    pub block_threshold: f64,
    /// Score at-or-above which [`ReputationEngine::decide`] returns
    /// [`ReputationDecision::Backpressure`]. Default:
    /// [`REPUTATION_BACKPRESSURE_THRESHOLD`].
    pub backpressure_threshold: f64,
    /// Yield duration emitted by [`ReputationDecision::
    /// Backpressure`]. Default: [`REPUTATION_BACKPRESSURE_YIELD`].
    pub backpressure_yield: Duration,
    /// Quota for the per-`(identity, ip, lease)` keyed rate
    /// limiter. Default: [`default_governor_quota`].
    pub governor_quota: Quota,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            decay_constant: REPUTATION_DECAY_CONSTANT,
            block_threshold: REPUTATION_BLOCK_THRESHOLD,
            backpressure_threshold: REPUTATION_BACKPRESSURE_THRESHOLD,
            backpressure_yield: REPUTATION_BACKPRESSURE_YIELD,
            governor_quota: default_governor_quota(),
        }
    }
}

/// `REPUTATION_QUOTA_SUSTAINED` as a `NonZeroU32` —
/// `const`-evaluated so the panic-on-zero path is statically
/// unreachable.
const REPUTATION_QUOTA_SUSTAINED_NONZERO: NonZeroU32 =
    match NonZeroU32::new(REPUTATION_QUOTA_SUSTAINED) {
        Some(v) => v,
        None => panic!("REPUTATION_QUOTA_SUSTAINED const is non-zero by construction"),
    };

/// `REPUTATION_QUOTA_BURST` as a `NonZeroU32` — `const`-evaluated.
const REPUTATION_QUOTA_BURST_NONZERO: NonZeroU32 = match NonZeroU32::new(REPUTATION_QUOTA_BURST) {
    Some(v) => v,
    None => panic!("REPUTATION_QUOTA_BURST const is non-zero by construction"),
};

/// The workspace-default keyed-limiter quota:
/// [`REPUTATION_QUOTA_SUSTAINED`] RPS sustained, burst
/// [`REPUTATION_QUOTA_BURST`].
#[must_use]
#[expect(
    clippy::missing_const_for_fn,
    reason = "governor 0.10's `Quota::per_second` / `allow_burst` are not \
              declared `const fn`, so this wrapper cannot be const either; \
              clippy mis-promotes because the bodies happen to satisfy \
              const-eval rules. Re-evaluate when the upstream marks them const."
)]
pub fn default_governor_quota() -> Quota {
    Quota::per_second(REPUTATION_QUOTA_SUSTAINED_NONZERO)
        .allow_burst(REPUTATION_QUOTA_BURST_NONZERO)
}

// ---------------------------------------------------------------------------
// ReputationEngine
// ---------------------------------------------------------------------------

/// Triple key for the per-`(identity, ip, lease)` keyed limiter.
/// `Hash + Eq + Clone + Send + Sync + 'static` per
/// `governor::state::keyed::KeyedStateStore`'s blanket impl
/// requirement.
type TripleKey = (IdentityKey, IpAddr, LeaseId);

/// Concrete keyed-limiter type: `governor 0.10`'s
/// `DefaultKeyedStateStore<K>` is the std `HashMap`-backed default
/// (no `dashmap` feature on the workspace's pin), and
/// `DefaultClock` is the workspace-default monotonic clock.
type Limiter = RateLimiter<TripleKey, DefaultKeyedStateStore<TripleKey>, DefaultClock>;

/// Per-relay R10 v0.1 reputation engine.
///
/// `Clone` is cheap (single `Arc` bump). The handlers and the
/// listener pipeline both hold their own clone, all of which point
/// at the same `Inner`.
#[derive(Clone)]
pub struct ReputationEngine {
    inner: Arc<Inner>,
}

struct Inner {
    /// Per-identity decay-tracked scores.
    scores: PapayaMap<IdentityKey, ReputationScore>,
    /// Per-`(identity, ip, lease)` keyed rate limiter.
    limiter: Limiter,
    /// Tunable thresholds + decay constant.
    ///
    /// TODO(R10-followup): swap `Arc<ReputationConfig>` for
    /// `Arc<arc_swap::ArcSwap<ReputationConfig>>` per U13 so a hot
    /// `POST /v1/admin/config/reload` can mutate thresholds
    /// without dropping in-flight scores.
    config: Arc<ReputationConfig>,
}

impl core::fmt::Debug for ReputationEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReputationEngine")
            .field("scored_identities", &self.inner.scores.pin().len())
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

impl Default for ReputationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ReputationEngine {
    /// Build an engine with the workspace-default
    /// [`ReputationConfig`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(ReputationConfig::default())
    }

    /// Build an engine with a caller-supplied [`ReputationConfig`].
    /// Used by the behavioral gate test to dial the decay constant
    /// to a 1-second half-life so the round-trip completes inside
    /// a few seconds.
    #[must_use]
    pub fn with_config(config: ReputationConfig) -> Self {
        let limiter = RateLimiter::keyed(config.governor_quota);
        Self {
            inner: Arc::new(Inner {
                scores: PapayaMap::new(),
                limiter,
                config: Arc::new(config),
            }),
        }
    }

    /// Borrow the engine's [`ReputationConfig`].
    #[must_use]
    pub fn config(&self) -> &ReputationConfig {
        &self.inner.config
    }

    /// Project the score for `identity` to `now`. Returns 0.0 for
    /// an identity the engine has never seen.
    #[must_use]
    pub fn score_at(&self, identity: IdentityKey, now: Timestamp) -> f64 {
        self.inner
            .scores
            .pin()
            .get(&identity)
            .map_or(0.0, |s| s.projected(now, self.inner.config.decay_constant))
    }

    /// Convenience: project the score for `identity` to
    /// `Timestamp::now()`.
    #[must_use]
    pub fn score(&self, identity: IdentityKey) -> f64 {
        self.score_at(identity, Timestamp::now())
    }

    /// Record a reputation-affecting signal.
    ///
    /// Atomically updates the score for `identity` via papaya's
    /// CAS-style [`papaya::HashMap::update_or_insert_with`]:
    /// concurrent signals against the same identity serialise
    /// through the CAS and **never overwrite each other** (two
    /// concurrent `record_signal(_, _, 10.0)` calls always sum to
    /// 20.0 in the stored value).
    ///
    /// `weight` is sanitised: non-finite weights (`NaN` / `±inf`)
    /// would poison the score and silently route every future
    /// `decide()` to [`ReputationDecision::Allow`] (every `>=`
    /// against `NaN` is `false`).  Non-finite weights are dropped
    /// — the call becomes a no-op.  Negative weights are accepted
    /// (the engine surface is symmetric; a future "good behaviour"
    /// signal would feed a negative weight).
    ///
    /// `signal_kind` is currently informational — it is reserved
    /// for future per-signal-kind weight policies + the U13
    /// per-signal audit-span emission.
    ///
    /// TODO(R10-followup): emit a `tracing::info` span here per
    /// signal kind so the audit log captures the full causal
    /// chain (currently only [`Self::decide`] is instrumented).
    pub fn record_signal(&self, identity: IdentityKey, signal_kind: SignalKind, weight: f64) {
        // Touch `signal_kind` so the parameter is not flagged as
        // unused while the per-kind weight policy is deferred.
        let _ = signal_kind;
        // NaN/±inf would poison every subsequent threshold check
        // (`NaN >= threshold` is false), so reject at the gate
        // rather than store a sentinel.
        if !weight.is_finite() {
            return;
        }
        let decay_constant = self.inner.config.decay_constant;
        // Sample `now` once per signal — keeping the closure
        // deterministic in its (Option<&V>) input is what papaya's
        // CAS retry/memoisation contract requires.
        let now = Timestamp::now();
        let pinned = self.inner.scores.pin();
        // Single CAS update.  papaya's `update_or_insert_with`
        // serialises concurrent writers via internal CAS retries;
        // because both branches' output is a pure function of
        // `(prior, now, weight, decay_constant)`, two concurrent
        // signals always sum into the committed value.
        //
        // `now < prior.last_updated` is possible under wall-clock
        // skew (or simply a fast concurrent commit landing
        // between our `now` sample and the closure's read of the
        // current entry).  We clamp the projection target to
        // `max(now, prior.last_updated)` so the stored
        // `last_updated` is monotonically non-decreasing per
        // identity, and `apply_decay`'s `elapsed_seconds <= 0.0`
        // short-circuit triggers when we have no fresh window to
        // decay through.
        pinned.update_or_insert_with(
            identity,
            |prior: &ReputationScore| {
                let target = if now < prior.last_updated {
                    prior.last_updated
                } else {
                    now
                };
                let decayed = prior.projected(target, decay_constant);
                let next_value = decayed + weight;
                ReputationScore {
                    // Sanitise: arithmetic overflow (`±inf`) or
                    // any non-finite intermediate must not
                    // poison the stored invariant
                    // "value.is_finite()".
                    value: if next_value.is_finite() {
                        next_value
                    } else {
                        0.0
                    },
                    last_updated: target,
                }
            },
            || ReputationScore {
                value: weight,
                last_updated: now,
            },
        );
    }

    /// Run the v0.1 R10 decision pipeline against the supplied
    /// `(identity, ip, lease)` triple.
    ///
    /// Steps (per plan U12):
    /// 1. (canonicalize IP — caller's responsibility per R12-canon;
    ///    the engine treats `ip` verbatim).
    /// 2. Check the keyed governor limiter; on miss, record
    ///    [`SignalKind::RateLimited`] (weight 1.0) and return
    ///    [`ReputationDecision::Block`] with
    ///    [`BlockReason::RateLimited`].
    /// 3. Load the projected score.
    /// 4. If `score >= block_threshold`, record
    ///    [`SignalKind::BlockedRequest`] (weight 1.0) and return
    ///    [`ReputationDecision::Block`] with
    ///    [`BlockReason::ReputationExceeded`].
    /// 5. If `score >= backpressure_threshold`, return
    ///    [`ReputationDecision::Backpressure`].
    /// 6. Else, return [`ReputationDecision::Allow`].
    ///
    /// TODO(R10-followup): step 4 should bypass the block branch
    /// for ENS-named identities (plan U12 §"flow"); requires
    /// wiring `Arc<dyn portal_crypto::EnsResolver>` into the
    /// engine. The minimum-engine apex is unconditional.
    #[tracing::instrument(
        level = "warn",
        skip_all,
        fields(
            identity = %hex_identity(&identity),
            ip = %ip,
            lease = %lease,
            score_before = tracing::field::Empty,
            score_after = tracing::field::Empty,
            decision = tracing::field::Empty,
        ),
    )]
    pub fn decide(&self, identity: IdentityKey, ip: IpAddr, lease: &LeaseId) -> ReputationDecision {
        let span = tracing::Span::current();
        let now = Timestamp::now();
        let score_before = self.score_at(identity, now);
        span.record("score_before", score_before);

        // Step 2: keyed governor limiter.
        let triple_key: TripleKey = (identity, ip, lease.clone());
        if self.inner.limiter.check_key(&triple_key).is_err() {
            self.record_signal(identity, SignalKind::RateLimited, 1.0);
            let score_after = self.score_at(identity, Timestamp::now());
            span.record("score_after", score_after);
            let decision = ReputationDecision::Block(BlockReason::RateLimited);
            span.record("decision", decision.label());
            return decision;
        }

        // Step 4: hard-block apex.
        //
        // TODO(R10-followup): consult `Arc<dyn EnsResolver>` here
        // and bypass the block branch when the SIWE-claimed
        // address resolves to an ENS name (plan U12 step 4 carve-
        // out — "score >= block_threshold AND identity is not
        // ENS-named → Block").
        if score_before >= self.inner.config.block_threshold {
            self.record_signal(identity, SignalKind::BlockedRequest, 1.0);
            let score_after = self.score_at(identity, Timestamp::now());
            span.record("score_after", score_after);
            let decision = ReputationDecision::Block(BlockReason::ReputationExceeded);
            span.record("decision", decision.label());
            return decision;
        }

        // Step 5: backpressure band.
        if score_before >= self.inner.config.backpressure_threshold {
            span.record("score_after", score_before);
            let decision = ReputationDecision::Backpressure(self.inner.config.backpressure_yield);
            span.record("decision", decision.label());
            return decision;
        }

        // Step 6: allow.
        span.record("score_after", score_before);
        span.record("decision", ReputationDecision::Allow.label());
        ReputationDecision::Allow
    }

    /// Number of identities currently tracked in the score table.
    /// Exposed for tests + future Phase 7 admin observability.
    #[must_use]
    pub fn tracked_identities(&self) -> usize {
        self.inner.scores.pin().len()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format an [`IdentityKey`] as lowercase hex for tracing fields.
///
/// The workspace does not yet pull a `hex` crate; rolling our own
/// 40-char encoder keeps the dep matrix narrow. The cost is a
/// 64-byte stack buffer per `decide()` call (negligible against
/// the limiter + papaya lookup amortisation).
fn hex_identity(identity: &IdentityKey) -> String {
    let mut out = String::with_capacity(identity.0.len() * 2);
    for &byte in &identity.0 {
        out.push(nibble_to_hex(byte >> 4));
        out.push(nibble_to_hex(byte & 0x0f));
    }
    out
}

const fn nibble_to_hex(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        // Unreachable: callers always mask to 4 bits via `>> 4` /
        // `& 0x0f`. Returning `'?'` keeps the function `const fn`
        // and total without forcing a non-deny `expect_used`.
        _ => '?',
    }
}

// ---------------------------------------------------------------------------
// Tests — unit-level
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::float_cmp,
    reason = "test-only setup: unwraps on known-good fixtures; \
              float comparisons are exact-bit checks against fresh-zero scores"
)]
mod tests {
    use super::*;

    fn fixed_now() -> Timestamp {
        // 2026-05-04T12:00:00Z — deterministic anchor for the
        // decay-math fixture below.
        Timestamp::from_second(1_778_155_200).unwrap()
    }

    #[test]
    fn decay_constant_const_matches_ln2_over_24h() {
        let computed = f64::ln(2.0) / REPUTATION_DECAY_HALF_LIFE_SECS;
        // The const is rounded to 18 significant digits; the
        // tolerance reflects that.
        assert!(
            (computed - REPUTATION_DECAY_CONSTANT).abs() < 1e-15,
            "REPUTATION_DECAY_CONSTANT {REPUTATION_DECAY_CONSTANT} should equal \
             ln(2)/{REPUTATION_DECAY_HALF_LIFE_SECS} = {computed}",
        );
    }

    #[test]
    fn apply_decay_zero_score_returns_zero() {
        let now = fixed_now();
        let later = now
            .saturating_add(jiff::SignedDuration::from_secs(60))
            .unwrap_or(Timestamp::MAX);
        let out = apply_decay(0.0, now, later, REPUTATION_DECAY_CONSTANT);
        assert_eq!(out, 0.0);
    }

    #[test]
    fn apply_decay_zero_elapsed_is_identity() {
        let now = fixed_now();
        let out = apply_decay(42.0, now, now, REPUTATION_DECAY_CONSTANT);
        assert_eq!(out, 42.0);
    }

    #[test]
    fn apply_decay_one_halflife_halves_the_score() {
        let now = fixed_now();
        let half_life_lambda = f64::ln(2.0); // 1-second half-life
        let one_sec_later = now
            .saturating_add(jiff::SignedDuration::from_secs(1))
            .unwrap_or(Timestamp::MAX);
        let out = apply_decay(10.0, now, one_sec_later, half_life_lambda);
        assert!(
            (out - 5.0).abs() < 1e-9,
            "decayed score {out} should be ~5.0 after one half-life",
        );
    }

    #[test]
    fn fresh_engine_score_is_zero() {
        let engine = ReputationEngine::new();
        let id = IdentityKey([0x11u8; 32]);
        assert_eq!(engine.score(id), 0.0);
        assert_eq!(engine.tracked_identities(), 0);
    }

    #[test]
    fn record_signal_then_score_returns_weight() {
        let engine = ReputationEngine::new();
        let id = IdentityKey([0x22u8; 32]);
        engine.record_signal(id, SignalKind::RateLimited, 7.5);
        // Default config has a 24h half-life, so the score
        // observed immediately after `record_signal` is ~7.5
        // (decay over single-digit nanoseconds is unobservable
        // at f64 precision).
        let score = engine.score(id);
        assert!(
            (score - 7.5).abs() < 1e-6,
            "score {score} should be ~7.5 immediately after record_signal",
        );
        assert_eq!(engine.tracked_identities(), 1);
    }

    #[test]
    fn decide_below_threshold_allows() {
        let engine = ReputationEngine::new();
        let id = IdentityKey([0x33u8; 32]);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let lease = LeaseId::from("test-lease");
        let decision = engine.decide(id, ip, &lease);
        assert_eq!(decision, ReputationDecision::Allow);
    }

    #[test]
    fn block_reason_display_matches_label() {
        assert_eq!(
            BlockReason::ReputationExceeded.to_string(),
            "reputation_exceeded",
        );
        assert_eq!(BlockReason::RateLimited.to_string(), "rate_limited");
    }

    #[test]
    fn decision_label_round_trip() {
        assert_eq!(ReputationDecision::Allow.label(), "allow");
        assert_eq!(
            ReputationDecision::Backpressure(Duration::from_millis(10)).label(),
            "backpressure",
        );
        assert_eq!(
            ReputationDecision::Block(BlockReason::RateLimited).label(),
            "block",
        );
    }

    #[test]
    fn hex_identity_renders_full_32_bytes() {
        let id = IdentityKey([0xabu8; 32]);
        let hex = hex_identity(&id);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c == 'a' || c == 'b'));
    }

    #[test]
    fn default_governor_quota_is_constructible() {
        let q = default_governor_quota();
        assert_eq!(q.burst_size().get(), REPUTATION_QUOTA_BURST);
    }
}
