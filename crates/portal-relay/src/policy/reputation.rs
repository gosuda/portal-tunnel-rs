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
//!   that consults `Arc<dyn EnsResolver>` lands in a follow-up
//!   commit alongside the resolver-wiring work.
//! - **Honeypot path matcher.** `Arc<HoneypotMatcher>` (compile-
//!   time path glob set against `/.env`, `/wp-admin/*`, `/.git/*`)
//!   feeds [`SignalKind::HoneypotHit`] from the listener pipeline;
//!   the signal variant exists already so call sites can stub
//!   today.
//! - **Persistence.** Engine-side `reputation.json` round-trip
//!   helpers ([`ReputationEngine::persist_to_path`] +
//!   [`ReputationEngine::restore_from_path`]) consume U5
//!   [`crate::state::persistence::write_json_atomic`] +
//!   [`crate::state::persistence::read_json`] over a
//!   `Vec<ReputationSnapshotEntry>` DTO (see
//!   [`ReputationSnapshotEntry`]) with hex-encoded identities. The
//!   60s-cadence task that drives the helpers from the relay's run
//!   loop is plan U12 step 6's remaining persistence requirement
//!   and lands with Phase 5 B8.
//! - **ADR-0007.** Decay / threshold / weight defaults are set to
//!   reasonable v0.1 values and pinned as `pub const`; the formal
//!   ADR justifying those choices is a separate decision artifact
//!   commit.
//! - **Hot-reload (engine-side).** Landed:
//!   [`ReputationEngine::swap_config`] atomic-swaps the
//!   `(ReputationConfig, RateLimiter)` pair behind
//!   [`arc_swap::ArcSwap`] so concurrent
//!   [`ReputationEngine::decide`] / [`ReputationEngine::record_signal`]
//!   calls observe either the old pair or the new pair, never a mix.
//!   The SIGHUP / admin-api reload **run-loop trigger** that calls
//!   `swap_config` from a config-file change is Phase 5 B8 territory
//!   — engine-side carve-out only here.
//! - **Per-signal tracing.** Only [`ReputationEngine::decide`]
//!   carries `#[tracing::instrument]` this iteration; emitting a
//!   per-signal-kind audit span on every [`ReputationEngine::
//!   record_signal`] lands in a follow-up commit.

use std::collections::HashMap as StdHashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use compact_str::CompactString;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use jiff::{Timestamp, Unit};
use papaya::HashMap as PapayaMap;
use tokio_util::sync::CancellationToken;

pub use crate::state::lease_registry::IdentityKey;

use crate::error::RelayResult;
use crate::policy::honeypot::HoneypotMatcher;
use crate::state::persistence::{read_json, write_json_atomic};

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

/// Default per-signal weight for [`SignalKind::RateLimited`].
///
/// Matches the previously hardcoded `1.0` literal at the engine's
/// internal rate-limit callsite, so behavior is bit-identical under
/// the default [`ReputationConfig`]. Per-kind tuning is an
/// ADR-0007 decision; this constant is the v0.1 placeholder.
pub const REPUTATION_RATE_LIMITED_WEIGHT: f64 = 1.0;

/// Default per-signal weight for [`SignalKind::HoneypotHit`].
///
/// `25.0` per ADR-0007 §"Per-signal weights" — a honeypot path match is
/// high-signal (production tenants do not request `/.env` or
/// `/.git/config`). At the `100.0` block threshold + 24 h half-life
/// decay constant, this means four honeypot hits inside one decay
/// window cross the block threshold, while a single accidental
/// misconfigured-probe hit decays well below threshold within hours.
/// Plan U12 §Approach also names this exact value (25.0).
///
/// The listener-pipeline wiring that drives `record_signal(_,
/// HoneypotHit, _)` from a matched glob is a separate followup
/// (`TODO(R10-followup)` markers below); the weight constant is
/// independent of that wiring.
pub const REPUTATION_HONEYPOT_HIT_WEIGHT: f64 = 25.0;

/// Default per-signal weight for [`SignalKind::BlockedRequest`].
///
/// Matches the previously hardcoded `1.0` literal at the engine's
/// internal blocked-request callsite. Per-kind tuning is an
/// ADR-0007 decision.
pub const REPUTATION_BLOCKED_REQUEST_WEIGHT: f64 = 1.0;

/// Default cadence between [`reputation_persist_loop`] ticks.
///
/// Phase 5 plan U12 §Approach calls for the reputation-engine
/// snapshot to be flushed via [`ReputationEngine::persist_to_path`]
/// on a 60-second cadence so a relay restart loses at most one
/// minute of accumulated score. The value is exposed as a `pub
/// const` so a future operator-tuning surface (admin API or
/// `runtime.json` field) can override it without touching the
/// loop body.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "Phase 5 plan U12 pins the literal `Duration::from_secs(60)` shape; \
              keeping the seconds constructor matches the rest of the relay's \
              cadence consts (e.g. `JANITOR_INTERVAL = Duration::from_secs(5)`)"
)]
pub const REPUTATION_PERSIST_INTERVAL: Duration = Duration::from_secs(60);

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
    /// (`/.env`, `/wp-admin/*`, …). The engine owns the matcher
    /// (see [`ReputationEngine::record_honeypot_if_match`] +
    /// [`ReputationEngine::with_config_and_honeypot_matcher`]) so
    /// listener-pipeline call sites invoke a single one-liner per
    /// request — no extra plumbing needed.
    ///
    /// TODO(R10-followup): wire the per-request invocation from the
    /// SDK + discovery API request handlers so `record_honeypot_if_match`
    /// fires on every inbound request URI before downstream
    /// dispatch (the engine API exists today; the call site does
    /// not yet).
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
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
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

/// Per-engine tuning surface.
///
/// Held behind an `Arc` inside an [`arc_swap::ArcSwap`]-backed
/// `EngineState` so [`ReputationEngine::swap_config`] atomic-swaps
/// the config and its paired keyed limiter as one unit.
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
    /// Per-signal-kind weight policy. Operator-overridable map
    /// consulted by [`ReputationEngine::record_signal_default`] (and
    /// by extension every engine-internal `record_signal` call site
    /// inside [`ReputationEngine::decide`]) so the v0.1 hardcoded
    /// `1.0` weight is now a config-driven knob without changing
    /// observable behavior.
    ///
    /// Lookup falls back to `1.0` for any [`SignalKind`] not present
    /// in the map (see [`ReputationConfig::weight_for`]); the
    /// `Default` impl populates every variant currently defined so
    /// the fallback only runs after a future `#[non_exhaustive]`
    /// addition until that variant is wired into the default map.
    pub signal_weights: StdHashMap<SignalKind, f64>,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        let mut signal_weights = StdHashMap::with_capacity(3);
        signal_weights.insert(SignalKind::RateLimited, REPUTATION_RATE_LIMITED_WEIGHT);
        signal_weights.insert(SignalKind::HoneypotHit, REPUTATION_HONEYPOT_HIT_WEIGHT);
        signal_weights.insert(
            SignalKind::BlockedRequest,
            REPUTATION_BLOCKED_REQUEST_WEIGHT,
        );
        Self {
            decay_constant: REPUTATION_DECAY_CONSTANT,
            block_threshold: REPUTATION_BLOCK_THRESHOLD,
            backpressure_threshold: REPUTATION_BACKPRESSURE_THRESHOLD,
            backpressure_yield: REPUTATION_BACKPRESSURE_YIELD,
            governor_quota: default_governor_quota(),
            signal_weights,
        }
    }
}

impl ReputationConfig {
    /// Look up the configured per-signal weight for `kind`, falling
    /// back to `1.0` when the kind is not present in
    /// [`Self::signal_weights`].
    ///
    /// The fallback exists for two reasons: (a) a future
    /// `#[non_exhaustive]` [`SignalKind`] variant lands before the
    /// `Default` impl is updated to populate it, and (b) operators
    /// may build a `ReputationConfig` by hand without seeding every
    /// kind. `1.0` matches the previously hardcoded engine-internal
    /// weight literal so the fallback path is bit-compatible with
    /// pre-plumbing behavior.
    #[must_use]
    pub fn weight_for(&self, kind: SignalKind) -> f64 {
        self.signal_weights.get(&kind).copied().unwrap_or(1.0)
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

/// Atomic-swap unit for hot-reload: holds the
/// [`ReputationConfig`] plus the keyed [`Limiter`] that the
/// config's `governor_quota` instantiates. Held behind
/// [`arc_swap::ArcSwap`] so a config swap rebuilds the limiter
/// inside the same `store` and never leaves the engine quoting
/// the old quota under the new threshold doc.
struct EngineState {
    config: Arc<ReputationConfig>,
    limiter: Limiter,
}

struct Inner {
    /// Per-identity decay-tracked scores. Lock-free reads/writes
    /// on the hot path.
    scores: PapayaMap<IdentityKey, ReputationScore>,
    /// Atomic-swap pointer to the current `(config, limiter)`
    /// pair. Hot-swap rebuilds both inside one `store()` so the
    /// limiter never quotes the old `governor_quota` under the
    /// new threshold doc.
    state: arc_swap::ArcSwap<EngineState>,
    /// Compiled honeypot path matcher consulted by
    /// [`ReputationEngine::record_honeypot_if_match`]. Held as
    /// `Arc<HoneypotMatcher>` so listener-pipeline call sites can
    /// invoke the engine without cloning the underlying pattern
    /// vectors. v0.1 stores this on `Inner` (not on `EngineState`)
    /// because matcher hot-reload is a U13 deliverable that pairs
    /// `arc-swap<HoneypotMatcher>` with `arc-swap<ReputationConfig>`
    /// inside the same swap unit; landing it here today keeps the
    /// listener-pipeline integration unblockable while leaving the
    /// hot-reload story for U13.
    honeypot_matcher: Arc<HoneypotMatcher>,
    /// Per-identity ENS-named presence cache. Populated by the
    /// (future) `/v1/sdk/register` handler after a successful
    /// `EnsResolver::resolve(siwe_address)` lookup, consulted by
    /// [`ReputationEngine::decide`] step 4 to bypass the
    /// block-at-threshold branch for ENS-named identities (plan
    /// U12 §"flow"). v0.1 stores presence-only (`()` value) — the
    /// bypass decision is boolean, the actual ENS name is not
    /// load-bearing for the engine's policy logic. A future
    /// audit-shape-richness commit may upgrade the value type to
    /// `EnsName` for richer span-field surface.
    ///
    /// Lock-free per-identity insert / remove / get on the hot
    /// path matches the `scores` storage discipline.
    ens_named: PapayaMap<IdentityKey, ()>,
}

impl core::fmt::Debug for ReputationEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let state = self.inner.state.load();
        f.debug_struct("ReputationEngine")
            .field("scored_identities", &self.inner.scores.pin().len())
            .field("config", state.config.as_ref())
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

    /// Build an engine with a caller-supplied [`ReputationConfig`]
    /// and the workspace-default [`HoneypotMatcher`].
    ///
    /// Used by the behavioral gate test to dial the decay constant
    /// to a 1-second half-life so the round-trip completes inside
    /// a few seconds. Operators who need a non-default honeypot
    /// pattern set use [`Self::with_config_and_honeypot_matcher`].
    #[must_use]
    pub fn with_config(config: ReputationConfig) -> Self {
        Self::with_config_and_honeypot_matcher(config, HoneypotMatcher::default())
    }

    /// Build an engine with caller-supplied [`ReputationConfig`]
    /// AND [`HoneypotMatcher`]. Use this when the operator-tuned
    /// honeypot pattern set differs from
    /// [`HoneypotMatcher::with_defaults`] (the workspace default
    /// of `/.env`, `/.git/*`, `/wp-admin/*` per Phase 5 plan U12).
    ///
    /// The matcher hot-reload story (`arc-swap<HoneypotMatcher>`
    /// alongside `arc-swap<ReputationConfig>`) is a U13 deliverable;
    /// this constructor seeds the matcher once at engine-build
    /// time so the listener-pipeline integration is unblockable
    /// today, with the swap surface added later.
    #[must_use]
    pub fn with_config_and_honeypot_matcher(
        config: ReputationConfig,
        honeypot_matcher: HoneypotMatcher,
    ) -> Self {
        let state = Self::build_state(config);
        Self {
            inner: Arc::new(Inner {
                scores: PapayaMap::new(),
                state: arc_swap::ArcSwap::new(Arc::new(state)),
                honeypot_matcher: Arc::new(honeypot_matcher),
                ens_named: PapayaMap::new(),
            }),
        }
    }

    /// Construct an [`EngineState`] from a [`ReputationConfig`]:
    /// build the keyed [`Limiter`] from `config.governor_quota` and
    /// pair it with the config inside one struct so an
    /// [`arc_swap::ArcSwap::store`] can swap both atomically.
    fn build_state(config: ReputationConfig) -> EngineState {
        let limiter = RateLimiter::keyed(config.governor_quota);
        EngineState {
            config: Arc::new(config),
            limiter,
        }
    }

    /// Atomically swap the engine's `(config, limiter)` pair.
    ///
    /// Builds a fresh keyed rate limiter from
    /// `new_config.governor_quota` and stores both inside one
    /// [`arc_swap::ArcSwap::store`] so concurrent
    /// [`Self::decide`] / [`Self::record_signal`] calls observe
    /// either the old pair or the new pair, never a mix
    /// (Hoare invariant: the engine never reports a `config()`
    /// value the limiter is not enforcing).
    ///
    /// This is the engine-side carve-out from Phase 5 B8; the
    /// SIGHUP / admin-api reload run-loop **trigger** that calls
    /// this method on a config-file change lands with B8.
    ///
    /// Note that the keyed limiter's per-key budget table is reset
    /// (each tenant restarts under the new `governor_quota`). This
    /// is the documented v0.1 hot-swap semantic — operators reload
    /// when they want the new policy applied uniformly, not when
    /// they want a partial graft.
    ///
    /// The per-identity score table is **not** reset; reputation
    /// accumulates across reloads.
    pub fn swap_config(&self, new_config: ReputationConfig) {
        let new_state = Self::build_state(new_config);
        self.inner.state.store(Arc::new(new_state));
    }

    /// Borrow the engine's [`ReputationConfig`] as a cheap clone of
    /// the current [`Arc`] inside the [`arc_swap::ArcSwap`] pair.
    ///
    /// Returns an owned `Arc` (rather than a borrowed `&`) because
    /// the underlying pointer can be replaced at any moment by
    /// [`Self::swap_config`]; cloning the `Arc` lets the caller hold
    /// onto the snapshot they observed without keeping the engine's
    /// load-guard alive. Auto-deref through `Arc<ReputationConfig>`
    /// keeps existing `engine.config().some_field` call sites
    /// compiling without change.
    #[must_use]
    pub fn config(&self) -> Arc<ReputationConfig> {
        Arc::clone(&self.inner.state.load().config)
    }

    /// Project the score for `identity` to `now`. Returns 0.0 for
    /// an identity the engine has never seen.
    #[must_use]
    pub fn score_at(&self, identity: IdentityKey, now: Timestamp) -> f64 {
        let decay_constant = self.inner.state.load().config.decay_constant;
        self.inner
            .scores
            .pin()
            .get(&identity)
            .map_or(0.0, |s| s.projected(now, decay_constant))
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
    /// `signal_kind` is captured in the tracing span emitted by this
    /// function (see [`macro@tracing::instrument`] attribute below). The
    /// per-signal-kind WEIGHT policy (different default weights for
    /// honeypot vs rate-limit vs blocked-request) is now plumbed
    /// through [`ReputationConfig::signal_weights`] +
    /// [`ReputationConfig::weight_for`]; callers that want the
    /// configured weight should prefer
    /// [`Self::record_signal_default`] over passing a literal here.
    /// This explicit-weight overload remains as the lower-level API
    /// for callers (e.g., honeypot wiring) that need to amplify or
    /// dampen a single observation independent of policy.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(
            identity = %hex_identity(&identity),
            signal_kind = ?signal_kind,
            weight = weight,
            // Best-effort snapshot — see record-site comment for the
            // racy-observation contract.
            observed_score_after = tracing::field::Empty,
            dropped = tracing::field::Empty,
        ),
    )]
    pub fn record_signal(&self, identity: IdentityKey, signal_kind: SignalKind, weight: f64) {
        let span = tracing::Span::current();
        // NaN/±inf would poison every subsequent threshold check
        // (`NaN >= threshold` is false), so reject at the gate
        // rather than store a sentinel.
        if !weight.is_finite() {
            span.record("dropped", "non_finite_weight");
            return;
        }
        let decay_constant = self.inner.state.load().config.decay_constant;
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
        // Best-effort snapshot — emitted as `observed_score_after`.
        // The re-read can race a concurrent `record_signal` from
        // another thread that lands between our CAS and our re-read,
        // so the value reported here is the score we observe, not
        // strictly the post-state of THIS signal's CAS landing.
        // Exact landing-value capture would require threading the
        // closure's `next_value` out via interior mutability, which
        // papaya 0.2's update closure shape does not accommodate
        // cheaply; the racy-observation contract is acceptable for
        // audit logging because every signal still emits its own
        // span and the temporal ordering is preserved.
        let observed = self.score_at(identity, now);
        span.record("observed_score_after", observed);
    }

    /// Record a signal using the per-kind weight configured in
    /// [`ReputationConfig::signal_weights`].
    ///
    /// Equivalent to `self.record_signal(identity, signal_kind,
    /// w)` where `w` is the per-kind weight pulled from the engine's
    /// current [`ReputationConfig::signal_weights`] entry (read
    /// through the [`arc_swap::ArcSwap`] guard so a concurrent
    /// [`Self::swap_config`] is observed atomically with its paired
    /// limiter rebuild). Engine-internal callsites in
    /// [`Self::decide`] use this so the previously hardcoded `1.0`
    /// weight is now a config-driven knob; under the
    /// [`ReputationConfig::default`] map every variant maps to
    /// `1.0`, so behavior is bit-identical until an operator
    /// overrides a weight or a future variant lands without a
    /// default-map entry (in which case the [`ReputationConfig::
    /// weight_for`] fallback to `1.0` keeps the path well-defined).
    pub fn record_signal_default(&self, identity: IdentityKey, signal_kind: SignalKind) {
        let weight = self.inner.state.load().config.weight_for(signal_kind);
        self.record_signal(identity, signal_kind, weight);
    }

    /// Check `path` against the configured [`HoneypotMatcher`]; if
    /// it matches, record a [`SignalKind::HoneypotHit`] signal at the
    /// configured weight (default `25.0` per ADR-0007) and return
    /// `true`. Returns `false` (no signal recorded) on miss.
    ///
    /// This is the listener-pipeline call site enumerated in
    /// honeypot.rs §"Out-of-scope (TODO follow-up)" — the engine
    /// owns the matcher and the recording so SDK/discovery handlers
    /// invoke it as a one-liner per request:
    ///
    /// ```text
    /// engine.record_honeypot_if_match(identity, request.uri().path());
    /// ```
    ///
    /// Caller responsibilities:
    /// - **Strip query strings before calling.** The matcher is a
    ///   pure path predicate (honeypot.rs §"Match semantics"); it
    ///   does NOT split on `?`. A caller passing a query-bearing
    ///   string will get a match if the prefix portion matches a
    ///   configured glob (the `accept-on-the-side-of-blocking-an-
    ///   attacker` posture is documented and pinned by
    ///   `glob_matches_query_bearing_paths_against_default_set`).
    /// - **Deduplicate within a request.** A request whose path
    ///   matches multiple patterns produces one signal. The
    ///   matcher is short-circuit on the exact-match check, so this
    ///   is structurally guaranteed today; callers should still
    ///   invoke this once per request to avoid scoring an N-segment
    ///   path-rewrite chain N times.
    #[must_use = "the boolean return signals whether a honeypot signal was recorded; \
                  callers that ignore it lose the ability to short-circuit downstream \
                  pipeline stages on a match"]
    pub fn record_honeypot_if_match(&self, identity: IdentityKey, path: &str) -> bool {
        if !self.inner.honeypot_matcher.matches(path) {
            return false;
        }
        self.record_signal_default(identity, SignalKind::HoneypotHit);
        true
    }

    /// Borrow the engine's [`HoneypotMatcher`] for read-only use
    /// (e.g., the admin `/v1/admin/policy/snapshot` endpoint
    /// reporting compiled pattern counts, or a test asserting
    /// the configured pattern set).
    #[must_use]
    pub fn honeypot_matcher(&self) -> Arc<HoneypotMatcher> {
        Arc::clone(&self.inner.honeypot_matcher)
    }

    /// Mark `identity` as ENS-named — populated by the (future)
    /// `/v1/sdk/register` handler after a successful
    /// `EnsResolver::resolve(siwe_address)` lookup. Subsequent
    /// [`Self::decide`] calls bypass the block-at-threshold branch
    /// (plan U12 §"flow" step 4) for marked identities; backpressure
    /// (step 5) and the keyed governor limiter (step 2) still apply.
    ///
    /// Idempotent — re-marking a present identity is a no-op.
    pub fn mark_ens_named(&self, identity: IdentityKey) {
        self.inner.ens_named.pin().insert(identity, ());
    }

    /// Remove `identity` from the ENS-named cache. Called by the
    /// (future) registration / lease-eviction path when an ENS name
    /// expires or a tenant is deregistered. The bypass at
    /// [`Self::decide`] step 4 stops applying immediately on the
    /// next call.
    ///
    /// Idempotent — removing an absent identity is a no-op.
    pub fn unmark_ens_named(&self, identity: IdentityKey) {
        self.inner.ens_named.pin().remove(&identity);
    }

    /// Returns `true` iff `identity` was previously passed to
    /// [`Self::mark_ens_named`] and has not been
    /// [`Self::unmark_ens_named`]-ed since. Read-only — does not
    /// mutate the cache. Used by [`Self::decide`] step 4 and
    /// exposed for the admin policy-snapshot endpoint.
    #[must_use]
    pub fn is_ens_named(&self, identity: IdentityKey) -> bool {
        self.inner.ens_named.pin().contains_key(&identity)
    }

    /// Run the v0.1 R10 decision pipeline against the supplied
    /// `(identity, ip, lease)` triple.
    ///
    /// Steps (per plan U12):
    /// 1. (canonicalize IP — caller's responsibility per R12-canon;
    ///    the engine treats `ip` verbatim).
    /// 2. Check the keyed governor limiter; on miss, record
    ///    [`SignalKind::RateLimited`] via
    ///    [`Self::record_signal_default`] and return
    ///    [`ReputationDecision::Block`] with
    ///    [`BlockReason::RateLimited`].
    /// 3. Load the projected score.
    /// 4. If `score >= block_threshold`, record
    ///    [`SignalKind::BlockedRequest`] via
    ///    [`Self::record_signal_default`] and return
    ///    [`ReputationDecision::Block`] with
    ///    [`BlockReason::ReputationExceeded`].
    /// 5. If `score >= backpressure_threshold`, return
    ///    [`ReputationDecision::Backpressure`].
    /// 6. Else, return [`ReputationDecision::Allow`].
    ///
    /// Step 4 honors the ENS-Sybil-gating bypass — identities
    /// previously passed to [`Self::mark_ens_named`] (populated by
    /// the future `/v1/sdk/register` handler after an
    /// `EnsResolver::resolve(siwe_address)` lookup) skip the
    /// block branch and fall through to step 5's backpressure
    /// check. The bypass surfaces in the audit span as
    /// `sybil_bypass = true`.
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
            sybil_bypass = tracing::field::Empty,
        ),
    )]
    pub fn decide(&self, identity: IdentityKey, ip: IpAddr, lease: &LeaseId) -> ReputationDecision {
        let span = tracing::Span::current();
        // The limiter + threshold reads in this method body share
        // one load; nested calls (`score_at`, `record_signal_default`)
        // re-load the ArcSwap independently. Atomicity is per-load,
        // not per-`decide` — a concurrent `swap_config` either lands
        // fully before or fully after each load, never mid-load.
        let state = self.inner.state.load();
        let now = Timestamp::now();
        let score_before = self.score_at(identity, now);
        span.record("score_before", score_before);

        // Step 2: keyed governor limiter.
        let triple_key: TripleKey = (identity, ip, lease.clone());
        if state.limiter.check_key(&triple_key).is_err() {
            self.record_signal_default(identity, SignalKind::RateLimited);
            let score_after = self.score_at(identity, Timestamp::now());
            span.record("score_after", score_after);
            let decision = ReputationDecision::Block(BlockReason::RateLimited);
            span.record("decision", decision.label());
            return decision;
        }

        // Step 4: hard-block apex with ENS-Sybil-gating bypass.
        //
        // Plan U12 step 4: "score >= block_threshold AND identity
        // is not ENS-named → Block". The presence cache is
        // populated by the (future) `/v1/sdk/register` handler
        // after `EnsResolver::resolve(siwe_address)` returns
        // `Some(name)`; consulted here as a `bool`. ENS-named
        // identities still get backpressure (step 5) and rate-limit
        // (step 2) — only the hard-block branch is bypassed.
        if score_before >= state.config.block_threshold {
            if self.is_ens_named(identity) {
                // Sybil-gating bypass — record the audit field and
                // fall through to step 5's backpressure check.
                span.record("sybil_bypass", true);
            } else {
                self.record_signal_default(identity, SignalKind::BlockedRequest);
                let score_after = self.score_at(identity, Timestamp::now());
                span.record("score_after", score_after);
                let decision = ReputationDecision::Block(BlockReason::ReputationExceeded);
                span.record("decision", decision.label());
                return decision;
            }
        }

        // Step 5: backpressure band.
        if score_before >= state.config.backpressure_threshold {
            span.record("score_after", score_before);
            let decision = ReputationDecision::Backpressure(state.config.backpressure_yield);
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

    /// Capture the current score table as an owned in-memory
    /// snapshot.
    ///
    /// The snapshot is a point-in-time read; concurrent
    /// `record_signal` calls may land between iterator steps, so the
    /// returned map is "what was observed during this iteration",
    /// not a strict atomic snapshot of the engine.  For audit /
    /// persistence layering this is acceptable — the engine's job is
    /// to expose a best-effort observable; the state/operator layer
    /// is the right place to compose this with
    /// `state::persistence::write_json_atomic` and decide cadence,
    /// file mode, and recovery semantics.
    #[must_use]
    pub fn snapshot(&self) -> std::collections::HashMap<IdentityKey, ReputationScore> {
        let pinned = self.inner.scores.pin();
        pinned.iter().map(|(k, v)| (*k, *v)).collect()
    }

    /// Restore (merge) an externally-supplied score map into the
    /// engine.  Existing entries with the same `IdentityKey` are
    /// overwritten; entries not present in the input are left
    /// untouched so a post-restore signal sees the union of disk +
    /// new state.
    ///
    /// Non-finite (`NaN` / `±inf`) values in the input are silently
    /// dropped — the same invariant `record_signal` enforces, applied
    /// to recovery to avoid contaminating the in-memory state with a
    /// poisoned on-disk row.
    pub fn restore_from_snapshot(
        &self,
        snap: std::collections::HashMap<IdentityKey, ReputationScore>,
    ) {
        let pinned = self.inner.scores.pin();
        for (id, score) in snap {
            if score.value.is_finite() {
                pinned.insert(id, score);
            }
        }
    }

    /// Persist the engine's current score snapshot to `path` via the
    /// workspace's atomic-write helper
    /// ([`crate::state::persistence::write_json_atomic`]).
    ///
    /// The on-disk shape is `Vec<ReputationSnapshotEntry>` (see
    /// [`ReputationSnapshotEntry`]) — an explicit DTO list rather
    /// than a `HashMap<IdentityKey, _>`,
    /// because `serde_json` rejects non-string map keys and
    /// `IdentityKey` serializes as a `[u8; 32]` array. Each entry
    /// carries the identity as a 64-char lowercase hex string + the
    /// `ReputationScore` pair. The helper owns the temp-file +
    /// rename + parent-fsync contract; this method exists so the
    /// eventual 60s-cadence persistence loop in Phase 5 B8 can call
    /// a single async function rather than re-deriving the
    /// snapshot/encode/serialize/write quadruple at the call site.
    ///
    /// Iteration order over the snapshot map is unspecified; tests
    /// that compare on-disk bytes verbatim must therefore restore
    /// through [`Self::restore_from_path`] and compare via
    /// [`Self::snapshot`] rather than via raw file content.
    ///
    /// # Errors
    ///
    /// Surfaces any [`crate::error::RelayError`] from the underlying
    /// atomic-write helper:
    /// - [`crate::error::RelayError::Io`] for FS failures (parent
    ///   create, temp-write, rename, parent-fsync).
    /// - [`crate::error::RelayError::Config`] if `serde_json`
    ///   refuses the snapshot (in practice unreachable because the
    ///   DTO is plain data).
    pub async fn persist_to_path(&self, path: &Path) -> RelayResult<()> {
        let snap = self.snapshot();
        let entries: Vec<ReputationSnapshotEntry> = snap
            .into_iter()
            .map(|(identity, score)| ReputationSnapshotEntry {
                identity_hex: hex_identity(&identity),
                score,
            })
            .collect();
        write_json_atomic(path, &entries).await
    }

    /// Restore an engine snapshot from `path` via the workspace's
    /// JSON reader ([`crate::state::persistence::read_json`]),
    /// converting each on-disk hex identity back to an
    /// [`IdentityKey`] and merging the result into the in-memory
    /// score table via [`Self::restore_from_snapshot`].
    ///
    /// The merge semantics match `restore_from_snapshot`: entries
    /// not present in the file are left untouched, and non-finite
    /// values in the file are silently dropped (the same invariant
    /// `record_signal` enforces). A malformed `identity_hex` field
    /// (wrong length or non-hex byte) fails the call as a whole —
    /// partial restore would silently lose rows and is rejected.
    ///
    /// # Errors
    ///
    /// Surfaces any [`crate::error::RelayError`] from the underlying
    /// reader, plus a [`crate::error::RelayError::Config`] for any
    /// row whose `identity_hex` is not a 64-char lowercase hex
    /// string:
    /// - [`crate::error::RelayError::Io`] when the file is missing
    ///   or unreadable.
    /// - [`crate::error::RelayError::Config`] on JSON deserialization
    ///   failure (corrupt file, schema drift) or invalid hex
    ///   identity.
    pub async fn restore_from_path(&self, path: &Path) -> RelayResult<()> {
        let entries: Vec<ReputationSnapshotEntry> = read_json(path).await?;
        let mut snap: std::collections::HashMap<IdentityKey, ReputationScore> =
            std::collections::HashMap::with_capacity(entries.len());
        for entry in entries {
            let id = parse_hex_identity(&entry.identity_hex).map_err(|reason| {
                crate::error::RelayError::Config(format!(
                    "invalid identity_hex {:?} in {}: {reason}",
                    entry.identity_hex,
                    path.display(),
                ))
            })?;
            // Duplicate identity rows would have the second
            // silently overwrite the first, defeating the
            // one-score-per-identity invariant the in-memory
            // snapshot guarantees by construction. Reject the file
            // up-front so the operator sees the corruption.
            if snap.contains_key(&id) {
                return Err(crate::error::RelayError::Config(format!(
                    "duplicate identity_hex {:?} in {}",
                    entry.identity_hex,
                    path.display(),
                )));
            }
            snap.insert(id, entry.score);
        }
        self.restore_from_snapshot(snap);
        Ok(())
    }
}

/// Drive [`ReputationEngine::persist_to_path`] on a fixed cadence
/// until `cancel` fires.
///
/// Phase 5 plan U12 §Approach: "load score, decay + add weight,
/// persist via U5 atomic-write helper on a 60s cadence." This is
/// the cadence half — the load/decay/add halves live on the
/// engine itself. The default cadence is
/// [`REPUTATION_PERSIST_INTERVAL`]; tests pass a shorter value so
/// they complete in well under a second.
///
/// ## Cadence semantics
///
/// Uses [`tokio::time::interval`] with
/// [`tokio::time::MissedTickBehavior::Skip`] so a paused or
/// scheduling-starved process does not burst-fire a backlog of
/// writes when it resumes. The loop body is wrapped in a
/// `tokio::select!` that races the cancellation token against the
/// next tick: when cancellation fires, the loop exits at the
/// `select` arm boundary without a final partial write.
///
/// ## Error handling
///
/// A failed persist (transient I/O, JSON serialize failure, parent
/// directory unwritable, …) is logged via `tracing::error!` and
/// the loop continues. The cadence task is best-effort durability;
/// it deliberately does not propagate errors back to the server
/// orchestrator because a transient FS hiccup must not kill the
/// reputation snapshot loop for the lifetime of the relay.
///
/// ## Cancellation safety
///
/// The first tick is consumed synchronously (per
/// [`tokio::time::interval`]'s default behaviour) so the spawning
/// task does not write immediately on spawn. From then on the
/// task races `cancel.cancelled()` against `ticker.tick()` in a
/// biased `select!` so cancellation always wins ties — dropping
/// the task or cancelling the token interrupts the wait, never an
/// in-flight write.
pub async fn reputation_persist_loop(
    engine: ReputationEngine,
    path: PathBuf,
    interval: Duration,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the immediate first tick so spawning the task doesn't
    // synchronously fire a persist before any signal has been
    // recorded. Mirrors the [`crate::server::janitor_loop`] discipline.
    let _ = ticker.tick().await;
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                tracing::debug!("reputation persist loop cancelled");
                break;
            }
            _ = ticker.tick() => {
                if let Err(err) = engine.persist_to_path(&path).await {
                    // identity_count is the operator's primary signal of
                    // how much state is at risk when persistence is
                    // failing — without it, a quiet long-running outage
                    // of the cadence loop is invisible from logs alone.
                    // The snapshot allocation cost is acceptable on this
                    // (already-rare) error path.
                    tracing::error!(
                        error = %err,
                        path = %path.display(),
                        identity_count = engine.snapshot().len(),
                        "reputation snapshot persist failed; \
                         continuing cadence loop",
                    );
                }
            }
        }
    }
}

/// Persisted-on-disk row for the reputation snapshot.
///
/// Used by [`ReputationEngine::persist_to_path`] +
/// [`ReputationEngine::restore_from_path`]. The list-of-entries
/// shape exists so the on-disk JSON has string keys (the identity
/// in lowercase hex), which is what `serde_json` requires from map
/// keys; the in-memory engine continues to use
/// `HashMap<IdentityKey, ReputationScore>` and the conversion lives
/// at the disk boundary.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ReputationSnapshotEntry {
    /// 64-char lowercase hex encoding of the 32-byte
    /// [`IdentityKey`] — matches `hex_identity`'s output.
    pub identity_hex: String,
    /// The decay-tracked score paired with its `last_updated`
    /// timestamp.
    pub score: ReputationScore,
}

impl core::fmt::Debug for ReputationSnapshotEntry {
    /// R-S5-2: per-row reputation data must not surface verbatim in
    /// `Debug` output (logs, panic dumps, error messages). Expose a
    /// short prefix of `identity_hex` so a leaked log row can be
    /// located in diagnostics, but redact the score and the
    /// `last_updated` timestamp so an attacker reading a
    /// Debug-formatted snapshot row cannot reconstruct the score
    /// table or its threshold-distance distribution, and cannot
    /// infer the time-of-last-violation side channel from the
    /// timestamp.
    ///
    /// Note: `Serialize` is unaffected — the JSON persistence shape
    /// still carries the full row contents because the file is
    /// gated by U5's 0600 mode + atomic-write helper, not by Debug.
    /// Only the `Debug` text surface is redacted.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let prefix = self
            .identity_hex
            .get(..8)
            .unwrap_or(self.identity_hex.as_str());
        f.debug_struct("ReputationSnapshotEntry")
            .field("identity_hex_prefix", &format_args!("{prefix}…"))
            .field("score", &format_args!("<redacted per R-S5-2>"))
            .finish()
    }
}

/// Parse a 64-char lowercase hex string back into an
/// [`IdentityKey`].
///
/// Accepts only the exact shape produced by `hex_identity` —
/// length 64, lowercase, [0-9a-f] — so a malformed file fails
/// fast at the disk boundary rather than poisoning the in-memory
/// score table with a default-zero or all-zero identity.
fn parse_hex_identity(hex: &str) -> Result<IdentityKey, &'static str> {
    if hex.len() != 64 {
        return Err("expected 64 hex characters");
    }
    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(IdentityKey(out))
}

const fn hex_nibble(b: u8) -> Result<u8, &'static str> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err("non-lowercase-hex character"),
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

    /// R-S5-2: a Debug-formatted [`ReputationSnapshotEntry`] must
    /// not leak the score value, the `last_updated` timestamp, nor
    /// the full identity hex. Pins the redaction contract so a
    /// future `#[derive(Debug)]` resurrection (e.g., during a
    /// refactor) fails the test immediately rather than silently
    /// exposing per-tenant reputation in logs.
    ///
    /// Uses the existing [`fixed_now`] fixture (2026-05-04T12:00:00Z)
    /// so the timestamp-absence assertion names a deterministic
    /// string rather than asserting the absence of "every
    /// conceivable timestamp shape".
    #[test]
    fn snapshot_entry_debug_redacts_per_r_s5_2() {
        let ts = fixed_now();
        let entry = ReputationSnapshotEntry {
            identity_hex: "abcdef0123456789".repeat(4),
            score: ReputationScore {
                value: 99.7,
                last_updated: ts,
            },
        };
        let ts_debug = format!("{ts:?}");
        let formatted = format!("{entry:?}");

        assert!(
            !formatted.contains("99.7"),
            "score value leaked in Debug: {formatted}"
        );
        assert!(
            !formatted.contains(&ts_debug),
            "timestamp Debug leaked in Debug: ts={ts_debug} entry={formatted}"
        );
        assert!(
            formatted.contains("abcdef01"),
            "identity prefix missing from Debug: {formatted}"
        );
        assert!(
            !formatted.contains(&"abcdef0123456789".repeat(4)),
            "full identity_hex leaked in Debug: {formatted}"
        );
        assert!(
            formatted.contains("<redacted per R-S5-2>"),
            "redaction sentinel missing from Debug: {formatted}"
        );
    }

    #[test]
    fn snapshot_then_restore_round_trips_score_table() {
        let engine = ReputationEngine::new();
        let id_a = IdentityKey([1u8; 32]);
        let id_b = IdentityKey([2u8; 32]);

        engine.record_signal(id_a, SignalKind::HoneypotHit, 25.0);
        engine.record_signal(id_b, SignalKind::RateLimited, 5.0);

        let snap = engine.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap.contains_key(&id_a));
        assert!(snap.contains_key(&id_b));

        // Restore into a fresh engine and confirm the values land.
        let restored = ReputationEngine::new();
        assert_eq!(restored.tracked_identities(), 0);
        restored.restore_from_snapshot(snap);
        assert_eq!(restored.tracked_identities(), 2);
        let snap2 = restored.snapshot();
        assert!((snap2[&id_a].value - 25.0).abs() < 1e-9);
        assert!((snap2[&id_b].value - 5.0).abs() < 1e-9);
    }

    #[test]
    fn restore_drops_non_finite_poisoned_rows() {
        let engine = ReputationEngine::new();
        let good = IdentityKey([3u8; 32]);
        let bad_nan = IdentityKey([4u8; 32]);
        let bad_inf = IdentityKey([5u8; 32]);

        let mut snap = std::collections::HashMap::new();
        snap.insert(
            good,
            ReputationScore {
                value: 42.0,
                last_updated: Timestamp::now(),
            },
        );
        snap.insert(
            bad_nan,
            ReputationScore {
                value: f64::NAN,
                last_updated: Timestamp::now(),
            },
        );
        snap.insert(
            bad_inf,
            ReputationScore {
                value: f64::INFINITY,
                last_updated: Timestamp::now(),
            },
        );

        engine.restore_from_snapshot(snap);
        let result = engine.snapshot();
        assert_eq!(result.len(), 1, "only the finite row must survive");
        assert!(result.contains_key(&good));
        assert!(!result.contains_key(&bad_nan));
        assert!(!result.contains_key(&bad_inf));
    }

    #[test]
    fn restore_merges_rather_than_replaces() {
        // Pre-existing in-memory state is preserved when the snapshot
        // does not name the identity.
        let engine = ReputationEngine::new();
        let pre_existing = IdentityKey([6u8; 32]);
        let from_disk = IdentityKey([7u8; 32]);

        engine.record_signal(pre_existing, SignalKind::HoneypotHit, 10.0);

        let mut snap = std::collections::HashMap::new();
        snap.insert(
            from_disk,
            ReputationScore {
                value: 20.0,
                last_updated: Timestamp::now(),
            },
        );
        engine.restore_from_snapshot(snap);

        let result = engine.snapshot();
        assert_eq!(result.len(), 2);
        assert!(result.contains_key(&pre_existing));
        assert!(result.contains_key(&from_disk));
    }

    /// Default `ReputationConfig::signal_weights` populates every
    /// currently-defined `SignalKind` variant at the corresponding
    /// `REPUTATION_*_WEIGHT` constant. Pinning each variant
    /// individually (rather than iterating) keeps the test
    /// `#[non_exhaustive]`-friendly: a future variant lands without
    /// breaking this assertion, and the deferred-default lookup
    /// path is covered separately by
    /// `weight_for_falls_back_to_one_when_kind_absent`.
    #[test]
    fn default_signal_weights_populate_known_variants() {
        let cfg = ReputationConfig::default();
        assert_eq!(
            cfg.weight_for(SignalKind::RateLimited),
            REPUTATION_RATE_LIMITED_WEIGHT,
        );
        assert_eq!(
            cfg.weight_for(SignalKind::HoneypotHit),
            REPUTATION_HONEYPOT_HIT_WEIGHT,
        );
        assert_eq!(
            cfg.weight_for(SignalKind::BlockedRequest),
            REPUTATION_BLOCKED_REQUEST_WEIGHT,
        );
    }

    /// `weight_for` returns `1.0` when the requested `SignalKind` is
    /// absent from the map. Pins the documented fallback contract
    /// so a future `#[non_exhaustive]` variant added before the
    /// `Default` map is updated does not silently produce a
    /// zero-weight signal.
    #[test]
    fn weight_for_falls_back_to_one_when_kind_absent() {
        let mut cfg = ReputationConfig::default();
        cfg.signal_weights.clear();
        assert_eq!(cfg.weight_for(SignalKind::RateLimited), 1.0);
        assert_eq!(cfg.weight_for(SignalKind::HoneypotHit), 1.0);
        assert_eq!(cfg.weight_for(SignalKind::BlockedRequest), 1.0);
    }

    /// `record_signal_default` consults `weight_for` and produces
    /// the same effect as `record_signal(_, kind, configured_weight)`.
    /// Overrides one variant's weight to `5.0` and confirms the
    /// post-record score reflects the configured value, not the
    /// default `1.0`.
    #[test]
    fn record_signal_default_uses_configured_weight() {
        let mut cfg = ReputationConfig::default();
        cfg.signal_weights.insert(SignalKind::RateLimited, 5.0);
        let engine = ReputationEngine::with_config(cfg);
        let id = IdentityKey([0xddu8; 32]);
        engine.record_signal_default(id, SignalKind::RateLimited);
        let score = engine.score(id);
        assert!(
            (score - 5.0).abs() < 1e-6,
            "score {score} should be ~5.0 after record_signal_default \
             with configured weight 5.0",
        );
    }

    /// `record_honeypot_if_match` records a [`SignalKind::HoneypotHit`]
    /// signal at the configured weight when the path matches the
    /// engine's [`HoneypotMatcher`], and returns `true`. On miss it
    /// records nothing and returns `false`.
    ///
    /// Pins the listener-pipeline contract: a single honeypot hit
    /// produces a single signal at the ADR-0007 default weight
    /// (`25.0`), and the score after one hit equals the weight.
    #[test]
    fn record_honeypot_if_match_records_hit_at_configured_weight() {
        let engine = ReputationEngine::new();
        let id = IdentityKey([0xa1u8; 32]);

        // /.env is in the workspace-default pattern set; matches.
        let matched = engine.record_honeypot_if_match(id, "/.env");
        assert!(matched, "/.env must match the workspace-default set");

        let score = engine.score(id);
        assert!(
            (score - REPUTATION_HONEYPOT_HIT_WEIGHT).abs() < 1e-6,
            "after one hit, score {score} should equal the configured \
             HoneypotHit weight ({REPUTATION_HONEYPOT_HIT_WEIGHT})",
        );
    }

    /// `record_honeypot_if_match` returns `false` and records no
    /// signal when the path does not match any configured honeypot
    /// pattern.
    #[test]
    fn record_honeypot_if_match_skips_non_matching_path() {
        let engine = ReputationEngine::new();
        let id = IdentityKey([0xb2u8; 32]);

        let matched = engine.record_honeypot_if_match(id, "/v1/sdk/register");
        assert!(
            !matched,
            "/v1/sdk/register must not match the workspace-default set",
        );

        let score = engine.score(id);
        assert!(
            score == 0.0,
            "score {score} should be 0.0 (no signal recorded on miss)",
        );
    }

    /// `with_config_and_honeypot_matcher` honors a caller-supplied
    /// matcher: a path NOT in the workspace defaults but in the
    /// caller's set must match, and a workspace-default path NOT in
    /// the caller's set must NOT match. Pins that the explicit
    /// constructor replaces (rather than augments) the default
    /// pattern set.
    #[test]
    fn with_config_and_honeypot_matcher_honors_caller_supplied_set() {
        let cfg = ReputationConfig::default();
        let matcher = HoneypotMatcher::from_patterns(["/admin-only-path"]);
        let engine = ReputationEngine::with_config_and_honeypot_matcher(cfg, matcher);
        let id = IdentityKey([0xc3u8; 32]);

        // Caller-supplied pattern matches.
        assert!(engine.record_honeypot_if_match(id, "/admin-only-path"));
        // Workspace-default pattern does NOT match (replaced, not merged).
        let id2 = IdentityKey([0xc4u8; 32]);
        assert!(!engine.record_honeypot_if_match(id2, "/.env"));
    }

    /// `honeypot_matcher()` returns an [`Arc`] handle to the engine's
    /// configured matcher; pattern counts must reflect the workspace
    /// defaults (3 patterns: 1 exact `/.env`, 2 prefix `/.git/*`,
    /// `/wp-admin/*`). Pins the read-only accessor surface used by
    /// the admin policy-snapshot endpoint.
    #[test]
    fn honeypot_matcher_accessor_returns_workspace_defaults() {
        let engine = ReputationEngine::new();
        let matcher = engine.honeypot_matcher();
        assert_eq!(matcher.exact_pattern_count(), 1, "/.env");
        assert_eq!(matcher.prefix_pattern_count(), 2, "/.git/* + /wp-admin/*");
    }

    /// `mark_ens_named` + `is_ens_named` round-trip; `unmark_ens_named`
    /// clears the bit. Both mark and unmark are idempotent.
    #[test]
    fn ens_named_cache_round_trips() {
        let engine = ReputationEngine::new();
        let id = IdentityKey([0xe1u8; 32]);

        assert!(!engine.is_ens_named(id), "fresh engine: not marked");
        engine.mark_ens_named(id);
        assert!(engine.is_ens_named(id), "after mark: present");

        // Re-mark is idempotent.
        engine.mark_ens_named(id);
        assert!(engine.is_ens_named(id), "after re-mark: still present");

        engine.unmark_ens_named(id);
        assert!(!engine.is_ens_named(id), "after unmark: absent");

        // Re-unmark is idempotent.
        engine.unmark_ens_named(id);
        assert!(!engine.is_ens_named(id), "after re-unmark: still absent");
    }

    /// Plan U12 step 4 bypass: at-or-above `block_threshold` an
    /// ENS-named identity falls through to step 5 (Backpressure)
    /// instead of returning `Block(ReputationExceeded)`. Pins the
    /// Sybil-gating bypass — the load-bearing carve-out R10 v0.1
    /// relies on for false-positive recovery.
    #[test]
    fn decide_above_threshold_bypasses_block_for_ens_named_identity() {
        let engine = ReputationEngine::new();
        let id = IdentityKey([0xe2u8; 32]);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let lease: LeaseId = CompactString::new("lease-x");

        // Force the score above block_threshold by recording a
        // signal heavy enough to exceed the default 100.0 ceiling.
        engine.record_signal(id, SignalKind::HoneypotHit, 150.0);
        let score = engine.score(id);
        assert!(score >= REPUTATION_BLOCK_THRESHOLD);

        // Without ENS-marker: block.
        let decision = engine.decide(id, ip, &lease);
        assert!(
            matches!(
                decision,
                ReputationDecision::Block(BlockReason::ReputationExceeded),
            ),
            "non-ENS identity at score >= block_threshold must Block, got {decision:?}",
        );

        // With ENS-marker: bypass to Backpressure.
        engine.mark_ens_named(id);
        let decision = engine.decide(id, ip, &lease);
        assert!(
            matches!(decision, ReputationDecision::Backpressure(_)),
            "ENS-named identity at score >= block_threshold must \
             Backpressure (step 4 bypass + step 5 fall-through), got {decision:?}",
        );

        // After unmark: back to Block.
        engine.unmark_ens_named(id);
        let decision = engine.decide(id, ip, &lease);
        assert!(
            matches!(
                decision,
                ReputationDecision::Block(BlockReason::ReputationExceeded),
            ),
            "after unmark, identity at score >= block_threshold must \
             Block again, got {decision:?}",
        );
    }

    /// The bypass does NOT apply to step 2 (governor key-triple
    /// rate limit). An ENS-named identity that exhausts the keyed
    /// limiter is still rate-limited — Sybil gating only carves
    /// out the reputation-block branch (step 4).
    #[test]
    fn ens_named_identity_still_rate_limited_by_governor() {
        let engine = ReputationEngine::new();
        let id = IdentityKey([0xe3u8; 32]);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let lease: LeaseId = CompactString::new("lease-y");

        engine.mark_ens_named(id);

        // Drain the keyed limiter for this triple by issuing a burst
        // larger than the default Quota's burst capacity. The first
        // few calls return Allow; subsequent calls return
        // Block(RateLimited) regardless of ENS-named state.
        let mut hit_rate_limit = false;
        for _ in 0..1000 {
            if matches!(
                engine.decide(id, ip, &lease),
                ReputationDecision::Block(BlockReason::RateLimited),
            ) {
                hit_rate_limit = true;
                break;
            }
        }
        assert!(
            hit_rate_limit,
            "ENS-named identity must still trip the keyed governor \
             after a burst — Sybil bypass is only for the reputation \
             block branch (step 4), not the rate limiter (step 2)",
        );
    }

    /// `reputation_persist_loop` flushes the engine's score
    /// snapshot to disk on the configured cadence and exits
    /// cleanly on cancellation.
    ///
    /// Test shape (Phase 5 plan U12 §Approach acceptance criterion 4):
    ///
    /// 1. Spawn the loop with a SHORT 100ms interval so the test
    ///    completes well under the 2s budget.
    /// 2. Record a signal on the engine.
    /// 3. Wait long enough for one tick to elapse.
    /// 4. Assert `reputation.json` exists on disk and the row we
    ///    persisted round-trips through
    ///    [`ReputationEngine::restore_from_path`] to a fresh
    ///    engine.
    /// 5. Cancel the loop's token and `await` its `JoinHandle`,
    ///    confirming the task exits cleanly (no panic, no abort,
    ///    no orphan).
    #[tokio::test]
    async fn reputation_persist_loop_flushes_on_cadence_and_exits_on_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reputation.json");

        let engine = ReputationEngine::new();
        let id = IdentityKey([0xc3u8; 32]);
        engine.record_signal(id, SignalKind::RateLimited, 4.5);

        let cancel = CancellationToken::new();
        let loop_engine = engine.clone();
        let loop_path = path.clone();
        let loop_cancel = cancel.clone();
        // R9: structured spawn — we hold the JoinHandle below,
        // cancel the token, and `.await` the handle before the
        // test returns. Test code is allow-listed for the lint by
        // the workspace clippy.toml escape clause.
        #[expect(
            clippy::disallowed_methods,
            reason = "test code per R9: stored JoinHandle + CancellationToken \
                      awaited at the end of the test"
        )]
        let handle = tokio::spawn(async move {
            reputation_persist_loop(
                loop_engine,
                loop_path,
                Duration::from_millis(100),
                loop_cancel,
            )
            .await;
        });

        // Wait for at least one tick to fire. We poll the file's
        // existence rather than `sleep` for a fixed budget so a
        // slow scheduler does not flake the test, while a fast
        // scheduler still completes quickly.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if tokio::fs::metadata(&path).await.is_ok() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "reputation.json was not written within 2s — \
                 cadence loop is not flushing on the configured interval",
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // The on-disk row must round-trip back to the score we
        // recorded (+/- a tiny decay over the few-ms tick window).
        let reader = ReputationEngine::new();
        reader.restore_from_path(&path).await.unwrap();
        let restored = reader.snapshot();
        assert_eq!(restored.len(), 1, "expected exactly one persisted row");
        let restored_score = restored.get(&id).unwrap().value;
        assert!(
            (restored_score - 4.5).abs() < 1e-3,
            "round-tripped score {restored_score} should be ~4.5 \
             (tiny decay over the sub-second tick window is acceptable)",
        );

        // Cancel and confirm clean exit. A task that has not
        // exited within 1s of cancellation is considered stuck.
        cancel.cancel();
        let join_result = tokio::time::timeout(Duration::from_secs(1), handle).await;
        match join_result {
            Ok(Ok(())) => {}
            Ok(Err(join_err)) => {
                panic!("reputation_persist_loop panicked / was aborted: {join_err}")
            }
            Err(elapsed) => {
                panic!("reputation_persist_loop did not exit within 1s of cancellation: {elapsed}")
            }
        }
    }

    /// `persist_to_path` then `restore_from_path` round-trips the
    /// score table through the workspace's atomic-write helper +
    /// JSON reader. The DTO list shape (`Vec<ReputationSnapshotEntry>`)
    /// is the on-disk surface; verifying via post-restore
    /// `snapshot()` keeps the test independent of map iteration
    /// order.
    #[tokio::test]
    async fn persist_and_restore_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reputation.json");

        let writer = ReputationEngine::new();
        let id_a = IdentityKey([0xa1u8; 32]);
        let id_b = IdentityKey([0xb2u8; 32]);
        writer.record_signal(id_a, SignalKind::RateLimited, 7.0);
        writer.record_signal(id_b, SignalKind::HoneypotHit, 3.0);
        writer.persist_to_path(&path).await.unwrap();

        let reader = ReputationEngine::new();
        reader.restore_from_path(&path).await.unwrap();
        let restored = reader.snapshot();
        assert_eq!(restored.len(), 2);
        assert!(
            (restored.get(&id_a).unwrap().value - 7.0).abs() < 1e-6,
            "id_a score should round-trip to ~7.0",
        );
        assert!(
            (restored.get(&id_b).unwrap().value - 3.0).abs() < 1e-6,
            "id_b score should round-trip to ~3.0",
        );
    }

    /// `restore_from_path` rejects a file with an invalid hex
    /// identity (wrong length / non-lowercase-hex byte) as
    /// [`crate::error::RelayError::Config`] rather than silently
    /// inserting a zero-bytes identity.
    #[tokio::test]
    async fn restore_rejects_invalid_identity_hex() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reputation.json");
        // Hand-crafted file with one valid row plus one invalid
        // (uppercase 'F' fails the lowercase-hex parser).
        let bad = serde_json::json!([
            { "identity_hex": "00".repeat(32), "score": { "value": 1.0, "last_updated": "2026-05-04T00:00:00Z" } },
            { "identity_hex": "F".repeat(64),  "score": { "value": 1.0, "last_updated": "2026-05-04T00:00:00Z" } }
        ]);
        tokio::fs::write(&path, bad.to_string()).await.unwrap();

        let engine = ReputationEngine::new();
        let result = engine.restore_from_path(&path).await;
        assert!(
            matches!(result, Err(crate::error::RelayError::Config(_))),
            "expected Config error for invalid hex; got {result:?}",
        );
        // Engine state is unchanged on failure.
        assert_eq!(engine.tracked_identities(), 0);
    }

    /// `restore_from_path` rejects a file with duplicate
    /// `identity_hex` rows so the in-memory invariant
    /// (one-score-per-identity, no later-overwrite ambiguity) is
    /// preserved at the disk boundary.
    #[tokio::test]
    async fn restore_rejects_duplicate_identity_hex() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reputation.json");
        let dupe = serde_json::json!([
            { "identity_hex": "11".repeat(32), "score": { "value": 1.0, "last_updated": "2026-05-04T00:00:00Z" } },
            { "identity_hex": "11".repeat(32), "score": { "value": 9.0, "last_updated": "2026-05-04T00:00:00Z" } }
        ]);
        tokio::fs::write(&path, dupe.to_string()).await.unwrap();

        let engine = ReputationEngine::new();
        let result = engine.restore_from_path(&path).await;
        assert!(
            matches!(result, Err(crate::error::RelayError::Config(_))),
            "expected Config error for duplicate identity_hex; got {result:?}",
        );
        assert_eq!(engine.tracked_identities(), 0);
    }

    /// `swap_config` resets limiter state. The pre-swap limiter
    /// (large burst, exhausted by N back-to-back hits) is replaced
    /// by a fresh limiter under the new `governor_quota`, so the
    /// first post-swap `decide()` is `Allow` — the bucket state
    /// did not carry over.
    #[test]
    fn swap_config_rebuilds_limiter_under_new_quota() {
        // Pre-swap: a roomy quota whose burst we will fully drain.
        let cfg = ReputationConfig {
            governor_quota: Quota::per_second(NonZeroU32::new(100).unwrap())
                .allow_burst(NonZeroU32::new(5).unwrap()),
            ..ReputationConfig::default()
        };
        let engine = ReputationEngine::with_config(cfg);

        let id = IdentityKey([0xeeu8; 32]);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let lease = LeaseId::from("swap-test");

        // Drain the burst-5 bucket then prove the limiter is tripped.
        for _ in 0..5 {
            assert_eq!(engine.decide(id, ip, &lease), ReputationDecision::Allow);
        }
        assert_eq!(
            engine.decide(id, ip, &lease),
            ReputationDecision::Block(BlockReason::RateLimited),
        );

        // Swap in a clearly different quota (burst-1) and watch the
        // first post-swap call land Allow — proves a fresh limiter,
        // not the exhausted pre-swap bucket.
        let new_cfg = ReputationConfig {
            governor_quota: Quota::per_second(NonZeroU32::new(1).unwrap())
                .allow_burst(NonZeroU32::new(1).unwrap()),
            block_threshold: 999.0,
            ..ReputationConfig::default()
        };
        engine.swap_config(new_cfg);

        assert_eq!(engine.decide(id, ip, &lease), ReputationDecision::Allow);
        assert_eq!(
            engine.decide(id, ip, &lease),
            ReputationDecision::Block(BlockReason::RateLimited),
        );
        // `block_threshold` visibility through `config()` after swap
        // is pinned by `swap_config_returns_new_config_via_getter`;
        // not re-asserted here.
    }

    /// `swap_config` does not touch the per-identity score table.
    /// Reputation accumulates across reloads — the v0.1 contract
    /// the rustdoc names.
    #[test]
    fn swap_config_preserves_score_table() {
        let engine = ReputationEngine::new();
        let id = IdentityKey([0xa5u8; 32]);
        engine.record_signal(id, SignalKind::RateLimited, 7.5);
        let before = engine.score(id);
        assert!((before - 7.5).abs() < 1e-6);

        engine.swap_config(ReputationConfig::default());

        let after = engine.score(id);
        assert!(
            (after - 7.5).abs() < 1e-6,
            "score {after} should survive swap_config (was {before})",
        );
        assert_eq!(engine.tracked_identities(), 1);
    }

    /// `swap_config` makes the new config visible through `config()`
    /// — the read-side getter returns the post-swap pair.
    #[test]
    fn swap_config_returns_new_config_via_getter() {
        let engine = ReputationEngine::new();
        assert_eq!(engine.config().block_threshold, REPUTATION_BLOCK_THRESHOLD);

        let new_cfg = ReputationConfig {
            block_threshold: 999.0,
            ..ReputationConfig::default()
        };
        engine.swap_config(new_cfg);

        assert_eq!(engine.config().block_threshold, 999.0);
    }
}
