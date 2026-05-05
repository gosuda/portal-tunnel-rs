//! Phase 5 B7 (narrowed) behavioral gate — R10 v0.1 per-relay
//! reputation engine.
//!
//! The plan U12 §"Test scenarios" entry pins five assertions; this
//! file owns the four "core engine" steps (the fifth — the 1000-
//! request governor-rejection step — is implemented as the final
//! scenario below).
//!
//! ## What this test gates
//!
//! Per plan U12 §"Test scenarios" — the **behavioral gate** for the
//! R10 v0.1 governor key-triple semantics + exponential-decay
//! round-trip:
//!
//! 1. Construct an engine with `decay_constant = ln(2)/1s` (1-second
//!    half-life — fast enough that a `tokio::time::sleep` of 1s
//!    produces an observable decay step inside the test).
//! 2. `record_signal(weight = 10.0)` → `score == 10.0`.
//! 3. Sleep 1 second of real wall-clock time → `score ≈ 5.0` (±0.5
//!    tolerance — the precise ratio is `2^-1`, but `tokio::time::
//!    sleep` is not millisecond-accurate on a loaded CI runner).
//! 4. `record_signal(weight = 10.0)` again → `score ≈ 15.0`.
//! 5. Submit 1000 `decide()` calls with the same `(identity, ip,
//!    lease)` triple within 1 second → at least one returns
//!    `Block` AND the score crosses `block_threshold`.
//!
//! ## Out of scope (deferred per plan)
//!
//! - **ENS Sybil-gating bypass** (plan U12 step 4 carve-out).  The
//!   minimum-engine apex blocks unconditionally; the bypass branch
//!   that consults `Arc<dyn EnsResolver>` lands in a follow-up
//!   commit alongside the resolver-wiring work.
//! - **Honeypot path matcher** (`Arc<HoneypotMatcher>` feeding
//!   `SignalKind::HoneypotHit` from the listener pipeline).

#![expect(
    clippy::expect_used,
    clippy::cast_precision_loss,
    clippy::missing_const_for_fn,
    clippy::match_same_arms,
    reason = "integration test: expect on known-good fixtures; usize→f64 \
              cast is bounded at task_count*signals_per_task = 1024 (well \
              within f64 mantissa); the BlockReason wildcard arm and the \
              ReputationExceeded arm intentionally bin into the same counter \
              so a future non_exhaustive variant is gracefully handled"
)]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use portal_relay::policy::reputation::{
    BlockReason, IdentityKey, LeaseId, ReputationConfig, ReputationDecision, ReputationEngine,
    SignalKind, default_governor_quota,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Build an engine with a 1-second decay half-life so the
/// behavioral gate's 1-second `tokio::time::sleep` produces an
/// observable score step.
///
/// Decay constant: `ln(2) / 1s`.  Block / backpressure thresholds
/// are kept at the workspace defaults (100.0 / 50.0) — the gate's
/// 1000-request burst step pushes the per-identity score across
/// the block threshold via `SignalKind::RateLimited` weight
/// accumulation when the keyed governor rejects.
fn build_test_engine() -> ReputationEngine {
    let config = ReputationConfig {
        decay_constant: f64::ln(2.0), // 1-second half-life
        // Defaults for the rest — explicit so a future change to
        // the workspace defaults does not silently change the
        // test's apex thresholds.
        block_threshold: 100.0,
        backpressure_threshold: 50.0,
        backpressure_yield: Duration::from_millis(50),
        governor_quota: default_governor_quota(),
        // Scenario 5 (1000-request burst) depends on
        // `SignalKind::RateLimited` weight = 1.0; using the
        // workspace `Default` map keeps that single dependency
        // pinned without spreading future fields into the fixture.
        signal_weights: ReputationConfig::default().signal_weights,
    };
    ReputationEngine::with_config(config)
}

fn test_identity() -> IdentityKey {
    // 32-byte placeholder identity — the engine treats the bytes
    // as opaque; all that matters for the gate is that the same
    // key plumbed through every call site hashes consistently.
    IdentityKey([0x42u8; 32])
}

fn test_ip() -> IpAddr {
    "203.0.113.42"
        .parse()
        .expect("RFC 5737 TEST-NET-3 address parses")
}

fn test_lease() -> LeaseId {
    LeaseId::from("test-lease-r10-gate")
}

// ---------------------------------------------------------------------------
// Smoke: triple key is Hash + Eq + Clone — required by governor
// ---------------------------------------------------------------------------

#[tokio::test]
async fn triple_key_smoke_engine_serves_decide_calls() {
    let engine = build_test_engine();
    let id = test_identity();
    let ip = test_ip();
    let lease = test_lease();
    // Single decide() call confirms the governor::keyed surface
    // accepts the (IdentityKey, IpAddr, LeaseId) triple — if the
    // type weren't Hash + Eq + Clone + Send + Sync + 'static, this
    // call would not compile.
    let decision = engine.decide(id, ip, &lease);
    assert_eq!(decision, ReputationDecision::Allow);
}

// ---------------------------------------------------------------------------
// Behavioral gate: exponential-decay round trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exponential_decay_round_trip() {
    let engine = build_test_engine();
    let id = test_identity();

    // Step 1 (construct) — done above.

    // Step 2: record_signal(weight = 10.0) → score == 10.0.
    engine.record_signal(id, SignalKind::RateLimited, 10.0);
    let score_before_sleep = engine.score(id);
    assert!(
        (score_before_sleep - 10.0).abs() < 0.001,
        "score after first signal should be ~10.0, got {score_before_sleep}",
    );

    // Step 3: tokio sleep 1s → score after decay ≈ 5.0 (±0.5).
    //
    // Why 0.5 tolerance, not a tighter bound: tokio::time::sleep
    // is sub-millisecond on an idle reactor, but a busy CI runner
    // can stretch the wake-up by tens of ms.  At a 1-second half-
    // life that drift compounds in the exponential, so we widen
    // the band rather than chase fragile timing.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let score_after_decay = engine.score(id);
    assert!(
        (score_after_decay - 5.0).abs() < 0.5,
        "score after 1s decay should be ~5.0 (±0.5), got {score_after_decay}",
    );

    // Step 4: record_signal(weight = 10.0) again → score ≈ 15.0.
    //
    // The post-decay score is the projected ~5.0; adding 10 gives
    // ~15.  We use the same 0.5 band because the projection at
    // step 3 already absorbs the timing jitter, and step 4's
    // signal is recorded at the same wall-clock instant we just
    // observed.
    engine.record_signal(id, SignalKind::RateLimited, 10.0);
    let score_after_second_signal = engine.score(id);
    assert!(
        (score_after_second_signal - 15.0).abs() < 0.5,
        "score after second signal should be ~15.0 (±0.5), got {score_after_second_signal}",
    );
}

// ---------------------------------------------------------------------------
// Behavioral gate: 1000-request burst → governor blocks + score
// crosses block threshold
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn governor_burst_blocks_and_score_crosses_threshold() {
    let engine = build_test_engine();
    let id = test_identity();
    let ip = test_ip();
    let lease = test_lease();

    // Each rate-limit hit feeds `record_signal(_, RateLimited, 1.0)`
    // per the engine's decide() flow.  The default governor quota
    // is 50 RPS sustained / 100 burst.  Submitting 1000 requests
    // inside a 1-second window guarantees ≥800 governor rejections
    // (1000 - 100 burst capacity - ~50 sustained refill in <1s);
    // each rejection adds 1.0 to the score, so the score
    // accumulates well past the block_threshold (100.0).
    let mut governor_blocked_count = 0usize;
    let mut reputation_blocked_count = 0usize;
    let mut allowed_count = 0usize;

    for _ in 0..1000 {
        match engine.decide(id, ip, &lease) {
            ReputationDecision::Allow | ReputationDecision::Backpressure(_) => {
                allowed_count += 1;
            }
            ReputationDecision::Block(BlockReason::RateLimited) => {
                governor_blocked_count += 1;
            }
            ReputationDecision::Block(BlockReason::ReputationExceeded) => {
                reputation_blocked_count += 1;
            }
            // `BlockReason` is `#[non_exhaustive]` per the engine's
            // forward-compat surface; future variants are routed
            // here.  Treat as "Block" for the gate's "≥1 Block"
            // assertion.
            ReputationDecision::Block(_) => {
                reputation_blocked_count += 1;
            }
        }
    }

    // At least one Block decision (governor OR reputation).  The
    // plan's wording is "at least one returns Block" — both Block
    // variants satisfy that requirement.
    let total_blocks = governor_blocked_count + reputation_blocked_count;
    assert!(
        total_blocks >= 1,
        "expected ≥1 Block decision across 1000 requests, got \
         {total_blocks} ({governor_blocked_count} rate-limited, \
         {reputation_blocked_count} reputation-exceeded, \
         {allowed_count} allowed/backpressure)",
    );

    // The plan also requires the **score** to cross the block
    // threshold — that's what proves the governor signal is
    // feeding the reputation engine, not just the limiter.
    let final_score = engine.score(id);
    let threshold = engine.config().block_threshold;
    assert!(
        final_score >= threshold,
        "expected final score ≥ block_threshold ({threshold}), got {final_score} \
         (governor_blocked={governor_blocked_count}, \
         reputation_blocked={reputation_blocked_count}, \
         allowed={allowed_count})",
    );
}

// ---------------------------------------------------------------------------
// Concurrency safety: concurrent record_signal calls accumulate
// (defends the CAS update path)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_record_signal_calls_accumulate() {
    // Use the workspace-default 24-hour half-life so decay over
    // the test's wall-clock window is unobservable at f64
    // precision; this isolates the CAS-correctness property from
    // the decay arithmetic.
    let engine = Arc::new(ReputationEngine::new());
    let id = IdentityKey([0x77u8; 32]);

    let task_count = 16usize;
    let signals_per_task = 64usize;
    let weight = 1.0_f64;

    let mut handles = Vec::with_capacity(task_count);
    for _ in 0..task_count {
        let engine = Arc::clone(&engine);
        #[expect(
            clippy::disallowed_methods,
            reason = "test code per R9: 16 concurrent recorders joined via Vec<JoinHandle> at end of test"
        )]
        handles.push(tokio::spawn(async move {
            for _ in 0..signals_per_task {
                engine.record_signal(id, SignalKind::RateLimited, weight);
            }
        }));
    }
    for h in handles {
        h.await.expect("task should not panic");
    }

    let expected = (task_count * signals_per_task) as f64 * weight;
    let observed = engine.score(id);
    // Tolerance covers cumulative f64 rounding across 1024
    // additions — well below the "lost-update" magnitude (a single
    // lost update would drop the score by 1.0).
    assert!(
        (observed - expected).abs() < 0.1,
        "concurrent record_signal must accumulate: expected ~{expected}, got {observed}",
    );
}

// ---------------------------------------------------------------------------
// Non-finite weight defence: NaN / +inf must NOT poison the score
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_finite_weight_is_a_no_op() {
    let engine = ReputationEngine::new();
    let id = IdentityKey([0xccu8; 32]);

    engine.record_signal(id, SignalKind::RateLimited, 5.0);
    let baseline = engine.score(id);
    assert!((baseline - 5.0).abs() < 0.001);

    // NaN / ±inf weights would poison every threshold check
    // (`NaN >= block_threshold` is always false), silently routing
    // every future decide() to Allow.  The engine drops them.
    engine.record_signal(id, SignalKind::RateLimited, f64::NAN);
    engine.record_signal(id, SignalKind::RateLimited, f64::INFINITY);
    engine.record_signal(id, SignalKind::RateLimited, f64::NEG_INFINITY);
    let after = engine.score(id);
    assert!(
        after.is_finite(),
        "score must remain finite after non-finite weights, got {after}",
    );
    assert!(
        (after - baseline).abs() < 0.001,
        "non-finite weights must be no-ops: baseline {baseline}, after {after}",
    );
}
