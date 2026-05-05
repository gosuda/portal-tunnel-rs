//! [`Bridge`] — bounded async bridge from the axum keyless handler
//! into the sync rustls signing surface.
//!
//! ## Why a bridge exists at all
//!
//! [`rustls::sign::Signer::sign`] is **synchronous** by trait
//! contract.  The keyless mTLS axum handler (Phase 6b/A U3) is
//! async.  Calling a sync sign primitive directly from inside a
//! tokio task would block one runtime worker thread per concurrent
//! sign, starving the reactor under load.  ADR-0016 captures this
//! decision in full and names the rejected alternatives
//! (per-request [`tokio::task::spawn_blocking`] without bounding;
//! `block_on` inside the handler).
//!
//! The chosen shape is a bounded mpsc + dedicated **blocking-thread**
//! worker pool + `CancellationToken`:
//!
//! ```text
//!  handler --try_send(SignJob)--> mpsc --recv()--> supervisor task
//!     ^                                                    |
//!     |                                                    v
//!     |                                  spawn_blocking { Signer::sign }
//!     |                                                    |
//!     +----- await reply -- oneshot --- reply.send(result) +
//! ```
//!
//! - The mpsc bound is `BridgeConfig::queue_depth` (default 256).
//!   Once full, [`Bridge::sign`] returns [`KeylessError::QueueFull`];
//!   the U3 handler maps that to HTTP `503 Service Unavailable` so
//!   the backpressure is visible at the wire boundary instead of
//!   buffered invisibly.
//! - The supervisor task count is `BridgeConfig::worker_count`
//!   (default `max(2, available_parallelism / 4)`).  Each
//!   supervisor is a tokio task spawned on a caller-supplied
//!   [`tokio::task::JoinSet`] — the relay top-level `main` owns the
//!   `JoinSet` so all supervisors live inside its
//!   structured-concurrency scope (R9; same pattern as ADR-0014's
//!   overlay tasks).
//! - **Sync `Signer::sign` runs on a dedicated blocking thread via
//!   [`tokio::task::spawn_blocking`]**, NOT inside the supervisor's
//!   runtime task.  The supervisor's only job is to pull jobs from
//!   the mpsc, dispatch them to a blocking pool worker, await the
//!   blocking handle, and forward the result.  This is the contract
//!   that keeps CPU-heavy signing off the runtime worker threads.
//! - **`worker_count` IS the keyless signing concurrency cap.**
//!   Each supervisor awaits its in-flight `spawn_blocking` handle
//!   before reading the next job; at any instant at most
//!   `worker_count` blocking-pool threads are running `Signer::sign`
//!   on behalf of the keyless surface.  tokio's
//!   `max_blocking_threads` (default 512) is the outer envelope
//!   shared with the rest of the process; the keyless surface lives
//!   strictly under `worker_count` of that budget.  Operators who
//!   expect higher steady-state keyless throughput raise
//!   `worker_count` alongside the runtime's blocking-pool budget.
//! - Shutdown is cooperative: a [`CancellationToken`] propagated
//!   from the `JoinSet` owner unblocks each supervisor's `select!`
//!   arm and they exit after the in-flight `spawn_blocking`
//!   resolves.
//!
//! ## Single-Receiver fan-out
//!
//! [`tokio::sync::mpsc::Receiver`] is intentionally not `Clone` —
//! the type system says "one consumer".  The plan locks
//! `mpsc::Sender<SignJob>` (Phase 6b/A plan §U2 line 268), and the
//! workspace dep tree already pulls tokio + tokio-util; adding
//! `async-channel` for one mpmc primitive would be net negative.
//!
//! We therefore fan out by wrapping the receiver in
//! `Arc<tokio::sync::Mutex<mpsc::Receiver<SignJob>>>`.  Each
//! supervisor contends on `recv()` under the mutex.  The contention
//! is acceptable for the keyless workload: RSA-2048 signing on a
//! blocking thread takes ~1 ms; the mutex is held only for the
//! microsecond `recv()` step (the actual signing happens off the
//! mutex via `spawn_blocking`).  ADR-0016 §Considered alternatives
//! names this trade-off explicitly.

use std::sync::Arc;

use rustls::SignatureScheme;
use rustls::sign::SigningKey;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, instrument, warn};

use crate::keyless::error::KeylessError;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Worker-pool + queue sizing for [`Bridge`].
///
/// The defaults are workspace-derived rather than hand-tuned:
///
/// - `worker_count`: `max(2, available_parallelism / 4)`.  Each
///   supervisor awaits its in-flight `spawn_blocking` handle before
///   reading the next job from the mpsc, so this **is** the
///   keyless signing concurrency cap — at most `worker_count`
///   blocking-pool threads run `Signer::sign` on behalf of the
///   keyless surface at any instant.  A 4-core host runs 2
///   supervisors (the floor); a 16-core host runs 4.  Operators
///   who expect higher steady-state keyless throughput raise this
///   alongside the runtime's `max_blocking_threads` budget.
/// - `queue_depth`: 256.  Big enough to absorb a burst of in-flight
///   handler awaits without artificial 503s, small enough that the
///   queue cannot mask a worker stall (a 256-deep queue at 1 ms
///   per sign is ~256 ms of latent work — visible at the SLO).
///
/// Both values are operator-tunable via direct field set.  Phase
/// 6b/A U2 wires only the defaults; the operator-config surface
/// lands at U3 alongside `KeylessConfig`.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Number of supervisor tasks spawned on the caller's `JoinSet`.
    /// Each supervisor consumes from the shared mpsc and dispatches
    /// jobs to tokio's blocking pool via `spawn_blocking`, awaiting
    /// the in-flight handle before reading the next job.  Therefore
    /// this **is** the keyless signing concurrency cap — at any
    /// instant at most `worker_count` blocking-pool threads are
    /// running `Signer::sign` for the keyless surface.  The runtime
    /// `max_blocking_threads` knob (default 512) is the outer
    /// envelope shared with the rest of the process.
    pub worker_count: usize,
    /// Maximum number of in-flight `SignJob`s buffered in the mpsc
    /// before [`Bridge::sign`] starts returning
    /// [`KeylessError::QueueFull`].
    pub queue_depth: usize,
}

impl BridgeConfig {
    /// Workspace-default sizing.
    ///
    /// `worker_count = max(2, available_parallelism / 4)`,
    /// `queue_depth = 256`.
    ///
    /// `std::thread::available_parallelism` returns `Err` only on
    /// platforms where the runtime can't introspect CPU count; on
    /// those we fall back to the floor of 2 supervisors.
    #[must_use]
    pub fn workspace_default() -> Self {
        let parallelism =
            std::thread::available_parallelism().map_or(2, std::num::NonZeroUsize::get);
        Self {
            worker_count: usize::max(2, parallelism / 4),
            queue_depth: 256,
        }
    }

    /// Construct an explicit-size [`BridgeConfig`].
    ///
    /// Exposed so out-of-crate callers (notably the keyless mTLS
    /// integration test in `crates/portal-relay/tests/`) can build a
    /// `BridgeConfig` despite the type being `#[non_exhaustive]` —
    /// without this constructor the struct expression
    /// `BridgeConfig { worker_count, queue_depth }` is rejected at
    /// the crate boundary.
    ///
    /// Both fields are taken as [`NonZeroUsize`] so the constructor
    /// statically enforces the same invariants `Bridge::spawn`'s
    /// inner `usize::max(1, …)` floors imply: a 0-supervisor pool
    /// would deadlock the bridge, and `mpsc::channel(0)` panics —
    /// invariants we shouldn't restate at every caller.  Future
    /// additive fields land on this builder via separate
    /// `with_*` setters rather than as positional args.
    ///
    /// [`NonZeroUsize`]: std::num::NonZeroUsize
    #[must_use]
    pub const fn with_workers_and_queue(
        worker_count: std::num::NonZeroUsize,
        queue_depth: std::num::NonZeroUsize,
    ) -> Self {
        Self {
            worker_count: worker_count.get(),
            queue_depth: queue_depth.get(),
        }
    }
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self::workspace_default()
    }
}

// ---------------------------------------------------------------------------
// SignJob
// ---------------------------------------------------------------------------

/// Single keyless sign request flowing through the bridge.
///
/// `pub(crate)`-by-default — this type is the bridge's internal
/// wire shape; the public surface is `Bridge::sign(scheme, message)
/// -> Result<bytes, _>` and the U3 wire types (`SignRequest` /
/// `SignResponse`) layer above it.
struct SignJob {
    /// Bytes the worker passes verbatim to
    /// [`rustls::sign::Signer::sign`].  The U3 handler is
    /// responsible for prepending the
    /// `b"portal-tunnel/keyless-request/v1"` domain separator
    /// before reaching this struct (SEC-007 / Phase 6b/A U3).
    canonical_message: Vec<u8>,
    /// Negotiated signature scheme that the worker will pass to
    /// `choose_scheme(...)` on the inner `SigningKey`.
    scheme: SignatureScheme,
    /// Reply-back oneshot — supervisors send `Ok(signature_bytes)`
    /// on success, a typed [`KeylessError`] on failure.
    reply: oneshot::Sender<Result<Vec<u8>, KeylessError>>,
}

// ---------------------------------------------------------------------------
// Bridge
// ---------------------------------------------------------------------------

/// Async-callable handle in front of a sync rustls signing key.
///
/// Built via [`Bridge::spawn`], which takes:
/// - `signing_key`: the rustls `SigningKey` blocking workers share via `Arc`.
/// - `config`: supervisor count + queue depth.
/// - `joinset`: caller-owned `JoinSet<()>` — supervisors spawn here
///   so they live inside the caller's structured-concurrency scope
///   (R9).  The relay top-level `main` is the canonical owner.
/// - `cancellation`: caller-owned `CancellationToken` — fires to
///   shut supervisors down cooperatively.
///
/// Cloning a `Bridge` clones an `mpsc::Sender` (cheap) and the
/// `CancellationToken` (also an `Arc` clone).  Multiple handler
/// tasks can hold their own `Bridge` clone and submit jobs
/// concurrently; the queue depth is shared.
#[non_exhaustive]
#[derive(Clone)]
pub struct Bridge {
    /// Bounded sender into the supervisor pool.  `try_send` is the
    /// only path used (handler must surface backpressure at the
    /// wire); blocking `send` is intentionally not exposed.
    tx: mpsc::Sender<SignJob>,
    /// Cancellation token shared with the supervisor pool; cloned
    /// from the caller's owner.  Available on the `Bridge` so
    /// future admin endpoints (Phase 7) can observe shutdown
    /// progress without reaching into the caller's owner.
    cancellation: CancellationToken,
}

impl core::fmt::Debug for Bridge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Bridge")
            .field("queue_capacity", &self.tx.capacity())
            .field("queue_max_capacity", &self.tx.max_capacity())
            .field("cancelled", &self.cancellation.is_cancelled())
            .finish()
    }
}

impl Bridge {
    /// Spawn the supervisor pool on the caller's `JoinSet` and
    /// return a [`Bridge`] handle.
    ///
    /// All supervisors share `signing_key` by `Arc`; the inner
    /// rustls `SigningKey` is constructed once at adapter build
    /// time (`KeylessSignerAdapter::from_keyless_signing_key`) and
    /// never re-parsed.  Each blocking dispatch (per sign call)
    /// clones that `Arc` into the blocking thread.
    ///
    /// # Panics
    ///
    /// Never panics directly; will saturate `worker_count` to 1
    /// if the caller passes 0 (defensive — a 0-supervisor bridge
    /// would deadlock).
    #[must_use]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "constructor signature is intentionally consuming: \
                  callers hand off ownership of the Arc + config + cancellation \
                  to the bridge, which then internally clones into each \
                  supervisor task. Borrowing-shaped variants would force the \
                  caller to keep an unused outer copy alive for the bridge's \
                  lifetime."
    )]
    pub fn spawn(
        signing_key: Arc<dyn SigningKey>,
        config: BridgeConfig,
        joinset: &mut JoinSet<()>,
        cancellation: CancellationToken,
    ) -> Self {
        // Defensive: refuse a 0-supervisor pool.  Without this
        // guard, an operator misconfiguration would produce a
        // Bridge whose mpsc never drains; sign() would block
        // forever (or QueueFull immediately, depending on
        // queue_depth).  Using a floor of 1 keeps the type total.
        let worker_count = usize::max(1, config.worker_count);
        // Defensive: refuse a 0-depth queue.  tokio's `mpsc::channel`
        // panics on `buffer == 0`; we coerce to 1 instead so the
        // bridge degrades to "single in-flight job at a time"
        // instead of crashing the relay at startup.
        let queue_depth = usize::max(1, config.queue_depth);

        let (tx, rx) = mpsc::channel::<SignJob>(queue_depth);
        let rx = Arc::new(Mutex::new(rx));

        for supervisor_idx in 0..worker_count {
            let signing_key = Arc::clone(&signing_key);
            let rx = Arc::clone(&rx);
            let cancel = cancellation.clone();
            joinset.spawn(async move {
                supervisor_loop(signing_key, rx, cancel, supervisor_idx).await;
            });
        }

        Self { tx, cancellation }
    }

    /// Submit a keyless sign job and await the result.
    ///
    /// Non-blocking on submission: uses
    /// [`mpsc::Sender::try_send`], so a full queue surfaces as
    /// [`KeylessError::QueueFull`] immediately rather than
    /// silently buffering.  The U3 handler maps this to HTTP `503`.
    ///
    /// # Errors
    ///
    /// - [`KeylessError::QueueFull`] — queue at capacity (handler
    ///   should return 503 with a `Retry-After` header).
    /// - [`KeylessError::BridgeClosed`] — all supervisors have
    ///   already exited (cancellation has drained or the
    ///   `JoinSet` was joined).
    /// - [`KeylessError::WorkerPanic`] — the supervisor that
    ///   picked up the job exited without delivering a reply (most
    ///   likely a panic on the blocking thread; the `JoinSet`
    ///   owner surfaces the underlying panic separately on its
    ///   next `join_next`).
    /// - [`KeylessError::SignFailed`] — the inner `Signer::sign`
    ///   call returned an error; the rustls error string is
    ///   preserved verbatim.
    #[instrument(skip_all, fields(scheme = ?scheme, message_len = message.len()))]
    pub async fn sign(
        &self,
        scheme: SignatureScheme,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, KeylessError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let job = SignJob {
            canonical_message: message,
            scheme,
            reply: reply_tx,
        };
        match self.tx.try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                debug!("keyless bridge queue full; rejecting with QueueFull");
                return Err(KeylessError::QueueFull);
            }
            Err(TrySendError::Closed(_)) => {
                debug!("keyless bridge channel closed; rejecting with BridgeClosed");
                return Err(KeylessError::BridgeClosed);
            }
        }
        // Supervisor drops the oneshot::Sender after sending the
        // result; if the channel closes without a value, that's a
        // worker panic (see WorkerPanic rustdoc above).
        match reply_rx.await {
            Ok(result) => result,
            Err(_recv_error) => {
                error!("keyless bridge supervisor dropped reply channel without sending");
                Err(KeylessError::WorkerPanic)
            }
        }
    }

    /// Borrow the bridge's cancellation token.
    ///
    /// Exposed so admin / observability code can check whether
    /// shutdown has been initiated without needing a separate
    /// reference to the `JoinSet` owner's token.  The bridge itself
    /// does not call `.cancel()` — that is the caller's
    /// responsibility (the `JoinSet` owner).
    #[must_use]
    pub const fn cancellation_token(&self) -> &CancellationToken {
        &self.cancellation
    }
}

// ---------------------------------------------------------------------------
// Supervisor loop + blocking dispatch
// ---------------------------------------------------------------------------

/// Inner supervisor driver.
///
/// Each supervisor holds a clone of `Arc<Mutex<Receiver>>` and
/// races `recv()` under the mutex against the cancellation token.
/// On cancellation the loop exits without draining further jobs;
/// any `SignJob` already pulled from the queue is dispatched to a
/// blocking thread and its reply is delivered before the
/// supervisor exits.
///
/// **The supervisor itself does NOT sign.**  It only routes jobs
/// onto tokio's blocking pool via `spawn_blocking`.  This is the
/// contract that keeps CPU-heavy `Signer::sign` calls off the
/// runtime worker threads — see ADR-0016 §Decision.
#[instrument(skip_all, fields(supervisor_idx = supervisor_idx))]
#[expect(
    clippy::significant_drop_tightening,
    reason = "guard scope is bounded by the inner block enclosing the \
              tokio::select!; the lint fires across the select! macro \
              expansion (false positive — see clippy issue tracker for \
              significant-drop-tightening + tokio::select!). Tightening \
              further would require splitting the cancel-vs-recv race \
              into two awaits, losing the race semantics that justify \
              the bridge's cooperative-shutdown contract."
)]
async fn supervisor_loop(
    signing_key: Arc<dyn SigningKey>,
    rx: Arc<Mutex<mpsc::Receiver<SignJob>>>,
    cancel: CancellationToken,
    supervisor_idx: usize,
) {
    debug!("keyless bridge supervisor started");
    loop {
        // Single-receiver fan-out: contend on `recv()` under the
        // shared mutex.  The lock guard is held only across the
        // `recv()` await — once a job is pulled, the guard drops
        // at the end of the inner block (before the
        // `spawn_blocking` dispatch) so other supervisors can take
        // the next job concurrently.
        let job_opt = {
            let mut guard = rx.lock().await;
            tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    debug!("keyless bridge supervisor observed cancellation; exiting");
                    return;
                }
                job = guard.recv() => job,
            }
        };
        let Some(job) = job_opt else {
            // All `mpsc::Sender` clones dropped — bridge has been
            // taken out of service.  Supervisors exit cleanly.
            debug!("keyless bridge mpsc sender dropped; supervisor exiting");
            return;
        };

        // Dispatch the sync `Signer::sign` onto tokio's blocking
        // pool.  This is the load-bearing step: the sign primitive
        // can take ~1 ms (RSA-2048) and would otherwise block one
        // runtime worker per concurrent dispatch.  `spawn_blocking`
        // moves the work onto a dedicated OS thread from tokio's
        // blocking pool (size governed by the runtime builder's
        // `max_blocking_threads`, default 512).  Bounding is
        // already enforced upstream by the mpsc `queue_depth` plus
        // the supervisor count, so this is NOT the unbounded
        // per-request `spawn_blocking` antipattern called out in
        // ADR-0016 §Considered alternatives — every dispatch passes
        // through the bounded mpsc first.
        let sk = Arc::clone(&signing_key);
        let scheme = job.scheme;
        let message = job.canonical_message;
        let blocking_handle =
            tokio::task::spawn_blocking(move || sign_inner(sk.as_ref(), scheme, &message));

        let result = match blocking_handle.await {
            Ok(sign_result) => sign_result,
            Err(join_err) => {
                // Blocking thread panicked.  We surface this to
                // the caller as WorkerPanic so the handler can
                // map it to a 5xx; the JoinSet owner does not see
                // this panic directly because it occurred on the
                // blocking pool, not on a runtime task.
                error!(
                    error = %join_err,
                    "keyless bridge blocking dispatch panicked"
                );
                Err(KeylessError::WorkerPanic)
            }
        };

        if job.reply.send(result).is_err() {
            // Caller dropped the reply receiver — they cancelled
            // their await before we finished signing.  Not a fatal
            // condition; the next iteration picks up the next job.
            warn!("keyless bridge reply receiver dropped before result delivery");
        }
    }
}

/// Sync signing primitive — picks a scheme + delegates to
/// `Signer::sign`.
///
/// Pulled out of the supervisor loop so the test suite can call
/// the same code path through a stub `SigningKey` without spawning
/// a runtime.  Worker-local error mapping: rustls's `Error` is
/// flattened to `KeylessError::SignFailed(String)` so the variant
/// surface stays internal to the keyless module (R2).
///
/// **Runs on a blocking pool thread** (via `spawn_blocking`), not
/// on a runtime worker thread.
fn sign_inner(
    signing_key: &dyn SigningKey,
    scheme: SignatureScheme,
    message: &[u8],
) -> Result<Vec<u8>, KeylessError> {
    let Some(signer) = signing_key.choose_scheme(&[scheme]) else {
        return Err(KeylessError::SignFailed(format!(
            "signing key does not support requested scheme {scheme:?}"
        )));
    };
    signer
        .sign(message)
        .map_err(|e| KeylessError::SignFailed(format!("rustls signer error: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::panic,
    reason = "test-only setup + assertions"
)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use rustls::sign::{Signer, SigningKey};
    use rustls::{SignatureAlgorithm, SignatureScheme};

    use super::*;

    // ---- Stub SigningKey -------------------------------------------------
    //
    // The bridge tests must NOT pull rustls's actual crypto provider
    // — that's U3's integration territory.  A stub key returns the
    // input bytes verbatim from `Signer::sign`, so the test asserts
    // the bridge plumbing without exercising aws-lc-rs.

    #[derive(Debug)]
    struct StubSigningKey {
        scheme: SignatureScheme,
        /// Optional injection: when set, `sign()` returns this error
        /// shape so the tests can exercise the `SignFailed` path.
        force_error: bool,
        /// Counts the number of `Signer::sign` calls observed.
        call_count: Arc<AtomicUsize>,
    }

    impl StubSigningKey {
        fn new(scheme: SignatureScheme) -> (Self, Arc<AtomicUsize>) {
            let counter = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    scheme,
                    force_error: false,
                    call_count: Arc::clone(&counter),
                },
                counter,
            )
        }

        fn failing(scheme: SignatureScheme) -> Self {
            Self {
                scheme,
                force_error: true,
                call_count: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[derive(Debug)]
    struct StubSigner {
        scheme: SignatureScheme,
        force_error: bool,
        call_count: Arc<AtomicUsize>,
    }

    impl SigningKey for StubSigningKey {
        fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
            offered
                .iter()
                .find(|s| **s == self.scheme)
                .map(|s| -> Box<dyn Signer> {
                    Box::new(StubSigner {
                        scheme: *s,
                        force_error: self.force_error,
                        call_count: Arc::clone(&self.call_count),
                    })
                })
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            // Arbitrary tag — tests never assert on this field.
            SignatureAlgorithm::ED25519
        }
    }

    impl Signer for StubSigner {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.force_error {
                return Err(rustls::Error::General(
                    "stub forced sign failure".to_owned(),
                ));
            }
            // Deterministic stub: signature equals input.  Lets the
            // happy-path test assert exact equality.
            Ok(message.to_vec())
        }

        fn scheme(&self) -> SignatureScheme {
            self.scheme
        }
    }

    // ---- Test scenarios --------------------------------------------------

    /// Happy path: 2 supervisors, generous queue, 100 concurrent
    /// sign calls all complete and return the deterministic stub
    /// signature (== input bytes).
    ///
    /// **Queue sizing note.** `Bridge::sign` is non-blocking on
    /// submission (`try_send`), so a queue smaller than the
    /// concurrent-submitter count would correctly return
    /// `QueueFull` for some submitters under load — that's the
    /// designed backpressure shape, exercised in
    /// `queue_full_surfaces_queue_full_error` below.  This test
    /// asserts the "every job round-trips" contract; we therefore
    /// size the queue (`queue_depth = 128`) strictly above the
    /// submitter count (100) so backpressure cannot cause the
    /// round-trip assertion to flake.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn happy_path_concurrent_signs() {
        let (stub, counter) = StubSigningKey::new(SignatureScheme::RSA_PSS_SHA256);
        let key: Arc<dyn SigningKey> = Arc::new(stub);
        let mut joinset: JoinSet<()> = JoinSet::new();
        let cancel = CancellationToken::new();
        let bridge = Bridge::spawn(
            key,
            BridgeConfig {
                worker_count: 2,
                queue_depth: 128,
            },
            &mut joinset,
            cancel.clone(),
        );

        // Launch 100 concurrent signs.  See queue-sizing note in
        // the test rustdoc above for why `queue_depth = 128 > 100`.
        let mut handles = Vec::with_capacity(100);
        for i in 0..100u32 {
            let bridge = bridge.clone();
            #[expect(
                clippy::disallowed_methods,
                reason = "test code per R9: 100 concurrent submitters joined via Vec<JoinHandle> at end of test"
            )]
            handles.push(tokio::spawn(async move {
                let msg = format!("message-{i}").into_bytes();
                let result = bridge
                    .sign(SignatureScheme::RSA_PSS_SHA256, msg.clone())
                    .await
                    .expect("bridge.sign must succeed under healthy load");
                assert_eq!(result, msg, "stub returns input verbatim");
            }));
        }
        for h in handles {
            h.await.expect("join handle");
        }

        // Cancel + drain.
        cancel.cancel();
        // Drop the bridge so the mpsc Sender count goes to zero
        // and the supervisors exit even without the cancellation
        // arm racing first.
        drop(bridge);
        while let Some(res) = joinset.join_next().await {
            res.expect("supervisor join");
        }

        assert_eq!(
            counter.load(Ordering::SeqCst),
            100,
            "every sign call must have hit the stub"
        );
    }

    /// Edge case: queue depth 1, slow blocking signer, many
    /// concurrent senders → at least one must observe `QueueFull`.
    ///
    /// We force the contention by sleeping inside `sign` (note:
    /// this is a sync sleep because `Signer::sign` is sync — and
    /// because the dispatch goes through `spawn_blocking`, the
    /// sleep blocks a blocking-pool thread, not a runtime thread).
    /// 32 concurrent submitters with a 1-deep queue and a 50
    /// ms-per-job blocking dispatch will saturate the queue with
    /// overwhelming probability.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn queue_full_surfaces_queue_full_error() {
        #[derive(Debug)]
        struct SlowKey;
        #[derive(Debug)]
        struct SlowSigner;
        impl SigningKey for SlowKey {
            fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
                offered
                    .first()
                    .map(|_| -> Box<dyn Signer> { Box::new(SlowSigner) })
            }
            fn algorithm(&self) -> SignatureAlgorithm {
                SignatureAlgorithm::ED25519
            }
        }
        impl Signer for SlowSigner {
            fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
                std::thread::sleep(Duration::from_millis(50));
                Ok(message.to_vec())
            }
            fn scheme(&self) -> SignatureScheme {
                SignatureScheme::RSA_PSS_SHA256
            }
        }

        let key: Arc<dyn SigningKey> = Arc::new(SlowKey);
        let mut joinset: JoinSet<()> = JoinSet::new();
        let cancel = CancellationToken::new();
        let bridge = Bridge::spawn(
            key,
            BridgeConfig {
                worker_count: 1,
                queue_depth: 1,
            },
            &mut joinset,
            cancel.clone(),
        );

        // Fan out 32 concurrent submitters.  With queue depth 1 +
        // single supervisor + 50 ms-per-job blocking dispatch, the
        // queue saturates.
        let mut full_observed = false;
        let mut handles = Vec::new();
        for _ in 0..32u32 {
            let bridge = bridge.clone();
            #[expect(
                clippy::disallowed_methods,
                reason = "test code per R9: 32 concurrent submitters joined via Vec<JoinHandle> at end of test"
            )]
            handles.push(tokio::spawn(async move {
                bridge
                    .sign(SignatureScheme::RSA_PSS_SHA256, vec![0xAB; 16])
                    .await
            }));
        }
        for h in handles {
            match h.await.expect("join") {
                Ok(_sig) => {}
                Err(KeylessError::QueueFull) => {
                    full_observed = true;
                }
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }

        assert!(
            full_observed,
            "at least one submitter must have observed QueueFull"
        );

        cancel.cancel();
        drop(bridge);
        while let Some(res) = joinset.join_next().await {
            res.expect("supervisor join");
        }
    }

    /// Error path: the inner signer returns an error → workers
    /// surface `KeylessError::SignFailed(_)`.  Channel stays alive
    /// for surviving supervisors.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sign_inner_error_surfaces_sign_failed() {
        let key: Arc<dyn SigningKey> =
            Arc::new(StubSigningKey::failing(SignatureScheme::RSA_PSS_SHA256));
        let mut joinset: JoinSet<()> = JoinSet::new();
        let cancel = CancellationToken::new();
        let bridge = Bridge::spawn(
            key,
            BridgeConfig {
                worker_count: 2,
                queue_depth: 4,
            },
            &mut joinset,
            cancel.clone(),
        );

        let err = bridge
            .sign(SignatureScheme::RSA_PSS_SHA256, vec![1, 2, 3])
            .await
            .expect_err("forced stub error must surface");
        assert!(
            matches!(err, KeylessError::SignFailed(_)),
            "expected SignFailed, got: {err:?}"
        );

        // Bridge stays alive for further requests after the
        // error: send another job and verify it still gets routed
        // to the (still-failing) stub rather than getting
        // BridgeClosed.
        let err2 = bridge
            .sign(SignatureScheme::RSA_PSS_SHA256, vec![4, 5])
            .await
            .expect_err("second forced stub error must also surface");
        assert!(
            matches!(err2, KeylessError::SignFailed(_)),
            "expected second SignFailed, got: {err2:?}"
        );

        cancel.cancel();
        drop(bridge);
        while let Some(res) = joinset.join_next().await {
            res.expect("supervisor join");
        }
    }

    /// Integration: cancellation token fires → supervisors exit →
    /// new sends return `BridgeClosed`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_drains_workers_and_closes_channel() {
        let (stub, _counter) = StubSigningKey::new(SignatureScheme::RSA_PSS_SHA256);
        let key: Arc<dyn SigningKey> = Arc::new(stub);
        let mut joinset: JoinSet<()> = JoinSet::new();
        let cancel = CancellationToken::new();
        let bridge = Bridge::spawn(
            key,
            BridgeConfig {
                worker_count: 2,
                queue_depth: 4,
            },
            &mut joinset,
            cancel.clone(),
        );

        // Sanity-check the bridge works first.
        let sig = bridge
            .sign(SignatureScheme::RSA_PSS_SHA256, b"pre-cancel".to_vec())
            .await
            .expect("pre-cancel sign succeeds");
        assert_eq!(sig, b"pre-cancel");

        // Trigger cancellation; wait for all supervisors to exit.
        cancel.cancel();
        while let Some(res) = joinset.join_next().await {
            res.expect("supervisor join");
        }

        // After supervisors exit, the mpsc receiver is dropped.
        // New sends return BridgeClosed.  (The handler-side
        // mapping to 503 lives at U3.)
        let err = bridge
            .sign(SignatureScheme::RSA_PSS_SHA256, b"post-cancel".to_vec())
            .await
            .expect_err("post-cancel sign must fail");
        assert!(
            matches!(err, KeylessError::BridgeClosed),
            "expected BridgeClosed, got: {err:?}"
        );
    }

    /// Defensive: 0-supervisor / 0-depth config is sanitised, not
    /// panicked.  Regression guard for the constructor's
    /// `usize::max(1, …)` floors.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zero_config_is_sanitised_to_workable_floor() {
        let (stub, _counter) = StubSigningKey::new(SignatureScheme::RSA_PSS_SHA256);
        let key: Arc<dyn SigningKey> = Arc::new(stub);
        let mut joinset: JoinSet<()> = JoinSet::new();
        let cancel = CancellationToken::new();
        let bridge = Bridge::spawn(
            key,
            BridgeConfig {
                worker_count: 0,
                queue_depth: 0,
            },
            &mut joinset,
            cancel.clone(),
        );

        // A 1-supervisor, 1-depth queue is enough to round-trip a
        // single sign.
        let sig = bridge
            .sign(SignatureScheme::RSA_PSS_SHA256, b"floor-check".to_vec())
            .await
            .expect("sign must work even with 0/0 config (floored to 1/1)");
        assert_eq!(sig, b"floor-check");

        cancel.cancel();
        drop(bridge);
        while let Some(res) = joinset.join_next().await {
            res.expect("supervisor join");
        }
    }

    #[test]
    fn workspace_default_is_sane() {
        let cfg = BridgeConfig::workspace_default();
        assert!(cfg.worker_count >= 2, "worker count floor is 2");
        assert_eq!(cfg.queue_depth, 256, "default queue depth is 256");
    }

    #[tokio::test]
    async fn cancellation_token_is_observable_through_bridge() {
        let (stub, _counter) = StubSigningKey::new(SignatureScheme::RSA_PSS_SHA256);
        let key: Arc<dyn SigningKey> = Arc::new(stub);
        let mut joinset: JoinSet<()> = JoinSet::new();
        let cancel = CancellationToken::new();
        let bridge = Bridge::spawn(
            key,
            BridgeConfig::workspace_default(),
            &mut joinset,
            cancel.clone(),
        );
        assert!(!bridge.cancellation_token().is_cancelled());
        cancel.cancel();
        assert!(bridge.cancellation_token().is_cancelled());
        drop(bridge);
        while let Some(res) = joinset.join_next().await {
            res.expect("supervisor join");
        }
    }
}
