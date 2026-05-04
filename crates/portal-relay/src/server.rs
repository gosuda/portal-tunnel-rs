//! Top-level relay server orchestrator.
//!
//! Composes:
//! - [`crate::state::LeaseRegistry`] — papaya-backed lease store.
//! - [`crate::policy::PolicyRuntime`] — IP filter + proxy trust.
//! - 5s lease janitor task that drives `cleanup_expired`.
//!
//! Phase 5 B9 lands this orchestrator as a skeleton. Subsequent
//! batches wire the actual axum listeners, the QUIC backhaul
//! `Endpoint`, the keyless mTLS surface, and the metrics exporter.
//!
//! ## Lifecycle
//!
//! The server moves through three explicit states:
//!
//! - [`LifecyclePhase::Stopped`] — initial state. `start` is allowed.
//! - [`LifecyclePhase::Running`] — janitor + spawned tasks live.
//!   `start` rejects with `Config("server already started")`.
//! - [`LifecyclePhase::Stopping`] — `shutdown` has cancelled tasks
//!   and is awaiting their join. `start` rejects with
//!   `Config("server is shutting down")` so a concurrent restart
//!   cannot create a second `RuntimeState` while the prior tasks
//!   are still draining. After all tasks join, the state collapses
//!   back to `Stopped` and a subsequent `start` succeeds.
//!
//! Transitions are guarded by a single `tokio::sync::Mutex<Lifecycle>`.
//!
//! ## Shutdown completion semantics
//!
//! [`Server::shutdown`] is a **cancel-and-join** operation: every
//! caller is guaranteed to observe a fully-drained server before
//! the future resolves. This holds even when multiple callers
//! invoke `shutdown` concurrently AND when the future of the
//! caller that triggered the `Running -> Stopping` transition is
//! itself cancelled.
//!
//! ### Cancellation safety
//!
//! The actual drain (cancel + `JoinSet::join_next` + lifecycle
//! collapse) runs on a server-owned **detached `tokio::spawn`
//! task**. Every `shutdown` caller — including the one that
//! triggered the transition out of `Running` — observes
//! completion exclusively via a [`tokio::sync::watch::Receiver`].
//! Dropping a `shutdown` future therefore cannot strand the
//! lifecycle in `Stopping`: the detached task owns the
//! `RuntimeState` and the watch `Sender`, and is responsible for
//! collapsing `Stopping -> Stopped` and publishing
//! `DrainState::Complete` regardless of caller futures.
//!
//! ### Receiver cloning under the lock
//!
//! Concurrent `shutdown` callers that arrive while the state is
//! `Stopping` clone the `Receiver` while still holding the
//! lifecycle lock. Cloning under the lock is the load-bearing
//! race eliminator: even if the drain task publishes `Complete`
//! and drops the sender between our clone and our `await`, the
//! subsequent `changed()` call resolves synchronously (sender
//! observed as dropped) and `borrow()` shows the published value.
//! `tokio::sync::watch` is preferred over `Notify` here precisely
//! because `Notify::notified()` requires the future to be polled
//! BEFORE the notify call to capture a permit.

use std::sync::Arc;
use std::time::Duration;

use jiff::Timestamp;
use tokio::sync::{Mutex, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::error::RelayResult;
use crate::policy::PolicyRuntime;
use crate::state::LeaseRegistry;

/// Janitor cadence — Phase 5 spec U7 calls for 5s ticks. The choice
/// of constant matches Go's reference relay.
pub const JANITOR_INTERVAL: Duration = Duration::from_secs(5);

/// Top-level relay server. `Arc`-shareable.
///
/// Cloning produces a handle that points at the same orchestration
/// state — convenient for axum routers that need read-only access
/// to the lease registry + policy runtime.
#[derive(Clone)]
pub struct Server {
    inner: Arc<ServerInner>,
}

struct ServerInner {
    leases: LeaseRegistry,
    policy: Arc<PolicyRuntime>,
    /// Lifecycle guard. The mutex is held for short critical
    /// sections only — never across `JoinSet::join_next` awaits
    /// or other long-lived operations.
    lifecycle: Mutex<Lifecycle>,
}

/// Coarse-grained lifecycle phase reported by [`ServerStatus::phase`].
/// Internal callers should not rely on the integer representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecyclePhase {
    /// No janitor or spawned tasks. `start` is allowed.
    Stopped,
    /// Janitor is running. `start` rejects.
    Running,
    /// `shutdown` has been invoked; tasks are draining. `start`
    /// rejects until drain completes.
    Stopping,
}

/// Internal lifecycle representation. Carries the `RuntimeState`
/// inline in `Running`. `Stopping` carries a
/// [`watch::Receiver<DrainState>`] subscription handle so any
/// `shutdown` caller — concurrent or otherwise — can clone and
/// await completion without a lost-wakeup window. The
/// corresponding `Sender` and the `RuntimeState` itself live on
/// the spawned drain task, NOT on the caller future, so caller
/// cancellation cannot strand the lifecycle.
enum Lifecycle {
    Stopped,
    Running(RuntimeState),
    Stopping(watch::Receiver<DrainState>),
}

/// Drain status published via the watch channel. Initialised to
/// `InProgress` when `Stopping` is entered; flipped to `Complete`
/// just before the lifecycle collapses back to `Stopped`. Either
/// the sender being dropped or the value transitioning to
/// `Complete` is sufficient to release waiters; the watch channel
/// guarantees a synchronous observation regardless of polling
/// order, eliminating the lost-wakeup race a `Notify`-based
/// implementation would have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainState {
    InProgress,
    Complete,
}

impl Lifecycle {
    const fn phase(&self) -> LifecyclePhase {
        match self {
            Self::Stopped => LifecyclePhase::Stopped,
            Self::Running(_) => LifecyclePhase::Running,
            Self::Stopping(_) => LifecyclePhase::Stopping,
        }
    }
}

struct RuntimeState {
    cancel: CancellationToken,
    tasks: JoinSet<()>,
}

/// Operator-visible snapshot of the server's current state.
/// Subsequent batches extend with: listener addresses, identity
/// name, last-cleanup timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerStatus {
    /// Coarse lifecycle phase (Stopped / Running / Stopping).
    pub phase: LifecyclePhase,
    /// Convenience: `phase == Running`. Retained so callers that
    /// only care about the binary distinction don't have to import
    /// [`LifecyclePhase`].
    pub running: bool,
    /// Active lease count snapshot (lock-free read of the registry).
    pub lease_count: usize,
    /// Banned IP count snapshot.
    pub ip_filter_size: usize,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    /// Construct a new server with empty lease registry + default
    /// policy runtime. Call [`Server::start`] to launch the janitor.
    #[must_use]
    pub fn new() -> Self {
        Self::with_components(LeaseRegistry::new(), PolicyRuntime::new())
    }

    /// Construct with externally-supplied components. Phase 7's
    /// `portal-relay-bin` calls this with a `LeaseRegistry`
    /// pre-populated from disk (via `state::persistence`) and a
    /// `PolicyRuntime` configured from the on-disk admin settings.
    #[must_use]
    pub fn with_components(leases: LeaseRegistry, policy: PolicyRuntime) -> Self {
        Self {
            inner: Arc::new(ServerInner {
                leases,
                policy: Arc::new(policy),
                lifecycle: Mutex::new(Lifecycle::Stopped),
            }),
        }
    }

    /// Lease registry handle (cheap clone).
    #[must_use]
    pub fn leases(&self) -> LeaseRegistry {
        self.inner.leases.clone()
    }

    /// Policy runtime handle (cheap Arc clone).
    #[must_use]
    pub fn policy(&self) -> Arc<PolicyRuntime> {
        Arc::clone(&self.inner.policy)
    }

    /// Spawn the janitor task. Only valid from the
    /// [`LifecyclePhase::Stopped`] state.
    ///
    /// # Errors
    /// - [`crate::error::RelayError::Config`] with payload
    ///   `"server already started"` when the lifecycle is
    ///   [`LifecyclePhase::Running`].
    /// - [`crate::error::RelayError::Config`] with payload
    ///   `"server is shutting down"` when the lifecycle is
    ///   [`LifecyclePhase::Stopping`] (a prior `shutdown` is still
    ///   draining tasks). Callers may retry once shutdown
    ///   completes.
    pub async fn start(&self) -> RelayResult<()> {
        let mut guard = self.inner.lifecycle.lock().await;
        match &*guard {
            Lifecycle::Running(_) => {
                return Err(crate::error::RelayError::Config(
                    "server already started".to_owned(),
                ));
            }
            Lifecycle::Stopping(_) => {
                return Err(crate::error::RelayError::Config(
                    "server is shutting down".to_owned(),
                ));
            }
            Lifecycle::Stopped => {}
        }
        let cancel = CancellationToken::new();
        let mut tasks = JoinSet::new();

        // Janitor task.
        let leases = self.inner.leases.clone();
        let janitor_cancel = cancel.clone();
        tasks.spawn(async move {
            janitor_loop(leases, janitor_cancel).await;
        });

        *guard = Lifecycle::Running(RuntimeState { cancel, tasks });
        drop(guard);
        Ok(())
    }

    /// Cancel and join the janitor + any other spawned tasks.
    ///
    /// **Cancel-and-join semantics** — the returned future does
    /// not resolve until every spawned task has actually exited,
    /// regardless of which caller initiated the drain.
    ///
    /// **Cancellation-safe** — dropping this future does NOT
    /// abort the drain. The drain runs on a server-owned detached
    /// task spawned at the `Running -> Stopping` transition;
    /// callers only observe completion via a watch channel and
    /// hold no resources whose drop would interrupt the drain.
    ///
    /// Lifecycle semantics:
    /// - From `Running`: this caller spawns the drain task and
    ///   then awaits the same completion channel as any other
    ///   waiter. The drain task transitions
    ///   `Running -> Stopping(rx)`, drains the `JoinSet`,
    ///   collapses `Stopping -> Stopped`, and publishes
    ///   `DrainState::Complete`.
    /// - From `Stopping(rx)`: another caller already triggered
    ///   the drain. This caller clones the `Receiver` while still
    ///   holding the lifecycle lock and `await`s `changed()` to
    ///   observe the `Complete` transition (or the sender's
    ///   drop).
    /// - From `Stopped`: no-op (idempotent).
    pub async fn shutdown(&self) {
        // Phase 1: under the lock, classify the caller's role.
        // Either we trigger the drain (transition out of
        // `Running` and spawn the detached drain task), or we
        // piggy-back on an in-progress drain (`Stopping`), or
        // there is nothing to do (`Stopped`). In ALL cases we end
        // up with a `Receiver` to await — including the trigger
        // case. Owning only a `Receiver` (not the drain task,
        // not the `Sender`, not the `RuntimeState`) is what makes
        // this future cancellation-safe.
        let rx_opt = {
            let mut guard = self.inner.lifecycle.lock().await;
            let outcome = match &*guard {
                Lifecycle::Running(_) => {
                    let (tx, rx) = watch::channel(DrainState::InProgress);
                    let placeholder = Lifecycle::Stopping(rx.clone());
                    let prior = std::mem::replace(&mut *guard, placeholder);
                    let Lifecycle::Running(runtime) = prior else {
                        // Unreachable: we just matched `Running`
                        // under the same lock guard.
                        unreachable!("lifecycle changed under exclusive lock");
                    };
                    // Spawn the detached drain task. It owns the
                    // `RuntimeState` and the `Sender`; cancelling
                    // any caller's future does not affect it.
                    let inner = Arc::clone(&self.inner);
                    tokio::spawn(async move {
                        drain_task(inner, runtime, tx).await;
                    });
                    Some(rx)
                }
                Lifecycle::Stopping(rx) => Some(rx.clone()),
                Lifecycle::Stopped => None,
            };
            drop(guard);
            outcome
        };

        let Some(mut rx) = rx_opt else { return };

        // Phase 2: race-free completion wait.
        // `watch::Receiver::changed` resolves with `Ok(())` when
        // a new value is published (drain task flipped to
        // `Complete`) and with `Err(_)` once the sender is
        // dropped — both valid termination signals. We loop
        // until the borrowed value is `Complete` OR the sender
        // is dropped, whichever comes first.
        //
        // Cancellation note: dropping this future here only
        // drops the `Receiver`; the detached drain task keeps
        // running and will collapse the lifecycle on its own.
        loop {
            if matches!(*rx.borrow_and_update(), DrainState::Complete) {
                break;
            }
            if rx.changed().await.is_err() {
                // Sender dropped — drain definitely ended.
                break;
            }
        }
    }

    /// Snapshot operator-visible state.
    pub async fn status(&self) -> ServerStatus {
        let phase = self.inner.lifecycle.lock().await.phase();
        ServerStatus {
            phase,
            running: matches!(phase, LifecyclePhase::Running),
            lease_count: self.inner.leases.lease_count(),
            ip_filter_size: self.inner.policy.ip_filter.len(),
        }
    }
}

/// Detached server-owned drain task. Owns the `RuntimeState`
/// (including the `JoinSet`) and the watch `Sender`. Always
/// collapses `Stopping -> Stopped` and publishes
/// `DrainState::Complete` before exiting, so caller-future
/// cancellation cannot strand the lifecycle.
async fn drain_task(
    inner: Arc<ServerInner>,
    mut runtime: RuntimeState,
    tx: watch::Sender<DrainState>,
) {
    // Cancel and drain WITHOUT holding the lifecycle lock.
    // Concurrent `start` calls observe `Stopping` and reject;
    // concurrent `status` reads observe `Stopping` and do not
    // block. Concurrent `shutdown` callers clone our receiver and
    // park on `changed()`.
    runtime.cancel.cancel();
    while let Some(res) = runtime.tasks.join_next().await {
        if let Err(err) = res {
            tracing::warn!(?err, "server task join error");
        }
    }

    // Collapse back to `Stopped`. Take the lock for a short
    // critical section. We hold the lock while we publish
    // `Complete` so any new `Wait` arrival between collapse and
    // notify either observes `Stopped` directly (lock not yet
    // released) or observes `Complete` via its still-live
    // receiver clone.
    {
        let mut guard = inner.lifecycle.lock().await;
        debug_assert!(
            matches!(&*guard, Lifecycle::Stopping(_)),
            "lifecycle invariant: drain task's `Stopping` marker was clobbered",
        );
        *guard = Lifecycle::Stopped;
        // `send` returns `Err` if there are no receivers, which
        // is fine — we ignore. The receiver retained by the
        // triggering `shutdown` caller (or any concurrent
        // waiter) will see `Complete` synchronously on its next
        // poll.
        let _ = tx.send(DrainState::Complete);
        drop(guard);
    }
    // Sender drops on scope exit, which additionally wakes any
    // receiver still parked on `changed()` (they will get
    // `Err(_)` and exit their wait loop). Belt-and-braces wakeup
    // redundancy alongside the explicit `Complete` send.
    drop(tx);
}

/// Janitor loop body: every [`JANITOR_INTERVAL`] tick, sweep the
/// registry for expired leases. The `cleanup_expired(now)` return
/// value is currently unused; Phase 5 B7 (R10 reputation) wires it
/// to a fan-out audit channel for `lease.expire` events.
async fn janitor_loop(leases: LeaseRegistry, cancel: CancellationToken) {
    let mut ticker = tokio::time::interval(JANITOR_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Skip the immediate first tick so spawning the task doesn't
    // synchronously fire a cleanup pass.
    let _ = ticker.tick().await;
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                tracing::debug!("relay server janitor cancelled");
                break;
            }
            _ = ticker.tick() => {
                let now = Timestamp::now();
                let dropped = leases.cleanup_expired(now).await;
                if !dropped.is_empty() {
                    tracing::info!(
                        dropped = dropped.len(),
                        "lease janitor purged expired entries",
                    );
                }
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only setup")]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn new_server_has_empty_state() {
        let server = Server::new();
        let status = server.status().await;
        assert_eq!(status.phase, LifecyclePhase::Stopped);
        assert!(!status.running);
        assert_eq!(status.lease_count, 0);
        assert_eq!(status.ip_filter_size, 0);
    }

    #[tokio::test]
    async fn start_then_status_reports_running() {
        let server = Server::new();
        server.start().await.unwrap();
        let status = server.status().await;
        assert_eq!(status.phase, LifecyclePhase::Running);
        assert!(status.running);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_returns_status_to_not_running() {
        let server = Server::new();
        server.start().await.unwrap();
        server.shutdown().await;
        let status = server.status().await;
        assert_eq!(status.phase, LifecyclePhase::Stopped);
        assert!(!status.running);
    }

    #[tokio::test]
    async fn double_start_returns_error() {
        let server = Server::new();
        server.start().await.unwrap();
        let result = server.start().await;
        assert!(matches!(result, Err(crate::error::RelayError::Config(_))));
        server.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_is_idempotent() {
        let server = Server::new();
        server.start().await.unwrap();
        server.shutdown().await;
        // Second shutdown is a no-op.
        server.shutdown().await;
        let status = server.status().await;
        assert_eq!(status.phase, LifecyclePhase::Stopped);
    }

    #[tokio::test]
    async fn restart_after_shutdown_succeeds() {
        // Verifies the lifecycle collapses back to `Stopped` after
        // join completes, so a fresh `start` is permitted.
        let server = Server::new();
        server.start().await.unwrap();
        server.shutdown().await;
        server.start().await.unwrap();
        assert_eq!(
            server.status().await.phase,
            LifecyclePhase::Running,
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn concurrent_shutdown_callers_all_observe_drain() {
        // Cancel-and-join semantics: every shutdown caller must
        // see a fully-drained server when its future resolves.
        // Spawn N concurrent shutdowns; verify all of them
        // observe `Stopped` immediately after their `await`
        // returns.
        let server = Server::new();
        server.start().await.unwrap();

        let mut handles = Vec::new();
        for _ in 0..8 {
            let s = server.clone();
            handles.push(tokio::spawn(async move {
                s.shutdown().await;
                // At the moment this future resolves, the server
                // MUST be `Stopped` — not `Stopping`.
                let phase = s.status().await.phase;
                assert_eq!(
                    phase,
                    LifecyclePhase::Stopped,
                    "concurrent shutdown caller observed phase {phase:?} \
                     instead of Stopped",
                );
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }

    #[tokio::test]
    async fn shutdown_waiter_blocks_until_drain_completes() {
        // The waiter path (`Stopping` arm) must not return early.
        // Verify the waiter only completes once the drain task
        // has collapsed `Stopping -> Stopped`.
        let server = Server::new();
        server.start().await.unwrap();

        // Trigger: starts the shutdown.
        let trigger = {
            let s = server.clone();
            tokio::spawn(async move { s.shutdown().await })
        };

        // Best-effort: give the drain task a chance to take the
        // `Stopping` transition. We poll the phase until we
        // observe `Stopping` OR `Stopped` (drain may have already
        // completed on a fast machine).
        let waiter_phase_before = loop {
            let phase = server.status().await.phase;
            if matches!(phase, LifecyclePhase::Stopping | LifecyclePhase::Stopped) {
                break phase;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        };

        // Waiter: subscribes to the in-progress drain (or no-ops
        // if drain already completed).
        let waiter = {
            let s = server.clone();
            tokio::spawn(async move {
                s.shutdown().await;
                s.status().await.phase
            })
        };

        let waiter_phase_after = waiter.await.unwrap();
        trigger.await.unwrap();

        // Whatever phase we observed BEFORE awaiting the waiter,
        // AFTER the waiter resolves the server must be `Stopped`.
        assert_eq!(
            waiter_phase_after,
            LifecyclePhase::Stopped,
            "waiter returned without seeing drained state \
             (phase before wait was {waiter_phase_before:?})",
        );
    }

    #[tokio::test]
    async fn shutdown_waiter_after_drain_completion_does_not_hang() {
        // Regression test for the lost-wakeup window: a `Wait`
        // caller that clones the receiver under the lifecycle
        // lock must complete even if the drainer publishes
        // `Complete` and drops the sender between the clone and
        // the `await`. The `watch` channel guarantees a
        // synchronous observation of either `Complete` or
        // sender-dropped, so the wait must not hang.
        //
        // We reproduce the window by injecting a `Stopping`
        // marker whose sender we manually drop BEFORE invoking
        // shutdown; the second shutdown caller must observe
        // sender-dropped (the `Err(_)` path of `changed()`) and
        // exit promptly.
        let server = Server::new();
        // Manually install a `Stopping` whose sender is already
        // dropped — this models "drain task published Complete
        // and dropped sender just before our clone".
        {
            let (tx, rx) = watch::channel(DrainState::Complete);
            drop(tx);
            let mut guard = server.inner.lifecycle.lock().await;
            *guard = Lifecycle::Stopping(rx);
        }
        // This shutdown call takes the `Wait` arm. With the
        // sender already dropped, `changed()` returns `Err(_)`
        // and the value is already `Complete` — the wait loop
        // exits immediately.
        let timed = tokio::time::timeout(Duration::from_secs(1), server.shutdown()).await;
        assert!(
            timed.is_ok(),
            "shutdown waiter must not hang on dropped sender",
        );

        // Restore `Stopped` so the server can be reused.
        {
            let mut guard = server.inner.lifecycle.lock().await;
            *guard = Lifecycle::Stopped;
        }
    }

    #[tokio::test]
    async fn shutdown_is_cancellation_safe() {
        // Regression test for the cancellation-strand bug: if
        // the caller that triggers `Running -> Stopping` has its
        // future cancelled, the drain MUST still complete and
        // the lifecycle MUST still collapse back to `Stopped`.
        // Otherwise a subsequent `start` would be permanently
        // rejected.
        let server = Server::new();
        server.start().await.unwrap();

        // Trigger a shutdown and then immediately drop the
        // caller's future (via `tokio::time::timeout` with a
        // zero deadline). The detached drain task must take
        // over and finish the drain.
        let s = server.clone();
        let _ = tokio::time::timeout(Duration::from_millis(0), s.shutdown()).await;

        // Verify the server eventually returns to `Stopped`
        // even though the trigger future was cancelled.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let phase = server.status().await.phase;
            if matches!(phase, LifecyclePhase::Stopped) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "lifecycle stuck at {phase:?} after cancelled shutdown caller",
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // And: a fresh `start` succeeds, proving the lifecycle
        // is truly recoverable.
        server.start().await.unwrap();
        server.shutdown().await;
    }

    #[tokio::test]
    async fn concurrent_start_during_shutdown_is_rejected() {
        // The Codex-flagged race: a `start` issued while a prior
        // `shutdown` is still draining tasks must not create a new
        // `RuntimeState` alongside the still-running old tasks.
        // The lifecycle state machine guarantees this by parking
        // in `Stopping` until join completes.
        //
        // We exercise the rejection path directly by injecting the
        // `Stopping` marker so the rejection code path is covered
        // even on hosts where a real drain completes faster than
        // a competing `start` can race in.
        let server = Server::new();
        server.start().await.unwrap();

        let (injected_tx, injected_rx) = watch::channel(DrainState::InProgress);
        let prior = {
            let mut guard = server.inner.lifecycle.lock().await;
            std::mem::replace(&mut *guard, Lifecycle::Stopping(injected_rx))
        };

        let result = server.start().await;
        assert!(
            matches!(
                result,
                Err(crate::error::RelayError::Config(ref msg))
                    if msg == "server is shutting down",
            ),
            "expected shutting-down rejection, got {result:?}",
        );

        // Restore Running state so the eventual `shutdown` can
        // drain the original tasks cleanly.
        {
            let mut guard = server.inner.lifecycle.lock().await;
            *guard = prior;
        }
        // Drop the injected sender so any incidental waiters
        // (none expected in this test) wake up.
        drop(injected_tx);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn leases_handle_is_cheap_clone() {
        let server = Server::new();
        let h1 = server.leases();
        let h2 = server.leases();
        // Both handles point at the same registry — registering
        // through one is visible through the other.
        let now = Timestamp::now();
        let later = now
            .saturating_add(jiff::SignedDuration::from_secs(60))
            .unwrap_or(Timestamp::MAX);
        let rec = crate::state::LeaseRecord::new(
            crate::state::IdentityKey([1u8; 32]),
            "alice.test".into(),
            Vec::new(),
            later,
            now,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        );
        h1.register(rec).await.unwrap();
        assert_eq!(h2.lease_count(), 1);
    }
}
