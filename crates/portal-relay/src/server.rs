//! Top-level relay server orchestrator.
//!
//! Composes:
//! - [`crate::state::LeaseRegistry`] — papaya-backed lease store.
//! - [`crate::policy::PolicyRuntime`] — IP filter + proxy trust.
//! - 5s lease janitor task that drives `cleanup_expired`.
//!
//! Phase 5 B9 lands this orchestrator as a skeleton. The composition
//! glue that mounts the [`crate::api`] / [`crate::admin`] /
//! [`crate::discovery`] axum routers and the [`crate::keyless`] mTLS
//! surface onto live listeners, plus the `metrics-exporter-prometheus`
//! integration that publishes the `/metrics` endpoint, is the work of
//! subsequent commits. See this crate's `lib.rs` for current Phase 5
//! status.
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

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use jiff::Timestamp;
use portal_crypto::{BoxedEnsResolver, Ed25519Verifier, RelayEd25519Key};
use portal_net::PortAllocator;
use secrecy::SecretBox;
use tokio::sync::{Mutex, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::api::{AdminState, SdkState, DiscoveryState};
use crate::error::RelayResult;
use crate::policy::{PolicyRuntime, REPUTATION_PERSIST_INTERVAL, ReputationEngine};
use crate::reload::ReloadHandle;
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
    /// Optional hot-reload handle. `Some` after
    /// [`Server::with_reload_handle`]; `None` for servers
    /// constructed via [`Server::new`] or the bare
    /// [`Server::with_components`] (e.g. tests). The
    /// [`crate::api::AdminState`] returned by [`Server::admin_state`]
    /// surfaces this directly to the admin router.
    ///
    /// `with_reload_handle` allocates a fresh
    /// [`Mutex<Lifecycle>`](Lifecycle) rather than mutating in place
    /// because the builder consumes `self` and returns a new
    /// `Arc<ServerInner>`: a fresh `Lifecycle::Stopped` ensures
    /// post-`start()` misuse cannot accidentally share lifecycle
    /// state with the orphaned [`RuntimeState`] on the old
    /// `Arc<ServerInner>`.
    reload_handle: Option<Arc<ReloadHandle>>,
    /// Optional reputation-persistence pair. `Some` after
    /// [`Server::with_reputation_persistence`]; `None` for
    /// servers without an engine wired in (e.g. the bare
    /// [`Server::new`] used by lifecycle tests). When `Some`,
    /// [`Server::start`] spawns a [`crate::policy::reputation_persist_loop`]
    /// task into the `JoinSet` that flushes the engine's score
    /// snapshot to `path` every [`REPUTATION_PERSIST_INTERVAL`]
    /// until shutdown cancels the token.
    ///
    /// The pair is held flat (engine + `PathBuf`) rather than
    /// boxed into a sub-struct because both fields are cheap-clone
    /// and there is exactly one consumer (`start`) that reads them.
    reputation_persistence: Option<(ReputationEngine, PathBuf)>,
    /// Optional reputation engine bound to the SDK trust-boundary
    /// router. `Some` after [`Server::with_reputation_engine`];
    /// `None` for servers without an engine wired into the SDK
    /// surface (the bare [`Server::new`] used by lifecycle tests).
    /// [`Server::sdk_state`] consumes this field — `None` panics
    /// with a clear message because the (future) `/v1/sdk/register`
    /// handler treats engine access as a required dependency.
    ///
    /// # Coupling discipline
    ///
    /// Operators that set both [`Self::reputation_persistence`]
    /// (via [`Server::with_reputation_persistence`]) and this
    /// field (via [`Server::with_reputation_engine`]) are
    /// responsible for passing the **same** [`ReputationEngine`]
    /// instance into both: the cadence loop and the SDK handler
    /// must share a single Arc graph so a `mark_ens_named` write
    /// from the handler is observable by the persist loop's
    /// snapshot. The Server's plumbing does NOT enforce this in
    /// v0.1 — a future ergonomic improvement could collapse the
    /// two builders into one, but that is out of scope here.
    reputation_engine: Option<ReputationEngine>,
    /// Optional ENS resolver bound to the SDK trust-boundary
    /// router. `Some` after [`Server::with_ens_resolver`]; `None`
    /// for demo / no-ENS-configured deployments. Surfaced into
    /// [`SdkState::ens_resolver`] verbatim.
    ens_resolver: Option<BoxedEnsResolver>,
    /// Optional lease-token signing-key + verifier pair. `Some`
    /// after [`Server::with_relay_protocol_key`] (which derives
    /// the verifier from the same key in one shot to satisfy the
    /// [`SdkState`] verifier/signer pairing invariant); `None`
    /// until the builder is invoked. The pair is held flat (one
    /// `Option` over both halves) so the type system encodes the
    /// "either both Some, or both None" invariant — eliminating
    /// the structurally-unreachable orphan-`None` panic that a
    /// two-field shape (one `Option` per half) would force every
    /// `sdk_state` reader to defend against. Surfaced into
    /// [`SdkState::lease_token_signing_key`] /
    /// [`SdkState::lease_token_verifier`] when
    /// [`Server::sdk_state`] is called.
    relay_protocol: Option<RelayProtocolPair>,
    /// Optional TCP port allocator. `Some` after
    /// [`Server::with_reload_handle`] when the attached
    /// [`RuntimeConfig`](crate::config::RuntimeConfig) has
    /// `tcp_enabled == true`; constructed from the config's
    /// `tcp_min_port` and `tcp_max_port` with a fixed grace
    /// period. `None` when `tcp_enabled` is false, when no reload
    /// handle is attached, or when the port range is empty.
    /// Wrapped in `Arc` because `PortAllocator` does not (yet)
    /// derive `Clone`.
    port_allocator: Option<Arc<PortAllocator>>,
    /// Lifecycle guard. The mutex is held for short critical
    /// sections only — never across `JoinSet::join_next` awaits
    /// or other long-lived operations.
    lifecycle: Mutex<Lifecycle>,
}

/// Paired lease-token signing key + derived verifier, held together
/// inside [`ServerInner::relay_protocol`] as a single `Option`.
///
/// The pairing is set in one shot by
/// [`Server::with_relay_protocol_key`]: the verifier is derived from
/// the same key (via [`portal_crypto::verifying_key`]) and the two
/// handles are then bundled here. Holding them as one struct rather
/// than two parallel `Option`s on `ServerInner` removes a
/// structurally-unreachable orphan-`None` arm from
/// [`Server::sdk_state`] — a regression there would mean either both
/// halves are `Some` or both are `None`, never a torn state.
struct RelayProtocolPair {
    /// Shared lease-token signing key. `Arc<SecretBox<…>>` because
    /// [`portal_crypto::Ed25519Signer`] borrows from the underlying
    /// key (lifetime `'k`) and therefore cannot itself be
    /// `Arc`-wrapped; handlers reach for a fresh signer at call time.
    key: Arc<SecretBox<RelayEd25519Key>>,
    /// Shared lease-token verifier, derived from `key` at builder
    /// time so handlers don't redo the scalar multiplication on
    /// every verify call.
    verifier: Arc<Ed25519Verifier>,
}

impl RelayProtocolPair {
    /// Cheap-`Arc` clone of both halves of the pair. Used by
    /// [`ServerInner::clone_for_rebuild`] so each builder doesn't
    /// have to spell out the per-field `Arc::clone` ceremony.
    fn arc_clone(&self) -> Self {
        Self {
            key: Arc::clone(&self.key),
            verifier: Arc::clone(&self.verifier),
        }
    }
}

impl ServerInner {
    /// Clone every field except `lifecycle`, which is reset to a
    /// fresh `Mutex<Lifecycle::Stopped>`.
    ///
    /// The Server's builders consume `self` and return a new
    /// `Arc<ServerInner>`; allocating a fresh `Lifecycle::Stopped`
    /// guarantees post-`start()` misuse cannot accidentally share
    /// lifecycle state with the orphaned [`RuntimeState`] on the old
    /// `Arc<ServerInner>`. Every other field is either a cheap-`Arc`
    /// clone or a value clone of an `Arc`-shaped option.
    ///
    /// Builders use this with struct-update syntax —
    /// `..self.inner.clone_for_rebuild()` — to override only the
    /// field they change, so adding a tenth field requires touching
    /// only this helper rather than every builder body.
    fn clone_for_rebuild(&self) -> Self {
        Self {
            leases: self.leases.clone(),
            policy: Arc::clone(&self.policy),
            reload_handle: self.reload_handle.as_ref().map(Arc::clone),
            reputation_persistence: self.reputation_persistence.clone(),
            reputation_engine: self.reputation_engine.clone(),
            ens_resolver: self.ens_resolver.clone(),
            relay_protocol: self
                .relay_protocol
                .as_ref()
                .map(RelayProtocolPair::arc_clone),
            port_allocator: self.port_allocator.as_ref().map(Arc::clone),
            lifecycle: Mutex::new(Lifecycle::Stopped),
        }
    }
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
    ///
    /// The resulting server has no [`ReloadHandle`] attached. Use
    /// [`Self::with_reload_handle`] to bind one before [`Self::start`].
    #[must_use]
    pub fn with_components(leases: LeaseRegistry, policy: PolicyRuntime) -> Self {
        Self {
            inner: Arc::new(ServerInner {
                leases,
                policy: Arc::new(policy),
                reload_handle: None,
                reputation_persistence: None,
                reputation_engine: None,
                ens_resolver: None,
                relay_protocol: None,
                port_allocator: None,
                lifecycle: Mutex::new(Lifecycle::Stopped),
            }),
        }
    }

    /// Bind a [`ReloadHandle`] to this server, returning a fresh
    /// `Server` whose [`Self::admin_state`] surfaces the handle to
    /// the admin trust-boundary router (`POST /v1/admin/config/reload`).
    ///
    /// # Hoare invariant
    ///
    /// Must be called before [`Self::start`]. A new internal
    /// `ServerInner` is constructed by cloning the existing
    /// `leases` (cheap [`LeaseRegistry`] clone) and `policy`
    /// (cheap `Arc` clone) and attaching the supplied handle; the
    /// new lifecycle is fresh `Lifecycle::Stopped`. Calling this
    /// after `start()` is operator misuse: the prior `RuntimeState`
    /// (with its janitor task) is orphaned on the old
    /// `Arc<ServerInner>` while the new one starts a disconnected
    /// lifecycle. The bin crate's `serve` flow places this call
    /// between `with_components` and `start`, where the invariant
    /// holds by construction.
    ///
    /// In debug builds a `debug_assert!` on `lifecycle.try_lock()`
    /// surfaces the misuse: a non-`Stopped` phase under
    /// `try_lock`'s synchronous probe (no `.await`) panics. Release
    /// builds trust the caller per the doc-only contract.
    #[must_use]
    pub fn with_reload_handle(self, handle: Arc<ReloadHandle>) -> Self {
        const TCP_PORT_GRACE: Duration = Duration::from_mins(1);
        debug_assert!(
            self.inner
                .lifecycle
                .try_lock()
                .is_ok_and(|guard| matches!(*guard, Lifecycle::Stopped)),
            "Server::with_reload_handle must be called before start(); \
             try_lock failed (contention) or lifecycle is not Stopped",
        );
        // Per `ServerInner::clone_for_rebuild`'s contract: every
        // unset field carries forward verbatim, only `reload_handle`
        // is overridden, and `lifecycle` is reset to a fresh
        // `Stopped` so misuse-after-start cannot share state with
        // the orphaned `Arc<ServerInner>`.
        let runtime = handle.current();
        let port_allocator = if runtime.tcp_enabled {
            Some(Arc::new(PortAllocator::new(
                runtime.tcp_min_port,
                runtime.tcp_max_port,
                TCP_PORT_GRACE,
            )))
        } else {
            None
        };
        Self {
            inner: Arc::new(ServerInner {
                reload_handle: Some(handle),
                port_allocator,
                ..self.inner.clone_for_rebuild()
            }),
        }
    }

    /// Bind a [`ReputationEngine`] together with the on-disk path
    /// at which the engine's score snapshot should be persisted on
    /// the [`REPUTATION_PERSIST_INTERVAL`] cadence.
    ///
    /// Calling this builder enables the reputation-persist task —
    /// a [`crate::policy::reputation_persist_loop`] driver — to be
    /// spawned alongside the lease janitor when [`Self::start`] is
    /// invoked. Without this builder, [`Self::start`] spawns only
    /// the janitor and the reputation engine (if any) is not
    /// flushed by the orchestrator.
    ///
    /// # Hoare invariant
    ///
    /// Must be called before [`Self::start`] for the same reason
    /// [`Self::with_reload_handle`] documents: the builder consumes
    /// `self` and returns a new internal `Arc<ServerInner>` whose
    /// lifecycle is fresh [`LifecyclePhase::Stopped`]. Calling
    /// this after `start()` is operator misuse — the prior
    /// `RuntimeState` is orphaned on the old `Arc<ServerInner>`
    /// while the new one starts a disconnected lifecycle.
    ///
    /// In debug builds a `debug_assert!` on `lifecycle.try_lock()`
    /// surfaces the misuse.
    #[must_use]
    pub fn with_reputation_persistence(self, engine: ReputationEngine, path: PathBuf) -> Self {
        debug_assert!(
            self.inner
                .lifecycle
                .try_lock()
                .is_ok_and(|guard| matches!(*guard, Lifecycle::Stopped)),
            "Server::with_reputation_persistence must be called before start(); \
             try_lock failed (contention) or lifecycle is not Stopped",
        );
        Self {
            inner: Arc::new(ServerInner {
                reputation_persistence: Some((engine, path)),
                ..self.inner.clone_for_rebuild()
            }),
        }
    }

    /// Bind a [`ReputationEngine`] to this server's SDK trust-
    /// boundary surface. The (future) `POST /v1/sdk/register`
    /// handler reads through [`SdkState::engine`] (set by
    /// [`Self::sdk_state`]) to call
    /// [`ReputationEngine::mark_ens_named`] after a successful
    /// SIWE+ENS gating check.
    ///
    /// # Coupling discipline
    ///
    /// Operators who set both [`Self::with_reputation_persistence`]
    /// **and** this builder are responsible for passing the **same**
    /// [`ReputationEngine`] instance to both. The cadence loop and
    /// the SDK handler must share a single Arc graph so a
    /// `mark_ens_named` write from the handler is observable by the
    /// persist loop's snapshot. The Server's plumbing does NOT
    /// enforce this in v0.1 — a future ergonomic improvement could
    /// collapse the two builders into one, but that is out of scope
    /// for this slice. The bin crate is the canonical site that
    /// threads one engine clone through both call sites.
    ///
    /// # Hoare invariant
    ///
    /// Must be called before [`Self::start`] for the same reason
    /// [`Self::with_reload_handle`] documents: the builder consumes
    /// `self` and returns a new internal `Arc<ServerInner>` whose
    /// lifecycle is fresh [`LifecyclePhase::Stopped`]. Calling
    /// this after `start()` is operator misuse — the prior
    /// `RuntimeState` is orphaned on the old `Arc<ServerInner>`
    /// while the new one starts a disconnected lifecycle.
    ///
    /// In debug builds a `debug_assert!` on `lifecycle.try_lock()`
    /// surfaces the misuse.
    #[must_use]
    pub fn with_reputation_engine(self, engine: ReputationEngine) -> Self {
        debug_assert!(
            self.inner
                .lifecycle
                .try_lock()
                .is_ok_and(|guard| matches!(*guard, Lifecycle::Stopped)),
            "Server::with_reputation_engine must be called before start(); \
             try_lock failed (contention) or lifecycle is not Stopped",
        );
        if let Some(handle) = &self.inner.reload_handle {
            let engine = engine.clone();
            // TODO(B8): derive ReputationConfig from RuntimeConfig once reputation
            // fields are added to RuntimeConfig. Until then, reload resets to default.
            handle.on_reload(move |_runtime: &crate::config::RuntimeConfig| {
                engine.swap_config(crate::policy::ReputationConfig::default());
            });
        }
        Self {
            inner: Arc::new(ServerInner {
                reputation_engine: Some(engine),
                ..self.inner.clone_for_rebuild()
            }),
        }
    }

    /// Bind a [`BoxedEnsResolver`] to this server's SDK trust-
    /// boundary surface. The (future) `POST /v1/sdk/register`
    /// handler reads through [`SdkState::ens_resolver`] (set by
    /// [`Self::sdk_state`]) to drive the `address → ENS name`
    /// lookup that gates the
    /// [`ReputationEngine::mark_ens_named`] call.
    ///
    /// Optional in [`SdkState`]: deployments without an ENS
    /// resolver configured (demo / development / no-RPC paths)
    /// run with [`SdkState::ens_resolver`] left at `None`, and
    /// the handler accepts the registration without performing
    /// the ENS-bypass-marking step.
    ///
    /// # Hoare invariant
    ///
    /// Must be called before [`Self::start`]; same lifecycle
    /// contract as [`Self::with_reload_handle`].
    #[must_use]
    pub fn with_ens_resolver(self, resolver: BoxedEnsResolver) -> Self {
        debug_assert!(
            self.inner
                .lifecycle
                .try_lock()
                .is_ok_and(|guard| matches!(*guard, Lifecycle::Stopped)),
            "Server::with_ens_resolver must be called before start(); \
             try_lock failed (contention) or lifecycle is not Stopped",
        );
        Self {
            inner: Arc::new(ServerInner {
                ens_resolver: Some(resolver),
                ..self.inner.clone_for_rebuild()
            }),
        }
    }

    /// Bind a [`SecretBox<RelayEd25519Key>`] to this server's lease-
    /// token signer/verifier surface. Materialises the verifier once
    /// from [`portal_crypto::verifying_key`] and stores both the key
    /// (as `Arc<SecretBox<…>>`) and the derived [`Ed25519Verifier`]
    /// (as `Arc<Ed25519Verifier>`) on the server's internal state, so
    /// every subsequent [`Self::sdk_state`] call surfaces the matched
    /// pair through [`SdkState::lease_token_signing_key`] and
    /// [`SdkState::lease_token_verifier`].
    ///
    /// The (future) `POST /v1/sdk/register` and `POST /v1/sdk/renew`
    /// handlers consume [`SdkState::lease_token_signing_key`] to mint
    /// lease-access tokens via [`crate::state::lease_token::issue`];
    /// `GET /v1/sdk/connect` consumes
    /// [`SdkState::lease_token_verifier`] to verify them.
    ///
    /// # Coupling discipline
    ///
    /// Operators who set [`Self::with_reputation_persistence`] (the
    /// cadence loop's persisted-engine path) AND this builder are
    /// responsible for passing **consistent** material across the
    /// two surfaces. The (future) cadence loop's persisted engine
    /// will sign tokens it issues during eviction-recovery using
    /// the same material the SDK handler-consumed signer uses; the
    /// Server's plumbing does NOT enforce this in v0.1. The bin
    /// crate is the canonical site that threads one
    /// [`SecretBox<RelayEd25519Key>`] through both call sites.
    ///
    /// # Hoare invariant
    ///
    /// Must be called before [`Self::start`]; same lifecycle
    /// contract as [`Self::with_reload_handle`]. The verifier is
    /// derived once at builder time (a single scalar multiplication
    /// over the public-key portion of the signing key) and shared
    /// across handlers via `Arc`-clone, avoiding per-call rederivation
    /// inside the handler hot path.
    #[must_use]
    pub fn with_relay_protocol_key(self, key: SecretBox<RelayEd25519Key>) -> Self {
        debug_assert!(
            self.inner
                .lifecycle
                .try_lock()
                .is_ok_and(|guard| matches!(*guard, Lifecycle::Stopped)),
            "Server::with_relay_protocol_key must be called before start(); \
             try_lock failed (contention) or lifecycle is not Stopped",
        );
        let key = Arc::new(key);
        let verifier = Arc::new(Ed25519Verifier::new(portal_crypto::verifying_key(&key)));
        Self {
            inner: Arc::new(ServerInner {
                relay_protocol: Some(RelayProtocolPair { key, verifier }),
                ..self.inner.clone_for_rebuild()
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

    /// Optional hot-reload handle (cheap `Arc` clone of the
    /// option's contents). `Some` after
    /// [`Self::with_reload_handle`]; `None` otherwise.
    #[must_use]
    pub fn reload_handle(&self) -> Option<Arc<ReloadHandle>> {
        self.inner.reload_handle.as_ref().map(Arc::clone)
    }

    /// Optional reputation-engine handle bound to the SDK trust-
    /// boundary surface (cheap `Arc`-clone internally). `Some`
    /// after [`Self::with_reputation_engine`]; `None` otherwise.
    #[must_use]
    pub fn reputation_engine(&self) -> Option<ReputationEngine> {
        self.inner.reputation_engine.clone()
    }

    /// Optional ENS resolver bound to the SDK trust-boundary
    /// surface (cheap `Arc`-clone internally). `Some` after
    /// [`Self::with_ens_resolver`]; `None` otherwise.
    #[must_use]
    pub fn ens_resolver(&self) -> Option<BoxedEnsResolver> {
        self.inner.ens_resolver.clone()
    }

    /// Build the [`AdminState`] consumed by
    /// [`crate::api::build_admin_router`]. Canonical bridge between
    /// server orchestration and the admin axum router: the bin
    /// crate constructs the `Server`, attaches the optional reload
    /// handle, and then asks the server for an `AdminState` to
    /// hand to the router builder.
    #[must_use]
    pub fn admin_state(&self) -> AdminState {
        AdminState {
            leases: self.leases(),
            policy: self.policy(),
            reload: self.reload_handle(),
        }
    }

    /// Build the [`SdkState`] consumed by
    /// [`crate::api::build_sdk_router`]. Canonical bridge between
    /// server orchestration and the SDK axum router: the bin
    /// crate constructs the `Server`, attaches the reputation
    /// engine (via [`Self::with_reputation_engine`]), the
    /// relay-protocol key (via [`Self::with_relay_protocol_key`]),
    /// and the optional ENS resolver (via [`Self::with_ens_resolver`]),
    /// and then asks the server for an `SdkState` to hand to the
    /// router builder.
    ///
    /// # Panics
    ///
    /// Panics with a clear message when either
    /// [`Self::with_reputation_engine`] or
    /// [`Self::with_relay_protocol_key`] has not been called: the
    /// (future) `POST /v1/sdk/register` handler treats engine access
    /// as a required dependency, and every lease-issuing /
    /// lease-verifying SDK handler treats the relay-protocol key
    /// pair as one. The admin-router path tolerates a missing reload
    /// handle (it surfaces 503 `FeatureUnavailable` at the handler
    /// layer); the SDK-router path does not have a corresponding
    /// fallback. Callers that do not want this panic should not
    /// call `sdk_state` — `Server::admin_router` and the
    /// lease-janitor lifecycle remain reachable without it.
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "the panic carries the required-precondition contract documented on \
                  this method's `# Panics` section; callers that have not invoked \
                  `with_reputation_engine` / `with_relay_protocol_key` are \
                  operator-misuse and the eager panic surfaces the misconfiguration \
                  at orchestrator-bridge time rather than as a confusing \
                  handler-level NPE later"
    )]
    pub fn sdk_state(&self) -> SdkState {
        let engine = self.inner.reputation_engine.clone().expect(
            "Server::sdk_state requires Server::with_reputation_engine to be called first; \
             the future SDK /v1/sdk/register handler treats engine access as a required dependency",
        );
        // The signer/verifier pairing is held as a single
        // `Option<RelayProtocolPair>` on `ServerInner`, so we
        // unwrap once and destructure — the prior two-step
        // `.expect(...).expect(...)` chain (and its
        // structurally-unreachable second arm) is gone at the
        // type level: either both halves are present or neither
        // is.
        let RelayProtocolPair { key, verifier } = self
            .inner
            .relay_protocol
            .as_ref()
            .map(RelayProtocolPair::arc_clone)
            .expect(
                "Server::sdk_state requires Server::with_relay_protocol_key to be called first; \
                 the future SDK /v1/sdk/register and /v1/sdk/connect handlers treat the \
                 lease-token signer/verifier pair as a required dependency",
            );
        SdkState {
            leases: self.leases(),
            policy: self.policy(),
            engine,
            ens_resolver: self.ens_resolver(),
            lease_token_signing_key: key,
            lease_token_verifier: verifier,
        }
    }

    /// Build the [`DiscoveryState`] consumed by
    /// [`crate::api::build_discovery_router`]. Canonical bridge between
    /// server orchestration and the discovery axum router: the bin
    /// crate constructs the `Server` and then asks for a
    /// `DiscoveryState` to hand to the router builder.
    #[must_use]
    pub fn discovery_state(&self) -> DiscoveryState {
        DiscoveryState {
            leases: self.leases(),
        }
    }

    /// Hand the assembled admin [`axum::Router`] off for listener
    /// mounting. Canonical orchestrator-to-router bridge: future
    /// HTTPS listener wiring (admin trust-boundary) calls through
    /// this single entry point rather than reaching for
    /// [`Self::admin_state`] + [`crate::api::build_admin_router`]
    /// independently at every mount site.
    ///
    /// # Lifecycle
    ///
    /// Callable at any time. [`Self::admin_state`] is a cheap
    /// reader (cloning `LeaseRegistry`, `Arc<PolicyRuntime>`, and
    /// the optional `Arc<ReloadHandle>`); [`crate::api::build_admin_router`]
    /// is `axum::Router::new().route(...).with_state(...)` shape —
    /// no I/O, no state-dependent allocation. Calling before
    /// [`Self::start`] or after [`Self::shutdown`] is fine.
    ///
    /// # Endpoint contract
    ///
    /// The returned router responds to all five current admin
    /// endpoints regardless of whether [`Self::with_reload_handle`]
    /// was invoked:
    ///
    /// - `POST /v1/admin/config/reload` — surfaces 503
    ///   `FeatureUnavailable` when no reload handle is attached.
    /// - `GET  /v1/admin/config/current` — surfaces 503
    ///   `FeatureUnavailable` when no reload handle is attached.
    /// - `GET  /v1/admin/health` — stateless liveness; always 200.
    /// - `GET  /v1/admin/policy/snapshot` — derived effective
    ///   policy state; always 200, sentinel values (`None` cap,
    ///   `0` ban count) when no reload handle is attached.
    /// - `GET  /v1/admin/lease/count` — active-lease count from
    ///   the registry's lock-free read; always 200, count `0` for
    ///   an empty registry. Independent of reload-handle attachment.
    ///
    /// `Server::new()` (no `with_reload_handle`) therefore yields a
    /// router that still serves the three always-200 endpoints
    /// (health, policy/snapshot, lease/count) while the two
    /// stateful endpoints surface a documented 503.
    #[must_use]
    #[expect(
        clippy::double_must_use,
        reason = "wrapper-fn boundary contract: `axum::Router` is `#[must_use]` \
                  but the orchestrator-to-router bridge re-affirms it here, \
                  matching the discipline on `crate::api::build_admin_router`"
    )]
    pub fn admin_router(&self) -> axum::Router {
        crate::api::build_admin_router(self.admin_state())
    }

    /// Hand the assembled discovery [`axum::Router`] off for listener
    /// mounting. Canonical orchestrator-to-router bridge: future
    /// HTTPS listener wiring (discovery trust-boundary) calls through
    /// this single entry point rather than reaching for
    /// [`Self::discovery_state`] + [`crate::api::build_discovery_router`]
    /// independently at every mount site.
    ///
    /// # Lifecycle
    ///
    /// Callable at any time. [`Self::discovery_state`] is a cheap
    /// reader (cloning `LeaseRegistry` only); [`crate::api::build_discovery_router`]
    /// is `axum::Router::new().route(...).with_state(...)` shape —
    /// no I/O, no state-dependent allocation. Calling before
    /// [`Self::start`] or after [`Self::shutdown`] is fine.
    ///
    /// # Endpoint contract
    ///
    /// The returned router responds to the discovery endpoint:
    ///
    /// - `GET /v1/discovery/leases` — lists all active leases;
    ///   always 200, empty array when no leases are registered.
    #[must_use]
    #[expect(
        clippy::double_must_use,
        reason = "wrapper-fn boundary contract: `axum::Router` is `#[must_use]` \
                  but the orchestrator-to-router bridge re-affirms it here, \
                  matching the discipline on `crate::api::build_discovery_router`"
    )]
    pub fn discovery_router(&self) -> axum::Router {
        crate::api::build_discovery_router(self.discovery_state())
    }

    /// Hand the assembled SDK [`axum::Router`] off for listener
    /// mounting. Canonical orchestrator-to-router bridge: future
    /// HTTPS listener wiring (SDK trust-boundary) calls through
    /// this single entry point rather than reaching for
    /// [`Self::sdk_state`] + [`crate::api::build_sdk_router`]
    /// independently at every mount site.
    ///
    /// # Lifecycle
    ///
    /// Callable at any time. [`Self::sdk_state`] is a cheap
    /// reader; [`crate::api::build_sdk_router`]
    /// is `axum::Router::new().route(...).with_state(...)` shape —
    /// no I/O, no state-dependent allocation. Calling before
    /// [`Self::start`] or after [`Self::shutdown`] is fine.
    ///
    /// # Panics
    ///
    /// Panics with a clear message when either
    /// [`Self::with_reputation_engine`] or
    /// [`Self::with_relay_protocol_key`] has not been called.
    /// See [`Self::sdk_state`] for the precondition contract.
    #[must_use]
    #[expect(
        clippy::double_must_use,
        reason = "wrapper-fn boundary contract: `axum::Router` is `#[must_use]` \
                  but the orchestrator-to-router bridge re-affirms it here, \
                  matching the discipline on `crate::api::build_sdk_router`"
    )]
    pub fn sdk_router(&self) -> axum::Router {
        crate::api::build_sdk_router(self.sdk_state())
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

        // R10 reputation-persist cadence task. Only spawned when
        // the operator opted in via
        // [`Self::with_reputation_persistence`]; the bare
        // [`Self::new`] / [`Self::with_components`] paths leave
        // this `None` and `start` is a janitor-only spawn.
        if let Some((engine, path)) = &self.inner.reputation_persistence {
            let engine = engine.clone();
            let path = path.clone();
            let persist_cancel = cancel.clone();
            tasks.spawn(async move {
                crate::policy::reputation_persist_loop(
                    engine,
                    path,
                    REPUTATION_PERSIST_INTERVAL,
                    persist_cancel,
                )
                .await;
            });
        }

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
                    // R9: lifecycle-collapsing detached drain. The task is
                    // intentionally outside the structured-concurrency
                    // hierarchy — it owns the `JoinSet` (inside `runtime`)
                    // and must outlive any caller so cancellation cannot
                    // strand the lifecycle in `Stopping`.
                    #[expect(
                        clippy::disallowed_methods,
                        reason = "R9: lifecycle-collapsing detached drain; owns the JoinSet and outlives all callers"
                    )]
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
/// value is currently unused; a follow-up wires it to a fan-out
/// audit channel for `lease.expire` events.
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
                let report = leases.cleanup_expired(now).await;
                if !report.dropped_leases.is_empty() || report.dropped_challenges > 0 {
                    tracing::info!(
                        dropped_leases = report.dropped_leases.len(),
                        dropped_challenges = report.dropped_challenges,
                        "lease janitor purged expired entries",
                    );
                }
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::expect_used, reason = "test-only setup")]
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
        assert_eq!(server.status().await.phase, LifecyclePhase::Running,);
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
            #[expect(
                clippy::disallowed_methods,
                reason = "test code per R9: 8 concurrent shutdown callers joined via Vec<JoinHandle> at end of test"
            )]
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
            #[expect(
                clippy::disallowed_methods,
                reason = "test code per R9: trigger handle awaited at end of test"
            )]
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
            #[expect(
                clippy::disallowed_methods,
                reason = "test code per R9: waiter handle awaited at end of test"
            )]
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

    fn baseline_bootstrap() -> crate::config::RelayServerConfig {
        crate::config::RelayServerConfig::new(
            compact_str::CompactString::const_new("server-test-relay"),
            std::path::PathBuf::from("/var/lib/portal/relay"),
            std::path::PathBuf::from("/etc/portal/api.key"),
            std::path::PathBuf::from("/etc/portal/keyless.key"),
            std::path::PathBuf::from("/etc/portal/quic.key"),
        )
    }

    #[tokio::test]
    async fn with_reload_handle_attaches_handle() {
        let handle = Arc::new(ReloadHandle::new(
            baseline_bootstrap(),
            crate::config::RuntimeConfig::default(),
        ));
        let server = Server::new().with_reload_handle(Arc::clone(&handle));
        assert!(server.reload_handle().is_some());
        assert!(server.admin_state().reload.is_some());
    }

    #[tokio::test]
    async fn default_server_has_no_reload_handle() {
        let server = Server::new();
        assert!(server.reload_handle().is_none());
        assert!(server.admin_state().reload.is_none());
    }

    #[tokio::test]
    async fn admin_state_carries_server_components() {
        // Build a server with non-default leases (one record
        // pre-registered) and observe both surfaces via `admin_state`:
        // `leases` shares the live registry, `reload` mirrors the
        // attached handle.
        let leases = LeaseRegistry::new();
        let now = Timestamp::now();
        let later = now
            .saturating_add(jiff::SignedDuration::from_secs(60))
            .unwrap_or(Timestamp::MAX);
        let rec = crate::state::LeaseRecord::new(
            crate::state::IdentityKey([7u8; 32]),
            "alice.test".into(),
            Vec::new(),
            later,
            now,
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        );
        leases.register(rec).await.unwrap();

        let handle = Arc::new(ReloadHandle::new(
            baseline_bootstrap(),
            crate::config::RuntimeConfig::default(),
        ));
        let server = Server::with_components(leases, PolicyRuntime::new())
            .with_reload_handle(Arc::clone(&handle));

        let admin = server.admin_state();
        assert_eq!(admin.leases.lease_count(), 1);
        assert!(admin.reload.is_some());
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

    /// Test-fixture relay-protocol key. Deterministic seed; not used
    /// outside the inline test harness.
    fn fixture_relay_protocol_key() -> SecretBox<RelayEd25519Key> {
        portal_crypto::ed25519_from_seed_for_test([0xEEu8; 32])
    }

    #[tokio::test]
    async fn with_reputation_engine_lands_in_sdk_state() {
        // Behavioral identity check: the engine the builder
        // received and the engine surfaced via `sdk_state()` must
        // be the same Arc graph. We mark via the builder-passed
        // handle and read via the state-extracted handle; if the
        // server made an internal copy somewhere along the way,
        // the read would not see the mark.
        let engine = ReputationEngine::new();
        let server = Server::new()
            .with_reputation_engine(engine.clone())
            .with_relay_protocol_key(fixture_relay_protocol_key());
        let state = server.sdk_state();

        let id = crate::policy::IdentityKey([0xAB; 32]);
        assert!(!engine.is_ens_named(id), "fresh engine: not marked");
        engine.mark_ens_named(id);
        assert!(
            state.engine.is_ens_named(id),
            "mark on builder-passed engine handle MUST be observable via \
             SdkState::engine — the engine must traverse the builder + \
             sdk_state path as a shared Arc graph",
        );

        // And: the accessor surfaces the same engine.
        let accessor_engine = server
            .reputation_engine()
            .expect("with_reputation_engine wired the engine");
        assert!(
            accessor_engine.is_ens_named(id),
            "Server::reputation_engine() accessor surfaces the same Arc graph",
        );

        // Reverse-direction Arc-identity: mark via the accessor handle
        // and read via the state-extracted handle. The original assertion
        // above proves builder→state shares an Arc; this proves
        // accessor→state shares the SAME Arc (catches a regression
        // where `reputation_engine()` accessor would clone-construct a
        // new instance instead of routing through `ServerInner::reputation_engine`).
        let id_reverse = crate::policy::IdentityKey([0xCD; 32]);
        accessor_engine.mark_ens_named(id_reverse);
        assert!(
            state.engine.is_ens_named(id_reverse),
            "mark on accessor-returned engine handle MUST be observable \
             via SdkState::engine — both paths must share one Arc graph",
        );
    }

    /// Minimal stub [`portal_crypto::EnsResolver`] used to wrap a
    /// [`BoxedEnsResolver`] for builder-plumbing tests. Always
    /// errors / returns `Ok(None)` — handler-level behavioral
    /// coverage lives in the future `/v1/sdk/register` commit.
    struct ServerStubEnsResolver;

    impl portal_crypto::EnsResolver for ServerStubEnsResolver {
        #[expect(
            clippy::manual_async_fn,
            reason = "explicit impl Future + Send return is required to satisfy the trait's Send bound"
        )]
        fn resolve<'a>(
            &'a self,
            _name: &'a str,
        ) -> impl core::future::Future<
            Output = Result<portal_crypto::EthAddress, portal_crypto::EnsError>,
        > + Send
        + 'a {
            async move {
                Err(portal_crypto::EnsError::NameNotFound(
                    "server-test-stub".to_owned(),
                ))
            }
        }

        #[expect(
            clippy::manual_async_fn,
            reason = "explicit impl Future + Send return is required to satisfy the trait's Send bound"
        )]
        fn resolve_reverse(
            &self,
            _addr: portal_crypto::EthAddress,
        ) -> impl core::future::Future<Output = Result<Option<String>, portal_crypto::EnsError>>
        + Send
        + '_ {
            async move { Ok(None) }
        }
    }

    #[tokio::test]
    async fn with_ens_resolver_lands_in_sdk_state_or_none_default() {
        // Default path: no resolver wired in, sdk_state surfaces None.
        let engine = ReputationEngine::new();
        let server_default = Server::new()
            .with_reputation_engine(engine.clone())
            .with_relay_protocol_key(fixture_relay_protocol_key());
        let state_default = server_default.sdk_state();
        assert!(
            state_default.ens_resolver.is_none(),
            "default state: ens_resolver is None for demo / no-ENS deployments",
        );
        assert!(server_default.ens_resolver().is_none());

        // Wired path: with_ens_resolver(some) surfaces Some via sdk_state.
        let resolver = BoxedEnsResolver::new(ServerStubEnsResolver);
        let server_wired = Server::new()
            .with_reputation_engine(engine)
            .with_ens_resolver(resolver)
            .with_relay_protocol_key(fixture_relay_protocol_key());
        let state_wired = server_wired.sdk_state();
        assert!(
            state_wired.ens_resolver.is_some(),
            "with_ens_resolver(some) surfaces ens_resolver in SdkState",
        );
        assert!(server_wired.ens_resolver().is_some());
    }

    /// AC8 — the lease-token signer/verifier round-trips end-to-end
    /// through `Server::with_relay_protocol_key` → `sdk_state()`. Mints
    /// a token via the carried signer (constructed ad-hoc per the
    /// borrowed-signer contract), verifies via the carried verifier,
    /// and asserts the decoded claims match the issued identity. A
    /// regression that breaks the signer/verifier pairing inside
    /// `Server::sdk_state` (e.g. a verifier derived from a different
    /// key, or a mid-flight zeroisation of the carried key bytes)
    /// would either fail signature verification or surface a
    /// post-decode claims mismatch.
    #[tokio::test]
    async fn with_relay_protocol_key_round_trips_through_sdk_state() {
        use crate::state::IdentityKey;
        use crate::state::lease_token;

        let engine = ReputationEngine::new();
        let server = Server::new()
            .with_reputation_engine(engine)
            .with_relay_protocol_key(fixture_relay_protocol_key());
        let state = server.sdk_state();

        // Mint via the borrowed-signer-over-Arc<SecretBox<…>> shape
        // documented in `SdkState::lease_token_signing_key`.
        let signer = portal_crypto::Ed25519Signer::new(&state.lease_token_signing_key);
        let identity = IdentityKey([0x99u8; 32]);
        let expires_at = jiff::Timestamp::now()
            .saturating_add(jiff::SignedDuration::from_secs(60))
            .unwrap_or(jiff::Timestamp::MAX);
        let token = lease_token::issue(identity, expires_at, &signer)
            .expect("issue under the carried signer must succeed");

        let claims =
            lease_token::verify(&token, &state.lease_token_verifier, jiff::Timestamp::now())
                .expect(
                    "verify under the carried verifier must succeed for a freshly-issued token",
                );
        assert_eq!(
            claims.identity, identity.0,
            "decoded identity must round-trip through issue/verify under the SdkState-carried pair",
        );
        assert_eq!(
            claims.expires_at,
            expires_at.as_second(),
            "decoded expiry must round-trip through issue/verify under the SdkState-carried pair",
        );
    }
}
