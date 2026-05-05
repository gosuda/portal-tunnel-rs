//! SEC-010 hot-reload primitive.
//!
//! Phase 5 U13 lands the workspace-level
//! `Arc<arc_swap::ArcSwap<RuntimeConfig>>` aggregator for non-key
//! surfaces. Trust-boundary keys ([`crate::config::RelayServerConfig`]'s
//! `*_key_path` fields) require process restart per R-S5-4; the
//! [`ReloadHandle::reload`] method rejects in-place key path mutation
//! with [`ReloadError::TrustBoundaryKeyRequiresRestart`].
//!
//! ## Atomicity invariant
//!
//! Concurrent readers see either the OLD [`RuntimeConfig`] or the NEW
//! [`RuntimeConfig`], never a mix — [`arc_swap::ArcSwap::store`] is
//! atomic at the pointer level. A reader that calls
//! [`ReloadHandle::current`] mid-swap gets a snapshot from one side
//! of the swap; subsequent calls observe the new state.
//!
//! ## Consumer wiring
//!
//! This iteration ships the primitive only. Phase 5 B8 follow-ups
//! wire individual consumers (`PolicyRuntime`, `AnnounceLimiter`, SDK
//! rate-limit layer, admin auth lockout policy, `ReputationEngine`)
//! to read from a single shared [`ReloadHandle`]. Until those
//! follow-ups land, the handle is a working primitive without
//! consumers.

#[cfg(feature = "config_file_watch")]
pub mod file_watch;

use std::sync::Arc;

use arc_swap::ArcSwap;
use thiserror::Error;

use crate::config::{RelayServerConfig, RuntimeConfig};

/// Reload-time errors.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ReloadError {
    /// One or more trust-boundary key paths in the new
    /// [`RelayServerConfig`] differ from the bootstrap config. Per
    /// R-S5-4, key rotation requires process restart, not in-place
    /// reload. Operator must restart the relay binary.
    #[error(
        "trust-boundary key path mutation requires process restart: \
         changed paths = {changed_paths:?}"
    )]
    TrustBoundaryKeyRequiresRestart {
        /// Names of the bootstrap config fields that differ from the
        /// originally-loaded values.
        changed_paths: Vec<&'static str>,
    },
}

/// Hot-reload handle.
///
/// Holds the immutable bootstrap [`RelayServerConfig`] (cloned on
/// construction; never mutated) plus the live
/// `Arc<ArcSwap<RuntimeConfig>>` that consumers read from.
#[derive(Clone)]
pub struct ReloadHandle {
    bootstrap: Arc<RelayServerConfig>,
    runtime: Arc<ArcSwap<RuntimeConfig>>,
}

impl core::fmt::Debug for ReloadHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReloadHandle")
            .field("bootstrap", &self.bootstrap)
            .finish_non_exhaustive()
    }
}

impl ReloadHandle {
    /// Construct a handle from bootstrap + initial runtime config.
    /// The bootstrap config is captured by value (cloned into an
    /// [`Arc`]) and is the reference against which subsequent
    /// [`Self::reload`] calls diff trust-boundary key paths.
    #[must_use]
    pub fn new(bootstrap: RelayServerConfig, runtime: RuntimeConfig) -> Self {
        Self {
            bootstrap: Arc::new(bootstrap),
            runtime: Arc::new(ArcSwap::from_pointee(runtime)),
        }
    }

    /// Borrow the bootstrap config.
    ///
    /// Returns an `Arc<RelayServerConfig>` clone (cheap reference
    /// bump). Callers who only need to read fields can use `&*` deref
    /// or hold the [`Arc`] for the lifetime they need.
    #[must_use]
    pub fn bootstrap(&self) -> Arc<RelayServerConfig> {
        Arc::clone(&self.bootstrap)
    }

    /// Snapshot the current [`RuntimeConfig`].
    ///
    /// Returns an `Arc<RuntimeConfig>`-flavored snapshot via
    /// [`arc_swap::ArcSwap::load_full`]. The returned [`Arc`]
    /// outlives the handle's next reload — readers can hold it
    /// across `await` points without keeping a guard alive.
    #[must_use]
    pub fn current(&self) -> Arc<RuntimeConfig> {
        self.runtime.load_full()
    }

    /// Apply a new `(bootstrap_candidate, runtime)` pair atomically.
    ///
    /// Compares `bootstrap_candidate` against the handle's recorded
    /// bootstrap config; any difference in trust-boundary key paths
    /// returns [`ReloadError::TrustBoundaryKeyRequiresRestart`]
    /// WITHOUT performing the swap. On success, atomically stores
    /// the new [`RuntimeConfig`] and emits a [`tracing::info`] audit
    /// event named `event = "config.reload"` with the
    /// `swapped_fields` array enumerating the names of mutated
    /// runtime fields.
    ///
    /// ## Atomicity invariant
    ///
    /// The swap is observable to concurrent readers via
    /// [`Self::current`] — readers see either the OLD or the NEW
    /// [`RuntimeConfig`], never a mix. This is the contract pinned
    /// by `concurrent_readers_see_old_or_new_never_mixed` in
    /// `tests/arc_swap_reload.rs`.
    ///
    /// # Errors
    ///
    /// Returns
    /// [`ReloadError::TrustBoundaryKeyRequiresRestart`] when the
    /// `bootstrap_candidate` mutates `state_dir`,
    /// `api_https_key_path`, `keyless_signing_key_path`, or
    /// `quic_identity_key_path` (the trust-boundary fields per
    /// R-S5-4). The relay's `name` is NOT trust-boundary; mutating
    /// it is rejected here too because v0.1 treats the entire
    /// bootstrap config as immutable post-startup (a stricter
    /// discipline that simplifies operator expectations).
    pub fn reload(
        &self,
        bootstrap_candidate: &RelayServerConfig,
        runtime_candidate: RuntimeConfig,
    ) -> Result<(), ReloadError> {
        let mut changed_paths: Vec<&'static str> = Vec::new();
        if self.bootstrap.name != bootstrap_candidate.name {
            changed_paths.push("name");
        }
        if self.bootstrap.state_dir != bootstrap_candidate.state_dir {
            changed_paths.push("state_dir");
        }
        if self.bootstrap.api_https_key_path != bootstrap_candidate.api_https_key_path {
            changed_paths.push("api_https_key_path");
        }
        if self.bootstrap.keyless_signing_key_path != bootstrap_candidate.keyless_signing_key_path {
            changed_paths.push("keyless_signing_key_path");
        }
        if self.bootstrap.quic_identity_key_path != bootstrap_candidate.quic_identity_key_path {
            changed_paths.push("quic_identity_key_path");
        }
        if !changed_paths.is_empty() {
            return Err(ReloadError::TrustBoundaryKeyRequiresRestart { changed_paths });
        }

        let prev = self.runtime.load_full();
        let mut swapped_fields: Vec<&'static str> = Vec::new();
        if prev.bps_per_identity != runtime_candidate.bps_per_identity {
            swapped_fields.push("bps_per_identity");
        }
        if prev.ip_ban_list != runtime_candidate.ip_ban_list {
            swapped_fields.push("ip_ban_list");
        }

        self.runtime.store(Arc::new(runtime_candidate));

        tracing::info!(
            event = "config.reload",
            swapped_fields = ?swapped_fields,
            "RuntimeConfig hot-reload applied",
        );

        Ok(())
    }
}
