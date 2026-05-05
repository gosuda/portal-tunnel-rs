//! Relay configuration: the Phase 5 U13 bootstrap/runtime split.
//!
//! [`RelayServerConfig`] is the bootstrap subset (immutable post-
//! startup; trust-boundary key paths, listener bind addrs, on-disk
//! state directory); [`RuntimeConfig`] is the hot-reloadable subset
//! that [`crate::reload::ReloadHandle`] swaps via `arc-swap`.
//!
//! ## R-S5-4 split rationale
//!
//! Trust-boundary keys (`ApiHttpsKey`, `KeylessSigningKey`,
//! `QuicIdentityKey`) require process restart per round-2 reviewer
//! convergence; the loader rejects in-place key rotation with a typed
//! [`crate::reload::ReloadError::TrustBoundaryKeyRequiresRestart`].
//! Non-key surfaces (`approver` mode, `bps_manager` limits,
//! `ip_filter` ban list, R10 thresholds) hot-reload via
//! [`arc_swap::ArcSwap`] with an audit-trail entry per swap.

use std::path::PathBuf;

use compact_str::CompactString;

/// Bootstrap relay configuration — immutable post-startup.
///
/// Holds the trust-boundary key paths, listener bind addrs, and the
/// on-disk state directory. Reloading attempts that mutate any field
/// here surface as
/// [`crate::reload::ReloadError::TrustBoundaryKeyRequiresRestart`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RelayServerConfig {
    /// Operator-friendly relay name (used in tracing + audit log).
    pub name: CompactString,
    /// On-disk state directory for lease registry + cert material.
    pub state_dir: PathBuf,
    /// Path to the API HTTPS signing key (PEM-encoded). Trust-boundary;
    /// rotation requires process restart per R-S5-4.
    pub api_https_key_path: PathBuf,
    /// Path to the keyless signing key (PEM-encoded). Trust-boundary.
    pub keyless_signing_key_path: PathBuf,
    /// Path to the QUIC backhaul identity key. Trust-boundary.
    pub quic_identity_key_path: PathBuf,
}

impl RelayServerConfig {
    /// Construct a minimal bootstrap config. Phase 5 U13 follow-up
    /// replaces this with a figment-driven builder.
    #[must_use]
    pub const fn new(
        name: CompactString,
        state_dir: PathBuf,
        api_https_key_path: PathBuf,
        keyless_signing_key_path: PathBuf,
        quic_identity_key_path: PathBuf,
    ) -> Self {
        Self {
            name,
            state_dir,
            api_https_key_path,
            keyless_signing_key_path,
            quic_identity_key_path,
        }
    }
}

/// Hot-reloadable relay configuration subset.
///
/// `RuntimeConfig` is held behind
/// `Arc<arc_swap::ArcSwap<RuntimeConfig>>` in
/// [`crate::reload::ReloadHandle`]. Every consumer that reads from
/// this struct does so via a one-load-per-method `state.load()`
/// pattern — never via a long-lived `Arc<RuntimeConfig>` borrow.
///
/// ## v0.1 fields
///
/// This iteration ships the type-level shape with one representative
/// hot-reloadable field per non-key surface so the reload primitive
/// has something to swap in tests. Subsequent B8 follow-ups extend
/// this struct as each consumer is wired through.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RuntimeConfig {
    /// Per-identity bytes-per-second cap consulted by the (future)
    /// BPS-manager surface. Operator-tunable; hot-reloadable. `0`
    /// means "no per-identity BPS cap" (open).
    pub bps_per_identity: u64,
    /// IP addresses on the operator-managed ban list. Consumed by
    /// (future) `IpFilter::replace_bans` on reload. Empty by default.
    pub ip_ban_list: Vec<std::net::IpAddr>,
}

impl RuntimeConfig {
    /// Construct a fully-defaulted runtime config.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bps_per_identity: 0,
            ip_ban_list: Vec::new(),
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self::new()
    }
}
