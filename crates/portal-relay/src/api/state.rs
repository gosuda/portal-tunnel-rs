//! Per-surface state structs.
//!
//! Each axum router carries the minimum state it legitimately needs.
//! Cross-surface state escape is type-rejected: a handler on the
//! discovery router cannot accidentally reach the admin policy
//! mutators because its state struct doesn't carry the handle.
//!
//! Phase 5 B6 lands the type plumbing only — fields land alongside
//! their consuming handlers in subsequent batches.

use std::sync::Arc;

use crate::policy::PolicyRuntime;
use crate::state::LeaseRegistry;

/// State carried by the SDK trust-boundary router. SDK handlers see
/// the lease registry (read + write) and the policy runtime (read).
#[derive(Clone)]
pub struct SdkState {
    /// Lease registry (read + write).
    pub leases: LeaseRegistry,
    /// Policy runtime (read-only from the SDK surface).
    pub policy: Arc<PolicyRuntime>,
}

/// State carried by the admin trust-boundary router. Admin handlers
/// see the lease registry (read-only) and the policy runtime
/// (read + write — admin can ban/unban IPs, set BPS, etc).
#[derive(Clone)]
pub struct AdminState {
    /// Lease registry (read-only from the admin surface).
    pub leases: LeaseRegistry,
    /// Policy runtime (read + write).
    pub policy: Arc<PolicyRuntime>,
}

/// State carried by the discovery trust-boundary router. Discovery
/// handlers see only the lease registry's hostname index — no policy
/// mutation surface, no admin state.
#[derive(Clone)]
pub struct DiscoveryState {
    /// Lease registry (read-only, hostname-index queries only).
    pub leases: LeaseRegistry,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_are_cheaply_cloneable() {
        // Smoke test that the state types compile and clone without
        // owning anything heavy directly. This is the type-level
        // contract that subsequent handlers rely on.
        let leases = LeaseRegistry::new();
        let policy = Arc::new(PolicyRuntime::new());
        let _sdk = SdkState {
            leases: leases.clone(),
            policy: Arc::clone(&policy),
        };
        let _admin = AdminState {
            leases: leases.clone(),
            policy,
        };
        let _disc = DiscoveryState { leases };
    }
}
