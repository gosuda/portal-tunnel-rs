//! Shared helpers for the admin-router integration test suite.
//!
//! Each integration-test file in `crates/portal-relay/tests/` is a
//! separate test crate compiled by cargo. Sharing helpers requires
//! the canonical `mod common;` idiom: this file lives at
//! `tests/common/mod.rs` (not `tests/common.rs`, which would be
//! treated as its own test crate and trigger a "no main" warning).
//! Each test file that needs these helpers declares `mod common;` at
//! the top.
//!
//! Only helpers truly shared across ≥2 admin-router test files belong
//! here. File-specific helpers (e.g. `post_reload`, `get_current`,
//! `assert_runtime_unchanged`) stay in their own test files because
//! their shape is endpoint-specific and centralizing them would force
//! a single helper to know about every endpoint.

// Each test file declaring `mod common;` compiles this file as part
// of its own test crate. Some test crates use both helpers
// (admin_reload_endpoint, admin_get_current_config), others use only
// one (server_admin_router_chain uses baseline_bootstrap only). An
// `#[expect(dead_code)]` attribute would be unfulfilled in the
// crates that use both helpers; `#[allow(dead_code)]` is the
// correct shape — the lint may or may not fire per-crate, and we
// don't want either case to break the build.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use compact_str::CompactString;
use portal_relay::api::AdminState;
use portal_relay::policy::PolicyRuntime;
use portal_relay::state::LeaseRegistry;
use portal_relay::{RelayServerConfig, ReloadHandle};

/// Build a deterministic bootstrap config for the reload handle.
/// All admin-router integration tests use the same canonical paths
/// so a future change to `RelayServerConfig::new`'s required-field
/// shape lands in one place rather than three.
pub fn baseline_bootstrap() -> RelayServerConfig {
    RelayServerConfig::new(
        CompactString::const_new("test-relay"),
        PathBuf::from("/var/lib/portal/relay"),
        PathBuf::from("/etc/portal/api.key"),
        PathBuf::from("/etc/portal/keyless.key"),
        PathBuf::from("/etc/portal/quic.key"),
    )
}

/// Build an `AdminState` carrying the supplied (optional) reload
/// handle, with default lease registry + policy runtime.
pub fn admin_state_with(reload: Option<Arc<ReloadHandle>>) -> AdminState {
    AdminState {
        leases: LeaseRegistry::new(),
        policy: Arc::new(PolicyRuntime::new()),
        reload,
    }
}
