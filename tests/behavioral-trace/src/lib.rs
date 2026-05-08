//! Behavioral-trace harness (Phase 7 U8.6).
//!
//! Captures canonical scenarios from the Go reference implementation
//! (`gosuda/portal-tunnel` v2.1.8) as wire/state output fixtures,
//! then replays them against the Rust port asserting
//! state-equivalence on the curated subset.
//!
//! See `CURATION.md` for the curation criteria.

pub mod docker;
pub mod fixtures;
pub mod replay;

/// Harness entry point.
pub struct BehavioralTrace;

impl Default for BehavioralTrace {
    fn default() -> Self {
        Self::new()
    }
}

impl BehavioralTrace {
    /// Create a new trace harness.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}
