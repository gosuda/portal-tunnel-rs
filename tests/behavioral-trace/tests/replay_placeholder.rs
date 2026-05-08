//! Behavioral-trace replay placeholder.
//!
//! Full replay tests require Go fixture capture infrastructure
//! and a Docker sidecar pinned to `gosuda/portal-tunnel` v2.1.8.

use behavioral_trace::BehavioralTrace;

#[test]
fn harness_compiles() {
    let _ = BehavioralTrace::new();
}
