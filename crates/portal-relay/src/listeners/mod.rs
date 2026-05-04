//! Dual-stack v4+v6 listener helpers + R12-canon entry point.
//!
//! Phase 5 U3 fills in:
//! - `dual_stack.rs` — `bind_dual_stack(addr_v4, addr_v6, …)`.
//! - `canonicalize.rs` — `canonicalize_source(addr) -> SocketAddr`.
//!
//! Until U3 lands, this module is empty. The R12 invariant is owned
//! by `portal-net::dual_stack` (Phase 3 B2); Phase 5 U3 exposes the
//! relay-side policy entry point by **delegating** to that owner —
//! never duplicating the helper. Per the workspace one-owner contract,
//! this module re-exports / wraps the `portal-net` API rather than
//! reimplementing it.
