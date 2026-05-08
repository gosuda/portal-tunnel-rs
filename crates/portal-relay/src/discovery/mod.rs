//! Discovery announce / refresh / query primitives.
//!
//! The discovery surface lands in follow-up commits. See this
//! crate's `lib.rs` for current Phase 5 status.
//!
//! v0.1 scaffold: the [`crate::api::state::DiscoveryState`] type
//! and the hostname-index read surface on [`crate::state::LeaseRegistry`]
//! are the only discovery-visible primitives today. The actual
//! announce/refresh/query axum handlers and the overlay peer-sync
//! integration remain deferred.
