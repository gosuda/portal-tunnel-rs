//! Admin API helpers — auth, audit log, mutation helpers.
//!
//! Distinct from [`crate::api::admin`], which carries the HTTP
//! handlers for the admin trust-boundary router (the five endpoints
//! enumerated there). This module is reserved for auth gating,
//! audit-log emit, and helper traits shared across the admin
//! surface. None of those have landed yet — the handler-side
//! trust boundary is enforced today by listener-level mTLS / unix
//! socket / loopback-only per the threat model. See this crate's
//! `lib.rs` for current Phase 5 status.
