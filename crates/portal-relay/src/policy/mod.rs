//! Policy engine — base ACL/throttling + R10 v0.1 anti-abuse.
//!
//! Phase 5 fills in:
//! - U7 `base.rs` — IP filter + BPS throttling + proxy-trust.
//! - U8/U9/U10/U11 — R10 reputation, Sybil gating, descriptor verify,
//!   honeypot, audit log.
