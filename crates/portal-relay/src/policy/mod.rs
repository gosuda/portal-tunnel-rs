//! Policy engine — base ACL/throttling + R10 v0.1 anti-abuse.
//!
//! Phase 5 B5 lands the minimum viable surface: `PolicyRuntime`
//! aggregator + `IpFilter` + `ProxyTrust`. Phase 5 B7 (narrowed)
//! lands the **core** R10 v0.1 per-relay reputation engine in
//! [`reputation`]. Subsequent batches extend with `Approver`,
//! `BpsManager`, ENS Sybil-gating bypass + honeypot matcher +
//! persistence per plan U12 follow-ups.

pub mod ip_filter;
pub mod proxy_trust;
pub mod reputation;
pub mod runtime;

pub use ip_filter::IpFilter;
pub use proxy_trust::ProxyTrust;
pub use reputation::{
    BlockReason, IdentityKey, LeaseId, REPUTATION_BACKPRESSURE_THRESHOLD,
    REPUTATION_BACKPRESSURE_YIELD, REPUTATION_BLOCK_THRESHOLD, REPUTATION_DECAY_CONSTANT,
    REPUTATION_DECAY_HALF_LIFE_SECS, REPUTATION_QUOTA_BURST, REPUTATION_QUOTA_SUSTAINED,
    ReputationConfig, ReputationDecision, ReputationEngine, ReputationScore, SignalKind,
    apply_decay, default_governor_quota,
};
pub use runtime::PolicyRuntime;
