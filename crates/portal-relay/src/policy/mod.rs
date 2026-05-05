//! Policy engine — base ACL/throttling + R10 v0.1 anti-abuse.
//!
//! Phase 5 B3 lands the U6 base-policy port (narrowed): the
//! [`runtime::PolicyRuntime`] aggregator together with
//! [`ip_filter::IpFilter`] and [`proxy_trust::ProxyTrust`]. The
//! Phase 5 plan's U6 unit also sketched `Approver` and
//! `BpsManager`; both were deferred to a follow-up commit and are
//! not yet in tree. Phase 5 B7 (narrowed) lands the **core** R10
//! v0.1 per-relay reputation engine in [`reputation`] plus the
//! [`honeypot`] path-matcher struct. The U12 R10-engine follow-ups
//! are flagged inline by `TODO(R10-followup)` markers in
//! `reputation.rs` (ENS Sybil-gating exemption, honeypot call-site
//! wiring). The per-signal-kind weight plumbing, the engine-side
//! `reputation.json` persist/restore helpers, and the engine-side
//! hot-swap surface ([`reputation::ReputationEngine::swap_config`])
//! have all landed; the SIGHUP / admin-api reload run-loop trigger
//! that calls `swap_config` on a config-file change remains Phase 5
//! B8 territory. See this crate's `lib.rs` for current Phase 5
//! status.

pub mod honeypot;
pub mod ip_filter;
pub mod proxy_trust;
pub mod reputation;
pub mod runtime;

pub use honeypot::{HONEYPOT_DEFAULT_PATTERNS, HoneypotMatcher};
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
