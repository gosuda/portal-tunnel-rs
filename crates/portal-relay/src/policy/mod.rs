//! Policy engine — base ACL/throttling + R10 v0.1 anti-abuse.
//!
//! Phase 5 B5 lands the minimum viable surface: `PolicyRuntime`
//! aggregator + `IpFilter` + `ProxyTrust`. Subsequent batches extend
//! with `Approver`, `BpsManager`, and the R10 reputation engine.

pub mod ip_filter;
pub mod proxy_trust;
pub mod runtime;

pub use ip_filter::IpFilter;
pub use proxy_trust::ProxyTrust;
pub use runtime::PolicyRuntime;
