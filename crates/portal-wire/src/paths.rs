//! Well-known HTTP paths (non-exhaustive; `utoipa` extends in Phase 5).

/// Health probe (unversioned).
pub const HEALTHZ: &str = "/healthz";
/// Prometheus scrape (unversioned, R11 v0.1).
pub const METRICS: &str = "/metrics";

/// API prefix for versioned routes.
pub const V1: &str = "/v1";
