//! MITM probe exporter label (SEC-013).

/// RFC 5705 / TLS exporter label for MITM detection (`portal` generation 2).
pub const MITM_PROBE_LABEL: &[u8] = b"portal-tunnel/mitm-probe/v2";

/// Alias used by SDK and docs that refer to `PROBE_LABEL`.
pub const PROBE_LABEL: &[u8] = MITM_PROBE_LABEL;
