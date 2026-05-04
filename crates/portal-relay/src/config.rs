//! Relay configuration. Phase 5 U13 (`reload/`) lands the figment-driven
//! loader; this module currently only declares the placeholder type so
//! crate-root re-exports compile.

use compact_str::CompactString;
use std::path::PathBuf;

/// Top-level relay configuration. Phase 5 U13 fills in the fields as
/// the lease/policy/discovery surfaces land.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RelayConfig {
    /// Operator-friendly relay name (used in tracing + audit log).
    pub name: CompactString,
    /// On-disk state directory for lease registry + cert material.
    pub state_dir: PathBuf,
}

impl RelayConfig {
    /// Construct a minimal config. Phase 5 U13 replaces this with a
    /// figment-driven builder.
    #[must_use]
    pub const fn new(name: CompactString, state_dir: PathBuf) -> Self {
        Self { name, state_dir }
    }
}
