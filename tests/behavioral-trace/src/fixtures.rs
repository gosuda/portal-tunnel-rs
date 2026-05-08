//! Fixture loading and validation.
//!
//! Fixtures live under `../fixtures/<scenario>/{input.json,go_output.json}`.

use std::path::PathBuf;

/// Resolve the fixture directory relative to the workspace root.
#[must_use]
pub fn fixture_dir() -> PathBuf {
    let manifest = std::env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest).join("fixtures")
}
