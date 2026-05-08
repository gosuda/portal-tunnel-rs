//! Build-time manifest from the embedded upstream `config.toml`.
//!
//! Parsed once at program start via [`embedded_manifest`]; the TOML
//! string is baked into the binary by [`include_str!`].

use compact_str::CompactString;

/// Parsed representation of `assets/config.toml`.
#[derive(Debug, Clone, serde::Deserialize)]
#[non_exhaustive]
pub struct Manifest {
    /// Release metadata.
    pub release: Release,
    /// Wire-protocol version numbers.
    pub protocol: Protocol,
    /// Bootstrap relay list.
    pub bootstrap: Bootstrap,
}

/// `[release]` table.
#[derive(Debug, Clone, serde::Deserialize)]
#[non_exhaustive]
pub struct Release {
    /// Release tag (e.g. `v2.2.1`).
    pub version: CompactString,
    /// URL prefix for release artifacts.
    pub base_url: CompactString,
}

/// `[protocol]` table.
#[derive(Debug, Clone, serde::Deserialize)]
#[non_exhaustive]
pub struct Protocol {
    /// Tunnel protocol version.
    pub tunnel: CompactString,
    /// Discovery protocol version.
    pub discovery: CompactString,
}

/// `[bootstrap]` table.
#[derive(Debug, Clone, serde::Deserialize)]
#[non_exhaustive]
pub struct Bootstrap {
    /// Hard-coded bootstrap relay URLs.
    pub relays: Vec<CompactString>,
}

/// Static manifest parsed at first access.
///
/// # Panics
/// Panics if the embedded `config.toml` is malformed. This is a
/// compile-time/bundle correctness invariant, not a runtime failure
/// mode.
pub fn embedded_manifest() -> &'static Manifest {
    use std::sync::OnceLock;
    static MANIFEST: OnceLock<Manifest> = OnceLock::new();
    MANIFEST.get_or_init(|| {
        let raw = include_str!("../assets/config.toml");
        toml::from_str(raw).expect("embedded config.toml is valid TOML")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_manifest_parses_and_has_expected_relays() {
        let m = embedded_manifest();
        assert!(!m.release.version.is_empty());
        assert!(!m.protocol.tunnel.is_empty());
        assert!(!m.protocol.discovery.is_empty());
        assert!(
            !m.bootstrap.relays.is_empty(),
            "bootstrap relay list must not be empty"
        );
    }

    #[test]
    fn release_version_matches_cargo_pkg() {
        let m = embedded_manifest();
        assert_eq!(
            m.release.version.as_str(),
            "v2.2.1",
            "embedded manifest version must match upstream"
        );
    }
}
