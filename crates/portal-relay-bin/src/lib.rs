//! `portal-relay-bin` library surface.
//!
//! The binary crate's testable subcommand logic lives behind a thin
//! library target so integration tests under `tests/` can drive
//! `init` and the config-bundle loader directly without spawning a
//! subprocess. The binary entry point in `src/main.rs` consumes the
//! same modules.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Operator-facing env-var prefix layered onto `runtime.json` via figment.
///
/// Example: `PORTAL_RELAY_BPS_PER_IDENTITY=4096` overrides the runtime's
/// `bps_per_identity`. The env layer is applied AFTER the JSON file, so
/// the env var wins.
///
/// Trust-boundary key paths in `bootstrap.json` are NOT overridable
/// (immutable post-startup); only `runtime.json` fields accept the env
/// overlay. This keeps the bootstrap half single-sourced and auditable.
///
/// The trailing underscore is intentional. `figment::providers::Env`
/// (used inside [`portal_relay::RelayConfigBundle::from_files_with_env`])
/// performs a literal-prefix match — without the trailing `_`, an env
/// var like `PORTAL_RELAYX_FOO` would collide with the prefix.
pub const ENV_PREFIX: &str = "PORTAL_RELAY_";

pub mod init;
pub mod load;
pub mod manifest;
pub mod tui;

#[cfg(test)]
mod tests {
    use super::*;

    /// `ENV_PREFIX` MUST end with `_`. Figment's
    /// [`figment::providers::Env::prefixed`] performs a literal-prefix
    /// match: without the trailing underscore, an env var like
    /// `PORTAL_RELAYX_FOO` would collide with the prefix and silently
    /// be interpreted as a `RuntimeConfig` field. Pinning the exact
    /// constant value keeps a future refactor from accidentally
    /// dropping the underscore or renaming the prefix in a way that
    /// breaks operator runbooks.
    #[test]
    fn env_prefix_is_portal_relay_underscore() {
        assert_eq!(
            ENV_PREFIX, "PORTAL_RELAY_",
            "ENV_PREFIX is the operator-facing env-var contract; \
             changing it is a breaking change for K8s/Docker deployments",
        );
    }
}
