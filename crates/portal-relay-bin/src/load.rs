//! Binary-side config-bundle loader.
//!
//! Wraps [`RelayConfigBundle::from_files_with_env`] with the binary's
//! `Ok(None)`-on-missing-bootstrap convention so `serve` can boot
//! without the operator having run `portal-relay init` first. See
//! [`crate::ENV_PREFIX`] for the trust-boundary rationale (bootstrap
//! immutable, runtime env-overlaid).
//!
//! # Outcomes
//!
//! - `Ok(Some(bundle))` if both `bootstrap.json` and `runtime.json`
//!   exist and parse cleanly (env overlay applied to runtime).
//! - `Ok(None)` if `bootstrap.json` is missing
//!   (`std::io::ErrorKind::NotFound`); a missing `runtime.json` is
//!   silently tolerated by figment's non-required `Json::file`
//!   provider — the env layer or [`portal_relay::RuntimeConfig`]
//!   defaults supply values.
//! - `Err(_)` for any other failure (malformed JSON, permissions,
//!   env-var type mismatch, unknown env-var key, etc.).
//!
//! See [`crate::ENV_PREFIX`] for the operator-facing env-var
//! convention.

use std::path::Path;

use eyre::Context as _;
use portal_relay::{ConfigLoadError, RelayConfigBundle};

/// Load `state_dir/bootstrap.json` + `state_dir/runtime.json`,
/// applying the env-overlay layer to the runtime half.
///
/// Returns `Ok(None)` when `bootstrap.json` is missing
/// (`std::io::ErrorKind::NotFound`) — the operator has not run
/// `portal-relay init` yet. A missing `runtime.json` is silently
/// tolerated by figment's non-required `Json::file` provider: the
/// env layer (or [`RuntimeConfig`] defaults) supplies values, so a
/// `K8s` deployment shipping only env vars + bootstrap.json boots
/// without a stub `runtime.json`.
///
/// # Errors
///
/// Returns an error wrapping the underlying [`ConfigLoadError`] for
/// any failure mode that is NOT "bootstrap.json missing":
///
/// - Bootstrap I/O error other than `NotFound` (permissions, ENOTDIR).
/// - Bootstrap JSON deserialization error (unknown field, missing
///   required field, malformed JSON).
/// - Runtime figment provider chain failure: malformed runtime.json,
///   env-var type mismatch, unknown env-var key surfaced via the
///   `RuntimeConfig` `deny_unknown_fields` policy.
///
/// [`RuntimeConfig`]: portal_relay::RuntimeConfig
pub async fn load_bundle_if_present(state_dir: &Path) -> eyre::Result<Option<RelayConfigBundle>> {
    let bootstrap_path = state_dir.join("bootstrap.json");
    let runtime_path = state_dir.join("runtime.json");

    match RelayConfigBundle::from_files_with_env(&bootstrap_path, &runtime_path, crate::ENV_PREFIX)
        .await
    {
        Ok(bundle) => Ok(Some(bundle)),
        Err(ConfigLoadError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            // Bootstrap missing — operator has not run `portal-relay
            // init`. Fall through to default `PolicyRuntime`. (A
            // missing `runtime.json` does NOT reach this arm: figment's
            // `Json::file` is non-required by default and silently
            // treats a missing file as an empty dict.)
            Ok(None)
        }
        Err(other) => Err(other).context("loading config bundle"),
    }
}
