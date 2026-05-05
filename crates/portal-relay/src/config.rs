//! Relay configuration: the Phase 5 U13 bootstrap/runtime split.
//!
//! [`RelayServerConfig`] is the bootstrap subset (immutable post-
//! startup; trust-boundary key paths, listener bind addrs, on-disk
//! state directory); [`RuntimeConfig`] is the hot-reloadable subset
//! that [`crate::reload::ReloadHandle`] swaps via `arc-swap`.
//!
//! ## R-S5-4 split rationale
//!
//! Trust-boundary keys (`ApiHttpsKey`, `KeylessSigningKey`,
//! `QuicIdentityKey`) require process restart per round-2 reviewer
//! convergence; the loader rejects in-place key rotation with a typed
//! [`crate::reload::ReloadError::TrustBoundaryKeyRequiresRestart`].
//! Non-key surfaces (`approver` mode, `bps_manager` limits,
//! `ip_filter` ban list, R10 thresholds) hot-reload via
//! [`arc_swap::ArcSwap`] with an audit-trail entry per swap.
//!
//! ## JSON shape (serde policy)
//!
//! Both structs derive `serde::Serialize` + `serde::Deserialize` so
//! the workspace consumers — the file-watcher behind
//! `cfg(feature = "config_file_watch")`, the
//! `POST /v1/admin/config/reload` and `GET /v1/admin/config/current`
//! handlers, the figment-driven
//! [`RelayConfigBundle::from_files_with_env`] loader, and the
//! operator-facing `portal-relay init` subcommand — share a stable
//! JSON contract. Each struct picks a different policy on purpose:
//!
//! - [`RuntimeConfig`] composes `#[serde(default)]` with
//!   `#[serde(deny_unknown_fields)]`. The `default` half is
//!   forward-compat: an operator's older config-file keeps loading
//!   when a future B8 follow-up adds a new field (missing keys
//!   default-fill). The `deny_unknown_fields` half is operator-typo
//!   detection on the hot-reload path: a typo in
//!   `bps_per_identity` (e.g. `bps_per_idenity`) returns `Err`
//!   instead of silently leaving the previous limit in place. The
//!   two attributes compose — old payloads still load, but
//!   unrecognised keys surface.
//! - [`RelayServerConfig`] uses `#[serde(deny_unknown_fields)]` —
//!   any unknown JSON key returns `Err`, surfacing operator typos
//!   (e.g. `api_https_keypath` for `api_https_key_path`) at load
//!   time rather than silently dropping the field. No
//!   `#[serde(default)]`: every bootstrap field must be present.
//!
//! Example bootstrap payload ([`RelayServerConfig`]):
//!
//! ```json
//! {
//!   "name": "relay-edge-01",
//!   "state_dir": "/var/lib/portal-relay",
//!   "api_https_key_path": "/etc/portal-relay/api-https.key",
//!   "keyless_signing_key_path": "/etc/portal-relay/keyless.key",
//!   "quic_identity_key_path": "/etc/portal-relay/quic-id.key"
//! }
//! ```
//!
//! Example runtime payload ([`RuntimeConfig`]):
//!
//! ```json
//! {
//!   "bps_per_identity": 4096,
//!   "ip_ban_list": ["10.0.0.1"]
//! }
//! ```

use std::path::{Path, PathBuf};

use compact_str::CompactString;

/// Bootstrap relay configuration — immutable post-startup.
///
/// Holds the trust-boundary key paths, listener bind addrs, and the
/// on-disk state directory. Reloading attempts that mutate any field
/// here surface as
/// [`crate::reload::ReloadError::TrustBoundaryKeyRequiresRestart`].
///
/// Serde policy: `#[serde(deny_unknown_fields)]` — unknown JSON keys
/// are rejected so operator typos in the bootstrap config surface as
/// deserialize errors rather than silently dropped fields.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct RelayServerConfig {
    /// Operator-friendly relay name (used in tracing + audit log).
    pub name: CompactString,
    /// On-disk state directory for lease registry + cert material.
    pub state_dir: PathBuf,
    /// Path to the API HTTPS signing key (PEM-encoded). Trust-boundary;
    /// rotation requires process restart per R-S5-4.
    pub api_https_key_path: PathBuf,
    /// Path to the keyless signing key (PEM-encoded). Trust-boundary.
    pub keyless_signing_key_path: PathBuf,
    /// Path to the QUIC backhaul identity key. Trust-boundary.
    pub quic_identity_key_path: PathBuf,
}

impl RelayServerConfig {
    /// Construct a minimal bootstrap config. Phase 5 U13 follow-up
    /// replaces this with a figment-driven builder.
    #[must_use]
    pub const fn new(
        name: CompactString,
        state_dir: PathBuf,
        api_https_key_path: PathBuf,
        keyless_signing_key_path: PathBuf,
        quic_identity_key_path: PathBuf,
    ) -> Self {
        Self {
            name,
            state_dir,
            api_https_key_path,
            keyless_signing_key_path,
            quic_identity_key_path,
        }
    }
}

/// Hot-reloadable relay configuration subset.
///
/// `RuntimeConfig` is held behind
/// `Arc<arc_swap::ArcSwap<RuntimeConfig>>` in
/// [`crate::reload::ReloadHandle`]. Every consumer that reads from
/// this struct does so via a one-load-per-method `state.load()`
/// pattern — never via a long-lived `Arc<RuntimeConfig>` borrow.
///
/// ## v0.1 fields
///
/// This iteration ships the type-level shape with one representative
/// hot-reloadable field per non-key surface so the reload primitive
/// has something to swap in tests. Subsequent B8 follow-ups extend
/// this struct as each consumer is wired through.
///
/// Serde policy: `#[serde(default)]` composed with
/// `#[serde(deny_unknown_fields)]`. The `default` half is
/// forward-compat — every field default-fills when missing from the
/// JSON input, so an older config-file keeps loading when a future
/// B8 follow-up adds a new field. The `deny_unknown_fields` half is
/// operator-typo detection on the hot-reload path — a typo in a
/// hot-reloaded key (e.g. `bps_per_idenity` for `bps_per_identity`)
/// returns `Err` instead of silently no-op'ing the swap.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Per-identity bytes-per-second cap consulted by the (future)
    /// BPS-manager surface. Operator-tunable; hot-reloadable. `0`
    /// means "no per-identity BPS cap" (open).
    pub bps_per_identity: u64,
    /// IP addresses on the operator-managed ban list. Consumed by
    /// (future) `IpFilter::replace_bans` on reload. Empty by default.
    pub ip_ban_list: Vec<std::net::IpAddr>,
}

impl RuntimeConfig {
    /// Construct a fully-defaulted runtime config.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bps_per_identity: 0,
            ip_ban_list: Vec::new(),
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// In-memory aggregate of the on-disk configuration files.
///
/// Combines the immutable [`RelayServerConfig`] (bootstrap; trust-
/// boundary key paths) and the hot-reloadable [`RuntimeConfig`]
/// (operator-tunable surface) into a single ergonomic carrier so
/// the operator workflow has a single entry point from disk to a
/// running [`crate::reload::ReloadHandle`].
///
/// This is the v0.1 simple two-file loader. A figment-driven
/// multi-source loader (env-var overrides, layered defaults,
/// combined single-file format) remains B8 territory.
///
/// # Operator workflow
///
/// ```rust,no_run
/// # use portal_relay::RelayConfigBundle;
/// # use std::path::PathBuf;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let bundle = RelayConfigBundle::from_files(
///     &PathBuf::from("./bootstrap.json"),
///     &PathBuf::from("./runtime.json"),
/// ).await?;
/// let handle = bundle.into_handle();
/// // Optionally:
/// // let _watcher = portal_relay::watch_runtime_config(
/// //     std::sync::Arc::new(handle.clone()),
/// //     PathBuf::from("./runtime.json"),
/// // )?;
/// # Ok(()) }
/// ```
///
/// # Two-file rationale
///
/// [`RelayServerConfig`] and [`RuntimeConfig`] carry different
/// serde policies: the bootstrap is strict-no-defaults
/// (`deny_unknown_fields`, no `default`), while the runtime is
/// forward-compat (`default + deny_unknown_fields`).
/// Two files preserve both policies cleanly — combining them
/// would require either a wrapping struct (whose strict-bootstrap
/// policy would propagate to the runtime half and break forward-
/// compat) or `#[serde(flatten)]` (which would lose strict-
/// bootstrap on missing keys). Splitting the on-disk format
/// avoids forcing a shared deserializer policy across two halves
/// that intentionally diverge.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RelayConfigBundle {
    /// Bootstrap (immutable post-startup) half.
    pub server: RelayServerConfig,
    /// Hot-reloadable half.
    pub runtime: RuntimeConfig,
}

impl RelayConfigBundle {
    /// Construct a bundle from in-memory configs.
    #[must_use]
    pub const fn new(server: RelayServerConfig, runtime: RuntimeConfig) -> Self {
        Self { server, runtime }
    }

    /// Read both configs from disk asynchronously.
    ///
    /// Reads `server_path` as JSON-deserialized [`RelayServerConfig`]
    /// (strict; rejects unknown keys; rejects missing keys) and
    /// `runtime_path` as JSON-deserialized [`RuntimeConfig`]
    /// (`default`-fills missing keys; rejects unknown keys).
    ///
    /// # Errors
    ///
    /// - [`ConfigLoadError::Io`] if either file cannot be opened
    ///   or read (file missing, permissions denied, ENOTDIR, etc).
    ///   The error's `path` field names which file failed.
    /// - [`ConfigLoadError::Deserialize`] if either file parses
    ///   as JSON but does not match the expected serde policy
    ///   (unknown key on either; missing required field on the
    ///   bootstrap; malformed JSON). The error's `path` field
    ///   names which file failed.
    pub async fn from_files(
        server_path: &Path,
        runtime_path: &Path,
    ) -> Result<Self, ConfigLoadError> {
        let server = load_server_config(server_path).await?;

        let runtime_bytes =
            tokio::fs::read(runtime_path)
                .await
                .map_err(|source| ConfigLoadError::Io {
                    path: runtime_path.to_path_buf(),
                    source,
                })?;
        let runtime: RuntimeConfig = serde_json::from_slice(&runtime_bytes).map_err(|source| {
            ConfigLoadError::Deserialize {
                path: runtime_path.to_path_buf(),
                source: Box::new(source),
            }
        })?;

        Ok(Self { server, runtime })
    }

    /// Read both configs from disk asynchronously, with env-var
    /// overrides layered onto the runtime half via figment.
    ///
    /// Bootstrap (`server_path`) is read strictly — env vars never
    /// override the trust-boundary key paths. Runtime (`runtime_path`)
    /// is loaded through a figment Provider chain:
    /// `Json::file(runtime_path)` then `Env::prefixed(env_prefix)`,
    /// so an operator setting e.g. `PORTAL_BPS_PER_IDENTITY=4096`
    /// overrides the runtime.json value of `bps_per_identity`.
    /// Field names are figment-conventional: env-var key (uppercase)
    /// strips the prefix and lowercases.
    ///
    /// `env_prefix` is matched literally — figment's `Env::prefixed`
    /// performs no implicit append. Operators should typically include
    /// the trailing underscore (e.g. `"PORTAL_"`, not `"PORTAL"`); a
    /// missing underscore makes `PORTALX_FOO` collide with the prefix.
    ///
    /// The runtime side still respects [`RuntimeConfig`]'s
    /// `deny_unknown_fields` policy: an env var that does not match a
    /// `RuntimeConfig` field surfaces as
    /// [`ConfigLoadError::Figment`] rather than a silent no-op.
    ///
    /// # Errors
    ///
    /// - [`ConfigLoadError::Io`] if `server_path` cannot be read.
    /// - [`ConfigLoadError::Deserialize`] if `server_path` fails the
    ///   strict-bootstrap serde policy.
    /// - [`ConfigLoadError::Figment`] if the figment Provider chain
    ///   for the runtime half fails (file read error, JSON parse
    ///   error, env-var type mismatch, unknown env-var key, etc).
    ///
    /// # Notes
    ///
    /// Process-global env-var state is read at call time. Tests using
    /// `figment::Jail::expect_with(...)` get scoped isolation.
    ///
    /// The figment provider chain is synchronous — `Json::file` reads
    /// `runtime_path` off the calling thread. The runtime config is a
    /// small JSON document (`bps_per_identity` + an IP ban list), so the
    /// blocking-I/O cost stays inside the latency budget for one-shot
    /// startup config loads. We do NOT route through
    /// [`tokio::task::spawn_blocking`] here: the synchronous read keeps
    /// the error path single-variant ([`ConfigLoadError::Figment`])
    /// without a join-error variant that does not exist in the
    /// pure-JSON [`Self::from_files`] sibling. Operators who need
    /// non-blocking semantics on a hot-reload cadence go through the
    /// `config_file_watch` feature, not this entry point.
    pub async fn from_files_with_env(
        server_path: &Path,
        runtime_path: &Path,
        env_prefix: &str,
    ) -> Result<Self, ConfigLoadError> {
        use figment::{
            Figment,
            providers::{Env, Format, Json},
        };

        let server = load_server_config(server_path).await?;

        let runtime = Figment::new()
            .merge(Json::file(runtime_path))
            .merge(Env::prefixed(env_prefix))
            .extract::<RuntimeConfig>()
            .map_err(|source| ConfigLoadError::Figment {
                path: runtime_path.to_path_buf(),
                source: Box::new(source),
            })?;

        Ok(Self { server, runtime })
    }

    /// Consume the bundle and produce a [`crate::reload::ReloadHandle`].
    #[must_use]
    pub fn into_handle(self) -> crate::reload::ReloadHandle {
        crate::reload::ReloadHandle::new(self.server, self.runtime)
    }
}

/// Read the bootstrap config from disk and parse it under
/// [`RelayServerConfig`]'s strict-no-defaults serde policy.
///
/// Shared between [`RelayConfigBundle::from_files`] and
/// [`RelayConfigBundle::from_files_with_env`]: both load the bootstrap
/// half identically (no env override on trust-boundary key paths),
/// only the runtime half differs across the two entry points.
///
/// Free-standing rather than an inherent fn on [`RelayConfigBundle`]
/// because it operates only on `server_path` and produces a
/// [`RelayServerConfig`] — there is no `&self` to bind, and putting
/// it inside the `impl RelayConfigBundle` block as an associated fn
/// would obscure that it constructs a *component* of the bundle
/// rather than a complete bundle.
async fn load_server_config(server_path: &Path) -> Result<RelayServerConfig, ConfigLoadError> {
    let server_bytes =
        tokio::fs::read(server_path)
            .await
            .map_err(|source| ConfigLoadError::Io {
                path: server_path.to_path_buf(),
                source,
            })?;
    serde_json::from_slice(&server_bytes).map_err(|source| ConfigLoadError::Deserialize {
        path: server_path.to_path_buf(),
        source: Box::new(source),
    })
}

/// Errors that can surface during [`RelayConfigBundle::from_files`].
///
/// Each variant carries the `path` that failed so the operator's
/// log message is unambiguous when both files are listed in the
/// same `from_files` call: callers can attribute the failure to
/// the bootstrap path or the runtime path without re-checking
/// disk state.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ConfigLoadError {
    /// File-system error reading the named path (file missing,
    /// permissions denied, ENOTDIR, etc).
    #[error("config file I/O error at {path:?}: {source}")]
    Io {
        /// The path the loader was reading when the error fired.
        path: PathBuf,
        /// Underlying [`std::io::Error`] from the read attempt.
        #[source]
        source: std::io::Error,
    },
    /// JSON deserialization error against the expected serde
    /// policy (unknown key, missing required field, malformed
    /// JSON). The `serde_json::Error` is boxed to keep the enum
    /// payload small.
    #[error("config file deserialize error at {path:?}: {source}")]
    Deserialize {
        /// The path whose JSON contents failed to deserialize.
        path: PathBuf,
        /// Underlying [`serde_json::Error`], boxed.
        #[source]
        source: Box<serde_json::Error>,
    },
    /// Figment merge / extract error from
    /// [`RelayConfigBundle::from_files_with_env`]. Wraps any failure in
    /// env-overlay extraction (bad env-var value, type mismatch,
    /// `deny_unknown_fields` trip) into a structured variant the
    /// operator can attribute to the env-var path. The runtime
    /// path the figment was overlaying is named so the error message
    /// stays unambiguous. The `figment::Error` is boxed to keep the
    /// enum payload small (matching the [`Self::Deserialize`]
    /// `Box<serde_json::Error>` precedent).
    #[error("config env-overlay error at {path:?}: {source}")]
    Figment {
        /// The runtime config path the env vars were overlaying.
        path: PathBuf,
        /// Underlying [`figment::Error`], boxed.
        #[source]
        source: Box<figment::Error>,
    },
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only setup")]
#[expect(
    clippy::result_large_err,
    reason = "figment::Jail::expect_with closure signature returns Result<_, figment::Error>; \
              the 208-byte payload is figment's API surface, not ours to box"
)]
mod tests {
    use super::*;

    fn sample_bootstrap() -> RelayServerConfig {
        RelayServerConfig::new(
            CompactString::from("relay-edge-01"),
            PathBuf::from("/var/lib/portal-relay"),
            PathBuf::from("/etc/portal-relay/api-https.key"),
            PathBuf::from("/etc/portal-relay/keyless.key"),
            PathBuf::from("/etc/portal-relay/quic-id.key"),
        )
    }

    #[test]
    fn runtime_config_round_trips_through_json() {
        let original = RuntimeConfig {
            bps_per_identity: 4096,
            ip_ban_list: vec!["10.0.0.1".parse().unwrap()],
        };
        let encoded = serde_json::to_string(&original).unwrap();
        let decoded: RuntimeConfig = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn runtime_config_deserializes_empty_json_to_default() {
        let decoded: RuntimeConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(decoded, RuntimeConfig::default());
        assert_eq!(decoded.bps_per_identity, 0);
        assert!(decoded.ip_ban_list.is_empty());
    }

    #[test]
    fn runtime_config_deserializes_partial_json_with_defaults() {
        let decoded: RuntimeConfig = serde_json::from_str(r#"{"bps_per_identity": 1024}"#).unwrap();
        assert_eq!(decoded.bps_per_identity, 1024);
        assert!(decoded.ip_ban_list.is_empty());
    }

    #[test]
    fn runtime_config_rejects_unknown_field() {
        // Composes with #[serde(default)]: the deny still fires even
        // though every known field would otherwise default-fill. This
        // pins the operator-typo-detection half of the dual policy —
        // a hot-reload payload with a typo'd limit returns Err rather
        // than silently leaving the previous value in place.
        let payload = r#"{"bps_per_idenity": 1024}"#;
        let err = serde_json::from_str::<RuntimeConfig>(payload).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "expected unknown-field error, got: {err}",
        );
    }

    #[test]
    fn runtime_config_rejects_unknown_field_alongside_valid_field() {
        // Composition pin: a payload that carries BOTH a valid
        // known field AND a typo'd sibling must reject. Without
        // this assertion, a future contributor who naively splits
        // `default` and `deny_unknown_fields` into separate structs
        // would still pass `runtime_config_rejects_unknown_field`
        // (which exercises only the fully-typo'd shape). This pin
        // is the operator-realistic shape: an existing config file
        // grows a typo on a new field while keeping the old one
        // working.
        let payload = r#"{"bps_per_identity": 1024, "bps_per_idenity": 2048}"#;
        let err = serde_json::from_str::<RuntimeConfig>(payload).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "expected unknown-field error on composition, got: {err}",
        );
    }

    #[test]
    fn relay_server_config_round_trips_through_json() {
        let original = sample_bootstrap();
        let encoded = serde_json::to_string(&original).unwrap();
        let decoded: RelayServerConfig = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn relay_server_config_rejects_unknown_field() {
        let payload = r#"{
            "name": "test",
            "state_dir": "/tmp",
            "api_https_key_path": "/k1.pem",
            "keyless_signing_key_path": "/k2.pem",
            "quic_identity_key_path": "/k3.pem",
            "extra_field": "hello"
        }"#;
        let err = serde_json::from_str::<RelayServerConfig>(payload).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "expected unknown-field error, got: {err}",
        );
    }

    #[test]
    fn relay_server_config_rejects_missing_field() {
        let payload = r#"{"name": "test", "state_dir": "/tmp"}"#;
        let err = serde_json::from_str::<RelayServerConfig>(payload).unwrap_err();
        assert!(
            err.to_string().contains("missing field"),
            "expected missing-field error, got: {err}",
        );
    }

    fn sample_bootstrap_json() -> String {
        r#"{
            "name": "relay-edge-01",
            "state_dir": "/var/lib/portal-relay",
            "api_https_key_path": "/etc/portal-relay/api-https.key",
            "keyless_signing_key_path": "/etc/portal-relay/keyless.key",
            "quic_identity_key_path": "/etc/portal-relay/quic-id.key"
        }"#
        .to_owned()
    }

    fn sample_runtime_json() -> String {
        r#"{"bps_per_identity": 4096, "ip_ban_list": ["10.0.0.1"]}"#.to_owned()
    }

    fn sample_runtime() -> RuntimeConfig {
        RuntimeConfig {
            bps_per_identity: 4096,
            ip_ban_list: vec!["10.0.0.1".parse().unwrap()],
        }
    }

    #[tokio::test]
    async fn relay_config_bundle_loads_from_two_valid_json_files() {
        let dir = tempfile::tempdir().unwrap();
        let server_path = dir.path().join("bootstrap.json");
        let runtime_path = dir.path().join("runtime.json");
        tokio::fs::write(&server_path, sample_bootstrap_json())
            .await
            .unwrap();
        tokio::fs::write(&runtime_path, sample_runtime_json())
            .await
            .unwrap();

        let bundle = RelayConfigBundle::from_files(&server_path, &runtime_path)
            .await
            .unwrap();

        assert_eq!(bundle.server, sample_bootstrap());
        assert_eq!(bundle.runtime, sample_runtime());
    }

    #[tokio::test]
    async fn relay_config_bundle_io_error_for_missing_server_file() {
        let dir = tempfile::tempdir().unwrap();
        let server_path = dir.path().join("does-not-exist.json");
        let runtime_path = dir.path().join("runtime.json");
        tokio::fs::write(&runtime_path, sample_runtime_json())
            .await
            .unwrap();

        let err = RelayConfigBundle::from_files(&server_path, &runtime_path)
            .await
            .unwrap_err();

        match err {
            ConfigLoadError::Io { path, .. } => assert_eq!(path, server_path),
            other => panic!("expected ConfigLoadError::Io for server, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn relay_config_bundle_io_error_for_missing_runtime_file() {
        let dir = tempfile::tempdir().unwrap();
        let server_path = dir.path().join("bootstrap.json");
        let runtime_path = dir.path().join("does-not-exist.json");
        tokio::fs::write(&server_path, sample_bootstrap_json())
            .await
            .unwrap();

        let err = RelayConfigBundle::from_files(&server_path, &runtime_path)
            .await
            .unwrap_err();

        match err {
            ConfigLoadError::Io { path, .. } => assert_eq!(path, runtime_path),
            other => panic!("expected ConfigLoadError::Io for runtime, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn relay_config_bundle_deserialize_error_for_unknown_field_in_server() {
        let dir = tempfile::tempdir().unwrap();
        let server_path = dir.path().join("bootstrap.json");
        let runtime_path = dir.path().join("runtime.json");
        let bad_server = r#"{
            "name": "relay-edge-01",
            "state_dir": "/var/lib/portal-relay",
            "api_https_key_path": "/etc/portal-relay/api-https.key",
            "keyless_signing_key_path": "/etc/portal-relay/keyless.key",
            "quic_identity_key_path": "/etc/portal-relay/quic-id.key",
            "extra_field": "hello"
        }"#;
        tokio::fs::write(&server_path, bad_server).await.unwrap();
        tokio::fs::write(&runtime_path, sample_runtime_json())
            .await
            .unwrap();

        let err = RelayConfigBundle::from_files(&server_path, &runtime_path)
            .await
            .unwrap_err();

        match err {
            ConfigLoadError::Deserialize { path, source } => {
                assert_eq!(path, server_path);
                assert!(
                    source.to_string().contains("unknown field"),
                    "expected unknown-field error, got: {source}",
                );
            }
            other => panic!("expected ConfigLoadError::Deserialize, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn relay_config_bundle_deserialize_error_for_unknown_field_in_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let server_path = dir.path().join("bootstrap.json");
        let runtime_path = dir.path().join("runtime.json");
        tokio::fs::write(&server_path, sample_bootstrap_json())
            .await
            .unwrap();
        tokio::fs::write(&runtime_path, r#"{"bps_per_idenity": 1024}"#)
            .await
            .unwrap();

        let err = RelayConfigBundle::from_files(&server_path, &runtime_path)
            .await
            .unwrap_err();

        match err {
            ConfigLoadError::Deserialize { path, source } => {
                assert_eq!(path, runtime_path);
                assert!(
                    source.to_string().contains("unknown field"),
                    "expected unknown-field error, got: {source}",
                );
            }
            other => panic!("expected ConfigLoadError::Deserialize, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn relay_config_bundle_deserialize_error_for_missing_field_in_server() {
        let dir = tempfile::tempdir().unwrap();
        let server_path = dir.path().join("bootstrap.json");
        let runtime_path = dir.path().join("runtime.json");
        tokio::fs::write(&server_path, r#"{"name": "test", "state_dir": "/tmp"}"#)
            .await
            .unwrap();
        tokio::fs::write(&runtime_path, sample_runtime_json())
            .await
            .unwrap();

        let err = RelayConfigBundle::from_files(&server_path, &runtime_path)
            .await
            .unwrap_err();

        match err {
            ConfigLoadError::Deserialize { path, source } => {
                assert_eq!(path, server_path);
                assert!(
                    source.to_string().contains("missing field"),
                    "expected missing-field error, got: {source}",
                );
            }
            other => panic!("expected ConfigLoadError::Deserialize, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn relay_config_bundle_runtime_default_fills_empty_object() {
        let dir = tempfile::tempdir().unwrap();
        let server_path = dir.path().join("bootstrap.json");
        let runtime_path = dir.path().join("runtime.json");
        tokio::fs::write(&server_path, sample_bootstrap_json())
            .await
            .unwrap();
        tokio::fs::write(&runtime_path, "{}").await.unwrap();

        let bundle = RelayConfigBundle::from_files(&server_path, &runtime_path)
            .await
            .unwrap();

        assert_eq!(bundle.runtime, RuntimeConfig::default());
    }

    #[tokio::test]
    async fn relay_config_bundle_into_handle_constructs_reload_handle_with_bundle_state() {
        let bundle = RelayConfigBundle::new(sample_bootstrap(), sample_runtime());
        let expected_server = bundle.server.clone();
        let expected_runtime = bundle.runtime.clone();

        let handle = bundle.into_handle();

        assert_eq!(*handle.bootstrap(), expected_server);
        assert_eq!(*handle.current(), expected_runtime);
    }

    // ----- from_files_with_env tests -----
    //
    // These tests use `figment::Jail::expect_with` for env-var
    // isolation. Jail is the canonical figment-test harness: it
    // changes CWD to a per-closure tempdir and scopes env-var
    // mutations to the closure body, so parallel tests cannot
    // observe each other's process-global env state. Each test
    // picks a unique env prefix (`TEST_PORTAL_RELOAD_*`,
    // `TEST_PORTAL_OVERRIDE_*`, `TEST_PORTAL_UNKNOWN_*`) so even
    // if a runner ever stops giving us scoped isolation the
    // namespaces stay disjoint.
    //
    // Jail closures are synchronous; we spin a current-thread tokio
    // runtime inside the closure to drive the async `from_files*`
    // entry points. `block_on` is the documented sync-bridge for
    // tokio.

    fn jail_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|err| panic!("failed to build jail-scoped tokio runtime: {err}"))
    }

    #[test]
    fn from_files_with_env_no_envvar_matches_from_files() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("bootstrap.json", &sample_bootstrap_json())?;
            jail.create_file("runtime.json", &sample_runtime_json())?;

            // Inside Jail the CWD is the jail dir, so relative paths
            // resolve to the just-written files. We pass them as
            // `Path` to the loader.
            let server_path = std::path::Path::new("bootstrap.json");
            let runtime_path = std::path::Path::new("runtime.json");

            let rt = jail_runtime();
            let from_files_bundle = rt
                .block_on(RelayConfigBundle::from_files(server_path, runtime_path))
                .unwrap();
            let from_env_bundle = rt
                .block_on(RelayConfigBundle::from_files_with_env(
                    server_path,
                    runtime_path,
                    "TEST_PORTAL_RELOAD_",
                ))
                .unwrap();

            assert_eq!(from_files_bundle, from_env_bundle);
            Ok(())
        });
    }

    #[test]
    fn from_files_with_env_overrides_runtime_field() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("bootstrap.json", &sample_bootstrap_json())?;
            // Start the on-disk value at 0 so the override is the
            // observable change, not a coincidence.
            jail.create_file(
                "runtime.json",
                r#"{"bps_per_identity": 0, "ip_ban_list": []}"#,
            )?;

            jail.set_env("TEST_PORTAL_OVERRIDE_BPS_PER_IDENTITY", 4096_u64);

            let rt = jail_runtime();
            let bundle = rt
                .block_on(RelayConfigBundle::from_files_with_env(
                    std::path::Path::new("bootstrap.json"),
                    std::path::Path::new("runtime.json"),
                    "TEST_PORTAL_OVERRIDE_",
                ))
                .unwrap();

            assert_eq!(bundle.runtime.bps_per_identity, 4096);
            // Bootstrap stays untouched by the env layer.
            assert_eq!(bundle.server, sample_bootstrap());
            Ok(())
        });
    }

    #[test]
    fn from_files_with_env_rejects_unknown_envvar() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("bootstrap.json", &sample_bootstrap_json())?;
            jail.create_file("runtime.json", &sample_runtime_json())?;

            // An env-var key that does not name a `RuntimeConfig`
            // field. The figment Env provider turns this into a
            // `runtime_config.unknown_field` value, which trips
            // `deny_unknown_fields` at extract time.
            jail.set_env("TEST_PORTAL_UNKNOWN_UNKNOWN_FIELD", "value");

            let rt = jail_runtime();
            let err = rt
                .block_on(RelayConfigBundle::from_files_with_env(
                    std::path::Path::new("bootstrap.json"),
                    std::path::Path::new("runtime.json"),
                    "TEST_PORTAL_UNKNOWN_",
                ))
                .unwrap_err();

            match err {
                ConfigLoadError::Figment { path, source } => {
                    assert_eq!(path, std::path::Path::new("runtime.json"));
                    assert!(
                        source.to_string().contains("unknown")
                            || source.to_string().contains("unknown_field"),
                        "expected unknown-field error from env layer, got: {source}",
                    );
                }
                other => panic!("expected ConfigLoadError::Figment, got: {other:?}"),
            }
            Ok(())
        });
    }
}
