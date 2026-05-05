//! Integration tests for the binary-side env-overlaid config loader.
//!
//! Drives [`portal_relay_bin::load::load_bundle_if_present`] directly
//! to pin the binary's load path against three operator-realistic
//! shapes:
//!
//! 1. State-dir empty → `Ok(None)` (first-boot before `init`).
//! 2. State-dir populated + `PORTAL_RELAY_*` env var set → bundle
//!    loads with the env value layered onto the runtime half (the
//!    iter-145 wiring activated end-to-end).
//! 3. State-dir populated + unknown `PORTAL_RELAY_*` env key set →
//!    `Err(_)` (the figment `deny_unknown_fields` contract surfaces
//!    through the binary's wrapper).
//!
//! ## Why a sync-runtime-inside-Jail pattern (not `#[tokio::test]`)
//!
//! [`figment::Jail::expect_with`] is synchronous — its closure
//! signature is `FnOnce(&mut Jail) -> figment::Result<()>`. To drive
//! the async [`load_bundle_if_present`] we build a current-thread
//! tokio runtime inside the Jail closure and `.block_on(...)` the
//! load. This is the same convention the iter-144 figment-integration
//! tests use in `crates/portal-relay/src/config.rs`.
//!
//! ## Env-var state guarantee
//!
//! `figment::Jail` restores env vars and CWD to their pre-closure
//! values before its closure returns, so mutations do not persist
//! into subsequent tests in the same process. This guards the
//! sequential leak path only — it does NOT serialize against
//! concurrent test threads that might read env vars during the
//! closure window. The two tests below that set `PORTAL_RELAY_*`
//! env vars rely on the fact that no other test in this binary
//! reads `PORTAL_RELAY_*`, plus `cargo nextest`'s default
//! one-process-per-test mode (which converts the in-process race
//! into a cross-process non-issue). Under `cargo test` (single
//! process, multi-threaded) the concurrency window is open in
//! principle but unobserved in practice.

#![expect(clippy::unwrap_used, reason = "test-only setup")]
#![expect(clippy::expect_used, reason = "test-only setup")]
#![expect(
    clippy::result_large_err,
    reason = "figment::Jail::expect_with closure signature returns Result<_, figment::Error>; \
              the 208-byte payload is figment's API surface, not ours to box"
)]
#![expect(
    clippy::missing_const_for_fn,
    reason = "test-fixture helpers stay non-const so adding a non-const \
              builder later does not force a churning ripple of `const fn` removals"
)]

use portal_relay_bin::load::load_bundle_if_present;

/// Build a current-thread tokio runtime usable inside a synchronous
/// `figment::Jail::expect_with` closure to drive the async loader.
fn jail_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|err| panic!("failed to build jail-scoped tokio runtime: {err}"))
}

/// JSON shape of `bootstrap.json` matching the iter-123/124
/// `RelayServerConfig` strict serde policy. The key paths are
/// placeholders — the binary's load path does not validate that
/// they exist on disk; that is `serve`'s job downstream.
fn sample_bootstrap_json() -> &'static str {
    r#"{
        "name": "relay-edge-test",
        "state_dir": "/var/lib/portal-relay",
        "api_https_key_path": "/etc/portal-relay/api-https.key",
        "keyless_signing_key_path": "/etc/portal-relay/keyless.key",
        "quic_identity_key_path": "/etc/portal-relay/quic-id.key"
    }"#
}

/// JSON shape of `runtime.json` with `bps_per_identity` deliberately
/// pinned to 0 so the env-overlay test (which sets it to 4096) can
/// observe the override as the visible change rather than a
/// coincidence with the default.
fn sample_runtime_json_zero_bps() -> &'static str {
    r#"{"bps_per_identity": 0, "ip_ban_list": []}"#
}

/// JSON shape of a fully valid `runtime.json` (non-default values
/// across both fields), distinct from `_zero_bps` so the file value
/// vs env value is observable in assertions. The chosen value `1024`
/// is arbitrary — both `0` (the `_zero_bps` helper) and `1024` are
/// valid `u64` values; the suffix names the literal, not validity.
fn sample_runtime_json_with_bps_1024() -> &'static str {
    r#"{"bps_per_identity": 1024, "ip_ban_list": []}"#
}

#[test]
fn load_bundle_returns_none_when_state_dir_empty() {
    // No bootstrap.json + no runtime.json — the binary must boot
    // through with `Ok(None)` so `serve` falls back to the default
    // `PolicyRuntime` (the first-boot-before-`init` operator path).
    let dir = tempfile::tempdir().unwrap();
    let rt = jail_runtime();
    let result = rt.block_on(load_bundle_if_present(dir.path())).unwrap();
    assert!(
        result.is_none(),
        "empty state_dir must produce Ok(None), got Some(_)",
    );
}

#[test]
fn load_bundle_applies_env_overlay_via_jail() {
    // Pins the iter-145 wiring end-to-end: the binary's loader must
    // honor `PORTAL_RELAY_*` env vars on the runtime half. We start
    // the file at `bps_per_identity=0` and set the env to 4096; the
    // observable assertion on `bundle.runtime.bps_per_identity ==
    // 4096` is only true if the env layer is plumbed through.
    figment::Jail::expect_with(|jail| {
        jail.create_file("bootstrap.json", sample_bootstrap_json())?;
        jail.create_file("runtime.json", sample_runtime_json_zero_bps())?;
        jail.set_env("PORTAL_RELAY_BPS_PER_IDENTITY", 4096_u64);

        // Inside Jail, CWD is the jail tempdir; pass it as the
        // state_dir so the loader resolves bootstrap.json and
        // runtime.json relative to it.
        let state_dir = std::env::current_dir().expect("jail sets CWD to tempdir");

        let rt = jail_runtime();
        let bundle = rt
            .block_on(load_bundle_if_present(&state_dir))
            .expect("loader should succeed under Jail with valid files + env")
            .expect("loader should return Some(_) when both files exist");

        assert_eq!(
            bundle.runtime.bps_per_identity, 4096,
            "env-overlay must override file value (file=0, env=4096)",
        );
        assert_eq!(
            bundle.server.name.as_str(),
            "relay-edge-test",
            "bootstrap half must load unchanged from the file",
        );
        Ok(())
    });
}

#[test]
fn load_bundle_returns_err_on_unknown_env_field() {
    // Pins that figment's `deny_unknown_fields` contract surfaces
    // end-to-end through the binary's wrapper. An env var that does
    // not name a `RuntimeConfig` field (here:
    // `PORTAL_RELAY_UNKNOWN_FIELD`) must fail the load — operators
    // catch typos at startup rather than silently running with the
    // typo'd value ignored.
    figment::Jail::expect_with(|jail| {
        jail.create_file("bootstrap.json", sample_bootstrap_json())?;
        jail.create_file("runtime.json", sample_runtime_json_with_bps_1024())?;
        jail.set_env("PORTAL_RELAY_UNKNOWN_FIELD", "value");

        let state_dir = std::env::current_dir().expect("jail sets CWD to tempdir");

        let rt = jail_runtime();
        let result = rt.block_on(load_bundle_if_present(&state_dir));
        assert!(
            result.is_err(),
            "loader must surface unknown-env-field as Err(_), got: {result:?}",
        );
        Ok(())
    });
}
