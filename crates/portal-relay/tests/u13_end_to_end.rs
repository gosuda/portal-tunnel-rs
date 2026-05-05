//! U13 operator-workflow end-to-end composition tests.
//!
//! Each surface (`RelayConfigBundle::from_files`, `ReloadHandle`,
//! `PolicyRuntime::with_reload_handle`, the snapshot-read getters)
//! carries its own unit-test coverage; this file's tests pin the
//! COMPOSITION — that the load-from-disk → `ReloadHandle` →
//! `PolicyRuntime` → snapshot-read chain works as a unit, and that
//! hot-reload propagates through every link.
//!
//! Scope: NOT the file-watcher path (that lives in
//! `tests/config_file_watch.rs` behind a feature flag). These
//! tests exercise the explicit `handle.reload(...)` trigger.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only setup; integration test crate"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use compact_str::CompactString;
use portal_relay::policy::{IpFilter, PolicyRuntime};
use portal_relay::{RelayConfigBundle, RelayServerConfig, ReloadError, RuntimeConfig};

/// Build + serialise both bootstrap and runtime JSON files into `dir`.
/// Returns `(server_path, runtime_path)`.
async fn write_test_fixtures(dir: &Path, runtime: &RuntimeConfig) -> (PathBuf, PathBuf) {
    let server = RelayServerConfig::new(
        CompactString::from("relay-test"),
        dir.join("state"),
        dir.join("api-https.key"),
        dir.join("keyless.key"),
        dir.join("quic-id.key"),
    );
    let server_path = dir.join("bootstrap.json");
    let runtime_path = dir.join("runtime.json");
    tokio::fs::write(&server_path, serde_json::to_string(&server).unwrap())
        .await
        .unwrap();
    tokio::fs::write(&runtime_path, serde_json::to_string(runtime).unwrap())
        .await
        .unwrap();
    (server_path, runtime_path)
}

/// Build a non-default `RuntimeConfig` from public constructor + public
/// fields. `RuntimeConfig` is `#[non_exhaustive]` so external crates
/// cannot use struct-init or `..default()`; mutating named public
/// fields after `new()` is the supported path.
fn runtime_with(bps: u64, bans: Vec<&str>) -> RuntimeConfig {
    let mut runtime = RuntimeConfig::new();
    runtime.bps_per_identity = bps;
    runtime.ip_ban_list = bans.into_iter().map(|s| s.parse().unwrap()).collect();
    runtime
}

/// Invariant: values written to disk reach `PolicyRuntime` consumer
/// methods through the full load-from-disk → bundle → handle chain.
#[tokio::test]
async fn loader_to_policy_runtime_propagates_initial_runtime_state() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let initial = runtime_with(4096, vec!["10.0.0.1"]);
    let (server_path, runtime_path) = write_test_fixtures(tmp.path(), &initial).await;

    let bundle = RelayConfigBundle::from_files(&server_path, &runtime_path)
        .await
        .expect("from_files on well-formed fixtures");
    let handle = bundle.into_handle();
    let policy = PolicyRuntime::new().with_reload_handle(Arc::new(handle));

    assert!(policy.is_ip_banned("10.0.0.1".parse().unwrap()));
    assert!(!policy.is_ip_banned("9.9.9.9".parse().unwrap()));
    assert_eq!(policy.bps_cap_per_identity(), Some(4096));
}

/// Invariant: a successful `handle.reload(...)` propagates atomically
/// to `PolicyRuntime` reader methods — the same `PolicyRuntime`
/// instance reads the post-swap snapshot on subsequent calls.
#[tokio::test]
async fn hot_reload_via_handle_propagates_to_policy_runtime_methods() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let initial = runtime_with(4096, vec!["10.0.0.1"]);
    let (server_path, runtime_path) = write_test_fixtures(tmp.path(), &initial).await;

    let bundle = RelayConfigBundle::from_files(&server_path, &runtime_path)
        .await
        .expect("from_files on well-formed fixtures");
    let handle = Arc::new(bundle.into_handle());
    let policy = PolicyRuntime::new().with_reload_handle(Arc::clone(&handle));

    assert!(policy.is_ip_banned("10.0.0.1".parse().unwrap()));
    assert_eq!(policy.bps_cap_per_identity(), Some(4096));

    let bootstrap = handle.bootstrap();
    let next = runtime_with(100, vec!["192.168.1.1"]);
    handle
        .reload(&bootstrap, next)
        .expect("same bootstrap + new runtime swaps successfully");

    assert!(!policy.is_ip_banned("10.0.0.1".parse().unwrap()));
    assert!(policy.is_ip_banned("192.168.1.1".parse().unwrap()));
    assert_eq!(policy.bps_cap_per_identity(), Some(100));
}

/// Invariant (R-S5-4): a trust-boundary-key mutation is rejected
/// WITHOUT performing the runtime swap; consumer methods continue to
/// observe the original runtime state — no partial leak.
#[tokio::test]
async fn trust_boundary_violation_rejects_swap_keeps_runtime_state() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let initial = runtime_with(4096, vec!["10.0.0.1"]);
    let (server_path, runtime_path) = write_test_fixtures(tmp.path(), &initial).await;

    let bundle = RelayConfigBundle::from_files(&server_path, &runtime_path)
        .await
        .expect("from_files on well-formed fixtures");
    let handle = Arc::new(bundle.into_handle());
    let policy = PolicyRuntime::new().with_reload_handle(Arc::clone(&handle));

    let mut mutated_bootstrap = (*handle.bootstrap()).clone();
    mutated_bootstrap.state_dir = tmp.path().join("rotated-state");
    let next = runtime_with(100, vec!["192.168.1.1"]);

    let err = handle
        .reload(&mutated_bootstrap, next)
        .expect_err("state_dir mutation must be rejected");
    match err {
        ReloadError::TrustBoundaryKeyRequiresRestart { changed_paths } => {
            assert!(
                changed_paths.contains(&"state_dir"),
                "expected `state_dir` in changed_paths; got {changed_paths:?}",
            );
        }
        #[allow(
            unreachable_patterns,
            reason = "future ReloadError variants surface as test failure"
        )]
        other => panic!("expected TrustBoundaryKeyRequiresRestart; got {other:?}"),
    }

    assert!(policy.is_ip_banned("10.0.0.1".parse().unwrap()));
    assert!(!policy.is_ip_banned("192.168.1.1".parse().unwrap()));
    assert_eq!(policy.bps_cap_per_identity(), Some(4096));
}

/// Invariant: across the full chain, `is_ip_banned` is the union of
/// the in-memory `IpFilter` (dynamic bans) and the reload snapshot's
/// `ip_ban_list` (operator-managed bans) — both sources fire.
#[tokio::test]
async fn policy_runtime_unioned_with_inmemory_ip_filter() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let initial = runtime_with(0, vec!["10.0.0.1"]);
    let (server_path, runtime_path) = write_test_fixtures(tmp.path(), &initial).await;

    let bundle = RelayConfigBundle::from_files(&server_path, &runtime_path)
        .await
        .expect("from_files on well-formed fixtures");
    let handle = bundle.into_handle();

    let inmem = IpFilter::new();
    inmem.ban("7.7.7.7".parse().unwrap());
    let policy = PolicyRuntime::new()
        .with_ip_filter(inmem)
        .with_reload_handle(Arc::new(handle));

    assert!(policy.is_ip_banned("10.0.0.1".parse().unwrap()));
    assert!(policy.is_ip_banned("7.7.7.7".parse().unwrap()));
    assert!(!policy.is_ip_banned("9.9.9.9".parse().unwrap()));
}
