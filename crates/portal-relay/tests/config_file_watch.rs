//! U13 file-watcher integration tests.
//!
//! These tests are gated by `cfg(feature = "config_file_watch")`
//! AND marked `#[ignore]` by default. Real-FS `notify` events
//! are platform-dependent and CI-flaky; running them in CI
//! would create false-failure noise. To run manually:
//!
//! ```sh
//! cargo test --features config_file_watch \
//!     -p portal-relay --test config_file_watch -- --ignored
//! ```
//!
//! The non-flaky deserialize-and-reload contracts are pinned by
//! the unit tests in `tests/arc_swap_reload.rs` (iter-123) and
//! `crates/portal-relay/src/config.rs::tests` (iter-124); these
//! integration tests cover only the FS-event-trigger boundary.

#![cfg(feature = "config_file_watch")]
#![expect(
    clippy::expect_used,
    reason = "integration test: expect on known-good fixtures"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use compact_str::CompactString;
use portal_relay::{
    DEFAULT_DEBOUNCE, RelayServerConfig, ReloadHandle, RuntimeConfig, watch_runtime_config,
};

/// Build a deterministic bootstrap config the watcher will diff
/// against (the watcher uses `handle.bootstrap()` internally).
fn baseline_bootstrap() -> RelayServerConfig {
    RelayServerConfig::new(
        CompactString::const_new("test-relay"),
        PathBuf::from("/var/lib/portal/relay"),
        PathBuf::from("/etc/portal/api.key"),
        PathBuf::from("/etc/portal/keyless.key"),
        PathBuf::from("/etc/portal/quic.key"),
    )
}

/// Atomic-rename write: write to `<path>.tmp` then `rename` onto
/// `<path>`. Mirrors the operator-recommended write pattern the
/// watcher's atomicity caveat assumes.
fn atomic_write(path: &Path, contents: &str) {
    let parent = path.parent().expect("test path has a parent");
    let tmp = parent.join(format!(
        "{}.tmp",
        path.file_name()
            .expect("test path has a file name")
            .to_string_lossy(),
    ));
    std::fs::write(&tmp, contents).expect("write tmp file");
    std::fs::rename(&tmp, path).expect("atomic rename onto target");
}

/// Sleep for a multiple of the debouncer's quiescent window so
/// the watcher has time to flush a batch and run the reload.
async fn wait_for_debounce() {
    tokio::time::sleep(DEFAULT_DEBOUNCE * 4).await;
}

/// 1. Pin the happy-path FS-trigger boundary: an atomic-rename
///    write of a valid runtime-config JSON drives a swap on the
///    handle.
#[tokio::test]
#[ignore = "real-FS notify events are platform-dependent and CI-flaky"]
async fn watcher_applies_runtime_config_change() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("runtime.json");

    // Initial write so the watcher's parent-directory observer
    // has a stable fixture; the watcher itself does NOT eagerly
    // read at startup, so the handle stays at its default until
    // the post-spawn write.
    atomic_write(&path, r#"{"bps_per_identity": 1024, "ip_ban_list": []}"#);

    let handle = Arc::new(ReloadHandle::new(
        baseline_bootstrap(),
        RuntimeConfig::default(),
    ));
    assert_eq!(handle.current().bps_per_identity, 0);

    let join = watch_runtime_config(Arc::clone(&handle), path.clone()).expect("watcher spawn");

    wait_for_debounce().await;

    atomic_write(&path, r#"{"bps_per_identity": 4096, "ip_ban_list": []}"#);

    wait_for_debounce().await;

    assert_eq!(
        handle.current().bps_per_identity,
        4096,
        "runtime config should reflect the post-rename value",
    );

    join.abort();
}

/// 2. Resilience pin: a malformed JSON payload is logged and
///    skipped; the watcher continues, and the next valid write
///    drives a swap. Bad payloads do NOT terminate the loop.
#[tokio::test]
#[ignore = "real-FS notify events are platform-dependent and CI-flaky"]
async fn watcher_logs_and_continues_on_invalid_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("runtime.json");

    atomic_write(&path, r#"{"bps_per_identity": 1024, "ip_ban_list": []}"#);

    let handle = Arc::new(ReloadHandle::new(
        baseline_bootstrap(),
        RuntimeConfig::default(),
    ));
    let join = watch_runtime_config(Arc::clone(&handle), path.clone()).expect("watcher spawn");

    wait_for_debounce().await;

    // Malformed JSON: the deserialize step fails, the watcher
    // logs, and the runtime config stays at default.
    atomic_write(&path, "{");
    wait_for_debounce().await;
    assert_eq!(
        handle.current().bps_per_identity,
        0,
        "malformed payload must NOT swap the runtime config",
    );

    // Recovery: a subsequent valid write must land normally.
    atomic_write(&path, r#"{"bps_per_identity": 2048, "ip_ban_list": []}"#);
    wait_for_debounce().await;
    assert_eq!(
        handle.current().bps_per_identity,
        2048,
        "watcher must recover and apply the next valid write",
    );

    join.abort();
}

/// 3. Resilience pin: an unknown-field payload (per the
///    iter-124 `deny_unknown_fields` policy) is logged and
///    skipped; the watcher continues, and the next valid write
///    drives a swap.
#[tokio::test]
#[ignore = "real-FS notify events are platform-dependent and CI-flaky"]
async fn watcher_logs_and_continues_on_unknown_field() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("runtime.json");

    atomic_write(&path, r#"{"bps_per_identity": 1024, "ip_ban_list": []}"#);

    let handle = Arc::new(ReloadHandle::new(
        baseline_bootstrap(),
        RuntimeConfig::default(),
    ));
    let join = watch_runtime_config(Arc::clone(&handle), path.clone()).expect("watcher spawn");

    wait_for_debounce().await;

    // Unknown field: serde rejects per `deny_unknown_fields`,
    // the watcher logs, and the runtime config stays at default.
    // The payload carries every known field (so the only
    // possible deserialize-failure cause is the unknown
    // sibling) — this isolates the `deny_unknown_fields`
    // contract from the `default` half of the iter-124 policy.
    atomic_write(
        &path,
        r#"{"bps_per_identity": 8192, "ip_ban_list": [], "bps_per_idenity": 9999}"#,
    );
    wait_for_debounce().await;
    assert_eq!(
        handle.current().bps_per_identity,
        0,
        "unknown-field payload must NOT swap the runtime config",
    );

    // Recovery: a subsequent valid write must land normally.
    atomic_write(&path, r#"{"bps_per_identity": 3072, "ip_ban_list": []}"#);
    wait_for_debounce().await;
    assert_eq!(
        handle.current().bps_per_identity,
        3072,
        "watcher must recover and apply the next valid write",
    );

    join.abort();
}
