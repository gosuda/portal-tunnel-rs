//! Integration tests for `portal-relay init`.
//!
//! Drives `portal_relay_bin::init::run_init` directly (the binary's
//! testable subcommand logic lives behind a thin library target so
//! integration tests reach it without spawning a subprocess). Round-
//! trips the scaffolded files through `RelayConfigBundle::from_files`
//! to pin the bootstrap-from-disk contract end-to-end.

#![expect(clippy::unwrap_used, reason = "test-only setup")]

use std::path::PathBuf;

use portal_relay::{RelayConfigBundle, RuntimeConfig};
use portal_relay_bin::init::{InitArgs, run_init};

#[tokio::test]
async fn init_scaffolds_both_files_and_round_trips_through_loader() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir: PathBuf = dir.path().to_path_buf();

    run_init(&InitArgs {
        state_dir: state_dir.clone(),
        force: false,
    })
    .await
    .unwrap();

    let bootstrap_path = state_dir.join("bootstrap.json");
    let runtime_path = state_dir.join("runtime.json");
    assert!(bootstrap_path.exists(), "bootstrap.json should be written");
    assert!(runtime_path.exists(), "runtime.json should be written");

    let bundle = RelayConfigBundle::from_files(&bootstrap_path, &runtime_path)
        .await
        .unwrap();

    assert_eq!(bundle.runtime, RuntimeConfig::default());
    assert_eq!(bundle.server.name.as_str(), "portal-relay");
    assert_eq!(bundle.server.state_dir, state_dir);
    assert_eq!(
        bundle.server.api_https_key_path,
        state_dir.join("api-https.key")
    );
    assert_eq!(
        bundle.server.keyless_signing_key_path,
        state_dir.join("keyless.key"),
    );
    assert_eq!(
        bundle.server.quic_identity_key_path,
        state_dir.join("quic-id.key"),
    );
}

#[tokio::test]
async fn init_refuses_overwrite_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir: PathBuf = dir.path().to_path_buf();
    let bootstrap_path = state_dir.join("bootstrap.json");

    let pre_existing = "operator-edited contents";
    tokio::fs::write(&bootstrap_path, pre_existing)
        .await
        .unwrap();

    let result = run_init(&InitArgs {
        state_dir: state_dir.clone(),
        force: false,
    })
    .await;
    assert!(
        result.is_err(),
        "init should refuse to overwrite without --force"
    );

    let after = tokio::fs::read_to_string(&bootstrap_path).await.unwrap();
    assert_eq!(
        after, pre_existing,
        "pre-existing bootstrap.json must be preserved on refusal",
    );

    // The runtime.json should not have been written either — the
    // existence check runs before any directory or file mutation.
    let runtime_path = state_dir.join("runtime.json");
    assert!(
        !runtime_path.exists(),
        "runtime.json should not be created when init refuses",
    );
}

#[tokio::test]
async fn init_overwrites_with_force() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir: PathBuf = dir.path().to_path_buf();
    let bootstrap_path = state_dir.join("bootstrap.json");

    let pre_existing = "operator-edited contents";
    tokio::fs::write(&bootstrap_path, pre_existing)
        .await
        .unwrap();

    run_init(&InitArgs {
        state_dir: state_dir.clone(),
        force: true,
    })
    .await
    .unwrap();

    let after = tokio::fs::read_to_string(&bootstrap_path).await.unwrap();
    assert_ne!(
        after, pre_existing,
        "pre-existing bootstrap.json should be replaced under --force",
    );

    let runtime_path = state_dir.join("runtime.json");
    let bundle = RelayConfigBundle::from_files(&bootstrap_path, &runtime_path)
        .await
        .unwrap();
    assert_eq!(bundle.runtime, RuntimeConfig::default());
    assert_eq!(bundle.server.name.as_str(), "portal-relay");
}

#[tokio::test]
async fn init_creates_state_dir_if_missing() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("nested/sub/dir");
    assert!(
        !state_dir.exists(),
        "precondition: nested dir should not yet exist"
    );

    run_init(&InitArgs {
        state_dir: state_dir.clone(),
        force: false,
    })
    .await
    .unwrap();

    assert!(state_dir.join("bootstrap.json").exists());
    assert!(state_dir.join("runtime.json").exists());
}
