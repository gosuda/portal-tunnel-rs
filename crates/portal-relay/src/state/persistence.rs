//! Atomic-write JSON persistence with 0o600 perms (POSIX) +
//! crash-recovery rejection.
//!
//! Single owner of "write JSON to a relay state file" for the entire
//! crate. Intended consumers (each is wired in a follow-up commit;
//! none have a production call site against these helpers yet — only
//! the in-module tests exercise them):
//!
//! - identity persistence (full identity-bundle loader)
//! - lease registry snapshots
//! - admin settings
//! - R10 reputation snapshots
//!
//! See this crate's `lib.rs` for current Phase 5 status.
//!
//! ## Safety contract
//!
//! - Writes go to `<path>.tmp`, fsync the file, `rename` onto
//!   `<path>`, then fsync the parent directory on POSIX so the
//!   renamed dirent is durable across a crash. POSIX rename is
//!   atomic-replace.
//! - The `.tmp` file is created with `create_new(true)` so a stale
//!   sibling forces a hard error rather than silent overwrite. This
//!   is intentional: a leftover `.tmp` indicates a prior crash
//!   mid-write and the operator must clear it before the next write
//!   succeeds.
//! - On POSIX, the `.tmp` file is opened with `mode(0o600)` so the
//!   final renamed file inherits the restrictive perms.
//! - On read, if `<path>.tmp` exists alongside `<path>`, we
//!   `tracing::warn` and surface the orphan to the operator —
//!   indicates a prior crash mid-write; recovery is human-driven for
//!   v0.1.
//!
//! The temp-path scheme is deliberately deterministic
//! (`<path>.tmp`) so the reader's orphan-detection check is sound
//! against the writer's leftover artefacts. The trade-off is that
//! two concurrent writers to the same `path` will conflict via
//! `create_new(true)` — which is the desired behaviour, since the
//! crate guarantees a single writer per state file.

use std::path::{Path, PathBuf};

use serde::{Serialize, de::DeserializeOwned};

use crate::error::{RelayError, RelayResult};

/// Default mode for state files on Unix: owner read+write only.
pub const STATE_FILE_MODE: u32 = 0o600;

/// Serialize `value` to JSON and atomically write to `path`.
///
/// Creates the parent directory if missing. On POSIX the file is
/// created with mode 0o600 and the parent directory is fsync'd after
/// rename so the new dirent is durable across a crash.
///
/// # Errors
/// Returns [`RelayError::Io`] on any FS failure;
/// [`RelayError::Config`] on JSON serialization failure (the value
/// itself is malformed for serde).
pub async fn write_json_atomic<T: Serialize + Sync>(path: &Path, value: &T) -> RelayResult<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| RelayError::Config(format!("serialize {}: {e}", path.display())))?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let tmp = sibling_tmp(path);
    let write_result = write_inner(&tmp, &bytes, STATE_FILE_MODE).await;
    if let Err(err) = write_result {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(err);
    }
    if let Err(rename_err) = tokio::fs::rename(&tmp, path).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(RelayError::Io(rename_err));
    }
    // Parent-directory fsync makes the rename durable. On non-POSIX
    // platforms this is a no-op; the function documents the resulting
    // weaker guarantee at the module level.
    if let Some(parent) = path.parent() {
        fsync_dir(parent).await?;
    }
    Ok(())
}

/// Read + deserialize JSON from `path`.
///
/// If a `<path>.tmp` orphan sibling exists alongside the canonical
/// file, log a warning but still proceed (the canonical file is the
/// source of truth; the orphan indicates a prior crash mid-write
/// that the operator should clean up).
///
/// # Errors
/// Returns [`RelayError::Io`] when the file is missing or unreadable;
/// [`RelayError::Config`] on JSON deserialization failure.
pub async fn read_json<T: DeserializeOwned>(path: &Path) -> RelayResult<T> {
    let tmp = sibling_tmp(path);
    if tokio::fs::metadata(&tmp).await.is_ok() {
        tracing::warn!(
            path = %path.display(),
            tmp = %tmp.display(),
            "stale .tmp sibling indicates prior crash mid-write — \
             canonical file is still authoritative; remove the .tmp \
             once the relay confirms state integrity",
        );
    }
    let bytes = tokio::fs::read(path).await?;
    serde_json::from_slice(&bytes)
        .map_err(|e| RelayError::Config(format!("deserialize {}: {e}", path.display())))
}

async fn write_inner(tmp: &Path, bytes: &[u8], mode: u32) -> RelayResult<()> {
    use tokio::io::AsyncWriteExt as _;

    let mut opts = tokio::fs::OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    {
        // Windows: no per-file ACL discipline at this layer; the parent
        // directory's ACL is the operator's responsibility. Workspace
        // ADR documents the platform-conditional posture.
        let _ = mode;
    }
    let mut f = opts.open(tmp).await?;
    f.write_all(bytes).await?;
    f.sync_all().await?;
    Ok(())
}

/// Fsync the directory at `dir` so a preceding `rename` is durable
/// across a crash. POSIX-only; the non-Unix branch is a deliberate
/// no-op (Windows has no portable equivalent and the module-level
/// guarantee is documented as weaker on those platforms).
#[cfg(unix)]
async fn fsync_dir(dir: &Path) -> RelayResult<()> {
    let dir = dir.to_path_buf();
    let res = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let f = std::fs::File::open(&dir)?;
        f.sync_all()
    })
    .await
    .map_err(|join_err| {
        RelayError::Io(std::io::Error::other(format!("fsync_dir join: {join_err}")))
    })?;
    res.map_err(RelayError::Io)
}

#[cfg(not(unix))]
async fn fsync_dir(_dir: &Path) -> RelayResult<()> {
    Ok(())
}

/// Build the deterministic temp-path sibling: `<path>.tmp`. The
/// reader checks the same path for orphans, which keeps
/// crash-recovery detection sound.
fn sibling_tmp(path: &Path) -> PathBuf {
    let mut tmp = path.to_path_buf();
    let new_ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map_or_else(|| "tmp".to_owned(), |ext| format!("{ext}.tmp"));
    tmp.set_extension(new_ext);
    tmp
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only setup")]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tempfile::tempdir;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Sample {
        name: String,
        count: u32,
    }

    #[tokio::test]
    async fn round_trip_write_then_read() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sample.json");
        let value = Sample {
            name: "alice".into(),
            count: 42,
        };
        write_json_atomic(&path, &value).await.unwrap();
        let got: Sample = read_json(&path).await.unwrap();
        assert_eq!(got, value);
    }

    #[tokio::test]
    async fn write_creates_parent_directory() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested/sub/dir/sample.json");
        let value = Sample {
            name: "bob".into(),
            count: 7,
        };
        write_json_atomic(&path, &value).await.unwrap();
        assert!(tokio::fs::metadata(&path).await.is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_applies_unix_mode_0o600() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempdir().unwrap();
        let path = dir.path().join("secure.json");
        let value = Sample {
            name: "secret".into(),
            count: 1,
        };
        write_json_atomic(&path, &value).await.unwrap();
        let mode = tokio::fs::metadata(&path)
            .await
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[tokio::test]
    async fn read_missing_file_returns_io() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nope.json");
        let result: RelayResult<Sample> = read_json(&path).await;
        assert!(matches!(result, Err(RelayError::Io(_))));
    }

    #[tokio::test]
    async fn read_malformed_json_returns_config() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.json");
        tokio::fs::write(&path, b"{ this is not json")
            .await
            .unwrap();
        let result: RelayResult<Sample> = read_json(&path).await;
        assert!(matches!(result, Err(RelayError::Config(_))));
    }

    #[tokio::test]
    async fn overwrite_replaces_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sample.json");
        let v1 = Sample {
            name: "alice".into(),
            count: 1,
        };
        write_json_atomic(&path, &v1).await.unwrap();
        let v2 = Sample {
            name: "alice".into(),
            count: 999,
        };
        write_json_atomic(&path, &v2).await.unwrap();
        let got: Sample = read_json(&path).await.unwrap();
        assert_eq!(got, v2);
    }

    #[tokio::test]
    async fn stale_tmp_blocks_subsequent_write() {
        // create_new(true) on the deterministic .tmp path means a
        // crash-leftover sibling forces a hard error on the next
        // write — the operator must clean it up. This is the
        // crash-recovery rejection contract.
        let dir = tempdir().unwrap();
        let path = dir.path().join("sample.json");
        let stale = sibling_tmp(&path);
        tokio::fs::write(&stale, b"leftover").await.unwrap();
        let value = Sample {
            name: "carol".into(),
            count: 0,
        };
        let result = write_json_atomic(&path, &value).await;
        assert!(matches!(result, Err(RelayError::Io(_))));
    }
}
