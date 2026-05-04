//! Filesystem helpers: atomic write + `0o600`/`0o644` mode application
//! on Unix.
//!
//! All key + cert material flows through [`write_atomic_with_mode`] so a
//! crash mid-write cannot leave a half-written private key on disk.

use std::path::Path;

use rand_core::{OsRng, RngCore};

use crate::error::AcmeError;

/// Atomically write `bytes` to `path` with the supplied unix mode.
///
/// On Windows the `mode` argument is ignored (best effort).
/// Implementation: open a uniquely-named sibling temp file with
/// `create_new(true)`, write, fsync, then `rename` onto `path`.
///
/// # Errors
/// Returns [`AcmeError::Io`] on any FS failure. Best-effort cleanup of
/// the temp file on error.
pub async fn write_atomic_with_mode(
    path: &Path,
    bytes: &[u8],
    mode: u32,
) -> Result<(), AcmeError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = unique_sibling_tmp(parent);

    let write_result = write_inner(&tmp, bytes, mode).await;
    if write_result.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
        return write_result;
    }
    // Rename can also fail (cross-device, permission denied, parent
    // gone). On rename failure the temp file persists with our 0o600
    // mode and the secret bytes inside — best-effort remove so a
    // subsequent retry isn't blocked by `create_new(true)` on a stale
    // sibling.
    if let Err(rename_err) = tokio::fs::rename(&tmp, path).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(AcmeError::Io(rename_err));
    }
    Ok(())
}

async fn write_inner(tmp: &Path, bytes: &[u8], mode: u32) -> Result<(), AcmeError> {
    use tokio::io::AsyncWriteExt as _;

    let mut opts = tokio::fs::OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        // tokio::fs::OpenOptions exposes `mode()` natively on Unix.
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    {
        // mode is a Unix permission bitfield; on Windows the only
        // workable per-file ACL discipline is the parent dir's ACL.
        let _ = mode;
    }
    let mut f = opts.open(tmp).await?;
    f.write_all(bytes).await?;
    f.sync_all().await?;
    Ok(())
}

fn unique_sibling_tmp(dir: &Path) -> std::path::PathBuf {
    let mut nonce = [0u8; 8];
    OsRng.fill_bytes(&mut nonce);
    let hex = format!("{:016x}", u64::from_ne_bytes(nonce));
    dir.join(format!(".portal-acme-tmp-{hex}"))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only setup")]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn round_trip_write_then_read() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("x.bin");
        write_atomic_with_mode(&path, b"hello world", 0o600)
            .await
            .unwrap();
        let got = tokio::fs::read(&path).await.unwrap();
        assert_eq!(got, b"hello world");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_mode_0o600_is_applied() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempdir().unwrap();
        let path = dir.path().join("x.key");
        write_atomic_with_mode(&path, b"secret", 0o600)
            .await
            .unwrap();
        let mode = tokio::fs::metadata(&path).await.unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
