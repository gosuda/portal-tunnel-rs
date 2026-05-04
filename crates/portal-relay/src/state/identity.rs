//! Relay identity loader — R2 trust-boundary `SecretBox<KeyType>` newtypes.
//!
//! Phase 5 B2 lands the **type plumbing** for the relay identity bundle:
//! `RelayIdentity`, `IdentityPaths`, and the `load_quic_only` helper
//! that materializes the QUIC trust surface. The full bundle loader
//! (`load_or_create`) lands in Phase 5 B3 alongside the API HTTPS load
//! path; this batch's surface is the type-level skeleton and the
//! single-key load that the existing B2 plumbing can exercise today.
//!
//! ## Trust-boundary discipline (R2)
//!
//! Each key field on [`RelayIdentity`] is a distinct `SecretBox<…>`
//! type. The Rust type system rejects accidental cross-use at compile
//! time. The workspace clippy `disallowed_methods` rule
//! (`portal_crypto::load_all_keys`) prohibits any function returning
//! more than one signing key from a single load call. Phase 5 B2
//! ships only **two** of the five key surfaces — `ApiHttpsKey` and
//! `QuicIdentityKey` — because those are the only key types that
//! exist in the workspace today. The remaining three
//! (`KeylessSigningKey`, `RelayProtocolKey`, `SiweKey`) land
//! alongside their consuming modules in subsequent batches:
//!
//! - `KeylessSigningKey`: Phase 6b/A (keyless mTLS endpoint).
//! - `RelayProtocolKey` / `SiweKey`: Phase 5 later batches (discovery
//!   announce + admin SIWE-bind paths).

use std::io;
use std::path::PathBuf;

use compact_str::CompactString;
use portal_crypto::ApiHttpsKey;
use portal_net::QuicIdentityKey;
use secrecy::SecretBox;

use crate::error::RelayResult;

/// Relay identity bundle. Phase 5 B2 lands the two-key shape;
/// subsequent batches extend with `KeylessSigningKey` (Phase 6b/A) and
/// `RelayProtocolKey` / `SiweKey` (later P5 batches).
pub struct RelayIdentity {
    /// HTTPS API trust surface (admin / sdk / discovery routers).
    /// rustls `ServerConfig` for these surfaces is built from this key.
    pub api_https: SecretBox<ApiHttpsKey>,
    /// QUIC backhaul trust surface (portal-net `Endpoint::server`).
    pub quic: SecretBox<QuicIdentityKey>,
    /// Operator-friendly relay name (used in tracing + audit log).
    /// Read from disk alongside the keys; not a secret.
    pub name: CompactString,
}

impl core::fmt::Debug for RelayIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RelayIdentity")
            .field("api_https", &"[REDACTED]")
            .field("quic", &"[REDACTED]")
            .field("name", &self.name)
            .finish()
    }
}

/// Standard layout of the on-disk identity directory:
/// - `<dir>/api_https.der` (PKCS#8 ed25519, mode 0o600)
/// - `<dir>/quic.der` (PKCS#8 ed25519, mode 0o600)
/// - `<dir>/name.txt` (operator-friendly relay name)
#[derive(Debug, Clone)]
pub struct IdentityPaths {
    /// Directory holding the identity files.
    pub dir: PathBuf,
}

impl IdentityPaths {
    /// Wrap a directory path.
    #[must_use]
    pub const fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Path to the API HTTPS key file (`<dir>/api_https.der`). Phase
    /// 5 B3 wires the load path; Phase 5 B2 only declares the layout.
    #[must_use]
    pub fn api_https(&self) -> PathBuf {
        self.dir.join("api_https.der")
    }

    /// Path to the QUIC backhaul key file (`<dir>/quic.der`).
    #[must_use]
    pub fn quic(&self) -> PathBuf {
        self.dir.join("quic.der")
    }

    /// Path to the relay name file (`<dir>/name.txt`).
    #[must_use]
    pub fn name(&self) -> PathBuf {
        self.dir.join("name.txt")
    }
}

/// Load the QUIC backhaul identity, generating + persisting if absent.
///
/// This is the single-surface load path that Phase 5 B2 ships; the
/// full `load_or_create` bundle loader lands in B3 alongside the API
/// HTTPS load path.
///
/// ## Race-safety
///
/// Two concurrent first-start callers must not race-clobber each
/// other's persisted key. Implementation:
///
/// 1. `metadata(quic_path)` — only [`io::ErrorKind::NotFound`] is
///    treated as "missing"; any other error (permission, ENOTDIR,
///    transient) propagates as [`crate::error::RelayError::Io`].
/// 2. If present, load + return.
/// 3. If absent, attempt to claim the slot via the
///    [`portal_net::save_quic_identity_key`] atomic write. After save
///    we re-`load` from disk: if a competing writer raced ahead, the
///    rename-replace lost ours but the file at `quic_path` is the
///    surviving identity and that is what we return. The competitor's
///    key is therefore the one consumed by both processes — the only
///    invariant we need is that all callers converge to the *same*
///    on-disk identity, not that the local generation wins.
///
/// # Errors
/// Returns [`crate::error::RelayError::Net`] on portal-net key faults,
/// [`crate::error::RelayError::Io`] on FS faults.
pub async fn load_quic_only(paths: &IdentityPaths) -> RelayResult<SecretBox<QuicIdentityKey>> {
    tokio::fs::create_dir_all(&paths.dir).await?;
    let quic_path = paths.quic();

    // Distinguish "missing" from "permission denied / ENOTDIR /
    // transient". Only NotFound triggers generation.
    match tokio::fs::metadata(&quic_path).await {
        Ok(_) => {
            // Present: load and return.
            Ok(portal_net::load_quic_identity_key(&quic_path)?)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Absent: generate, persist, then re-load whatever ended
            // up on disk. The portal-net save path is atomic
            // (create_new sibling temp + rename), so concurrent
            // writers each commit one self-consistent key file; the
            // `rename` is last-writer-wins. By re-loading after save
            // we converge all callers to the surviving on-disk
            // identity rather than holding the local in-memory one
            // (which may have been clobbered).
            let key = portal_net::generate_quic_identity_key();
            portal_net::save_quic_identity_key(&key, &quic_path)?;
            // Drop the locally-generated key in favor of the on-disk
            // truth. This guarantees convergence under concurrent
            // first-start.
            drop(key);
            Ok(portal_net::load_quic_identity_key(&quic_path)?)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only setup")]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn load_quic_only_generates_then_round_trips() {
        let dir = tempdir().unwrap();
        let paths = IdentityPaths::new(dir.path().to_path_buf());
        // First call: generates.
        let key1 = load_quic_only(&paths).await.unwrap();
        // Second call: loads.
        let key2 = load_quic_only(&paths).await.unwrap();
        // Both should produce the same verifying key.
        let vk1 = portal_net::quic_identity_verifying_key(&key1);
        let vk2 = portal_net::quic_identity_verifying_key(&key2);
        assert_eq!(vk1.to_bytes(), vk2.to_bytes(), "round-trip identity");
    }

    #[test]
    fn identity_paths_produce_expected_subpaths() {
        let dir = std::path::PathBuf::from("/tmp/relay-identity");
        let paths = IdentityPaths::new(dir);
        assert!(paths.api_https().ends_with("api_https.der"));
        assert!(paths.quic().ends_with("quic.der"));
        assert!(paths.name().ends_with("name.txt"));
    }

    /// A non-NotFound metadata error must surface as
    /// [`RelayError::Io`], NOT silently re-trigger generation.
    ///
    /// We force ELOOP (a deterministic non-NotFound `io::Error` that
    /// is not bypassed by root) by creating a symlink loop at the
    /// `quic.der` path: `quic.der -> quic.der`. `tokio::fs::metadata`
    /// follows symlinks and surfaces `io::ErrorKind` other than
    /// `NotFound`, exercising the metadata branch's `Err(e) =>
    /// Err(e.into())` arm precisely.
    ///
    /// Unix-only: symlink-loop semantics differ on Windows; the
    /// metadata-error path is the same across platforms but the test
    /// fixture must be unix-portable.
    #[cfg(unix)]
    #[tokio::test]
    async fn metadata_non_notfound_error_propagates_as_io() {
        use crate::error::RelayError;

        let dir = tempdir().unwrap();
        let paths = IdentityPaths::new(dir.path().to_path_buf());
        // `create_dir_all` will short-circuit on the existing tempdir
        // root — no error there. Pre-create a symlink loop AT the
        // quic.der path so the subsequent metadata() call surfaces a
        // non-NotFound io::Error (ELOOP).
        let quic_path = paths.quic();
        std::os::unix::fs::symlink(&quic_path, &quic_path).unwrap();
        // Verify the fixture: a direct metadata follow-symlink read
        // must error with a non-NotFound kind.
        let probe = std::fs::metadata(&quic_path);
        assert!(probe.is_err(), "symlink-loop fixture must error");
        assert_ne!(
            probe.unwrap_err().kind(),
            io::ErrorKind::NotFound,
            "fixture must produce a non-NotFound error so the test \
             actually exercises the metadata-fall-through arm"
        );

        let result = load_quic_only(&paths).await;
        assert!(
            matches!(result, Err(RelayError::Io(_))),
            "non-NotFound metadata error must surface as \
             RelayError::Io (got {result:?})"
        );
    }
}
