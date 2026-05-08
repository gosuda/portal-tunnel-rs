//! Relay identity loader — R2 trust-boundary `SecretBox<KeyType>` newtypes.
//!
//! The current surface ships the **type plumbing** for the relay
//! identity bundle: `RelayIdentity`, `IdentityPaths`, the
//! `load_quic_only` helper, and the relay-protocol-key load path
//! (`load_relay_protocol_only`) consumed by [`crate::server::Server`]'s
//! lease-token signer/verifier wiring. The full bundle loader
//! (`load_or_create`) and the API HTTPS load path land in a follow-up
//! commit.
//!
//! ## Trust-boundary discipline (R2)
//!
//! Each key field on [`RelayIdentity`] is a distinct `SecretBox<…>`
//! type. The Rust type system rejects accidental cross-use at compile
//! time. The workspace clippy `disallowed_methods` rule
//! (`portal_crypto::load_all_keys`) prohibits any function returning
//! more than one signing key from a single load call. The current
//! `RelayIdentity` shape carries **four** of the six anticipated
//! key surfaces — `ApiHttpsKey`, `QuicIdentityKey`, `RelayEd25519Key`,
//! and `EchSeed`. The remaining two follow on as their consuming
//! surfaces wire the keys onto this bundle:
//!
//! - `KeylessSigningKey` (consumed by the keyless mTLS endpoint).
//! - `SiweKey` (consumed by the admin SIWE-bind path).

use std::io;
use std::path::PathBuf;

use compact_str::CompactString;
use portal_crypto::{ApiHttpsKey, RelayEd25519Key};
use portal_net::QuicIdentityKey;
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use zeroize::{Zeroize, Zeroizing};

use crate::error::RelayResult;

/// Relay identity bundle.
///
/// Currently carries the four-key shape (`api_https` + `quic` +
/// `relay_protocol` + `ech_seed`); follow-up commits extend it with
/// `KeylessSigningKey` and `SiweKey` as their consuming surfaces
/// wire those keys onto the bundle.
pub struct RelayIdentity {
    /// HTTPS API trust surface (admin / sdk / discovery routers).
    /// rustls `ServerConfig` for these surfaces is built from this key.
    pub api_https: SecretBox<ApiHttpsKey>,
    /// QUIC backhaul trust surface (portal-net `Endpoint::server`).
    pub quic: SecretBox<QuicIdentityKey>,
    /// Relay protocol-identity key (Phase 5 SDK-API S2). Materialised
    /// into a [`portal_crypto::Ed25519Signer`] (borrowed) at handler
    /// call sites and a long-lived [`portal_crypto::Ed25519Verifier`]
    /// at server start. Carried under [`SecretBox`] so accidental
    /// debug-print or copy is rejected by the secrecy crate's
    /// trust-boundary discipline.
    pub relay_protocol: SecretBox<RelayEd25519Key>,
    /// ECH (Encrypted Client Hello) seed for the relay's HTTPS
    /// fronting surface. 32 bytes of uniform random material used to
    /// derive ECH key material. Wrapped in [`SecretBox`] so it is
    /// redacted in logs and zeroized on drop.
    pub ech_seed: SecretBox<EchSeed>,
    /// Operator-friendly relay name (used in tracing + audit log).
    /// Read from disk alongside the keys; not a secret.
    pub name: CompactString,
}

impl core::fmt::Debug for RelayIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RelayIdentity")
            .field("api_https", &"[REDACTED]")
            .field("quic", &"[REDACTED]")
            .field("relay_protocol", &"[REDACTED]")
            .field("ech_seed", &"[REDACTED]")
            .field("name", &self.name)
            .finish()
    }
}

/// Newtype wrapper around the 32-byte ECH seed.
///
/// The inner `[u8; 32]` is stored in [`Zeroizing`] so it is wiped
/// from memory when the value is dropped.  This type is consumed
/// exclusively through [`secrecy::SecretBox<EchSeed>`].
pub struct EchSeed(Zeroizing<[u8; 32]>);

impl Zeroize for EchSeed {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Generate a fresh 32-byte ECH seed from the OS RNG.
#[must_use]
pub fn generate_ech_seed() -> SecretBox<EchSeed> {
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *seed);
    SecretBox::new(Box::new(EchSeed(seed)))
}

/// Save an ECH seed to disk as raw bytes with 0o600 perms (Unix).
///
/// Uses atomic write: creates a uniquely-named sibling temp file with
/// `create_new(true)`, fsyncs, then renames atomically over `path`.
///
/// # Errors
///
/// Returns [`crate::error::RelayError::Io`] on filesystem failure.
pub fn save_ech_seed(
    seed: &SecretBox<EchSeed>,
    path: &std::path::Path,
) -> Result<(), crate::error::RelayError> {
    use std::io::Write as _;

    let bytes: &[u8] = seed.expose_secret().0.as_slice();
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let tmp_path = unique_sibling_tmp(parent);

    let write_result = (|| -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut f = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&tmp_path)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            let mut f = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&tmp_path)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    write_result.map_err(crate::error::RelayError::Io)
}

/// Load an ECH seed from a raw 32-byte file.
///
/// # Errors
///
/// Returns [`crate::error::RelayError::Io`] on filesystem failure.
/// Returns [`crate::error::RelayError::Crypto`] if the file length
/// is not exactly 32 bytes.
pub fn load_ech_seed(
    path: &std::path::Path,
) -> Result<SecretBox<EchSeed>, crate::error::RelayError> {
    let data = std::fs::read(path).map_err(crate::error::RelayError::Io)?;
    if data.len() != 32 {
        return Err(crate::error::RelayError::Crypto(format!(
            "ECH seed file must be exactly 32 bytes, got {}",
            data.len()
        )));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&data);
    Ok(SecretBox::new(Box::new(EchSeed(seed))))
}

/// Return a path like `<dir>/.portal-relay-tmp-<16-hex-chars>` that does not
/// yet exist. The caller must open it with `create_new(true)`.
fn unique_sibling_tmp(dir: &std::path::Path) -> std::path::PathBuf {
    let mut nonce = [0u8; 8];
    OsRng.fill_bytes(&mut nonce);
    let hex = format!("{:016x}", u64::from_ne_bytes(nonce));
    dir.join(format!(".portal-relay-tmp-{hex}"))
}

/// Standard layout of the on-disk identity directory:
/// - `<dir>/api_https.der` (PKCS#8 ed25519, mode 0o600)
/// - `<dir>/quic.der` (PKCS#8 ed25519, mode 0o600)
/// - `<dir>/relay_protocol.json` (single-field JSON, mode 0o600 —
///   `{ "ed25519_secret_key": "<64 lowercase hex chars>" }` per
///   [`portal_crypto::load_relay_ed25519_key`])
/// - `<dir>/ech_seed.bin` (raw 32-byte seed, mode 0o600)
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

    /// Path to the API HTTPS key file (`<dir>/api_https.der`). The
    /// path layout is current; the load path that materializes
    /// `SecretBox<ApiHttpsKey>` from this file lands in a follow-up
    /// commit.
    #[must_use]
    pub fn api_https(&self) -> PathBuf {
        self.dir.join("api_https.der")
    }

    /// Path to the QUIC backhaul key file (`<dir>/quic.der`).
    #[must_use]
    pub fn quic(&self) -> PathBuf {
        self.dir.join("quic.der")
    }

    /// Path to the relay protocol-identity key file
    /// (`<dir>/relay_protocol.json`). Loaded via
    /// [`portal_crypto::load_relay_ed25519_key`] and consumed by
    /// [`load_relay_protocol_only`].
    #[must_use]
    pub fn relay_protocol(&self) -> PathBuf {
        self.dir.join("relay_protocol.json")
    }

    /// Path to the relay name file (`<dir>/name.txt`).
    #[must_use]
    pub fn name(&self) -> PathBuf {
        self.dir.join("name.txt")
    }

    /// Path to the ECH seed file (`<dir>/ech_seed.bin`).
    #[must_use]
    pub fn ech_seed(&self) -> PathBuf {
        self.dir.join("ech_seed.bin")
    }
}

/// Load the QUIC backhaul identity, generating + persisting if absent.
///
/// This is the single-surface load path the module ships today; the
/// full `load_or_create` bundle loader (which materializes
/// `SecretBox<ApiHttpsKey>` from disk and wires the future-extended
/// key surfaces) lands in a follow-up commit.
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

/// Load the relay protocol-identity ed25519 key from disk.
///
/// The file at [`IdentityPaths::relay_protocol`] is consumed by
/// [`portal_crypto::load_relay_ed25519_key`], which expects the
/// single-field JSON shape:
///
/// ```json
/// { "ed25519_secret_key": "<64 lowercase hex chars>" }
/// ```
///
/// Unlike [`load_quic_only`] this path does **not** generate-on-absent
/// today: `portal-crypto` exposes only the load surface for the relay
/// ed25519 key and the corresponding generator + atomic save lands
/// alongside the operator-tooling commit that owns initial-key
/// provisioning. Operators bootstrap the file out-of-band; until that
/// follow-up lands, `NotFound` surfaces as
/// [`crate::error::RelayError::Crypto`].
///
/// # Errors
///
/// - [`crate::error::RelayError::Io`] on filesystem faults — both the
///   parent-directory create and the key-file read (`NotFound`,
///   `EACCES`, `ELOOP`, …). Mirrors `load_quic_only`'s discipline so
///   operators triaging a missing or unreadable key get an `io:` error
///   message rather than a generic `crypto:` one.
/// - [`crate::error::RelayError::Crypto`] on malformed JSON, hex-
///   decode failure, length mismatch, or any other non-Io
///   [`portal_crypto::PortalCryptoError`] variant surfaced by the
///   loader.
pub async fn load_relay_protocol_only(
    paths: &IdentityPaths,
) -> RelayResult<SecretBox<RelayEd25519Key>> {
    tokio::fs::create_dir_all(&paths.dir).await?;
    let path = paths.relay_protocol();
    // `portal_crypto::load_relay_ed25519_key` is a synchronous read of
    // a small (≤200-byte) JSON file; calling it directly inside the
    // async fn is fine — `spawn_blocking` would be over-engineering for
    // a one-shot read on the start path.
    portal_crypto::load_relay_ed25519_key(&path).map_err(|e| match e {
        portal_crypto::PortalCryptoError::Io(io_err) => crate::error::RelayError::Io(io_err),
        other => crate::error::RelayError::Crypto(other.to_string()),
    })
}

/// Load the ECH seed, generating + persisting if absent.
///
/// Follows the exact same race-safe pattern as [`load_quic_only`]:
///
/// 1. `metadata(ech_seed_path)` — only [`io::ErrorKind::NotFound`] is
///    treated as "missing".
/// 2. If present, load and return.
/// 3. If absent, generate via [`generate_ech_seed`], persist atomically
///    via [`save_ech_seed`], then re-load from disk so concurrent
///    writers converge to the same on-disk identity regardless of which
///    generation "wins" the rename race.
///
/// # Errors
///
/// Returns [`crate::error::RelayError::Io`] on filesystem failure and
/// [`crate::error::RelayError::Crypto`] on malformed seed file.
pub async fn load_ech_seed_only(paths: &IdentityPaths) -> RelayResult<SecretBox<EchSeed>> {
    tokio::fs::create_dir_all(&paths.dir).await?;
    let ech_path = paths.ech_seed();

    match tokio::fs::metadata(&ech_path).await {
        Ok(_) => Ok(load_ech_seed(&ech_path)?),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let seed = generate_ech_seed();
            save_ech_seed(&seed, &ech_path)?;
            // Drop the locally-generated seed in favor of the on-disk
            // truth, guaranteeing convergence under concurrent
            // first-start.
            drop(seed);
            Ok(load_ech_seed(&ech_path)?)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only setup")]
#[expect(clippy::expect_used, reason = "test-only assertions")]
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
        assert!(paths.relay_protocol().ends_with("relay_protocol.json"));
        assert!(paths.ech_seed().ends_with("ech_seed.bin"));
        assert!(paths.name().ends_with("name.txt"));
    }

    /// `load_relay_protocol_only` round-trips: write a JSON key file
    /// that matches the `portal_crypto::load_relay_ed25519_key`
    /// single-field shape, load through the helper, and verify the
    /// derived `VerifyingKey` matches a direct `dalek` reconstruction
    /// from the same seed. Proves the loader correctly threads through
    /// portal-crypto without re-encoding or zeroising the bytes mid-flight.
    #[tokio::test]
    async fn load_relay_protocol_only_round_trips_from_disk() {
        use std::fmt::Write as _;
        use std::io::Write as _;

        let dir = tempdir().unwrap();
        let paths = IdentityPaths::new(dir.path().to_path_buf());
        // Pre-create the parent dir so we can drop a JSON file in it.
        std::fs::create_dir_all(&paths.dir).unwrap();

        let seed: [u8; 32] = [0x55u8; 32];
        let hex = seed.iter().fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        let json = format!(r#"{{"ed25519_secret_key": "{hex}"}}"#);
        std::fs::File::create(paths.relay_protocol())
            .unwrap()
            .write_all(json.as_bytes())
            .unwrap();

        let loaded = load_relay_protocol_only(&paths).await.unwrap();
        let vk_loaded = portal_crypto::verifying_key(&loaded);
        let sk_ref = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(
            vk_loaded.to_bytes(),
            sk_ref.verifying_key().to_bytes(),
            "loaded relay-protocol key must derive the same verifying key as a direct dalek seed",
        );
    }

    /// Missing-file surfaces as [`RelayError::Io`] — the loader
    /// matches on `PortalCryptoError::Io` and routes filesystem
    /// faults to the workspace's `Io` arm so operators triaging a
    /// missing or unreadable key see an `io:` error message rather
    /// than a generic `crypto:` one. Mirrors `load_quic_only`'s
    /// discipline.
    #[tokio::test]
    async fn load_relay_protocol_only_missing_file_surfaces_io_error() {
        use crate::error::RelayError;

        let dir = tempdir().unwrap();
        let paths = IdentityPaths::new(dir.path().to_path_buf());
        // Don't create the file — the helper must surface an Io
        // error with NotFound kind.
        let result = load_relay_protocol_only(&paths).await;
        match result {
            Err(RelayError::Io(io_err)) => {
                assert_eq!(
                    io_err.kind(),
                    std::io::ErrorKind::NotFound,
                    "missing relay_protocol.json must surface as Io(NotFound), got kind {:?}",
                    io_err.kind(),
                );
            }
            other => panic!(
                "missing relay_protocol.json must surface as RelayError::Io(NotFound), got {other:?}",
            ),
        }
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

    #[tokio::test]
    async fn load_ech_seed_only_generates_then_round_trips() {
        let dir = tempdir().unwrap();
        let paths = IdentityPaths::new(dir.path().to_path_buf());
        let seed1 = load_ech_seed_only(&paths)
            .await
            .expect("first load should generate");
        let seed2 = load_ech_seed_only(&paths)
            .await
            .expect("second load should round-trip");
        assert_eq!(
            seed1.expose_secret().0.as_slice(),
            seed2.expose_secret().0.as_slice(),
            "round-trip ECH seed"
        );
    }

    #[tokio::test]
    async fn load_ech_seed_only_preexisting_file_round_trips() {
        let dir = tempdir().unwrap();
        let paths = IdentityPaths::new(dir.path().to_path_buf());
        let seed1 = generate_ech_seed();
        save_ech_seed(&seed1, &paths.ech_seed()).expect("save preexisting seed");
        let seed2 = load_ech_seed_only(&paths)
            .await
            .expect("load preexisting seed");
        assert_eq!(
            seed1.expose_secret().0.as_slice(),
            seed2.expose_secret().0.as_slice(),
            "preexisting ECH seed must round-trip"
        );
    }

    #[tokio::test]
    async fn load_ech_seed_only_short_file_surfaces_crypto_error() {
        use crate::error::RelayError;

        let dir = tempdir().unwrap();
        let paths = IdentityPaths::new(dir.path().to_path_buf());
        std::fs::create_dir_all(&paths.dir).expect("create dir");
        {
            use std::io::Write as _;
            let mut f = std::fs::File::create(paths.ech_seed()).expect("create short file");
            f.write_all(b"short").expect("write short bytes");
        }
        let result = load_ech_seed_only(&paths).await;
        assert!(
            matches!(result, Err(RelayError::Crypto(_))),
            "short ECH seed file must surface as RelayError::Crypto, got {result:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn metadata_non_notfound_error_propagates_as_io_for_ech_seed() {
        use crate::error::RelayError;

        let dir = tempdir().unwrap();
        let paths = IdentityPaths::new(dir.path().to_path_buf());
        let ech_path = paths.ech_seed();
        std::os::unix::fs::symlink(&ech_path, &ech_path).unwrap();
        let probe = std::fs::metadata(&ech_path);
        assert!(probe.is_err(), "symlink-loop fixture must error");
        assert_ne!(
            probe.unwrap_err().kind(),
            io::ErrorKind::NotFound,
            "fixture must produce a non-NotFound error"
        );

        let result = load_ech_seed_only(&paths).await;
        assert!(
            matches!(result, Err(RelayError::Io(_))),
            "non-NotFound metadata error must surface as \
             RelayError::Io (got {result:?})"
        );
    }
}
