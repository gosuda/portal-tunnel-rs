//! TLS material helpers — build a [`rustls::ServerConfig`] from ACME on-disk
//! handoff (`fullchain.pem` + `privatekey.pem`).
//!
//! The paths correspond to the PEM files produced by ACME (fullchain.pem and
//! privatekey.pem).  This module reads those files and constructs a
//! [`rustls::ServerConfig`] that can be fed into the HTTPS / SDK listener
//! stack.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Errors emitted when converting ACME PEM files into a [`ServerConfig`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsBuildError {
    /// Failed to read a PEM file from disk.
    #[error("io error reading {path}: {source}")]
    Io {
        /// File path that caused the error.
        path: String,
        /// Underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// No certificates were found in the fullchain PEM.
    #[error("no certificates found in {0}")]
    EmptyCertChain(String),
    /// No private key was found in the private key PEM.
    #[error("no private key found in {0}")]
    MissingPrivateKey(String),
    /// PEM parse error in a certificate or private key file.
    #[error("pem parse error in {path}: {detail}")]
    PemParse {
        /// File path that caused the error.
        path: String,
        /// Underlying parse error detail.
        detail: String,
    },
    /// rustls rejected the cert / key pair (e.g. mismatched algorithm).
    #[error("tls configuration error: {0}")]
    TlsConfig(#[source] rustls::Error),
}

/// Build a [`rustls::ServerConfig`] from ACME `fullchain.pem` +
/// `privatekey.pem` paths.
///
/// The returned config uses the `aws_lc_rs` crypto provider, safe default
/// TLS protocol versions, no client auth, and ALPN `h2` + `http/1.1`.
///
/// # Errors
/// Returns [`TlsBuildError`] on IO failure, malformed PEM, missing
/// certificates / key, or rustls validation rejection.
pub fn build_server_config_from_acme_handoff(
    fullchain_path: &Path,
    private_key_path: &Path,
) -> Result<ServerConfig, TlsBuildError> {
    let cert_chain = read_cert_chain(fullchain_path)?;
    if cert_chain.is_empty() {
        return Err(TlsBuildError::EmptyCertChain(
            fullchain_path.display().to_string(),
        ));
    }

    let private_key = read_private_key(private_key_path)?;

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(TlsBuildError::TlsConfig)?
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(TlsBuildError::TlsConfig)?;

    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(cfg)
}

/// Read a PEM-encoded certificate chain from `path`.
pub fn read_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsBuildError> {
    let pem_bytes = fs::read(path).map_err(|e| TlsBuildError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let mut reader = std::io::BufReader::new(&pem_bytes[..]);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| TlsBuildError::PemParse {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    Ok(certs)
}

/// Read a PEM-encoded private key from `path`.
pub fn read_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsBuildError> {
    let pem_bytes = fs::read(path).map_err(|e| TlsBuildError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let mut reader = std::io::BufReader::new(&pem_bytes[..]);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| TlsBuildError::PemParse {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?
        .ok_or_else(|| TlsBuildError::MissingPrivateKey(path.display().to_string()))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only setup")]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
    use std::io::Write;

    fn write_pem(dir: &tempfile::TempDir, name: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(contents).unwrap();
        path
    }

    fn generate_self_signed_pems(
        dir: &tempfile::TempDir,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let fullchain = write_pem(dir, "fullchain.pem", cert.pem().as_bytes());
        let private_key = write_pem(dir, "privatekey.pem", key_pair.serialize_pem().as_bytes());
        (fullchain, private_key)
    }

    #[test]
    fn success_loads_self_signed_cert() {
        let dir = tempfile::tempdir().unwrap();
        let (fullchain, private_key) = generate_self_signed_pems(&dir);

        let cfg = build_server_config_from_acme_handoff(&fullchain, &private_key);
        assert!(cfg.is_ok(), "expected Ok(ServerConfig), got {cfg:?}");
    }

    #[test]
    fn error_missing_fullchain() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("fullchain.pem");
        let private_key = write_pem(&dir, "privatekey.pem", b"not a real key");

        let result = build_server_config_from_acme_handoff(&missing, &private_key);
        assert!(
            matches!(result, Err(TlsBuildError::Io { .. })),
            "expected Io error for missing fullchain, got {result:?}"
        );
    }

    #[test]
    fn error_invalid_pem() {
        let dir = tempfile::tempdir().unwrap();
        let fullchain = write_pem(&dir, "fullchain.pem", b"not a pem");
        let private_key = write_pem(&dir, "privatekey.pem", b"also not a pem");

        let result = build_server_config_from_acme_handoff(&fullchain, &private_key);
        assert!(
            matches!(
                result,
                Err(TlsBuildError::EmptyCertChain(_)
                    | TlsBuildError::MissingPrivateKey(_)
                    | TlsBuildError::PemParse { .. })
            ),
            "expected PEM-related error, got {result:?}"
        );
    }

    #[test]
    fn error_mismatched_key() {
        let dir = tempfile::tempdir().unwrap();

        let key_a = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let key_b = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();

        let params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        let cert = params.self_signed(&key_a).unwrap();

        let fullchain = write_pem(&dir, "fullchain.pem", cert.pem().as_bytes());
        let private_key = write_pem(&dir, "privatekey.pem", key_b.serialize_pem().as_bytes());

        let result = build_server_config_from_acme_handoff(&fullchain, &private_key);
        assert!(
            matches!(result, Err(TlsBuildError::TlsConfig(_))),
            "expected TlsConfig error for mismatched key, got {result:?}"
        );
    }
}
