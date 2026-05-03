use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::pkcs8::DecodePrivateKey;
use p384::ecdsa::SigningKey as P384SigningKey;
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::generate_simple_self_signed;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::{Pkcs1v15Sign, Pss, RsaPrivateKey};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sec1_07::DecodeEcPrivateKey;
use sha2_010::{Sha256 as Sha256_010, Sha384 as Sha384_010, Sha512 as Sha512_010};

use crate::wire::alpn::PORTAL_TUNNEL;

pub struct TlsMaterial {
    pub config: ServerConfig,
    pub keyless_signer: KeylessSigner,
    pub quic_config: quinn::ServerConfig,
}

#[derive(Clone)]
pub struct KeylessSigner {
    kind: KeylessSignerKind,
}

#[derive(Clone)]
enum KeylessSignerKind {
    EcdsaP256(P256SigningKey),
    EcdsaP384(P384SigningKey),
    Rsa(RsaPrivateKey),
}

impl KeylessSigner {
    pub fn sign_ecdsa_sha256(&self, digest: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.sign_ecdsa("ECDSA_SHA256", digest, 32)
    }

    pub fn sign_ecdsa_sha384(&self, digest: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.sign_ecdsa("ECDSA_SHA384", digest, 48)
    }

    pub fn sign_ecdsa_sha512(&self, digest: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.sign_ecdsa("ECDSA_SHA512", digest, 64)
    }

    pub fn sign_rsa_pkcs1v15_sha256(&self, digest: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.sign_rsa_pkcs1v15(
            "RSA_PKCS1V15_SHA256",
            digest,
            Pkcs1v15Sign::new::<Sha256_010>(),
        )
    }

    pub fn sign_rsa_pkcs1v15_sha384(&self, digest: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.sign_rsa_pkcs1v15(
            "RSA_PKCS1V15_SHA384",
            digest,
            Pkcs1v15Sign::new::<Sha384_010>(),
        )
    }

    pub fn sign_rsa_pkcs1v15_sha512(&self, digest: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.sign_rsa_pkcs1v15(
            "RSA_PKCS1V15_SHA512",
            digest,
            Pkcs1v15Sign::new::<Sha512_010>(),
        )
    }

    pub fn sign_rsa_pss_sha256(&self, digest: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.sign_rsa_pss("RSA_PSS_SHA256", digest, Pss::new::<Sha256_010>())
    }

    pub fn sign_rsa_pss_sha384(&self, digest: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.sign_rsa_pss("RSA_PSS_SHA384", digest, Pss::new::<Sha384_010>())
    }

    pub fn sign_rsa_pss_sha512(&self, digest: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.sign_rsa_pss("RSA_PSS_SHA512", digest, Pss::new::<Sha512_010>())
    }

    fn sign_ecdsa(
        &self,
        algorithm: &'static str,
        digest: &[u8],
        expected_len: usize,
    ) -> anyhow::Result<Vec<u8>> {
        if digest.len() != expected_len {
            bail!("invalid argument: {algorithm} digest must be {expected_len} bytes");
        }
        match &self.kind {
            KeylessSignerKind::EcdsaP256(signing_key) => {
                let signature: p256::ecdsa::Signature = signing_key
                    .sign_prehash(digest)
                    .with_context(|| format!("sign {algorithm} digest"))?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
            KeylessSignerKind::EcdsaP384(signing_key) => {
                let signature: p384::ecdsa::Signature = signing_key
                    .sign_prehash(digest)
                    .with_context(|| format!("sign {algorithm} digest"))?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
            KeylessSignerKind::Rsa(_) => {
                bail!("invalid argument: {algorithm} requires an ECDSA private key")
            }
        }
    }

    fn sign_rsa_pkcs1v15(
        &self,
        algorithm: &'static str,
        digest: &[u8],
        padding: Pkcs1v15Sign,
    ) -> anyhow::Result<Vec<u8>> {
        match &self.kind {
            KeylessSignerKind::Rsa(key) => key
                .sign_with_rng(&mut rand_core_06::OsRng, padding, digest)
                .with_context(|| format!("sign {algorithm} digest")),
            KeylessSignerKind::EcdsaP256(_) | KeylessSignerKind::EcdsaP384(_) => {
                bail!("invalid argument: {algorithm} requires an RSA private key")
            }
        }
    }

    fn sign_rsa_pss(
        &self,
        algorithm: &'static str,
        digest: &[u8],
        padding: Pss,
    ) -> anyhow::Result<Vec<u8>> {
        match &self.kind {
            KeylessSignerKind::Rsa(key) => key
                .sign_with_rng(&mut rand_core_06::OsRng, padding, digest)
                .with_context(|| format!("sign {algorithm} digest")),
            KeylessSignerKind::EcdsaP256(_) | KeylessSignerKind::EcdsaP384(_) => {
                bail!("invalid argument: {algorithm} requires an RSA private key")
            }
        }
    }
}

pub fn load_or_create_tls_material(
    identity_path: &Path,
    root_host: &str,
) -> anyhow::Result<TlsMaterial> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    fs::create_dir_all(identity_path).with_context(|| {
        format!(
            "create relay tls material directory {}",
            identity_path.display()
        )
    })?;

    let cert_path = identity_path.join("fullchain.pem");
    let key_path = identity_path.join("privatekey.pem");
    if !cert_path.exists() || !key_path.exists() {
        write_self_signed_tls_material(&cert_path, &key_path, root_host)?;
    }

    let cert_pem = fs::read(&cert_path)
        .with_context(|| format!("read certificate {}", cert_path.display()))?;
    let key_pem =
        fs::read(&key_path).with_context(|| format!("read private key {}", key_path.display()))?;

    let certs = parse_certs(&cert_pem)?;
    let key = parse_private_key(&key_pem)?;
    let keyless_signer = parse_keyless_signer(&key_pem)?;
    let quic_config = parse_quic_server_config(&cert_pem, &key_pem)?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("configure api tls certificate")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsMaterial {
        config,
        keyless_signer,
        quic_config,
    })
}

fn write_self_signed_tls_material(
    cert_path: &Path,
    key_path: &Path,
    root_host: &str,
) -> anyhow::Result<()> {
    let subject_alt_names = vec![root_host.to_string(), format!("*.{root_host}")];
    let generated = generate_simple_self_signed(subject_alt_names)
        .context("generate self-signed relay certificate")?;

    fs::write(cert_path, generated.cert.pem())
        .with_context(|| format!("write certificate {}", cert_path.display()))?;
    fs::write(key_path, generated.signing_key.serialize_pem())
        .with_context(|| format!("write private key {}", key_path.display()))?;
    Ok(())
}

fn parse_certs(raw: &[u8]) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(raw);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parse certificate pem")?;
    if certs.is_empty() {
        bail!("certificate pem does not contain any certificates");
    }
    Ok(certs)
}

fn parse_private_key(raw: &[u8]) -> anyhow::Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(raw);
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .next()
        .transpose()
        .context("parse pkcs8 private key pem")?
    {
        return Ok(PrivateKeyDer::Pkcs8(key));
    }

    let mut reader = BufReader::new(raw);
    if let Some(key) = rustls_pemfile::ec_private_keys(&mut reader)
        .next()
        .transpose()
        .context("parse ec private key pem")?
    {
        return Ok(PrivateKeyDer::Sec1(key));
    }

    let mut reader = BufReader::new(raw);
    if let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader)
        .next()
        .transpose()
        .context("parse rsa private key pem")?
    {
        return Ok(PrivateKeyDer::Pkcs1(key));
    }

    bail!("private key pem does not contain a supported private key")
}

fn parse_keyless_signer(raw: &[u8]) -> anyhow::Result<KeylessSigner> {
    let mut reader = BufReader::new(raw);
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .next()
        .transpose()
        .context("parse pkcs8 private key pem for keyless signer")?
    {
        let der = key.secret_pkcs8_der();
        if let Ok(signing_key) = P256SigningKey::from_pkcs8_der(der) {
            return Ok(KeylessSigner {
                kind: KeylessSignerKind::EcdsaP256(signing_key),
            });
        }
        if let Ok(signing_key) = P384SigningKey::from_pkcs8_der(der) {
            return Ok(KeylessSigner {
                kind: KeylessSignerKind::EcdsaP384(signing_key),
            });
        }
        if let Ok(signing_key) = RsaPrivateKey::from_pkcs8_der(der) {
            return Ok(KeylessSigner {
                kind: KeylessSignerKind::Rsa(signing_key),
            });
        }
        bail!("keyless signer pkcs8 private key is not ECDSA P-256/P-384 or RSA");
    }

    let mut reader = BufReader::new(raw);
    if let Some(key) = rustls_pemfile::ec_private_keys(&mut reader)
        .next()
        .transpose()
        .context("parse ec private key pem for keyless signer")?
    {
        let der = key.secret_sec1_der();
        if let Ok(signing_key) = P256SigningKey::from_sec1_der(der) {
            return Ok(KeylessSigner {
                kind: KeylessSignerKind::EcdsaP256(signing_key),
            });
        }
        if let Ok(signing_key) = P384SigningKey::from_sec1_der(der) {
            return Ok(KeylessSigner {
                kind: KeylessSignerKind::EcdsaP384(signing_key),
            });
        }
        bail!("keyless signer sec1 private key is not ECDSA P-256/P-384");
    }

    let mut reader = BufReader::new(raw);
    if let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader)
        .next()
        .transpose()
        .context("parse rsa private key pem for keyless signer")?
    {
        let signing_key = RsaPrivateKey::from_pkcs1_der(key.secret_pkcs1_der())
            .context("parse rsa pkcs1 keyless private key")?;
        return Ok(KeylessSigner {
            kind: KeylessSignerKind::Rsa(signing_key),
        });
    }

    bail!("keyless signer requires an ECDSA P-256/P-384 or RSA private key")
}

fn parse_quic_server_config(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> anyhow::Result<quinn::ServerConfig> {
    let certs = parse_certs(cert_pem)?;
    let key = parse_private_key(key_pem)?;
    let provider = rustls::crypto::ring::default_provider();
    let mut rustls_config = ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("configure quic tls protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("configure quic tls certificate")?;
    rustls_config.alpn_protocols = vec![PORTAL_TUNNEL.to_vec()];
    rustls_config.max_early_data_size = u32::MAX;

    let crypto =
        QuicServerConfig::try_from(Arc::new(rustls_config)).context("configure quic tls crypto")?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    transport.max_idle_timeout(Some(
        Duration::from_secs(60)
            .try_into()
            .expect("static quic idle timeout must fit"),
    ));
    transport.max_concurrent_bidi_streams(16u32.into());
    config.transport_config(Arc::new(transport));
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPublicKey;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::LineEnding;
    use sha2_010::Digest;

    #[test]
    fn keyless_signer_accepts_rsa_pkcs1_private_key() {
        let key = RsaPrivateKey::new(&mut rand_core_06::OsRng, 2048).unwrap();
        let key_pem = key.to_pkcs1_pem(LineEnding::LF).unwrap();
        let signer = parse_keyless_signer(key_pem.as_bytes()).unwrap();
        let digest = Sha256_010::digest(b"portal-tunnel-rsa-keyless");
        let public_key = RsaPublicKey::from(&key);

        let pkcs1_sig = signer.sign_rsa_pkcs1v15_sha256(&digest).unwrap();
        public_key
            .verify(Pkcs1v15Sign::new::<Sha256_010>(), &digest, &pkcs1_sig)
            .unwrap();

        let pss_sig = signer.sign_rsa_pss_sha256(&digest).unwrap();
        public_key
            .verify(Pss::new::<Sha256_010>(), &digest, &pss_sig)
            .unwrap();

        assert!(signer.sign_ecdsa_sha256(&digest).is_err());
    }
}
