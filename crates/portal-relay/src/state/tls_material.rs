use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;
use quinn::crypto::rustls::QuicServerConfig;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use sec1::DecodeEcPrivateKey;

pub struct TlsMaterial {
    pub config: ServerConfig,
    pub keyless_signer: KeylessSigner,
    pub quic_config: quinn::ServerConfig,
}

#[derive(Clone)]
pub struct KeylessSigner {
    ecdsa_p256: SigningKey,
}

impl KeylessSigner {
    pub fn sign_ecdsa_sha256(&self, digest: &[u8]) -> anyhow::Result<Vec<u8>> {
        if digest.len() != 32 {
            bail!("invalid argument: ECDSA_SHA256 digest must be 32 bytes");
        }
        let signature: p256::ecdsa::Signature = self
            .ecdsa_p256
            .sign_prehash(digest)
            .context("sign ECDSA_SHA256 digest")?;
        Ok(signature.to_der().as_bytes().to_vec())
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
    fs::write(key_path, generated.key_pair.serialize_pem())
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
        let signing_key = SigningKey::from_pkcs8_der(key.secret_pkcs8_der())
            .context("parse p256 pkcs8 keyless private key")?;
        return Ok(KeylessSigner {
            ecdsa_p256: signing_key,
        });
    }

    let mut reader = BufReader::new(raw);
    if let Some(key) = rustls_pemfile::ec_private_keys(&mut reader)
        .next()
        .transpose()
        .context("parse ec private key pem for keyless signer")?
    {
        let signing_key = SigningKey::from_sec1_der(key.secret_sec1_der())
            .context("parse p256 sec1 keyless private key")?;
        return Ok(KeylessSigner {
            ecdsa_p256: signing_key,
        });
    }

    bail!("keyless signer currently requires an ECDSA P-256 private key")
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
    rustls_config.alpn_protocols = vec![b"portal-tunnel".to_vec()];
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
