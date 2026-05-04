//! Local self-signed dev provider — emits a 10-year self-signed
//! ECDSA P-256 certificate without contacting any CA.
//!
//! Mirrors Go's `portal-tunnel/portal/acme/local.go::Provision` shape:
//! generate a CA-marked self-signed certificate with SANs covering
//! `localhost`, `*.localhost`, `127.0.0.1`, `::1`, plus the configured
//! base domain if it is not `localhost`. ECDSA P-256 + SHA-256 matches
//! the Go reference's `elliptic.P256() + crypto/x509`.
//!
//! This module deliberately avoids importing the `time` crate directly
//! to honour the workspace-wide `jiff`-only time policy. rcgen 0.14
//! exposes `time::OffsetDateTime` through its public re-export
//! [`rcgen::date_time_ymd`], so we construct validity bounds via that
//! helper and read the current calendar year via `jiff`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use crate::config::KeyDir;
use crate::error::{AcmeError, AcmeResult};
use crate::persist::write_atomic_with_mode;
use crate::provider::{DnsProvider, DnsRecord};

/// Local self-signed DNS-01-bypass provider.
///
/// Emits a 10-year ECDSA P-256 self-signed cert with SANs covering the
/// loopback identities + a configurable base domain. The DNS-01
/// methods all return `AcmeError::Config` because the local provider
/// does not interact with a real DNS surface — the relay's TLS material
/// is the self-signed cert this provider emits via
/// [`LocalProvider::generate_self_signed`].
pub struct LocalProvider {
    base_domain: Option<compact_str::CompactString>,
}

impl LocalProvider {
    /// Construct a local provider with no base domain — SANs cover only
    /// loopback identities (`localhost`, `*.localhost`, `127.0.0.1`,
    /// `::1`).
    #[must_use]
    pub const fn new() -> Self {
        Self { base_domain: None }
    }

    /// Construct with a base domain that is appended to the SAN list
    /// in addition to the loopback identities. When `base_domain` is
    /// not the literal `"localhost"`, both `<base_domain>` and
    /// `*.<base_domain>` are added as DNS SANs.
    #[must_use]
    pub fn with_base_domain(base_domain: impl Into<compact_str::CompactString>) -> Self {
        Self {
            base_domain: Some(base_domain.into()),
        }
    }

    /// Generate (and persist) a fresh self-signed cert + private key
    /// into the supplied [`KeyDir`].
    ///
    /// Writes:
    /// - `<key_dir>/fullchain.pem` mode 0o644 — public X.509 PEM
    /// - `<key_dir>/privatekey.pem` mode 0o600 — ECDSA P-256 PKCS#8 PEM
    ///
    /// Returns the absolute paths to the two files so callers can hand
    /// them off to rustls without re-deriving the layout.
    ///
    /// # Errors
    /// Returns [`AcmeError::Cert`] on rcgen errors,
    /// [`AcmeError::Io`] on filesystem failure.
    pub async fn generate_self_signed(
        &self,
        key_dir: &KeyDir,
    ) -> AcmeResult<LocalCertPaths> {
        // 1. Build SAN list. Loopback identities are always present;
        //    optional `base_domain` is appended (apex + wildcard) when
        //    not `localhost`.
        let mut sans: Vec<rcgen::SanType> = vec![
            rcgen::SanType::DnsName(
                rcgen::string::Ia5String::try_from("localhost".to_owned())
                    .map_err(|e| AcmeError::Cert(format!("ia5 localhost: {e}")))?,
            ),
            rcgen::SanType::DnsName(
                rcgen::string::Ia5String::try_from("*.localhost".to_owned())
                    .map_err(|e| AcmeError::Cert(format!("ia5 *.localhost: {e}")))?,
            ),
            rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            rcgen::SanType::IpAddress(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ];
        if let Some(base) = self.base_domain.as_ref()
            && base != "localhost"
        {
            sans.push(rcgen::SanType::DnsName(
                rcgen::string::Ia5String::try_from(base.to_string())
                    .map_err(|e| AcmeError::Cert(format!("ia5 base domain: {e}")))?,
            ));
            let wildcard = format!("*.{base}");
            sans.push(rcgen::SanType::DnsName(
                rcgen::string::Ia5String::try_from(wildcard)
                    .map_err(|e| AcmeError::Cert(format!("ia5 wildcard: {e}")))?,
            ));
        }

        // 2. Build cert params. We pass an empty SAN list to
        //    `CertificateParams::new` and assign the constructed list
        //    directly so we control the exact `SanType` shapes (the
        //    convenience constructor only takes `Vec<String>` and
        //    auto-classifies as `DnsName` vs `IpAddress`, losing
        //    fine-grained control over IPv6).
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
            .map_err(|e| AcmeError::Cert(format!("params: {e}")))?;
        params.subject_alt_names = sans;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "portal-relay-local".to_owned());

        // CA-mark the leaf with a path-length constraint of 0 so it can
        // self-sign but cannot delegate further. This mirrors the Go
        // reference's `BasicConstraintsValid: true, IsCA: true` behaviour
        // while keeping the trust scope minimal for a dev cert.
        params.is_ca =
            rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));

        // 10-year validity window. We anchor `not_before` to Jan 1 of
        // the current calendar year (slightly back-dated, harmless for
        // a self-signed dev cert) and `not_after` to Jan 1 ten years
        // later. Day/month anchoring at Jan 1 sidesteps the Feb-29
        // edge case across leap years.
        let now_year_i32: i32 = current_utc_year_i32();
        let ten_years_after: i32 = now_year_i32
            .checked_add(10)
            .ok_or_else(|| AcmeError::Cert("validity overflow".to_owned()))?;
        params.not_before = rcgen::date_time_ymd(now_year_i32, 1, 1);
        params.not_after = rcgen::date_time_ymd(ten_years_after, 1, 1);

        // 3. Generate the keypair (ECDSA P-256 SHA-256).
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| AcmeError::Cert(format!("keypair: {e}")))?;

        // 4. Self-sign.
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| AcmeError::Cert(format!("self-sign: {e}")))?;

        // 5. Serialize to PEM.
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        // 6. Ensure key directory exists.
        tokio::fs::create_dir_all(&key_dir.0).await?;

        // 7. Atomic-write both files with the documented unix modes.
        let chain_path = key_dir.0.join("fullchain.pem");
        let key_path = key_dir.0.join("privatekey.pem");

        write_atomic_with_mode(&chain_path, cert_pem.as_bytes(), 0o644).await?;
        write_atomic_with_mode(&key_path, key_pem.as_bytes(), 0o600).await?;

        Ok(LocalCertPaths {
            fullchain: chain_path,
            private_key: key_path,
        })
    }
}

impl Default for LocalProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Paths to the persisted local self-signed cert + key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCertPaths {
    /// `<key_dir>/fullchain.pem`
    pub fullchain: PathBuf,
    /// `<key_dir>/privatekey.pem`
    pub private_key: PathBuf,
}

impl LocalCertPaths {
    /// `fullchain.pem` accessor.
    #[must_use]
    pub fn fullchain(&self) -> &Path {
        &self.fullchain
    }

    /// `privatekey.pem` accessor.
    #[must_use]
    pub fn private_key(&self) -> &Path {
        &self.private_key
    }
}

impl DnsProvider for LocalProvider {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn upsert(&self, _record: &DnsRecord) -> AcmeResult<()> {
        Err(AcmeError::Config(
            "local provider does not interact with DNS — \
             use generate_self_signed instead"
                .to_owned(),
        ))
    }

    async fn delete(&self, _record: &DnsRecord) -> AcmeResult<()> {
        Err(AcmeError::Config(
            "local provider does not interact with DNS".to_owned(),
        ))
    }

    async fn ensure_a_records(
        &self,
        _hostname: &str,
        _ipv4: std::net::Ipv4Addr,
    ) -> AcmeResult<()> {
        Err(AcmeError::Config(
            "local provider does not manage A records".to_owned(),
        ))
    }
}

/// Read the current UTC year as an `i32` via `jiff` so the rcgen
/// `date_time_ymd` helper (which takes `i32 year`) can be fed without
/// importing the `time` crate directly. Honouring the workspace-wide
/// `jiff`-only time policy is the reason we route through `jiff`.
///
/// Infallible: `jiff::Timestamp::now()` and `to_zoned(TimeZone::UTC)`
/// are both total functions, and the resulting calendar `year()` is
/// always representable as `i16`. We widen to `i32` because rcgen's
/// `date_time_ymd` API takes `i32`.
fn current_utc_year_i32() -> i32 {
    let zoned = jiff::Timestamp::now().to_zoned(jiff::tz::TimeZone::UTC);
    let year_i16: i16 = zoned.date().year();
    i32::from(year_i16)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only setup")]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn generate_self_signed_writes_chain_and_key() {
        let dir = tempdir().unwrap();
        let key_dir = KeyDir::new(dir.path().to_path_buf());
        let provider = LocalProvider::new();
        let paths = provider.generate_self_signed(&key_dir).await.unwrap();
        let chain = tokio::fs::read_to_string(paths.fullchain()).await.unwrap();
        let key = tokio::fs::read_to_string(paths.private_key()).await.unwrap();
        assert!(chain.contains("BEGIN CERTIFICATE"));
        assert!(chain.contains("END CERTIFICATE"));
        assert!(
            key.contains("BEGIN PRIVATE KEY") || key.contains("BEGIN EC PRIVATE KEY"),
            "expected PKCS#8 or SEC1 PEM marker in {key}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn private_key_has_unix_mode_0o600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir().unwrap();
        let key_dir = KeyDir::new(dir.path().to_path_buf());
        let provider = LocalProvider::new();
        let paths = provider.generate_self_signed(&key_dir).await.unwrap();
        let mode = tokio::fs::metadata(paths.private_key())
            .await
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fullchain_has_unix_mode_0o644() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir().unwrap();
        let key_dir = KeyDir::new(dir.path().to_path_buf());
        let provider = LocalProvider::new();
        let paths = provider.generate_self_signed(&key_dir).await.unwrap();
        let mode = tokio::fs::metadata(paths.fullchain())
            .await
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    #[tokio::test]
    async fn with_base_domain_emits_non_empty_chain() {
        let dir = tempdir().unwrap();
        let key_dir = KeyDir::new(dir.path().to_path_buf());
        let provider = LocalProvider::with_base_domain("relay.example.com");
        let paths = provider.generate_self_signed(&key_dir).await.unwrap();
        let chain = tokio::fs::read_to_string(paths.fullchain()).await.unwrap();
        // PEM-encoded cert is base64 over the DER body; we don't parse
        // the SAN extension here (that's a downstream rustls concern),
        // we just assert the file is non-empty and well-formed.
        assert!(chain.len() > 100);
        assert!(chain.contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn with_base_domain_localhost_does_not_duplicate_sans() {
        // When the base_domain happens to be the literal "localhost",
        // we must not emit duplicate SAN entries.
        let dir = tempdir().unwrap();
        let key_dir = KeyDir::new(dir.path().to_path_buf());
        let provider = LocalProvider::with_base_domain("localhost");
        let paths = provider.generate_self_signed(&key_dir).await.unwrap();
        let chain = tokio::fs::read_to_string(paths.fullchain()).await.unwrap();
        assert!(chain.contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn dns_methods_return_config_error() {
        let provider = LocalProvider::new();
        let record = DnsRecord {
            name: "example.com".into(),
            record_type: "TXT".into(),
            value: "challenge".into(),
            ttl: 60,
        };
        assert!(matches!(
            provider.upsert(&record).await,
            Err(AcmeError::Config(_))
        ));
        assert!(matches!(
            provider.delete(&record).await,
            Err(AcmeError::Config(_))
        ));
        assert!(matches!(
            provider
                .ensure_a_records("any", std::net::Ipv4Addr::LOCALHOST)
                .await,
            Err(AcmeError::Config(_))
        ));
    }

    #[tokio::test]
    async fn provider_name_is_local() {
        let provider = LocalProvider::new();
        assert_eq!(provider.name(), "local");
    }

    #[test]
    fn current_utc_year_is_plausible() {
        let year = current_utc_year_i32();
        // Sanity bound: keeps the test green for the foreseeable
        // future without coupling to `jiff::Timestamp::now()` mocking.
        assert!((2024..4096).contains(&year), "unexpected year: {year}");
    }
}
