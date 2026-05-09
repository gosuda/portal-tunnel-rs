//! `instant-acme` client wrapper + on-disk persistence.
//!
//! Wraps [`instant_acme::Account`] with atomic on-disk persistence of the
//! account key, registration JSON, and issued certificate chain. Drives the
//! order → authorization → DNS-01 challenge → finalize → certificate dance
//! via a pluggable [`DnsProvider`].

use compact_str::CompactString;
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, NewAccount, NewOrder, RetryPolicy,
};
use jiff::Timestamp;
use tracing::{debug, info, instrument, warn};

use crate::config::{DirectoryUrl, KeyDir};
use crate::error::{AcmeError, AcmeResult};
use crate::persist::write_atomic_with_mode;
use crate::provider::{DnsProvider, DnsRecord};

/// File names for on-disk persistence.
const REGISTRATION_FILE: &str = "acme-registration.json";
const FULLCHAIN_FILE: &str = "fullchain.pem";
const PRIVATE_KEY_FILE: &str = "privatekey.pem";

/// Renewal window: renew if cert expires within 30 days.
const RENEWAL_WINDOW_DAYS: i64 = 30;

/// Initial wait before polling the ACME server so DNS has time to propagate.
/// Go's lego uses active propagation checks; v0.1 ships a conservative sleep
/// followed by ACME-side polling (the CA retries internally).
const DNS_INITIAL_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// ACME client wrapper — holds an [`instant_acme::Account`] plus the
/// directory URL and contact email needed for recovery.
pub struct AcmeClient {
    account: Account,
    directory_url: DirectoryUrl,
    contact_email: CompactString,
}

impl std::fmt::Debug for AcmeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeClient")
            .field("directory_url", &self.directory_url)
            .field("contact_email", &self.contact_email)
            .finish_non_exhaustive()
    }
}

impl AcmeClient {
    /// Load an existing account from disk, or create (and persist) a new one.
    ///
    /// 1. If `<key_dir>/acme-registration.json` exists, deserialize
    ///    [`AccountCredentials`] and restore the account via
    ///    `Account::builder().from_credentials(creds)`.
    /// 2. Otherwise generate an EC P-256 key pair, create a new account with
    ///    the CA, and atomically persist the credentials.
    ///
    /// # Errors
    /// Returns [`AcmeError::Io`] / [`AcmeError::Json`] on persistence
    /// failure, or [`AcmeError::Acme`] on RFC 8555 rejection.
    #[instrument(skip(key_dir), fields(directory = %directory_url.0))]
    pub async fn load_or_register(
        directory_url: DirectoryUrl,
        contact_email: CompactString,
        key_dir: &KeyDir,
    ) -> AcmeResult<Self> {
        let reg_path = key_dir.0.join(REGISTRATION_FILE);

        if let Ok(bytes) = tokio::fs::read(&reg_path).await {
            debug!(path = %reg_path.display(), "found existing registration");
            let creds: AccountCredentials = serde_json::from_slice(&bytes)?;
            let account = Account::builder()
                .map_err(|e| AcmeError::Acme(format!("builder: {e}")))?
                .from_credentials(creds)
                .await
                .map_err(|e| AcmeError::Acme(format!("restore account: {e}")))?;
            info!("restored ACME account from disk");
            return Ok(Self {
                account,
                directory_url,
                contact_email,
            });
        }

        info!("creating new ACME account");
        let (account, creds) = Self::create_account(&directory_url, &contact_email).await?;

        let creds_json = serde_json::to_vec(&creds)?;
        write_atomic_with_mode(&reg_path, &creds_json, 0o600).await?;

        info!("persisted new ACME account");
        Ok(Self {
            account,
            directory_url,
            contact_email,
        })
    }

    /// Obtain (or renew) a certificate for `domains` using the supplied
    /// `dns_provider` for DNS-01 challenge solving.
    ///
    /// # Flow
    /// 1. Create a new order.
    /// 2. For each authorization: extract the DNS-01 challenge, publish the
    ///    TXT record via `dns_provider`, and mark the challenge ready.
    /// 3. Wait for DNS propagation, then poll the order until `Ready`.
    /// 4. Finalize the order (generates CSR + private key).
    /// 5. Download the certificate chain.
    /// 6. Atomically write `fullchain.pem` + `privatekey.pem`.
    /// 7. Best-effort cleanup of TXT records.
    ///
    /// # Errors
    /// Returns [`AcmeError::Acme`] on CA rejection, [`AcmeError::Dns`] on
    /// DNS provider failure, or [`AcmeError::Io`] on cert write failure.
    #[instrument(skip(self, dns_provider), fields(domains = ?domains))]
    pub async fn obtain<P: DnsProvider + ?Sized>(
        &self,
        domains: &[CompactString],
        dns_provider: &P,
        key_dir: &KeyDir,
    ) -> AcmeResult<()> {
        let identifiers: Vec<Identifier> = domains
            .iter()
            .map(|d| Identifier::Dns(d.to_string()))
            .collect();

        info!("creating ACME order");
        let mut order = self
            .account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|e| AcmeError::Acme(format!("new_order: {e}")))?;

        let mut challenges: Vec<DnsRecord> = Vec::new();

        // --- publish DNS-01 TXT records ---
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.map_err(|e| AcmeError::Acme(format!("authz: {e}")))?;

            if authz.status == instant_acme::AuthorizationStatus::Valid {
                debug!("authorization already valid — skipping");
                continue;
            }

            let mut challenge = authz
                .challenge(ChallengeType::Dns01)
                .ok_or_else(|| AcmeError::Acme("missing DNS-01 challenge".to_owned()))?;

            let key_auth = challenge.key_authorization();
            let dns_value = key_auth.dns_value();
            let identifier = challenge.identifier().to_owned();

            let record = DnsRecord {
                name: CompactString::from(format!("_acme-challenge.{identifier}")),
                record_type: CompactString::const_new("TXT"),
                value: CompactString::from(dns_value),
                ttl: 60,
            };

            info!(record = %record.name, "publishing DNS-01 TXT record");
            if let Err(e) = dns_provider.upsert(&record).await {
                Self::cleanup_records(dns_provider, &challenges).await;
                return Err(AcmeError::Dns(format!("upsert {}: {e}", record.name)));
            }

            // Record is now live — track it for cleanup even if set_ready fails.
            challenges.push(record);

            if let Err(e) = challenge.set_ready().await {
                Self::cleanup_records(dns_provider, &challenges).await;
                return Err(AcmeError::Acme(format!("set_ready: {e}")));
            }
        }

        // Run the remainder of the flow, ensuring cleanup always fires.
        let result = Self::poll_finalize_and_persist(&mut order, key_dir).await;

        // Cleanup runs regardless of success or failure.
        Self::cleanup_records(dns_provider, &challenges).await;

        result
    }

    /// Check whether cert files already exist under `key_dir`.
    #[must_use]
    pub async fn cert_files_exist(key_dir: &KeyDir) -> bool {
        let chain = key_dir.0.join(FULLCHAIN_FILE);
        let key = key_dir.0.join(PRIVATE_KEY_FILE);
        tokio::fs::metadata(&chain).await.is_ok() && tokio::fs::metadata(&key).await.is_ok()
    }

    /// Determine whether the certificate on disk needs renewal.
    ///
    /// Returns `true` if:
    /// - The cert file does not exist.
    /// - The cert's `notAfter` is within 30 days of now.
    /// - The requested `domains` are not a subset of the cert's SAN list.
    ///
    /// # Errors
    /// Returns [`AcmeError::Cert`] on parse failure.
    #[must_use]
    pub fn should_renew(key_dir: &KeyDir, domains: &[CompactString]) -> bool {
        let chain_path = key_dir.0.join(FULLCHAIN_FILE);
        let Ok(pem_bytes) = std::fs::read(&chain_path) else {
            return true;
        };

        let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(&pem_bytes) else {
            return true;
        };
        let Ok(cert) = pem.parse_x509() else {
            return true;
        };

        // Check expiry
        let not_after = cert.validity().not_after;
        let now = Timestamp::now();
        let Ok(not_after_ts) = jiff::Timestamp::new(not_after.timestamp(), 0) else {
            return true;
        };

        let window = jiff::SignedDuration::from_secs(RENEWAL_WINDOW_DAYS * 24 * 60 * 60);
        let remaining = not_after_ts.duration_since(now);
        if remaining < window {
            return true;
        }

        // Check SAN coverage
        let cert_domains: std::collections::HashSet<String> = cert
            .subject_alternative_name()
            .ok()
            .flatten()
            .map(|ext| {
                ext.value
                    .general_names
                    .iter()
                    .filter_map(|gn| {
                        if let x509_parser::extensions::GeneralName::DNSName(d) = gn {
                            Some(d.to_string())
                        } else {
                            None
                        }
                    })
                    .collect::<std::collections::HashSet<_>>()
            })
            .unwrap_or_default();

        for domain in domains {
            if !cert_domains.contains(domain.as_str()) {
                return true;
            }
        }

        false
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    async fn poll_finalize_and_persist(
        order: &mut instant_acme::Order,
        key_dir: &KeyDir,
    ) -> AcmeResult<()> {
        // --- wait for DNS propagation ---
        info!("waiting for DNS propagation");
        tokio::time::sleep(DNS_INITIAL_WAIT).await;

        // --- poll order until Ready ---
        let retry = RetryPolicy::default();
        let state = order
            .poll_ready(&retry)
            .await
            .map_err(|e| AcmeError::Acme(format!("poll_ready: {e}")))?;

        if state != instant_acme::OrderStatus::Ready {
            return Err(AcmeError::Acme(format!(
                "order not ready after polling: {state:?}"
            )));
        }

        // --- finalize ---
        info!("finalizing order");
        let private_key_pem = order
            .finalize()
            .await
            .map_err(|e| AcmeError::Acme(format!("finalize: {e}")))?;

        let cert_chain_pem = order
            .poll_certificate(&retry)
            .await
            .map_err(|e| AcmeError::Acme(format!("poll_certificate: {e}")))?;

        // --- persist atomically ---
        let chain_path = key_dir.0.join(FULLCHAIN_FILE);
        let key_path = key_dir.0.join(PRIVATE_KEY_FILE);

        write_atomic_with_mode(&chain_path, cert_chain_pem.as_bytes(), 0o644).await?;
        write_atomic_with_mode(&key_path, private_key_pem.as_bytes(), 0o600).await?;

        info!("certificate materialized");
        Ok(())
    }

    async fn cleanup_records<P: DnsProvider + ?Sized>(dns_provider: &P, records: &[DnsRecord]) {
        for record in records {
            info!(record = %record.name, "cleaning up DNS-01 TXT record");
            if let Err(e) = dns_provider.delete(record).await {
                warn!(record = %record.name, error = %e, "TXT cleanup failed (non-fatal)");
            }
        }
    }

    async fn create_account(
        directory_url: &DirectoryUrl,
        contact_email: &CompactString,
    ) -> AcmeResult<(Account, AccountCredentials)> {
        let contact = format!("mailto:{contact_email}");
        let contact_refs: &[&str] = &[contact.as_str()];
        let (account, creds) = Account::builder()
            .map_err(|e| AcmeError::Acme(format!("builder: {e}")))?
            .create(
                &NewAccount {
                    contact: contact_refs,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory_url.0.to_string(),
                None,
            )
            .await
            .map_err(|e| AcmeError::Acme(format!("create account: {e}")))?;

        Ok((account, creds))
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test-only assertions")]

    use super::*;

    fn write_self_signed_cert(dir: &std::path::Path, san: &[&str], not_after_days: i64) {
        let mut params =
            rcgen::CertificateParams::new(san.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .expect("params");

        let now = jiff::Timestamp::now().to_zoned(jiff::tz::TimeZone::UTC);
        let not_before = now
            .checked_sub(jiff::Span::new().days(1))
            .expect("valid past date");
        let date = not_before.date();
        params.not_before = rcgen::date_time_ymd(
            i32::from(date.year()),
            date.month().try_into().expect("month in 1..=12"),
            date.day().try_into().expect("day in 1..=31"),
        );

        let not_after = now
            .checked_add(jiff::Span::new().days(not_after_days))
            .expect("valid future date");
        let date = not_after.date();
        params.not_after = rcgen::date_time_ymd(
            i32::from(date.year()),
            date.month().try_into().expect("month in 1..=12"),
            date.day().try_into().expect("day in 1..=31"),
        );

        let key_pair = rcgen::KeyPair::generate().expect("keypair");
        let cert = params.self_signed(&key_pair).expect("cert");
        std::fs::write(dir.join(FULLCHAIN_FILE), cert.pem()).expect("write");
    }

    #[test]
    fn should_renew_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_dir = KeyDir::new(dir.path().to_path_buf());
        let domains = vec![CompactString::from("example.com")];
        assert!(
            AcmeClient::should_renew(&key_dir, &domains),
            "missing cert => renew"
        );
    }

    #[test]
    fn should_renew_fresh_cert_covers_domains() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_dir = KeyDir::new(dir.path().to_path_buf());
        write_self_signed_cert(dir.path(), &["example.com"], 90);

        let domains = vec![CompactString::from("example.com")];
        assert!(
            !AcmeClient::should_renew(&key_dir, &domains),
            "fresh cert covering domains => no renew"
        );
    }

    #[test]
    fn should_renew_expiring_cert() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_dir = KeyDir::new(dir.path().to_path_buf());
        write_self_signed_cert(dir.path(), &["example.com"], 7);

        let domains = vec![CompactString::from("example.com")];
        assert!(
            AcmeClient::should_renew(&key_dir, &domains),
            "expiring cert => renew"
        );
    }

    #[test]
    fn should_renew_missing_domain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_dir = KeyDir::new(dir.path().to_path_buf());
        write_self_signed_cert(dir.path(), &["example.com"], 90);

        let domains = vec![
            CompactString::from("example.com"),
            CompactString::from("www.example.com"),
        ];
        assert!(
            AcmeClient::should_renew(&key_dir, &domains),
            "missing domain in SAN => renew"
        );
    }

    // ---- Adversarial tests ------------------------------------------------

    #[test]
    fn should_renew_corrupt_pem() {
        // A corrupted PEM file must trigger renewal rather than panic or
        // return a false negative.
        let dir = tempfile::tempdir().expect("tempdir");
        let key_dir = KeyDir::new(dir.path().to_path_buf());
        std::fs::write(dir.path().join(FULLCHAIN_FILE), b"not a pem").expect("write");

        let domains = vec![CompactString::from("example.com")];
        assert!(
            AcmeClient::should_renew(&key_dir, &domains),
            "corrupt PEM => renew"
        );
    }

    #[test]
    fn should_renew_pem_without_san() {
        // A certificate that lacks a SubjectAlternativeName extension has
        // an empty SAN set, so any requested domain is "missing".
        let dir = tempfile::tempdir().expect("tempdir");
        let key_dir = KeyDir::new(dir.path().to_path_buf());
        write_self_signed_cert(dir.path(), &[], 90);

        let domains = vec![CompactString::from("example.com")];
        assert!(
            AcmeClient::should_renew(&key_dir, &domains),
            "cert without SAN cannot cover any domain => renew"
        );
    }

    #[test]
    fn should_renew_empty_domains() {
        // Empty domain list is vacuously covered by any SAN set, so the
        // decision hinges purely on expiry. A fresh cert => no renew.
        let dir = tempfile::tempdir().expect("tempdir");
        let key_dir = KeyDir::new(dir.path().to_path_buf());
        write_self_signed_cert(dir.path(), &["example.com"], 90);

        let domains: Vec<CompactString> = vec![];
        assert!(
            !AcmeClient::should_renew(&key_dir, &domains),
            "empty domains list on fresh cert => no renew"
        );
    }
}
