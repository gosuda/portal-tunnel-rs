use std::fs;
use std::future::Future;
use std::io::BufReader;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use aws_config::BehaviorVersion;
use aws_credential_types::Credentials as AwsCredentials;
use aws_sdk_route53::Client as Route53SdkClient;
use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, ChangeStatus, ResourceRecord, ResourceRecordSet, RrType,
};
use aws_types::region::Region;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use google_cloud_auth::credentials::AccessTokenCredentials;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, Key, LetsEncrypt, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair, PKCS_RSA_SHA256, RsaKeySize};
use reqwest::Method;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::task::JoinHandle;
use tracing::{info, warn};
use url::Url;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

const FULL_CHAIN_FILE_NAME: &str = "fullchain.pem";
const KEY_FILE_NAME: &str = "privatekey.pem";
const ACCOUNT_KEY_FILE_NAME: &str = "acme-account.key";
const REGISTRATION_FILE_NAME: &str = "acme-registration.json";
const DEFAULT_ACME_EMAIL_PREFIX: &str = "acme@";
const RENEW_BEFORE_SECS: i64 = 30 * 24 * 60 * 60;
const RENEW_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const DNS_SYNC_INTERVAL: Duration = Duration::from_secs(10 * 60);
const DNS_PROPAGATION_WAIT: Duration = Duration::from_secs(30);
const ACME_OPERATION_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const GCLOUD_CHANGE_POLL_INTERVAL: Duration = Duration::from_secs(2);
const ROUTE53_CHANGE_POLL_INTERVAL: Duration = Duration::from_secs(2);
const PUBLIC_IPV4_ENDPOINTS: &[&str] = &[
    "https://api4.ipify.org",
    "https://ipv4.icanhazip.com",
    "https://v4.ident.me",
    "https://checkip.amazonaws.com",
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
];

#[derive(Clone)]
pub struct AcmeConfig {
    pub identity_path: PathBuf,
    pub base_domain: String,
    pub provider: AcmeDnsProviderConfig,
}

#[derive(Clone)]
pub enum AcmeDnsProviderConfig {
    Cloudflare {
        token: String,
    },
    GCloud {
        project_id: String,
        managed_zone: String,
    },
    Route53 {
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
        region: String,
        hosted_zone_id: String,
    },
}

#[derive(Clone)]
pub struct AcmeManager {
    identity_path: PathBuf,
    base_domain: String,
    dns: DnsProvider,
}

impl AcmeManager {
    pub fn new(cfg: AcmeConfig) -> anyhow::Result<Self> {
        let base_domain = normalize_base_domain(&cfg.base_domain);
        if base_domain.is_empty() {
            bail!("acme base domain is required");
        }
        if cfg.identity_path.as_os_str().is_empty() {
            bail!("acme identity path is required");
        }
        let dns = DnsProvider::new(cfg.provider)?;

        Ok(Self {
            identity_path: cfg.identity_path,
            base_domain,
            dns,
        })
    }

    pub async fn ensure_certificate(&self) -> anyhow::Result<()> {
        fs::create_dir_all(&self.identity_path).with_context(|| {
            format!(
                "create acme identity directory {}",
                self.identity_path.display()
            )
        })?;

        if is_local_relay_host(&self.base_domain) {
            info!(
                base_domain = %self.base_domain,
                "local relay host detected; using local tls material"
            );
            return Ok(());
        }

        if let Some(state) = self.existing_certificate_state()? {
            if state.covers_domains && !self.has_acme_state() {
                info!(
                    base_domain = %self.base_domain,
                    not_after_unix = state.not_after_unix,
                    "using manual relay certificate override"
                );
                self.sync_dns().await.context("sync dns records")?;
                return Ok(());
            }
            if state.covers_domains && !state.needs_renewal {
                info!(
                    base_domain = %self.base_domain,
                    not_after_unix = state.not_after_unix,
                    "managed relay certificate is current"
                );
                return Ok(());
            }
            if !state.covers_domains && !self.has_acme_state() {
                bail!(
                    "manual relay certificate must cover {} and *.{}",
                    self.base_domain,
                    self.base_domain
                );
            }
        }

        self.provision_certificate().await
    }

    pub fn start_maintenance(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut renew_ticker = tokio::time::interval(RENEW_INTERVAL);
            let mut dns_ticker = tokio::time::interval(DNS_SYNC_INTERVAL);
            renew_ticker.tick().await;
            dns_ticker.tick().await;

            loop {
                tokio::select! {
                    _ = dns_ticker.tick() => {
                        if let Err(err) = tokio::time::timeout(ACME_OPERATION_TIMEOUT, self.sync_dns()).await
                            .unwrap_or_else(|_| Err(anyhow::anyhow!("dns sync timed out")))
                        {
                            warn!(base_domain = %self.base_domain, error = %err, "sync dns records failed");
                        }
                    }
                    _ = renew_ticker.tick() => {
                        if let Err(err) = tokio::time::timeout(ACME_OPERATION_TIMEOUT, self.renew_if_needed()).await
                            .unwrap_or_else(|_| Err(anyhow::anyhow!("acme renewal timed out")))
                        {
                            warn!(base_domain = %self.base_domain, error = %err, "renew acme certificate failed");
                        }
                    }
                }
            }
        })
    }

    async fn renew_if_needed(&self) -> anyhow::Result<()> {
        if let Some(state) = self.existing_certificate_state()? {
            if state.covers_domains && !self.has_acme_state() {
                return Ok(());
            }
            if state.covers_domains && !state.needs_renewal {
                return Ok(());
            }
        }

        self.provision_certificate().await?;
        info!(
            base_domain = %self.base_domain,
            "acme certificate renewed on disk; restart the relay to load renewed tls material"
        );
        Ok(())
    }

    async fn provision_certificate(&self) -> anyhow::Result<()> {
        self.sync_dns().await.context("sync dns records")?;

        let account = self.load_or_create_account().await?;
        let domains = certificate_domains(&self.base_domain);
        let identifiers = domains
            .iter()
            .cloned()
            .map(Identifier::Dns)
            .collect::<Vec<_>>();
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .context("create acme order")?;

        let dns_records = self.prepare_dns_challenges(&mut order).await?;
        if !dns_records.is_empty() {
            info!(
                base_domain = %self.base_domain,
                record_count = dns_records.len(),
                wait_secs = DNS_PROPAGATION_WAIT.as_secs(),
                "waiting for dns-01 challenge propagation"
            );
            tokio::time::sleep(DNS_PROPAGATION_WAIT).await;
            self.mark_dns_challenges_ready(&mut order).await?;
        }

        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .context("poll acme order readiness")?;
        if status != OrderStatus::Ready {
            bail!("unexpected acme order status: {status:?}");
        }

        let key_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048)
            .context("generate rsa certificate key")?;
        let mut params =
            CertificateParams::new(domains).context("build acme certificate parameters")?;
        params.distinguished_name = DistinguishedName::new();
        let csr = params
            .serialize_request(&key_pair)
            .context("build acme certificate signing request")?;
        order
            .finalize_csr(csr.der())
            .await
            .context("finalize acme order")?;
        let cert_chain_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .context("poll acme certificate")?;
        if cert_chain_pem.trim().is_empty() {
            bail!("acme certificate response is empty");
        }

        write_file_atomic(&self.cert_path(), cert_chain_pem.as_bytes(), 0o644)
            .context("write acme certificate chain")?;
        write_file_atomic(&self.key_path(), key_pair.serialize_pem().as_bytes(), 0o600)
            .context("write acme private key")?;

        for record in dns_records {
            if let Err(err) = self
                .dns
                .delete_txt_record_value(&record.name, &record.value)
                .await
            {
                warn!(
                    record = %record.name,
                    error = %err,
                    "cleanup acme dns-01 challenge record failed"
                );
            }
        }

        info!(
            base_domain = %self.base_domain,
            cert_path = %self.cert_path().display(),
            key_path = %self.key_path().display(),
            "acme certificate provisioned"
        );
        Ok(())
    }

    async fn prepare_dns_challenges(
        &self,
        order: &mut instant_acme::Order,
    ) -> anyhow::Result<Vec<DnsChallengeRecord>> {
        let mut records = Vec::new();
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.context("load acme authorization")?;
            match authz.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                other => bail!("unexpected acme authorization status: {other:?}"),
            }

            let challenge = authz
                .challenge(ChallengeType::Dns01)
                .context("no dns-01 challenge found")?;
            let name = dns01_record_name(&challenge.identifier().to_string())?;
            let value = challenge.key_authorization().dns_value();
            self.dns
                .ensure_txt_record(&name, &value)
                .await
                .with_context(|| format!("ensure acme dns-01 TXT record {name}"))?;
            records.push(DnsChallengeRecord { name, value });
        }
        Ok(records)
    }

    async fn mark_dns_challenges_ready(
        &self,
        order: &mut instant_acme::Order,
    ) -> anyhow::Result<()> {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.context("load acme authorization")?;
            if authz.status != AuthorizationStatus::Pending {
                continue;
            }
            let mut challenge = authz
                .challenge(ChallengeType::Dns01)
                .context("no dns-01 challenge found")?;
            challenge
                .set_ready()
                .await
                .context("mark acme dns-01 challenge ready")?;
        }
        Ok(())
    }

    async fn load_or_create_account(&self) -> anyhow::Result<Account> {
        if self.account_key_path().exists() {
            let key_der = read_account_key(&self.account_key_path())?;
            let key = Key::from_pkcs8_der(key_der.clone_key()).context("parse acme account key")?;
            let (account, _) = Account::builder()
                .context("create acme account builder")?
                .create_from_key(
                    (key, PrivateKeyDer::Pkcs8(key_der)),
                    LetsEncrypt::Production.url().to_owned(),
                )
                .await
                .context("restore acme account from key")?;
            if !self.registration_path().exists() {
                self.write_registration_resource(&account)?;
            }
            return Ok(account);
        }

        let email = format!("{DEFAULT_ACME_EMAIL_PREFIX}{}", self.base_domain);
        let contacts = [format!("mailto:{email}")];
        let contact_refs = contacts.iter().map(String::as_str).collect::<Vec<_>>();
        let (account, credentials) = Account::builder()
            .context("create acme account builder")?
            .create(
                &NewAccount {
                    contact: &contact_refs,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                LetsEncrypt::Production.url().to_owned(),
                None,
            )
            .await
            .context("create acme account")?;
        write_account_key(&self.account_key_path(), credentials.private_key())
            .context("write acme account key")?;
        self.write_registration_resource(&account)?;
        Ok(account)
    }

    async fn sync_dns(&self) -> anyhow::Result<()> {
        if is_local_relay_host(&self.base_domain) {
            return Ok(());
        }
        let public_ipv4 = resolve_public_ipv4(self.dns.http()).await?;
        self.sync_dns_with_resolved_public_ipv4(&public_ipv4).await
    }

    async fn sync_dns_with_resolved_public_ipv4(&self, public_ipv4: &str) -> anyhow::Result<()> {
        if is_local_relay_host(&self.base_domain) {
            return Ok(());
        }
        self.validate_manual_certificate_override()?;
        self.dns
            .ensure_a_records(&self.base_domain, public_ipv4)
            .await
            .with_context(|| format!("ensure DNS A records for {}", self.base_domain))
    }

    fn validate_manual_certificate_override(&self) -> anyhow::Result<()> {
        let Some(state) = self.existing_certificate_state()? else {
            return Ok(());
        };
        if !self.has_acme_state() && !state.covers_domains {
            bail!(
                "manual relay certificate must cover {} and *.{}",
                self.base_domain,
                self.base_domain
            );
        }
        Ok(())
    }

    fn existing_certificate_state(&self) -> anyhow::Result<Option<CertificateState>> {
        if !self.cert_path().exists() || !self.key_path().exists() {
            return Ok(None);
        }
        let cert_pem = fs::read(self.cert_path())
            .with_context(|| format!("read certificate {}", self.cert_path().display()))?;
        let leaf = parse_first_certificate(&cert_pem)?;
        let (_, cert) =
            parse_x509_certificate(leaf.as_ref()).context("parse leaf x509 certificate")?;
        let not_after_unix = cert.validity().not_after.timestamp();
        let seconds_until_expiry = not_after_unix - chrono::Utc::now().timestamp();
        let covers_domains =
            certificate_covers_domains(&cert, &certificate_domains(&self.base_domain))?;
        Ok(Some(CertificateState {
            covers_domains,
            not_after_unix,
            needs_renewal: seconds_until_expiry < RENEW_BEFORE_SECS,
        }))
    }

    fn has_acme_state(&self) -> bool {
        self.account_key_path().exists() || self.registration_path().exists()
    }

    fn cert_path(&self) -> PathBuf {
        self.identity_path.join(FULL_CHAIN_FILE_NAME)
    }

    fn key_path(&self) -> PathBuf {
        self.identity_path.join(KEY_FILE_NAME)
    }

    fn account_key_path(&self) -> PathBuf {
        self.identity_path.join(ACCOUNT_KEY_FILE_NAME)
    }

    fn registration_path(&self) -> PathBuf {
        self.identity_path.join(REGISTRATION_FILE_NAME)
    }

    fn write_registration_resource(&self, account: &Account) -> anyhow::Result<()> {
        let contact = vec![format!(
            "mailto:{DEFAULT_ACME_EMAIL_PREFIX}{}",
            self.base_domain
        )];
        let resource = AcmeRegistrationResource {
            body: AcmeRegistrationBody {
                status: "valid",
                contact,
                terms_of_service_agreed: true,
            },
            uri: account.id(),
        };
        let serialized =
            serde_json::to_vec_pretty(&resource).context("serialize acme registration")?;
        write_file_atomic(&self.registration_path(), &serialized, 0o600)
            .context("write acme registration")
    }
}

#[derive(Debug, Serialize)]
struct AcmeRegistrationResource<'a> {
    body: AcmeRegistrationBody<'a>,
    uri: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AcmeRegistrationBody<'a> {
    status: &'a str,
    contact: Vec<String>,
    terms_of_service_agreed: bool,
}

#[derive(Debug)]
struct CertificateState {
    covers_domains: bool,
    not_after_unix: i64,
    needs_renewal: bool,
}

#[derive(Debug)]
struct DnsChallengeRecord {
    name: String,
    value: String,
}

type DnsFuture<'a, T> = Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send + 'a>>;

trait DnsProviderImpl: Send + Sync {
    fn ensure_a_records<'a>(
        &'a self,
        base_domain: &'a str,
        public_ipv4: &'a str,
    ) -> DnsFuture<'a, ()>;
    fn ensure_txt_record<'a>(&'a self, name: &'a str, value: &'a str) -> DnsFuture<'a, ()>;
    fn delete_txt_record_value<'a>(&'a self, name: &'a str, value: &'a str) -> DnsFuture<'a, ()>;
    fn http(&self) -> &reqwest::Client;
}

#[derive(Clone)]
struct DnsProvider(Arc<dyn DnsProviderImpl>);

impl DnsProvider {
    fn new(cfg: AcmeDnsProviderConfig) -> anyhow::Result<Self> {
        match cfg {
            AcmeDnsProviderConfig::Cloudflare { token } => {
                Ok(Self(Arc::new(CloudflareClient::new(token)?)))
            }
            AcmeDnsProviderConfig::GCloud {
                project_id,
                managed_zone,
            } => Ok(Self(Arc::new(GCloudClient::new(project_id, managed_zone)?))),
            AcmeDnsProviderConfig::Route53 {
                access_key_id,
                secret_access_key,
                session_token,
                region,
                hosted_zone_id,
            } => Ok(Self(Arc::new(Route53Client::new(
                access_key_id,
                secret_access_key,
                session_token,
                region,
                hosted_zone_id,
            )?))),
        }
    }

    async fn ensure_a_records(&self, base_domain: &str, public_ipv4: &str) -> anyhow::Result<()> {
        self.0.ensure_a_records(base_domain, public_ipv4).await
    }

    async fn ensure_txt_record(&self, name: &str, value: &str) -> anyhow::Result<()> {
        self.0.ensure_txt_record(name, value).await
    }

    async fn delete_txt_record_value(&self, name: &str, value: &str) -> anyhow::Result<()> {
        self.0.delete_txt_record_value(name, value).await
    }

    fn http(&self) -> &reqwest::Client {
        self.0.http()
    }
}

#[derive(Clone)]
struct CloudflareClient {
    token: String,
    http: reqwest::Client,
}

impl CloudflareClient {
    fn new(token: String) -> anyhow::Result<Self> {
        let token = token.trim().to_string();
        if token.is_empty() {
            bail!("cloudflare token is required when ACME_DNS_PROVIDER=cloudflare");
        }
        Ok(Self {
            token,
            http: reqwest::Client::new(),
        })
    }

    fn http(&self) -> &reqwest::Client {
        &self.http
    }

    async fn ensure_a_records(&self, base_domain: &str, public_ipv4: &str) -> anyhow::Result<()> {
        validate_ipv4(public_ipv4)?;
        let zone_id = self.find_zone_id(base_domain).await?;
        for name in [base_domain.to_string(), format!("*.{base_domain}")] {
            self.ensure_dns_record(&zone_id, &name, "A", public_ipv4)
                .await
                .with_context(|| format!("ensure A record for {name}"))?;
        }
        Ok(())
    }

    async fn ensure_txt_record(&self, name: &str, value: &str) -> anyhow::Result<()> {
        let name = normalize_hostname(name);
        if name.is_empty() {
            bail!("txt record name is required");
        }
        let value = value.trim();
        if value.is_empty() {
            bail!("txt record value is required");
        }
        let zone_id = self.find_zone_id(&name).await?;
        let records = self.list_dns_records(&zone_id, &name, "TXT").await?;
        if records
            .iter()
            .any(|record| record.name.eq_ignore_ascii_case(&name) && record.content.trim() == value)
        {
            return Ok(());
        }
        self.create_dns_record(&zone_id, "TXT", &name, value).await
    }

    async fn delete_txt_record_value(&self, name: &str, value: &str) -> anyhow::Result<()> {
        let name = normalize_hostname(name);
        let value = value.trim();
        if name.is_empty() || value.is_empty() {
            return Ok(());
        }
        let zone_id = self.find_zone_id(&name).await?;
        let records = self.list_dns_records(&zone_id, &name, "TXT").await?;
        for record in records {
            if record.name.eq_ignore_ascii_case(&name) && record.content.trim() == value {
                self.delete_dns_record(&zone_id, &record.id).await?;
            }
        }
        Ok(())
    }

    async fn find_zone_id(&self, domain: &str) -> anyhow::Result<String> {
        let domain = normalize_hostname(domain.trim_start_matches("*."));
        if domain.is_empty() {
            bail!("cloudflare zone domain is required");
        }
        let parts = domain.split('.').collect::<Vec<_>>();
        if parts.len() < 2 {
            bail!("domain {domain:?} is not eligible for cloudflare zone lookup");
        }
        for i in 0..parts.len() - 1 {
            let candidate = parts[i..].join(".");
            let zones = self.list_zones(&candidate).await?;
            if let Some(zone) = zones
                .into_iter()
                .find(|zone| zone.name.eq_ignore_ascii_case(&candidate))
            {
                return Ok(zone.id);
            }
        }
        bail!("no cloudflare zone found for {domain}")
    }

    async fn ensure_dns_record(
        &self,
        zone_id: &str,
        name: &str,
        record_type: &str,
        content: &str,
    ) -> anyhow::Result<()> {
        let records = self.list_dns_records(zone_id, name, record_type).await?;
        for record in records {
            if !record.name.eq_ignore_ascii_case(name) {
                continue;
            }
            if record.content == content {
                return Ok(());
            }
            return self
                .update_dns_record(zone_id, &record.id, record_type, name, content)
                .await;
        }
        self.create_dns_record(zone_id, record_type, name, content)
            .await
    }

    async fn list_zones(&self, name: &str) -> anyhow::Result<Vec<CloudflareZone>> {
        let mut url = cloudflare_api_url("/zones")?;
        url.query_pairs_mut().append_pair("name", name);
        self.send::<Vec<CloudflareZone>, ()>(Method::GET, url, None)
            .await
    }

    async fn list_dns_records(
        &self,
        zone_id: &str,
        name: &str,
        record_type: &str,
    ) -> anyhow::Result<Vec<CloudflareDnsRecord>> {
        let mut url = cloudflare_api_url(&format!("/zones/{zone_id}/dns_records"))?;
        url.query_pairs_mut()
            .append_pair("name", name)
            .append_pair("type", record_type);
        self.send::<Vec<CloudflareDnsRecord>, ()>(Method::GET, url, None)
            .await
    }

    async fn create_dns_record(
        &self,
        zone_id: &str,
        record_type: &str,
        name: &str,
        content: &str,
    ) -> anyhow::Result<()> {
        let url = cloudflare_api_url(&format!("/zones/{zone_id}/dns_records"))?;
        let body = CloudflareDnsRecordRequest::new(record_type, name, content);
        let _: CloudflareDnsRecord = self.send(Method::POST, url, Some(&body)).await?;
        Ok(())
    }

    async fn update_dns_record(
        &self,
        zone_id: &str,
        record_id: &str,
        record_type: &str,
        name: &str,
        content: &str,
    ) -> anyhow::Result<()> {
        let url = cloudflare_api_url(&format!("/zones/{zone_id}/dns_records/{record_id}"))?;
        let body = CloudflareDnsRecordRequest::new(record_type, name, content);
        let _: CloudflareDnsRecord = self.send(Method::PUT, url, Some(&body)).await?;
        Ok(())
    }

    async fn delete_dns_record(&self, zone_id: &str, record_id: &str) -> anyhow::Result<()> {
        let url = cloudflare_api_url(&format!("/zones/{zone_id}/dns_records/{record_id}"))?;
        let _: CloudflareDnsRecord = self
            .send::<CloudflareDnsRecord, ()>(Method::DELETE, url, None)
            .await?;
        Ok(())
    }

    async fn send<T, B>(&self, method: Method, url: Url, body: Option<&B>) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        if self.token.is_empty() {
            bail!("cloudflare token is required");
        }

        let mut request = self
            .http
            .request(method, url)
            .bearer_auth(&self.token)
            .header("content-type", "application/json");
        if let Some(body) = body {
            request = request.json(body);
        }

        let response = request.send().await.context("send cloudflare request")?;
        let status = response.status();
        let envelope: CloudflareEnvelope<T> = response
            .json()
            .await
            .context("decode cloudflare response")?;
        if !status.is_success() || !envelope.success {
            bail!(
                "cloudflare api request failed: {}",
                format_cloudflare_errors(&envelope.errors)
            );
        }
        Ok(envelope.result)
    }
}

#[derive(Debug, Deserialize)]
struct CloudflareEnvelope<T> {
    success: bool,
    result: T,
    #[serde(default)]
    errors: Vec<CloudflareApiError>,
}

#[derive(Debug, Deserialize)]
struct CloudflareApiError {
    code: Option<i64>,
    message: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareZone {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareDnsRecord {
    id: String,
    name: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct CloudflareDnsRecordRequest<'a> {
    #[serde(rename = "type")]
    record_type: &'a str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    proxied: Option<bool>,
}

impl<'a> CloudflareDnsRecordRequest<'a> {
    fn new(record_type: &'a str, name: &'a str, content: &'a str) -> Self {
        Self {
            record_type,
            name,
            content,
            ttl: 1,
            proxied: record_type.eq_ignore_ascii_case("A").then_some(false),
        }
    }
}

fn cloudflare_api_url(path: &str) -> anyhow::Result<Url> {
    Url::parse(&format!("https://api.cloudflare.com/client/v4{path}"))
        .context("build cloudflare api url")
}

impl DnsProviderImpl for CloudflareClient {
    fn ensure_a_records<'a>(
        &'a self,
        base_domain: &'a str,
        public_ipv4: &'a str,
    ) -> DnsFuture<'a, ()> {
        Box::pin(async move { self.ensure_a_records(base_domain, public_ipv4).await })
    }

    fn ensure_txt_record<'a>(&'a self, name: &'a str, value: &'a str) -> DnsFuture<'a, ()> {
        Box::pin(async move { self.ensure_txt_record(name, value).await })
    }

    fn delete_txt_record_value<'a>(&'a self, name: &'a str, value: &'a str) -> DnsFuture<'a, ()> {
        Box::pin(async move { self.delete_txt_record_value(name, value).await })
    }

    fn http(&self) -> &reqwest::Client {
        self.http()
    }
}

#[derive(Clone)]
struct GCloudClient {
    project_id: String,
    managed_zone: String,
    credentials: AccessTokenCredentials,
    http: reqwest::Client,
}

impl GCloudClient {
    fn new(project_id: String, managed_zone: String) -> anyhow::Result<Self> {
        let project_id = project_id.trim().to_string();
        let managed_zone = managed_zone.trim().to_string();
        if project_id.is_empty() {
            bail!("gcloud project id is required");
        }
        let credentials = google_cloud_auth::credentials::Builder::default()
            .with_scopes(["https://www.googleapis.com/auth/ndev.clouddns.readwrite"])
            .build_access_token_credentials()
            .context("load gcloud credentials")?;
        Ok(Self {
            project_id,
            managed_zone,
            credentials,
            http: reqwest::Client::new(),
        })
    }

    fn http(&self) -> &reqwest::Client {
        &self.http
    }

    async fn ensure_a_records(&self, base_domain: &str, public_ipv4: &str) -> anyhow::Result<()> {
        validate_ipv4(public_ipv4)?;
        let base_domain = normalize_base_domain(base_domain);
        if base_domain.is_empty() {
            bail!("base domain is required");
        }
        let zone = self.find_managed_zone(&base_domain).await?;
        for name in [base_domain.clone(), format!("*.{base_domain}")] {
            self.ensure_record_set(&zone.name, &name, "A", &[public_ipv4.trim().to_string()])
                .await
                .with_context(|| format!("upsert gcloud A record {name}"))?;
        }
        Ok(())
    }

    async fn ensure_txt_record(&self, name: &str, value: &str) -> anyhow::Result<()> {
        let name = normalize_hostname(name);
        let value = value.trim();
        if name.is_empty() {
            bail!("record name is required");
        }
        if value.is_empty() {
            bail!("txt record value is required");
        }
        let zone = self.find_managed_zone(&name).await?;
        let existing = self.list_record_sets(&zone.name, &name, "TXT").await?;
        let mut values = Vec::new();
        for record_set in &existing {
            for raw in &record_set.rrdatas {
                let normalized = txt_content(raw);
                if !normalized.is_empty() && !values.contains(&normalized) {
                    values.push(normalized);
                }
            }
        }
        if values.iter().any(|candidate| candidate == value) {
            return Ok(());
        }
        values.push(value.to_string());
        self.replace_record_set(
            &zone.name,
            existing,
            GCloudRecordSet::new(&name, "TXT", values),
        )
        .await
    }

    async fn delete_txt_record_value(&self, name: &str, value: &str) -> anyhow::Result<()> {
        let name = normalize_hostname(name);
        let value = value.trim();
        if name.is_empty() || value.is_empty() {
            return Ok(());
        }
        let zone = self.find_managed_zone(&name).await?;
        let existing = self.list_record_sets(&zone.name, &name, "TXT").await?;
        if existing.is_empty() {
            return Ok(());
        }
        let mut values = Vec::new();
        let mut removed = false;
        for record_set in &existing {
            for raw in &record_set.rrdatas {
                let normalized = txt_content(raw);
                if normalized == value {
                    removed = true;
                    continue;
                }
                if !normalized.is_empty() && !values.contains(&normalized) {
                    values.push(normalized);
                }
            }
        }
        if !removed {
            return Ok(());
        }
        if values.is_empty() {
            self.delete_record_sets(&zone.name, existing).await
        } else {
            self.replace_record_set(
                &zone.name,
                existing,
                GCloudRecordSet::new(&name, "TXT", values),
            )
            .await
        }
    }

    async fn find_managed_zone(&self, domain: &str) -> anyhow::Result<GCloudManagedZone> {
        if !self.managed_zone.is_empty() {
            let zone = self.get_managed_zone(&self.managed_zone).await?;
            if !zone.is_public()
                || !hostname_matches_base_domain(domain, &normalize_hostname(&zone.dns_name))
            {
                bail!("gcloud managed zone does not cover {domain}");
            }
            return Ok(zone);
        }
        for candidate in domain_candidates(domain) {
            let mut url = gcloud_dns_url(&format!("/projects/{}/managedZones", self.project_id))?;
            url.query_pairs_mut()
                .append_pair("dnsName", &fqdn(&candidate));
            let response: GCloudManagedZonesList =
                self.send(Method::GET, url, Option::<&()>::None).await?;
            if let Some(zone) = response
                .managed_zones
                .into_iter()
                .find(|zone| zone.is_public() && normalize_hostname(&zone.dns_name) == candidate)
            {
                return Ok(zone);
            }
        }
        bail!("no gcloud public managed zone found for {domain}")
    }

    async fn get_managed_zone(&self, name: &str) -> anyhow::Result<GCloudManagedZone> {
        let url = gcloud_dns_url(&format!(
            "/projects/{}/managedZones/{name}",
            self.project_id
        ))?;
        self.send(Method::GET, url, Option::<&()>::None).await
    }

    async fn ensure_record_set(
        &self,
        zone: &str,
        name: &str,
        record_type: &str,
        values: &[String],
    ) -> anyhow::Result<()> {
        let existing = self.list_record_sets(zone, name, record_type).await?;
        let desired = GCloudRecordSet::new(name, record_type, values.to_vec());
        if existing.len() == 1 && same_gcloud_record_set(&existing[0], &desired) {
            return Ok(());
        }
        self.replace_record_set(zone, existing, desired).await
    }

    async fn replace_record_set(
        &self,
        zone: &str,
        existing: Vec<GCloudRecordSet>,
        desired: GCloudRecordSet,
    ) -> anyhow::Result<()> {
        self.apply_change(
            zone,
            GCloudChange {
                additions: vec![desired],
                deletions: existing,
            },
        )
        .await
    }

    async fn delete_record_sets(
        &self,
        zone: &str,
        deletions: Vec<GCloudRecordSet>,
    ) -> anyhow::Result<()> {
        if deletions.is_empty() {
            return Ok(());
        }
        self.apply_change(
            zone,
            GCloudChange {
                additions: Vec::new(),
                deletions,
            },
        )
        .await
    }

    async fn apply_change(&self, zone: &str, change: GCloudChange) -> anyhow::Result<()> {
        let url = gcloud_dns_url(&format!(
            "/projects/{}/managedZones/{zone}/changes",
            self.project_id
        ))?;
        let response: GCloudChangeResponse = self.send(Method::POST, url, Some(&change)).await?;
        if response.status.eq_ignore_ascii_case("done") {
            return Ok(());
        }
        if response.id.trim().is_empty() {
            bail!("gcloud dns change response missing id");
        }
        for _ in 0..change_poll_attempts(ACME_OPERATION_TIMEOUT, GCLOUD_CHANGE_POLL_INTERVAL) {
            tokio::time::sleep(GCLOUD_CHANGE_POLL_INTERVAL).await;
            let url = gcloud_dns_url(&format!(
                "/projects/{}/managedZones/{zone}/changes/{}",
                self.project_id, response.id
            ))?;
            let response: GCloudChangeResponse =
                self.send(Method::GET, url, Option::<&()>::None).await?;
            if response.status.eq_ignore_ascii_case("done") {
                return Ok(());
            }
        }
        bail!("gcloud dns change did not reach done before timeout")
    }

    async fn list_record_sets(
        &self,
        zone: &str,
        name: &str,
        record_type: &str,
    ) -> anyhow::Result<Vec<GCloudRecordSet>> {
        let name = fqdn(name);
        let record_type = record_type.trim().to_ascii_uppercase();
        let mut url = gcloud_dns_url(&format!(
            "/projects/{}/managedZones/{zone}/rrsets",
            self.project_id
        ))?;
        url.query_pairs_mut()
            .append_pair("name", &name)
            .append_pair("type", &record_type);
        let response: GCloudRecordSetsList =
            self.send(Method::GET, url, Option::<&()>::None).await?;
        Ok(response
            .rrsets
            .into_iter()
            .filter(|set| {
                set.name.eq_ignore_ascii_case(&name)
                    && set.record_type.eq_ignore_ascii_case(&record_type)
            })
            .collect())
    }

    async fn send<T, B>(&self, method: Method, url: Url, body: Option<&B>) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let token = self
            .credentials
            .access_token()
            .await
            .context("load gcloud access token")?;
        let mut request = self
            .http
            .request(method, url)
            .bearer_auth(token.token)
            .header("content-type", "application/json");
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.context("send gcloud dns request")?;
        let status = response.status();
        if !status.is_success() {
            bail!("gcloud dns request failed with status {status}");
        }
        response.json().await.context("decode gcloud dns response")
    }
}

impl DnsProviderImpl for GCloudClient {
    fn ensure_a_records<'a>(
        &'a self,
        base_domain: &'a str,
        public_ipv4: &'a str,
    ) -> DnsFuture<'a, ()> {
        Box::pin(async move { self.ensure_a_records(base_domain, public_ipv4).await })
    }

    fn ensure_txt_record<'a>(&'a self, name: &'a str, value: &'a str) -> DnsFuture<'a, ()> {
        Box::pin(async move { self.ensure_txt_record(name, value).await })
    }

    fn delete_txt_record_value<'a>(&'a self, name: &'a str, value: &'a str) -> DnsFuture<'a, ()> {
        Box::pin(async move { self.delete_txt_record_value(name, value).await })
    }

    fn http(&self) -> &reqwest::Client {
        self.http()
    }
}

#[derive(Clone)]
struct Route53Client {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    region: String,
    hosted_zone_id: String,
    http: reqwest::Client,
}

impl Route53Client {
    fn new(
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
        region: String,
        hosted_zone_id: String,
    ) -> anyhow::Result<Self> {
        let access_key_id = access_key_id.trim().to_string();
        let secret_access_key = secret_access_key.trim().to_string();
        let session_token = session_token.trim().to_string();
        if !session_token.is_empty() && (access_key_id.is_empty() || secret_access_key.is_empty()) {
            bail!("route53 session token requires access key id and secret access key");
        }
        if access_key_id.is_empty() != secret_access_key.is_empty() {
            bail!("route53 access key id and secret access key must be supplied together");
        }
        Ok(Self {
            access_key_id,
            secret_access_key,
            session_token,
            region: region_or_default(&region),
            hosted_zone_id: normalize_route53_zone_id(&hosted_zone_id),
            http: reqwest::Client::new(),
        })
    }

    fn http(&self) -> &reqwest::Client {
        &self.http
    }

    async fn ensure_a_records(&self, base_domain: &str, public_ipv4: &str) -> anyhow::Result<()> {
        validate_ipv4(public_ipv4)?;
        let base_domain = normalize_base_domain(base_domain);
        if base_domain.is_empty() {
            bail!("base domain is required");
        }
        let client = self.sdk_client().await;
        let hosted_zone_id = self.find_hosted_zone_id(&client, &base_domain).await?;
        for name in [base_domain.clone(), format!("*.{base_domain}")] {
            self.upsert_record(
                &client,
                &hosted_zone_id,
                &name,
                RrType::A,
                vec![public_ipv4.trim().to_string()],
            )
            .await
            .with_context(|| format!("upsert route53 A record {name}"))?;
        }
        Ok(())
    }

    async fn ensure_txt_record(&self, name: &str, value: &str) -> anyhow::Result<()> {
        let name = normalize_hostname(name);
        let value = value.trim();
        if name.is_empty() {
            bail!("record name is required");
        }
        if value.is_empty() {
            bail!("txt record value is required");
        }
        let client = self.sdk_client().await;
        let hosted_zone_id = self.find_hosted_zone_id(&client, &name).await?;
        let mut values = self
            .get_record_set(&client, &hosted_zone_id, &name, RrType::Txt)
            .await?
            .map(|record_set| route53_record_values(&record_set))
            .unwrap_or_default();
        if values
            .iter()
            .any(|candidate| route53_txt_content(candidate) == value)
        {
            return Ok(());
        }
        values.push(route53_txt_value(value));
        self.upsert_record(&client, &hosted_zone_id, &name, RrType::Txt, values)
            .await
    }

    async fn delete_txt_record_value(&self, name: &str, value: &str) -> anyhow::Result<()> {
        let name = normalize_hostname(name);
        let value = value.trim();
        if name.is_empty() || value.is_empty() {
            return Ok(());
        }
        let client = self.sdk_client().await;
        let hosted_zone_id = self.find_hosted_zone_id(&client, &name).await?;
        let Some(record_set) = self
            .get_record_set(&client, &hosted_zone_id, &name, RrType::Txt)
            .await?
        else {
            return Ok(());
        };
        let mut values = Vec::new();
        let mut removed = false;
        for raw in route53_record_values(&record_set) {
            if route53_txt_content(&raw) == value {
                removed = true;
                continue;
            }
            values.push(raw);
        }
        if !removed {
            return Ok(());
        }
        if values.is_empty() {
            self.change_record(&client, &hosted_zone_id, ChangeAction::Delete, record_set)
                .await
        } else {
            self.upsert_record(&client, &hosted_zone_id, &name, RrType::Txt, values)
                .await
        }
    }

    async fn sdk_client(&self) -> Route53SdkClient {
        let mut loader = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(self.region.clone()));
        if !self.access_key_id.is_empty() && !self.secret_access_key.is_empty() {
            loader = loader.credentials_provider(AwsCredentials::new(
                self.access_key_id.clone(),
                self.secret_access_key.clone(),
                (!self.session_token.is_empty()).then(|| self.session_token.clone()),
                None,
                "portal-tunnel",
            ));
        }
        Route53SdkClient::new(&loader.load().await)
    }

    async fn find_hosted_zone_id(
        &self,
        client: &Route53SdkClient,
        domain: &str,
    ) -> anyhow::Result<String> {
        if !self.hosted_zone_id.is_empty() {
            return Ok(self.hosted_zone_id.clone());
        }
        let candidates = domain_candidates(domain);
        if candidates.is_empty() {
            bail!("invalid base domain for hosted zone lookup: {domain:?}");
        }
        let mut zones = Vec::new();
        let mut marker = None;
        loop {
            let response = client
                .list_hosted_zones()
                .set_marker(marker)
                .send()
                .await
                .context("list route53 hosted zones")?;
            let is_truncated = response.is_truncated();
            marker = response.next_marker.as_ref().map(ToString::to_string);
            for zone in &response.hosted_zones {
                if zone
                    .config()
                    .is_some_and(aws_sdk_route53::types::HostedZoneConfig::private_zone)
                {
                    continue;
                }
                let name = normalize_hostname(zone.name());
                let id = normalize_route53_zone_id(zone.id());
                if !name.is_empty() && !id.is_empty() {
                    zones.push((name, id));
                }
            }
            if !is_truncated {
                break;
            }
        }
        for candidate in candidates {
            if let Some((_, id)) = zones.iter().find(|(name, _)| name == &candidate) {
                return Ok(id.clone());
            }
        }
        bail!("no route53 public hosted zone found for {domain}")
    }

    async fn get_record_set(
        &self,
        client: &Route53SdkClient,
        hosted_zone_id: &str,
        name: &str,
        record_type: RrType,
    ) -> anyhow::Result<Option<ResourceRecordSet>> {
        let fqdn = fqdn(name);
        let response = client
            .list_resource_record_sets()
            .hosted_zone_id(hosted_zone_id)
            .start_record_name(fqdn.clone())
            .start_record_type(record_type.clone())
            .max_items(1)
            .send()
            .await
            .context("list route53 resource record sets")?;
        let Some(record_set) = response.resource_record_sets.into_iter().next() else {
            return Ok(None);
        };
        if record_set.name().eq_ignore_ascii_case(&fqdn) && record_set.r#type() == &record_type {
            Ok(Some(record_set))
        } else {
            Ok(None)
        }
    }

    async fn upsert_record(
        &self,
        client: &Route53SdkClient,
        hosted_zone_id: &str,
        name: &str,
        record_type: RrType,
        values: Vec<String>,
    ) -> anyhow::Result<()> {
        let record_set = route53_record_set(name, record_type, values)?;
        self.change_record(client, hosted_zone_id, ChangeAction::Upsert, record_set)
            .await
    }

    async fn change_record(
        &self,
        client: &Route53SdkClient,
        hosted_zone_id: &str,
        action: ChangeAction,
        record_set: ResourceRecordSet,
    ) -> anyhow::Result<()> {
        let change = Change::builder()
            .action(action)
            .resource_record_set(record_set)
            .build()
            .context("build route53 change")?;
        let batch = ChangeBatch::builder()
            .comment("Managed by Portal ACME")
            .changes(change)
            .build()
            .context("build route53 change batch")?;
        let output = client
            .change_resource_record_sets()
            .hosted_zone_id(hosted_zone_id)
            .change_batch(batch)
            .send()
            .await
            .context("change route53 resource record sets")?;
        let Some(change_info) = output.change_info else {
            return Ok(());
        };
        if change_info.status == ChangeStatus::Insync {
            return Ok(());
        }
        self.wait_for_change(client, change_info.id()).await
    }

    async fn wait_for_change(
        &self,
        client: &Route53SdkClient,
        change_id: &str,
    ) -> anyhow::Result<()> {
        for _ in 0..change_poll_attempts(ACME_OPERATION_TIMEOUT, ROUTE53_CHANGE_POLL_INTERVAL) {
            tokio::time::sleep(ROUTE53_CHANGE_POLL_INTERVAL).await;
            let output = client
                .get_change()
                .id(change_id)
                .send()
                .await
                .context("poll route53 change")?;
            if output
                .change_info
                .as_ref()
                .is_some_and(|info| info.status == ChangeStatus::Insync)
            {
                return Ok(());
            }
        }
        bail!("route53 change did not reach INSYNC before timeout")
    }
}

impl DnsProviderImpl for Route53Client {
    fn ensure_a_records<'a>(
        &'a self,
        base_domain: &'a str,
        public_ipv4: &'a str,
    ) -> DnsFuture<'a, ()> {
        Box::pin(async move { self.ensure_a_records(base_domain, public_ipv4).await })
    }

    fn ensure_txt_record<'a>(&'a self, name: &'a str, value: &'a str) -> DnsFuture<'a, ()> {
        Box::pin(async move { self.ensure_txt_record(name, value).await })
    }

    fn delete_txt_record_value<'a>(&'a self, name: &'a str, value: &'a str) -> DnsFuture<'a, ()> {
        Box::pin(async move { self.delete_txt_record_value(name, value).await })
    }

    fn http(&self) -> &reqwest::Client {
        self.http()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GCloudManagedZonesList {
    #[serde(default)]
    managed_zones: Vec<GCloudManagedZone>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GCloudManagedZone {
    name: String,
    dns_name: String,
    #[serde(default)]
    visibility: String,
}

impl GCloudManagedZone {
    fn is_public(&self) -> bool {
        self.visibility.is_empty() || self.visibility.eq_ignore_ascii_case("public")
    }
}

#[derive(Debug, Deserialize)]
struct GCloudRecordSetsList {
    #[serde(default)]
    rrsets: Vec<GCloudRecordSet>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct GCloudRecordSet {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    ttl: u32,
    #[serde(default)]
    rrdatas: Vec<String>,
}

impl GCloudRecordSet {
    fn new(name: &str, record_type: &str, values: Vec<String>) -> Self {
        let record_type = record_type.trim().to_ascii_uppercase();
        let rrdatas = if record_type == "TXT" {
            values
                .into_iter()
                .map(|value| gcloud_txt_value(&value))
                .collect()
        } else {
            values
        };
        Self {
            name: fqdn(name),
            record_type,
            ttl: 60,
            rrdatas,
        }
    }
}

#[derive(Debug, Serialize)]
struct GCloudChange {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    additions: Vec<GCloudRecordSet>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    deletions: Vec<GCloudRecordSet>,
}

#[derive(Debug, Deserialize)]
struct GCloudChangeResponse {
    id: String,
    status: String,
}

fn gcloud_dns_url(path: &str) -> anyhow::Result<Url> {
    Url::parse(&format!("https://dns.googleapis.com/dns/v1{path}"))
        .context("build gcloud dns api url")
}

fn same_gcloud_record_set(left: &GCloudRecordSet, right: &GCloudRecordSet) -> bool {
    if !left.name.eq_ignore_ascii_case(&right.name)
        || !left.record_type.eq_ignore_ascii_case(&right.record_type)
        || left.ttl != right.ttl
    {
        return false;
    }
    if left.record_type.eq_ignore_ascii_case("TXT") {
        return same_values(
            &left
                .rrdatas
                .iter()
                .map(|value| txt_content(value))
                .collect::<Vec<_>>(),
            &right
                .rrdatas
                .iter()
                .map(|value| txt_content(value))
                .collect::<Vec<_>>(),
        );
    }
    same_values(&left.rrdatas, &right.rrdatas)
}

fn change_poll_attempts(timeout: Duration, poll_interval: Duration) -> u32 {
    let timeout_millis = timeout.as_millis();
    let interval_millis = poll_interval.as_millis();
    if interval_millis == 0 {
        return 1;
    }
    let attempts = timeout_millis.div_ceil(interval_millis).max(1);
    u32::try_from(attempts).unwrap_or(u32::MAX)
}

fn gcloud_txt_value(value: &str) -> String {
    format!("\"{}\"", escape_dns_txt_content(value.trim()))
}

fn escape_dns_txt_content(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn txt_content(raw: &str) -> String {
    let trimmed = raw.trim();
    let Some(quoted) = trimmed
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    else {
        return trimmed.to_string();
    };
    let mut output = String::with_capacity(quoted.len());
    let mut chars = quoted.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(escaped) = chars.next() {
                output.push(escaped);
            }
        } else {
            output.push(ch);
        }
    }
    output
}

fn region_or_default(region: &str) -> String {
    let region = region.trim();
    if region.is_empty() {
        "us-east-1".to_string()
    } else {
        region.to_string()
    }
}

fn route53_record_set(
    name: &str,
    record_type: RrType,
    values: Vec<String>,
) -> anyhow::Result<ResourceRecordSet> {
    let records = values
        .into_iter()
        .map(|value| ResourceRecord::builder().value(value).build())
        .collect::<Result<Vec<_>, _>>()
        .context("build route53 resource records")?;
    ResourceRecordSet::builder()
        .name(fqdn(name))
        .r#type(record_type)
        .ttl(60)
        .set_resource_records(Some(records))
        .build()
        .context("build route53 resource record set")
}

fn route53_record_values(record_set: &ResourceRecordSet) -> Vec<String> {
    record_set
        .resource_records()
        .iter()
        .map(|record| record.value().to_string())
        .collect()
}

fn route53_txt_value(value: &str) -> String {
    format!("\"{}\"", escape_dns_txt_content(value.trim()))
}

fn route53_txt_content(raw: &str) -> String {
    txt_content(raw)
}

fn normalize_route53_zone_id(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("/hostedzone/")
        .trim()
        .to_string()
}

fn domain_candidates(domain: &str) -> Vec<String> {
    let normalized = normalize_hostname(domain.trim_start_matches("*."));
    let parts = normalized.split('.').collect::<Vec<_>>();
    if parts.len() < 2 {
        return Vec::new();
    }
    (0..parts.len() - 1)
        .map(|idx| parts[idx..].join("."))
        .collect()
}

fn hostname_matches_base_domain(hostname: &str, base_domain: &str) -> bool {
    let hostname = normalize_hostname(hostname);
    let base_domain = normalize_hostname(base_domain);
    hostname == base_domain || hostname.ends_with(&format!(".{base_domain}"))
}

fn fqdn(name: &str) -> String {
    let normalized = normalize_hostname(name);
    if normalized.ends_with('.') {
        normalized
    } else {
        format!("{normalized}.")
    }
}

fn same_values(left: &[String], right: &[String]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort();
    right.sort();
    left == right
}

async fn resolve_public_ipv4(http: &reqwest::Client) -> anyhow::Result<String> {
    let mut last_err = None;
    for endpoint in PUBLIC_IPV4_ENDPOINTS {
        let request = http
            .get(*endpoint)
            .header("user-agent", "portal-tunnel")
            .send();
        match tokio::time::timeout(Duration::from_secs(3), request).await {
            Ok(Ok(response)) if response.status().is_success() => {
                let text = response.text().await.context("read public ip response")?;
                let candidate = text.trim();
                if validate_ipv4(candidate).is_ok() {
                    return Ok(candidate.to_string());
                }
                last_err = Some(anyhow::anyhow!(
                    "invalid public ipv4 response: {candidate:?}"
                ));
            }
            Ok(Ok(response)) => {
                last_err = Some(anyhow::anyhow!(
                    "public ip endpoint returned {}",
                    response.status()
                ));
            }
            Ok(Err(err)) => last_err = Some(err.into()),
            Err(_) => last_err = Some(anyhow::anyhow!("public ip endpoint timed out")),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("public ipv4 detection failed")))
}

fn validate_ipv4(raw: &str) -> anyhow::Result<()> {
    match raw.trim().parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => Ok(()),
        _ => bail!("invalid ipv4 address: {raw:?}"),
    }
}

fn parse_first_certificate(raw: &[u8]) -> anyhow::Result<CertificateDer<'static>> {
    let mut reader = BufReader::new(raw);
    let cert = rustls_pemfile::certs(&mut reader)
        .next()
        .transpose()
        .context("parse certificate pem")?
        .context("certificate pem does not contain any certificates")?;
    Ok(cert)
}

fn read_account_key(path: &Path) -> anyhow::Result<PrivatePkcs8KeyDer<'static>> {
    let raw =
        fs::read(path).with_context(|| format!("read acme account key {}", path.display()))?;
    let mut reader = BufReader::new(raw.as_slice());
    let key = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .next()
        .transpose()
        .context("parse acme account key pem")?
        .context("acme account key pem does not contain a PKCS#8 private key")?;
    Ok(key)
}

fn write_account_key(path: &Path, key: &PrivatePkcs8KeyDer<'_>) -> anyhow::Result<()> {
    let pem = encode_pem("PRIVATE KEY", key.secret_pkcs8_der());
    write_file_atomic(path, pem.as_bytes(), 0o600)
}

fn encode_pem(label: &str, der: &[u8]) -> String {
    let encoded = BASE64_STANDARD.encode(der);
    let mut out = String::new();
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

fn certificate_domains(base_domain: &str) -> Vec<String> {
    vec![base_domain.to_string(), format!("*.{base_domain}")]
}

fn certificate_covers_domains(
    cert: &x509_parser::certificate::X509Certificate<'_>,
    domains: &[String],
) -> anyhow::Result<bool> {
    for domain in domains {
        if let Some(wildcard_domain) = domain.strip_prefix("*.") {
            if !certificate_covers_hostname(cert, &format!("probe.{wildcard_domain}"))? {
                return Ok(false);
            }
        } else if !certificate_covers_hostname(cert, domain)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn certificate_covers_hostname(
    cert: &x509_parser::certificate::X509Certificate<'_>,
    hostname: &str,
) -> anyhow::Result<bool> {
    let hostname = normalize_hostname(hostname);
    let Some(san) = cert
        .subject_alternative_name()
        .context("parse certificate subject alternative names")?
    else {
        return Ok(false);
    };
    Ok(san.value.general_names.iter().any(|name| match name {
        GeneralName::DNSName(pattern) => dns_pattern_matches(pattern, &hostname),
        _ => false,
    }))
}

fn dns_pattern_matches(pattern: &str, hostname: &str) -> bool {
    let pattern = normalize_hostname(pattern);
    if pattern == hostname {
        return true;
    }
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    let Some(left) = hostname.strip_suffix(&format!(".{suffix}")) else {
        return false;
    };
    !left.is_empty() && !left.contains('.')
}

fn dns01_record_name(identifier: &str) -> anyhow::Result<String> {
    let domain = normalize_hostname(identifier.trim_start_matches("*."));
    if domain.is_empty() {
        bail!("acme dns-01 identifier is empty");
    }
    Ok(format!("_acme-challenge.{domain}"))
}

fn format_cloudflare_errors(errors: &[CloudflareApiError]) -> String {
    if errors.is_empty() {
        return "unknown cloudflare api error".to_string();
    }
    errors
        .iter()
        .map(|err| match err.code {
            Some(code) => format!("[{code}] {}", err.message),
            None => err.message.clone(),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn write_file_atomic(path: &Path, contents: &[u8], mode: u32) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent directory {}", parent.display()))?;
    }
    let tmp_path = path.with_extension(format!("tmp-{}", std::process::id()));
    write_file_with_mode(&tmp_path, contents, mode)
        .with_context(|| format!("write temporary file {}", tmp_path.display()))?;
    fs::rename(&tmp_path, path)
        .with_context(|| format!("rename {} to {}", tmp_path.display(), path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn write_file_with_mode(path: &Path, contents: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(mode)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_file_with_mode(path: &Path, contents: &[u8], _mode: u32) -> anyhow::Result<()> {
    fs::write(path, contents)?;
    Ok(())
}

fn normalize_hostname(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_base_domain(raw: &str) -> String {
    normalize_hostname(raw).trim_start_matches("*.").to_string()
}

fn is_local_relay_host(host: &str) -> bool {
    matches!(
        normalize_hostname(host).as_str(),
        "localhost" | "127.0.0.1" | "::1"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns01_record_name_strips_wildcard_identifier() {
        assert_eq!(
            dns01_record_name("*.Example.COM.").unwrap(),
            "_acme-challenge.example.com"
        );
        assert_eq!(
            dns01_record_name("example.com").unwrap(),
            "_acme-challenge.example.com"
        );
    }

    #[test]
    fn dns_pattern_matches_single_label_wildcards() {
        assert!(dns_pattern_matches("*.example.com", "probe.example.com"));
        assert!(!dns_pattern_matches(
            "*.example.com",
            "deep.probe.example.com"
        ));
        assert!(!dns_pattern_matches("*.example.com", "example.com"));
        assert!(dns_pattern_matches("example.com", "example.com"));
    }

    #[test]
    fn route53_txt_values_are_quoted_escaped_and_unquoted() {
        let value = route53_txt_value(" challenge\\\"value ");
        assert_eq!(value, "\"challenge\\\\\\\"value\"");
        assert_eq!(route53_txt_content(&value), "challenge\\\"value");
    }

    #[test]
    fn gcloud_txt_values_are_quoted_and_escaped() {
        let value = gcloud_txt_value(" challenge\\\"value ");
        assert_eq!(value, "\"challenge\\\\\\\"value\"");
        assert_eq!(txt_content(&value), "challenge\\\"value");
    }

    #[test]
    fn gcloud_txt_content_normalizes_quoted_and_raw_values() {
        assert_eq!(txt_content("challenge-value"), "challenge-value");
        assert_eq!(txt_content("\"challenge-value\""), "challenge-value");
        assert_eq!(
            txt_content("\"challenge\\\\\\\"value\""),
            "challenge\\\"value"
        );
    }

    #[test]
    fn gcloud_record_set_compares_txt_values_after_normalization() {
        let left = GCloudRecordSet {
            name: "example.com.".to_string(),
            record_type: "TXT".to_string(),
            ttl: 60,
            rrdatas: vec!["raw".to_string(), "\"quoted\"".to_string()],
        };
        let right = GCloudRecordSet::new(
            "example.com",
            "txt",
            vec!["quoted".to_string(), "raw".to_string()],
        );
        assert!(same_gcloud_record_set(&left, &right));
    }

    #[test]
    fn change_poll_attempts_use_ceiling_division() {
        assert_eq!(
            change_poll_attempts(Duration::from_secs(5), Duration::from_secs(2)),
            3
        );
        assert_eq!(
            change_poll_attempts(Duration::from_secs(0), Duration::from_secs(2)),
            1
        );
        assert_eq!(
            change_poll_attempts(Duration::from_secs(5), Duration::from_secs(0)),
            1
        );
    }

    #[test]
    fn route53_zone_id_strips_hosted_zone_prefix() {
        assert_eq!(normalize_route53_zone_id("/hostedzone/Z123"), "Z123");
        assert_eq!(normalize_route53_zone_id("Z123"), "Z123");
    }

    #[test]
    fn gcloud_record_set_compares_values_without_order() {
        let left =
            GCloudRecordSet::new("example.com", "TXT", vec!["b".to_string(), "a".to_string()]);
        let right = GCloudRecordSet::new(
            "example.com.",
            "txt",
            vec!["a".to_string(), "b".to_string()],
        );
        assert!(same_gcloud_record_set(&left, &right));
    }

    #[test]
    fn acme_account_key_uses_upstream_file_name_and_pkcs8_pem() {
        assert_eq!(ACCOUNT_KEY_FILE_NAME, "acme-account.key");
        assert_eq!(REGISTRATION_FILE_NAME, "acme-registration.json");

        let (_, key) = Key::generate_pkcs8().unwrap();
        let pem = encode_pem("PRIVATE KEY", key.secret_pkcs8_der());
        let mut reader = BufReader::new(pem.as_bytes());
        let parsed = rustls_pemfile::pkcs8_private_keys(&mut reader)
            .next()
            .transpose()
            .unwrap()
            .unwrap();

        assert_eq!(parsed.secret_pkcs8_der(), key.secret_pkcs8_der());
    }

    #[test]
    fn acme_registration_resource_uses_upstream_json_shape() {
        let resource = AcmeRegistrationResource {
            body: AcmeRegistrationBody {
                status: "valid",
                contact: vec!["mailto:acme@example.com".to_string()],
                terms_of_service_agreed: true,
            },
            uri: "https://acme-v02.api.letsencrypt.org/acme/acct/123",
        };

        let value = serde_json::to_value(resource).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "body": {
                    "status": "valid",
                    "contact": ["mailto:acme@example.com"],
                    "termsOfServiceAgreed": true
                },
                "uri": "https://acme-v02.api.letsencrypt.org/acme/acct/123"
            })
        );
    }

    #[tokio::test]
    async fn manual_certificate_override_still_syncs_dns_a_records() {
        let identity_path = test_identity_path("manual-certificate-dns-sync");
        fs::create_dir_all(&identity_path).unwrap();
        write_test_certificate(&identity_path, "example.com");
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let manager = AcmeManager {
            identity_path: identity_path.clone(),
            base_domain: "example.com".to_string(),
            dns: DnsProvider(Arc::new(RecordingDnsProvider {
                calls: Arc::clone(&calls),
                http: reqwest::Client::new(),
            })),
        };

        manager
            .sync_dns_with_resolved_public_ipv4("203.0.113.10")
            .await
            .unwrap();

        assert_eq!(
            *calls.lock().unwrap(),
            vec![("example.com".to_string(), "203.0.113.10".to_string())]
        );
        fs::remove_dir_all(identity_path).unwrap();
    }

    struct RecordingDnsProvider {
        calls: Arc<std::sync::Mutex<Vec<(String, String)>>>,
        http: reqwest::Client,
    }

    impl DnsProviderImpl for RecordingDnsProvider {
        fn ensure_a_records<'a>(
            &'a self,
            base_domain: &'a str,
            public_ipv4: &'a str,
        ) -> DnsFuture<'a, ()> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .unwrap()
                    .push((base_domain.to_string(), public_ipv4.to_string()));
                Ok(())
            })
        }

        fn ensure_txt_record<'a>(&'a self, _name: &'a str, _value: &'a str) -> DnsFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }

        fn delete_txt_record_value<'a>(
            &'a self,
            _name: &'a str,
            _value: &'a str,
        ) -> DnsFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }

        fn http(&self) -> &reqwest::Client {
            &self.http
        }
    }

    fn write_test_certificate(identity_path: &Path, base_domain: &str) {
        let key_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
        let params = CertificateParams::new(certificate_domains(base_domain)).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        write_file_atomic(
            &identity_path.join(FULL_CHAIN_FILE_NAME),
            cert.pem().as_bytes(),
            0o644,
        )
        .unwrap();
        write_file_atomic(
            &identity_path.join(KEY_FILE_NAME),
            key_pair.serialize_pem().as_bytes(),
            0o600,
        )
        .unwrap();
    }

    fn test_identity_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "portal-relay-acme-{name}-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ))
    }
}
