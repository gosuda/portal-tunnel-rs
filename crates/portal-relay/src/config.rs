use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Parser;
use url::Url;

use crate::state::acme::{AcmeConfig, AcmeDnsProviderConfig};

#[derive(Clone, Parser)]
#[command(name = "portal-relay")]
#[command(about = "Portal relay server implemented in Rust")]
pub struct RelayConfig {
    #[arg(long, env = "PORTAL_URL", default_value = "https://localhost:4017")]
    pub portal_url: String,

    #[arg(long, env = "IDENTITY_PATH", default_value = "./.portal-certs")]
    pub identity_path: PathBuf,

    #[arg(long, env = "API_PORT", default_value_t = 4017)]
    pub api_port: u16,

    #[arg(long, env = "SNI_PORT", default_value_t = 443)]
    pub sni_port: u16,

    #[arg(long, env = "TRUST_PROXY_HEADERS", default_value_t = false)]
    pub trust_proxy_headers: bool,

    #[arg(long, env = "TRUSTED_PROXY_CIDRS", default_value = "")]
    pub trusted_proxy_cidrs: String,

    #[arg(long, env = "WIREGUARD_PORT", default_value_t = 51820)]
    pub wireguard_port: u16,

    #[arg(long, env = "UDP_ENABLED", default_value_t = false)]
    pub udp_enabled: bool,

    #[arg(long = "discovery", env = "DISCOVERY", default_value_t = false)]
    pub discovery_enabled: bool,

    #[arg(long, env = "BOOTSTRAPS", value_delimiter = ',')]
    pub bootstraps: Vec<String>,

    #[arg(long, env = "TCP_ENABLED", default_value_t = false)]
    pub tcp_enabled: bool,

    #[arg(long, env = "MIN_PORT", default_value_t = 0)]
    pub min_port: u16,

    #[arg(long, env = "MAX_PORT", default_value_t = 0)]
    pub max_port: u16,

    #[arg(long, env = "LANDING_PAGE_ENABLED", default_value_t = false)]
    pub landing_page_enabled: bool,

    #[arg(long, env = "FRONTEND_DIST")]
    pub frontend_dist: Option<PathBuf>,

    #[arg(long, env = "HEADLESS_SHELL_URL", default_value = "")]
    pub headless_shell_url: String,

    #[arg(long, env = "ACME_DNS_PROVIDER", default_value = "")]
    pub acme_dns_provider: String,

    #[arg(long, env = "ENS_GASLESS_ENABLED", default_value_t = false)]
    pub ens_gasless_enabled: bool,

    #[arg(long, env = "CLOUDFLARE_TOKEN", default_value = "")]
    pub cloudflare_token: String,

    #[arg(long, env = "GCP_PROJECT_ID", default_value = "")]
    pub gcp_project_id: String,

    #[arg(long, env = "GCP_MANAGED_ZONE", default_value = "")]
    pub gcp_managed_zone: String,

    #[arg(long, env = "AWS_ACCESS_KEY_ID", default_value = "")]
    pub aws_access_key_id: String,

    #[arg(long, env = "AWS_SECRET_ACCESS_KEY", default_value = "")]
    pub aws_secret_access_key: String,

    #[arg(long, env = "AWS_SESSION_TOKEN", default_value = "")]
    pub aws_session_token: String,

    #[arg(long, env = "AWS_REGION", default_value = "")]
    pub aws_region: String,

    #[arg(long, env = "AWS_HOSTED_ZONE_ID", default_value = "")]
    pub aws_hosted_zone_id: String,

    #[arg(long, env = "AWS_DNSSEC_KMS_KEY_ARN", default_value = "")]
    pub aws_dnssec_kms_key_arn: String,
}

impl std::fmt::Debug for RelayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayConfig")
            .field("portal_url", &self.portal_url)
            .field("identity_path", &self.identity_path)
            .field("api_port", &self.api_port)
            .field("sni_port", &self.sni_port)
            .field("trust_proxy_headers", &self.trust_proxy_headers)
            .field("trusted_proxy_cidrs", &self.trusted_proxy_cidrs)
            .field("wireguard_port", &self.wireguard_port)
            .field("udp_enabled", &self.udp_enabled)
            .field("discovery_enabled", &self.discovery_enabled)
            .field("bootstraps", &self.bootstraps)
            .field("tcp_enabled", &self.tcp_enabled)
            .field("min_port", &self.min_port)
            .field("max_port", &self.max_port)
            .field("landing_page_enabled", &self.landing_page_enabled)
            .field("frontend_dist", &self.frontend_dist)
            .field("headless_shell_url", &self.headless_shell_url)
            .field("acme_dns_provider", &self.acme_dns_provider)
            .field("ens_gasless_enabled", &self.ens_gasless_enabled)
            .field(
                "cloudflare_token",
                &redacted_if_present(&self.cloudflare_token),
            )
            .field("gcp_project_id", &self.gcp_project_id)
            .field("gcp_managed_zone", &self.gcp_managed_zone)
            .field(
                "aws_access_key_id",
                &redacted_if_present(&self.aws_access_key_id),
            )
            .field(
                "aws_secret_access_key",
                &redacted_if_present(&self.aws_secret_access_key),
            )
            .field(
                "aws_session_token",
                &redacted_if_present(&self.aws_session_token),
            )
            .field("aws_region", &self.aws_region)
            .field("aws_hosted_zone_id", &self.aws_hosted_zone_id)
            .field("aws_dnssec_kms_key_arn", &self.aws_dnssec_kms_key_arn)
            .finish()
    }
}

impl RelayConfig {
    pub fn normalize(mut self) -> anyhow::Result<Self> {
        self.portal_url = normalize_relay_url(&self.portal_url)?;
        self.bootstraps = normalize_relay_urls(&self.bootstraps)?;
        self.bootstraps.retain(|url| url != &self.portal_url);
        if self.identity_path.as_os_str().is_empty() {
            bail!("identity path is required");
        }
        self.headless_shell_url = self.headless_shell_url.trim().to_string();
        if !self.headless_shell_url.is_empty() {
            bail!("thumbnail generation via HEADLESS_SHELL_URL is not implemented");
        }
        self.normalize_acme_config()?;

        let has_port_range = self.min_port > 0 && self.max_port > 0;
        if self.udp_enabled || self.tcp_enabled {
            if !has_port_range {
                bail!("udp and tcp relay transport require a valid min port and max port range");
            }
            if self.min_port > self.max_port {
                bail!("min port must be less than or equal to max port");
            }
        }

        self.udp_enabled = self.udp_enabled && has_port_range;
        self.tcp_enabled = self.tcp_enabled && has_port_range;
        Ok(self)
    }

    fn normalize_acme_config(&mut self) -> anyhow::Result<()> {
        self.acme_dns_provider = self.acme_dns_provider.trim().to_ascii_lowercase();
        self.cloudflare_token = self.cloudflare_token.trim().to_string();
        self.gcp_project_id = self.gcp_project_id.trim().to_string();
        self.gcp_managed_zone = self.gcp_managed_zone.trim().to_string();
        self.aws_access_key_id = self.aws_access_key_id.trim().to_string();
        self.aws_secret_access_key = self.aws_secret_access_key.trim().to_string();
        self.aws_session_token = self.aws_session_token.trim().to_string();
        self.aws_region = self.aws_region.trim().to_string();
        self.aws_hosted_zone_id = self.aws_hosted_zone_id.trim().to_string();
        self.aws_dnssec_kms_key_arn = self.aws_dnssec_kms_key_arn.trim().to_string();

        if self.ens_gasless_enabled {
            bail!("ENS gasless automation is not implemented");
        }
        self.aws_hosted_zone_id = normalize_route53_zone_id(&self.aws_hosted_zone_id);

        match self.acme_dns_provider.as_str() {
            "" => {
                self.reject_provider_config_unless_selected("cloudflare", "CLOUDFLARE_TOKEN")?;
                self.reject_provider_config_unless_selected("gcloud", "GCP_PROJECT_ID")?;
                self.reject_provider_config_unless_selected("gcloud", "GCP_MANAGED_ZONE")?;
                self.reject_provider_config_unless_selected("route53", "AWS_ACCESS_KEY_ID")?;
                self.reject_provider_config_unless_selected("route53", "AWS_SECRET_ACCESS_KEY")?;
                self.reject_provider_config_unless_selected("route53", "AWS_SESSION_TOKEN")?;
                self.reject_provider_config_unless_selected("route53", "AWS_REGION")?;
                self.reject_provider_config_unless_selected("route53", "AWS_HOSTED_ZONE_ID")?;
                self.reject_provider_config_unless_selected("route53", "AWS_DNSSEC_KMS_KEY_ARN")?;
            }
            "cloudflare" => {
                self.reject_provider_config_unless_selected("gcloud", "GCP_PROJECT_ID")?;
                self.reject_provider_config_unless_selected("gcloud", "GCP_MANAGED_ZONE")?;
                self.reject_provider_config_unless_selected("route53", "AWS_ACCESS_KEY_ID")?;
                self.reject_provider_config_unless_selected("route53", "AWS_SECRET_ACCESS_KEY")?;
                self.reject_provider_config_unless_selected("route53", "AWS_SESSION_TOKEN")?;
                self.reject_provider_config_unless_selected("route53", "AWS_REGION")?;
                self.reject_provider_config_unless_selected("route53", "AWS_HOSTED_ZONE_ID")?;
                self.reject_provider_config_unless_selected("route53", "AWS_DNSSEC_KMS_KEY_ARN")?;
                if self.cloudflare_token.is_empty() {
                    bail!("CLOUDFLARE_TOKEN is required when ACME_DNS_PROVIDER=cloudflare");
                }
            }
            "gcloud" => {
                self.reject_provider_config_unless_selected("cloudflare", "CLOUDFLARE_TOKEN")?;
                self.reject_provider_config_unless_selected("route53", "AWS_ACCESS_KEY_ID")?;
                self.reject_provider_config_unless_selected("route53", "AWS_SECRET_ACCESS_KEY")?;
                self.reject_provider_config_unless_selected("route53", "AWS_SESSION_TOKEN")?;
                self.reject_provider_config_unless_selected("route53", "AWS_REGION")?;
                self.reject_provider_config_unless_selected("route53", "AWS_HOSTED_ZONE_ID")?;
                self.reject_provider_config_unless_selected("route53", "AWS_DNSSEC_KMS_KEY_ARN")?;
                if self.gcp_project_id.is_empty() {
                    bail!("GCP_PROJECT_ID is required when ACME_DNS_PROVIDER=gcloud");
                }
                if self.gcp_managed_zone.is_empty() {
                    bail!("GCP_MANAGED_ZONE is required when ACME_DNS_PROVIDER=gcloud");
                }
            }
            "route53" => {
                self.reject_provider_config_unless_selected("cloudflare", "CLOUDFLARE_TOKEN")?;
                self.reject_provider_config_unless_selected("gcloud", "GCP_PROJECT_ID")?;
                self.reject_provider_config_unless_selected("gcloud", "GCP_MANAGED_ZONE")?;
                if !self.aws_session_token.is_empty()
                    && (self.aws_access_key_id.is_empty() || self.aws_secret_access_key.is_empty())
                {
                    bail!("AWS_SESSION_TOKEN requires AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY");
                }
                if self.aws_access_key_id.is_empty() != self.aws_secret_access_key.is_empty() {
                    bail!("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be supplied together");
                }
                if !self.aws_dnssec_kms_key_arn.is_empty() {
                    bail!("AWS_DNSSEC_KMS_KEY_ARN is not supported by ACME_DNS_PROVIDER=route53");
                }
            }
            other => bail!("unsupported ACME_DNS_PROVIDER: {other}"),
        }
        Ok(())
    }

    fn reject_provider_config_unless_selected(
        &self,
        expected_provider: &str,
        field_name: &str,
    ) -> anyhow::Result<()> {
        let is_set = match field_name {
            "CLOUDFLARE_TOKEN" => !self.cloudflare_token.is_empty(),
            "GCP_PROJECT_ID" => !self.gcp_project_id.is_empty(),
            "GCP_MANAGED_ZONE" => !self.gcp_managed_zone.is_empty(),
            "AWS_ACCESS_KEY_ID" => !self.aws_access_key_id.is_empty(),
            "AWS_SECRET_ACCESS_KEY" => !self.aws_secret_access_key.is_empty(),
            "AWS_SESSION_TOKEN" => !self.aws_session_token.is_empty(),
            "AWS_REGION" => !self.aws_region.is_empty(),
            "AWS_HOSTED_ZONE_ID" => !self.aws_hosted_zone_id.is_empty(),
            "AWS_DNSSEC_KMS_KEY_ARN" => !self.aws_dnssec_kms_key_arn.is_empty(),
            _ => bail!("unknown provider config field: {field_name}"),
        };
        if is_set {
            bail!("{field_name} requires ACME_DNS_PROVIDER={expected_provider}");
        }
        Ok(())
    }

    pub fn api_listen_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.api_port)
    }

    pub fn sni_listen_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.sni_port)
    }

    pub fn root_host(&self) -> anyhow::Result<String> {
        root_host(&self.portal_url)
    }

    pub fn acme_config(&self, base_domain: &str) -> Option<AcmeConfig> {
        let provider = match self.acme_dns_provider.as_str() {
            "" => None,
            "cloudflare" => Some(AcmeDnsProviderConfig::Cloudflare {
                token: self.cloudflare_token.clone(),
            }),
            "gcloud" => Some(AcmeDnsProviderConfig::GCloud {
                project_id: self.gcp_project_id.clone(),
                managed_zone: self.gcp_managed_zone.clone(),
            }),
            "route53" => Some(AcmeDnsProviderConfig::Route53 {
                access_key_id: self.aws_access_key_id.clone(),
                secret_access_key: self.aws_secret_access_key.clone(),
                session_token: self.aws_session_token.clone(),
                region: self.aws_region.clone(),
                hosted_zone_id: self.aws_hosted_zone_id.clone(),
            }),
            _ => None,
        }?;
        Some(AcmeConfig {
            identity_path: self.identity_path.clone(),
            base_domain: base_domain.to_string(),
            provider,
        })
    }
}

pub fn normalize_relay_url(raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    let parsed = Url::parse(trimmed).with_context(|| format!("parse portal url {trimmed:?}"))?;
    if parsed.scheme() != "https" {
        bail!("relay urls must use https");
    }
    if parsed.host_str().unwrap_or_default().trim().is_empty() {
        bail!("relay url host is required");
    }

    let mut normalized = parsed;
    normalized.set_path("");
    normalized.set_query(None);
    normalized.set_fragment(None);
    Ok(normalized.to_string().trim_end_matches('/').to_string())
}

pub fn normalize_relay_urls(raw: &[String]) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    for item in raw {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        let normalized = normalize_relay_url(trimmed)?;
        if !out.contains(&normalized) {
            out.push(normalized);
        }
    }
    Ok(out)
}

pub fn root_host(portal_url: &str) -> anyhow::Result<String> {
    let parsed =
        Url::parse(portal_url).with_context(|| format!("parse portal url {portal_url:?}"))?;
    let host = parsed
        .host_str()
        .map(normalize_hostname)
        .filter(|host| !host.is_empty())
        .context("portal url host is required")?;
    Ok(host)
}

pub fn normalize_hostname(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_route53_zone_id(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("/hostedzone/")
        .trim()
        .to_string()
}

fn redacted_if_present(raw: &str) -> &str {
    if raw.is_empty() { "" } else { "<redacted>" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_relay_url_requires_https_and_strips_path() {
        let normalized = normalize_relay_url("https://Portal.Example.com:8443/admin?x=1").unwrap();
        assert_eq!(normalized, "https://portal.example.com:8443");
        assert!(normalize_relay_url("http://portal.example.com").is_err());
    }

    #[test]
    fn normalize_relay_urls_deduplicates_bootstraps() {
        let raw = vec![
            " https://Relay.Example.com/path ".to_string(),
            "https://relay.example.com".to_string(),
            String::new(),
        ];
        assert_eq!(
            normalize_relay_urls(&raw).unwrap(),
            vec!["https://relay.example.com".to_string()]
        );
    }

    #[test]
    fn config_disables_port_transports_without_range() {
        let cfg = base_config().normalize().unwrap();

        assert!(!cfg.udp_enabled);
        assert!(!cfg.tcp_enabled);
    }

    #[test]
    fn config_rejects_unimplemented_headless_thumbnail_config() {
        let mut cfg = base_config();
        cfg.headless_shell_url = "ws://headless-shell:9222".to_string();

        assert!(
            cfg.normalize()
                .unwrap_err()
                .to_string()
                .contains("thumbnail")
        );
    }

    #[test]
    fn config_accepts_cloudflare_acme_config() {
        let mut cfg = base_config();
        cfg.acme_dns_provider = "cloudflare".to_string();
        cfg.cloudflare_token = "cf-token".to_string();

        let cfg = cfg.normalize().unwrap();
        assert_eq!(cfg.acme_dns_provider, "cloudflare");
        assert_eq!(cfg.cloudflare_token, "cf-token");
    }

    #[test]
    fn config_rejects_cloudflare_acme_without_token() {
        let mut cfg = base_config();
        cfg.acme_dns_provider = "cloudflare".to_string();

        assert!(
            cfg.normalize()
                .unwrap_err()
                .to_string()
                .contains("CLOUDFLARE_TOKEN")
        );
    }

    #[test]
    fn config_rejects_unknown_acme_provider() {
        let mut cfg = base_config();
        cfg.acme_dns_provider = "typo".to_string();

        assert!(
            cfg.normalize()
                .unwrap_err()
                .to_string()
                .contains("unsupported ACME_DNS_PROVIDER")
        );
    }

    #[test]
    fn config_rejects_provider_specific_fields_when_acme_provider_is_empty() {
        let mut cfg = base_config();
        cfg.gcp_project_id = "project-id".to_string();

        assert!(
            cfg.normalize()
                .unwrap_err()
                .to_string()
                .contains("GCP_PROJECT_ID requires ACME_DNS_PROVIDER=gcloud")
        );
    }

    #[test]
    fn config_rejects_provider_specific_fields_when_acme_provider_mismatches() {
        let mut cfg = base_config();
        cfg.acme_dns_provider = "cloudflare".to_string();
        cfg.cloudflare_token = "cf-token".to_string();
        cfg.aws_hosted_zone_id = "Z123".to_string();

        assert!(
            cfg.normalize()
                .unwrap_err()
                .to_string()
                .contains("AWS_HOSTED_ZONE_ID requires ACME_DNS_PROVIDER=route53")
        );
    }

    #[test]
    fn config_rejects_route53_dnssec_kms_without_dnssec_support() {
        let mut cfg = base_config();
        cfg.acme_dns_provider = "route53".to_string();
        cfg.aws_dnssec_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/example".to_string();

        assert!(
            cfg.normalize()
                .unwrap_err()
                .to_string()
                .contains("AWS_DNSSEC_KMS_KEY_ARN")
        );
    }

    #[test]
    fn config_accepts_gcloud_acme_config() {
        let mut cfg = base_config();
        cfg.acme_dns_provider = "gcloud".to_string();
        cfg.gcp_project_id = "project-id".to_string();
        cfg.gcp_managed_zone = "portal-zone".to_string();

        let cfg = cfg.normalize().unwrap();
        assert_eq!(cfg.acme_dns_provider, "gcloud");
        assert_eq!(cfg.gcp_project_id, "project-id");
        assert_eq!(cfg.gcp_managed_zone, "portal-zone");
    }

    #[test]
    fn config_rejects_gcloud_acme_without_managed_zone() {
        let mut cfg = base_config();
        cfg.acme_dns_provider = "gcloud".to_string();
        cfg.gcp_project_id = "project-id".to_string();

        assert!(
            cfg.normalize()
                .unwrap_err()
                .to_string()
                .contains("GCP_MANAGED_ZONE")
        );
    }

    #[test]
    fn config_accepts_route53_acme_config() {
        let mut cfg = base_config();
        cfg.acme_dns_provider = "route53".to_string();
        cfg.aws_hosted_zone_id = "/hostedzone/Z123".to_string();

        let cfg = cfg.normalize().unwrap();
        assert_eq!(cfg.acme_dns_provider, "route53");
        assert_eq!(cfg.aws_hosted_zone_id, "Z123");
    }

    #[test]
    fn config_debug_redacts_acme_provider_secrets() {
        let mut cfg = base_config();
        cfg.cloudflare_token = "cf-token".to_string();
        cfg.aws_access_key_id = "access-key".to_string();
        cfg.aws_secret_access_key = "secret-key".to_string();
        cfg.aws_session_token = "session-token".to_string();

        let debug = format!("{cfg:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("cf-token"));
        assert!(!debug.contains("access-key"));
        assert!(!debug.contains("secret-key"));
        assert!(!debug.contains("session-token"));
    }

    fn base_config() -> RelayConfig {
        RelayConfig {
            portal_url: "https://localhost:4017".to_string(),
            identity_path: PathBuf::from(".portal-certs"),
            api_port: 4017,
            sni_port: 443,
            trust_proxy_headers: false,
            trusted_proxy_cidrs: String::new(),
            wireguard_port: 51820,
            udp_enabled: false,
            discovery_enabled: false,
            bootstraps: Vec::new(),
            tcp_enabled: false,
            min_port: 0,
            max_port: 0,
            landing_page_enabled: false,
            frontend_dist: None,
            headless_shell_url: String::new(),
            acme_dns_provider: String::new(),
            ens_gasless_enabled: false,
            cloudflare_token: String::new(),
            gcp_project_id: String::new(),
            gcp_managed_zone: String::new(),
            aws_access_key_id: String::new(),
            aws_secret_access_key: String::new(),
            aws_session_token: String::new(),
            aws_region: String::new(),
            aws_hosted_zone_id: String::new(),
            aws_dnssec_kms_key_arn: String::new(),
        }
    }
}
