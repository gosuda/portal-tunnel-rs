//! Top-level ACME configuration with `SecretBox`-wrapped credential
//! newtypes per SEC-012 trust-boundary policy.
//!
//! Each cloud-provider credential class becomes a distinct newtype so
//! mixing one provider's credential into another's call site is a
//! compile error, and `Debug`/`Display` formatting redacts the secret
//! body at the type level.

use std::path::PathBuf;

use compact_str::CompactString;
use secrecy::SecretBox;
use zeroize::Zeroize;

/// Cloudflare API token. Wraps a `SecretBox<String>`-equivalent so an
/// accidental `{:?}` formatting redacts the token at compile time.
pub struct CloudflareToken(SecretBox<CloudflareTokenInner>);

#[derive(Default)]
#[doc(hidden)]
pub struct CloudflareTokenInner(pub String);

impl Zeroize for CloudflareTokenInner {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl CloudflareToken {
    /// Wrap a token string. The original is moved into a zeroizing
    /// inner so it is wiped on drop.
    #[must_use]
    pub fn new(token: String) -> Self {
        Self(SecretBox::new(Box::new(CloudflareTokenInner(token))))
    }

    /// Expose the underlying token string. Use only at the API call
    /// site immediately before the cloud client consumes it.
    #[must_use]
    pub fn expose(&self) -> &str {
        use secrecy::ExposeSecret as _;
        &self.0.expose_secret().0
    }
}

/// Route53 credential pair (access key id + secret access key).
pub struct Route53Credentials(SecretBox<Route53Inner>);

#[derive(Default)]
#[doc(hidden)]
pub struct Route53Inner {
    /// AWS access key id (public-ish but kept in the same secret box
    /// so a single newtype carries both halves of the credential pair).
    pub access_key_id: String,
    /// AWS secret access key.
    pub secret_access_key: String,
}

impl Zeroize for Route53Inner {
    fn zeroize(&mut self) {
        self.access_key_id.zeroize();
        self.secret_access_key.zeroize();
    }
}

impl Route53Credentials {
    /// Wrap a Route53 access-key pair.
    #[must_use]
    pub fn new(access_key_id: String, secret_access_key: String) -> Self {
        Self(SecretBox::new(Box::new(Route53Inner {
            access_key_id,
            secret_access_key,
        })))
    }

    /// Expose the access key id. Pair with [`Self::secret_access_key`]
    /// at the AWS SDK call site only.
    #[must_use]
    pub fn access_key_id(&self) -> &str {
        use secrecy::ExposeSecret as _;
        &self.0.expose_secret().access_key_id
    }

    /// Expose the secret access key.
    #[must_use]
    pub fn secret_access_key(&self) -> &str {
        use secrecy::ExposeSecret as _;
        &self.0.expose_secret().secret_access_key
    }
}

/// Google Cloud service-account JSON, as raw bytes.
pub struct GcloudServiceAccount(SecretBox<GcloudInner>);

#[derive(Default)]
#[doc(hidden)]
pub struct GcloudInner(pub Vec<u8>);

impl Zeroize for GcloudInner {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl GcloudServiceAccount {
    /// Wrap service-account JSON bytes.
    #[must_use]
    pub fn new(json: Vec<u8>) -> Self {
        Self(SecretBox::new(Box::new(GcloudInner(json))))
    }

    /// Expose the service-account JSON bytes. Pair with the Google
    /// Cloud SDK at the call site immediately before consumption.
    #[must_use]
    pub fn json_bytes(&self) -> &[u8] {
        use secrecy::ExposeSecret as _;
        &self.0.expose_secret().0
    }
}

/// ACME directory URL — newtype around `compact_str::CompactString` to
/// disambiguate from plain strings at API boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryUrl(pub CompactString);

impl DirectoryUrl {
    /// Let's Encrypt production directory.
    pub const LE_PRODUCTION: &'static str = "https://acme-v02.api.letsencrypt.org/directory";

    /// Let's Encrypt staging directory (for tests).
    pub const LE_STAGING: &'static str = "https://acme-staging-v02.api.letsencrypt.org/directory";

    /// Build a directory URL from a string slice.
    #[must_use]
    pub fn new(url: &str) -> Self {
        Self(CompactString::from(url))
    }
}

/// On-disk key directory holding `acme-account.key`,
/// `acme-registration.json`, `fullchain.pem`, `privatekey.pem`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDir(pub PathBuf);

impl KeyDir {
    /// Wrap a directory path.
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self(path)
    }
}

/// Top-level ACME configuration. Constructed via `bon::Builder` for
/// readability at the call site.
#[derive(bon::Builder)]
pub struct AcmeConfig {
    /// CA directory URL.
    pub directory_url: DirectoryUrl,
    /// Operator contact email (per RFC 8555 §7.3.1).
    pub contact_email: CompactString,
    /// Domains the cert should cover (apex + wildcards).
    pub domains: Vec<CompactString>,
    /// On-disk key directory for account-key + chain persistence.
    pub key_dir: KeyDir,
}
