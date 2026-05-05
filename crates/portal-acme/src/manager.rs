//! `Manager` — top-level lifecycle façade for portal-acme.
//!
//! Composes the chosen [`crate::provider::DnsProvider`] with the on-disk persistence
//! layer ([`crate::persist`]) and the (forthcoming) `instant-acme`
//! client. Phase 4 Batch 6 ships **only the local-self-signed path**
//! end-to-end. The DNS providers landed in B3 (Cloudflare), B4
//! (Route53), and B5 (Google Cloud DNS); the `instant-acme` client
//! wrapper that wires those providers under
//! [`Manager::ensure_certificate`] for the three ACME modes is still
//! pending.
//!
//! Lifecycle (Go reference parity):
//! - `Manager::new(cfg)` validates config + selects the provider.
//! - `Manager::ensure_certificate()` materializes `(fullchain.pem,
//!   privatekey.pem)` on disk. Local mode generates a self-signed cert;
//!   ACME mode is deferred.
//! - `Manager::start(cancel)` spawns the maintenance loop (renew tick
//!   24h, DNS resync tick 10m). Local mode loops are a no-op — the
//!   self-signed cert has 10y validity and the local provider does not
//!   touch DNS.
//! - `Manager::shutdown()` cancels and joins.
//!
//! Phase 5 (`portal-relay`) consumes this façade by calling
//! [`Manager::ensure_certificate`] at boot and reading the returned
//! [`CertificateHandoff`] paths into rustls. The maintenance loop is
//! kept consistent across modes (even if the local-mode loop body is a
//! no-op) so Phase 5 sees a single shutdown surface and does not need
//! mode-specific plumbing.
//!
//! `PublicIpResolver` is intentionally **not** introduced in this
//! batch — per R8 minimalism it is deferred until the live ACME flow
//! (the pending instant-acme client wrapper) needs to publish A
//! records before solving DNS-01.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::{AcmeConfig, KeyDir};
use crate::error::{AcmeError, AcmeResult};
#[cfg(feature = "local")]
use crate::providers::local::LocalProvider;

/// Mode the manager is configured for.
///
/// Selected at `Manager::new` time from the [`AcmeConfig`]. The
/// [`Mode::LocalSelfSigned`] path is fully wired end-to-end. The
/// three ACME modes select between landed DNS providers, but the
/// dispatch wrapper that drives the instant-acme client through the
/// chosen provider is still pending — those arms return
/// [`AcmeError::Config`] until that wrapper lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Local self-signed dev mode (no DNS, no CA contact).
    LocalSelfSigned,
    /// ACME via Cloudflare DNS-01 (provider landed in B3; awaits
    /// instant-acme dispatch wrapper).
    AcmeCloudflare,
    /// ACME via Route53 DNS-01 (provider landed in B4; awaits
    /// instant-acme dispatch wrapper).
    AcmeRoute53,
    /// ACME via Google Cloud DNS-01 (provider landed in B5; awaits
    /// instant-acme dispatch wrapper).
    AcmeGcloud,
}

/// Selector passed to [`Manager::new`] to pick the issuance mode.
/// Future batches replace this with a richer config-driven selector
/// that reads cloud-credential secrets from [`AcmeConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderSelector {
    /// Force local self-signed regardless of `AcmeConfig` content.
    Local,
    /// Cloudflare ACME — requires [`crate::config::CloudflareToken`]
    /// in a future config field.
    Cloudflare,
    /// Route53 ACME — requires [`crate::config::Route53Credentials`].
    Route53,
    /// Google Cloud ACME — requires
    /// [`crate::config::GcloudServiceAccount`].
    Gcloud,
}

/// Top-level lifecycle façade.
pub struct Manager {
    cfg: AcmeConfig,
    mode: Mode,
    /// Set once `start()` is called; the maintenance loop runs until
    /// `shutdown()` cancels.
    runtime: Arc<Mutex<Option<ManagerRuntime>>>,
}

struct ManagerRuntime {
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

/// Handoff record returned by [`Manager::ensure_certificate`]. Phase 5
/// (`portal-relay::state::tls_material`) reads these paths and feeds
/// them to rustls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateHandoff {
    /// `<key_dir>/fullchain.pem` (mode 0o644).
    pub fullchain: PathBuf,
    /// `<key_dir>/privatekey.pem` (mode 0o600).
    pub private_key: PathBuf,
    /// Mode the cert was generated under.
    pub mode: Mode,
}

impl Manager {
    /// Construct a new manager with the supplied config + selector.
    ///
    /// # Errors
    /// Returns [`AcmeError::Config`] if the config + selector
    /// combination is incompatible (e.g., empty `domains` list for an
    /// ACME selector).
    pub fn new(cfg: AcmeConfig, selector: ProviderSelector) -> AcmeResult<Self> {
        if cfg.domains.is_empty() && !matches!(selector, ProviderSelector::Local) {
            return Err(AcmeError::Config(
                "ACME mode requires at least one domain".to_owned(),
            ));
        }
        let mode = match selector {
            ProviderSelector::Local => Mode::LocalSelfSigned,
            ProviderSelector::Cloudflare => Mode::AcmeCloudflare,
            ProviderSelector::Route53 => Mode::AcmeRoute53,
            ProviderSelector::Gcloud => Mode::AcmeGcloud,
        };
        Ok(Self {
            cfg,
            mode,
            runtime: Arc::new(Mutex::new(None)),
        })
    }

    /// Mode the manager was constructed in.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// Materialize `(fullchain.pem, privatekey.pem)` on disk under
    /// [`AcmeConfig::key_dir`] and return their paths.
    ///
    /// Local mode: generate a fresh self-signed cert via
    /// [`LocalProvider`].
    ///
    /// ACME modes: not yet implemented; returns
    /// [`AcmeError::Config`] until the instant-acme client wrapper
    /// lands.
    ///
    /// # Errors
    /// Returns [`AcmeError::Cert`] / [`AcmeError::Io`] on cert
    /// generation or write failure, or [`AcmeError::Config`] for any
    /// ACME mode in this batch.
    pub async fn ensure_certificate(&self) -> AcmeResult<CertificateHandoff> {
        match self.mode {
            Mode::LocalSelfSigned => self.ensure_certificate_local().await,
            Mode::AcmeCloudflare | Mode::AcmeRoute53 | Mode::AcmeGcloud => {
                Err(AcmeError::Config(format!(
                    "{:?} not implemented; waits on the instant-acme client wrapper",
                    self.mode,
                )))
            }
        }
    }

    /// Local-mode certificate materialization. Gated behind the
    /// `local` feature so a `--no-default-features` build that omits
    /// the local provider still compiles cleanly; in that case the
    /// local arm returns a `Config` error explaining the missing
    /// feature.
    #[cfg(feature = "local")]
    async fn ensure_certificate_local(&self) -> AcmeResult<CertificateHandoff> {
        let provider = self
            .cfg
            .domains
            .first()
            .map_or_else(LocalProvider::new, |base| {
                LocalProvider::with_base_domain(base.clone())
            });
        let paths = provider.generate_self_signed(&self.cfg.key_dir).await?;
        Ok(CertificateHandoff {
            fullchain: paths.fullchain,
            private_key: paths.private_key,
            mode: self.mode,
        })
    }

    /// Stub used when the `local` feature is disabled. Keeps the
    /// dispatch arm in [`Self::ensure_certificate`] compilable without
    /// `cfg`-fanning the match.
    #[cfg(not(feature = "local"))]
    async fn ensure_certificate_local(&self) -> AcmeResult<CertificateHandoff> {
        Err(AcmeError::Config(
            "local-self-signed mode requires the `local` feature".to_owned(),
        ))
    }

    /// Spawn the maintenance loop (renew tick 24h + DNS resync 10m).
    /// In local mode the loop is a no-op tick — the self-signed cert
    /// has 10y validity and the local provider does not touch DNS, but
    /// we still spawn the task so callers see a consistent shutdown
    /// surface across modes.
    ///
    /// # Errors
    /// Returns [`AcmeError::Config`] if the manager is already started.
    pub async fn start(&self) -> AcmeResult<()> {
        let mut guard = self.runtime.lock().await;
        if guard.is_some() {
            return Err(AcmeError::Config("manager already started".to_owned()));
        }
        let cancel = CancellationToken::new();
        let mode = self.mode;
        let key_dir = self.cfg.key_dir.clone();
        let cancel_loop = cancel.clone();
        // R9: structured spawn satisfies the OR clause — the maintenance task
        // is bound to a stored `JoinHandle` (drained by `Manager::shutdown`)
        // AND carries a `CancellationToken`. The Manager owns the lifecycle
        // surface; callers do not pass in a `JoinSet`. See clippy.toml R9
        // entry and docs/architecture.md §Structured concurrency invariant.
        #[expect(
            clippy::disallowed_methods,
            reason = "R9 OR clause: stored JoinHandle + CancellationToken; Manager owns lifecycle surface"
        )]
        let handle = tokio::spawn(async move {
            maintenance_loop(mode, key_dir, cancel_loop).await;
        });
        *guard = Some(ManagerRuntime { cancel, handle });
        drop(guard);
        Ok(())
    }

    /// Cancel the maintenance loop and await its exit. Idempotent —
    /// calling twice is safe.
    pub async fn shutdown(&self) {
        let runtime = {
            let mut guard = self.runtime.lock().await;
            guard.take()
        };
        if let Some(rt) = runtime {
            rt.cancel.cancel();
            let _ = rt.handle.await;
        }
    }

    /// Whether the cert + key files already exist on disk under
    /// [`AcmeConfig::key_dir`]. Cheap probe used by Phase 5 to skip
    /// regeneration on warm boot.
    pub async fn cert_files_exist(&self) -> bool {
        let chain = self.cfg.key_dir.0.join("fullchain.pem");
        let key = self.cfg.key_dir.0.join("privatekey.pem");
        tokio::fs::metadata(&chain).await.is_ok() && tokio::fs::metadata(&key).await.is_ok()
    }
}

/// Maintenance-loop body. Runs both the 24h renew tick and the 10m
/// DNS-resync tick under a single `tokio::select!` until cancelled. In
/// local mode both ticks are no-ops; in ACME modes (deferred) the
/// ticks dispatch to renewal + DNS resync.
//
// `Duration::from_hours` / `Duration::from_mins` are nightly-only
// (`duration_constructors`) at the workspace's MSRV (1.95). We keep
// the explicit `from_secs` arithmetic and silence the clippy
// readability lint inline rather than rewriting around an unstable
// API. Once the constructors stabilize, drop the allow + switch.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "from_hours/from_mins are nightly-only at MSRV 1.95"
)]
async fn maintenance_loop(mode: Mode, _key_dir: KeyDir, cancel: CancellationToken) {
    let mut renew_tick = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
    let mut dns_tick = tokio::time::interval(Duration::from_secs(10 * 60));
    // First-tick semantics: skip the immediate fire so the loop only
    // does work on cadence boundaries, not on spawn.
    renew_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    dns_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let _ = renew_tick.tick().await;
    let _ = dns_tick.tick().await;

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                tracing::debug!(?mode, "acme manager loop cancelled");
                break;
            }
            _ = renew_tick.tick() => {
                tracing::debug!(?mode, "acme manager renew tick");
                // Local mode: cert has 10y validity; nothing to do.
                // ACME modes (deferred): inspect cert expiry, re-issue.
            }
            _ = dns_tick.tick() => {
                tracing::debug!(?mode, "acme manager dns tick");
                // Local mode: provider does not touch DNS.
                // ACME modes (deferred): re-sync A records.
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only setup")]
mod tests {
    use super::*;
    use crate::config::{AcmeConfig, DirectoryUrl, KeyDir};
    use compact_str::CompactString;
    use tempfile::tempdir;

    fn local_config(key_dir: PathBuf) -> AcmeConfig {
        AcmeConfig::builder()
            .directory_url(DirectoryUrl::new(DirectoryUrl::LE_STAGING))
            .contact_email(CompactString::from("test@example.com"))
            .domains(vec![CompactString::from("localhost")])
            .key_dir(KeyDir::new(key_dir))
            .build()
    }

    #[tokio::test]
    async fn new_local_mode_constructs() {
        let dir = tempdir().unwrap();
        let cfg = local_config(dir.path().to_path_buf());
        let mgr = Manager::new(cfg, ProviderSelector::Local).unwrap();
        assert_eq!(mgr.mode(), Mode::LocalSelfSigned);
    }

    #[cfg(feature = "local")]
    #[tokio::test]
    async fn ensure_certificate_local_writes_files() {
        let dir = tempdir().unwrap();
        let cfg = local_config(dir.path().to_path_buf());
        let mgr = Manager::new(cfg, ProviderSelector::Local).unwrap();
        let handoff = mgr.ensure_certificate().await.unwrap();
        assert_eq!(handoff.mode, Mode::LocalSelfSigned);
        assert!(tokio::fs::metadata(&handoff.fullchain).await.is_ok());
        assert!(tokio::fs::metadata(&handoff.private_key).await.is_ok());
        assert!(mgr.cert_files_exist().await);
    }

    #[tokio::test]
    async fn ensure_certificate_acme_modes_return_config_error() {
        let dir = tempdir().unwrap();
        for selector in [
            ProviderSelector::Cloudflare,
            ProviderSelector::Route53,
            ProviderSelector::Gcloud,
        ] {
            let cfg = local_config(dir.path().to_path_buf());
            let mgr = Manager::new(cfg, selector).unwrap();
            let result = mgr.ensure_certificate().await;
            assert!(
                matches!(result, Err(AcmeError::Config(_))),
                "{selector:?} must return Config error in B6: {result:?}",
            );
        }
    }

    #[tokio::test]
    async fn start_then_shutdown_is_clean() {
        let dir = tempdir().unwrap();
        let cfg = local_config(dir.path().to_path_buf());
        let mgr = Manager::new(cfg, ProviderSelector::Local).unwrap();
        mgr.start().await.unwrap();
        // Idempotent shutdown.
        mgr.shutdown().await;
        mgr.shutdown().await;
    }

    #[tokio::test]
    async fn double_start_returns_config_error() {
        let dir = tempdir().unwrap();
        let cfg = local_config(dir.path().to_path_buf());
        let mgr = Manager::new(cfg, ProviderSelector::Local).unwrap();
        mgr.start().await.unwrap();
        let result = mgr.start().await;
        assert!(matches!(result, Err(AcmeError::Config(_))));
        mgr.shutdown().await;
    }

    #[tokio::test]
    async fn cert_files_exist_returns_false_initially() {
        let dir = tempdir().unwrap();
        let cfg = local_config(dir.path().to_path_buf());
        let mgr = Manager::new(cfg, ProviderSelector::Local).unwrap();
        assert!(!mgr.cert_files_exist().await);
    }

    #[tokio::test]
    async fn new_acme_mode_with_empty_domains_rejected() {
        let dir = tempdir().unwrap();
        let cfg = AcmeConfig::builder()
            .directory_url(DirectoryUrl::new(DirectoryUrl::LE_STAGING))
            .contact_email(CompactString::from("test@example.com"))
            .domains(Vec::<CompactString>::new())
            .key_dir(KeyDir::new(dir.path().to_path_buf()))
            .build();
        let result = Manager::new(cfg, ProviderSelector::Cloudflare);
        assert!(matches!(result, Err(AcmeError::Config(_))));
    }

    #[tokio::test]
    async fn new_local_mode_with_empty_domains_allowed() {
        let dir = tempdir().unwrap();
        let cfg = AcmeConfig::builder()
            .directory_url(DirectoryUrl::new(DirectoryUrl::LE_STAGING))
            .contact_email(CompactString::from("test@example.com"))
            .domains(Vec::<CompactString>::new())
            .key_dir(KeyDir::new(dir.path().to_path_buf()))
            .build();
        let mgr = Manager::new(cfg, ProviderSelector::Local).unwrap();
        assert_eq!(mgr.mode(), Mode::LocalSelfSigned);
    }
}
