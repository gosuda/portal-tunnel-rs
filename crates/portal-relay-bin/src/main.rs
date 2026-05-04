//! `portal-relay` binary — entry point.
//!
//! Phase 7 B1 ships a minimal `serve` subcommand that:
//! 1. Initializes tracing.
//! 2. Constructs a [`portal_acme::Manager`] in local-self-signed
//!    mode and materializes `(fullchain.pem, privatekey.pem)` on
//!    disk.
//! 3. Starts a [`portal_relay::Server`] (lease janitor + policy
//!    runtime).
//! 4. Waits for SIGINT/SIGTERM (or Ctrl+C on Windows) and
//!    cancels + drains the server.
//!
//! Subsequent batches wire the actual axum admin/sdk/discovery
//! listeners against the issued TLS material, the QUIC backhaul
//! `Endpoint`, the embedded frontend bundle, and the TUI
//! subcommand.
//!
//! ## Local-only argument policy
//!
//! `Manager::new` currently dispatches via [`ProviderSelector::Local`]
//! only — the Cloudflare / Route53 / Google Cloud arms are deferred
//! to Phase 4 B3-B5. To avoid silently producing self-signed
//! material when the operator clearly asked for real ACME issuance,
//! `serve` rejects any of `--acme-directory-url` /
//! `--contact-email` / `--domain` at parse time. Once provider
//! selection is wired (Phase 4 B3-B5 + this binary's follow-up
//! batch), the rejection is replaced by an explicit
//! `--provider <local|cloudflare|route53|gcloud>` flag.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use clap::{ArgMatches, CommandFactory, FromArgMatches, Parser, Subcommand, parser::ValueSource};
use compact_str::CompactString;
use eyre::{Context as _, eyre};
use portal_acme::{
    AcmeConfig, DirectoryUrl, KeyDir, Manager as AcmeManager, ProviderSelector,
};
use portal_relay::Server;
use tokio_util::sync::CancellationToken;

/// Top-level CLI.
#[derive(Debug, Parser)]
#[command(name = "portal-relay", version, about = "Portal tunnel relay server")]
struct Cli {
    /// Subcommand to invoke.
    #[command(subcommand)]
    command: Command,
}

/// Top-level subcommand dispatch.
#[derive(Debug, Subcommand)]
enum Command {
    /// Run the relay server until SIGINT/SIGTERM.
    Serve(ServeArgs),
}

/// Args for `portal-relay serve`.
#[derive(Debug, Parser)]
struct ServeArgs {
    /// On-disk state directory holding identity material + lease
    /// snapshots + TLS material.
    #[arg(long, default_value = "./relay-state")]
    state_dir: PathBuf,

    /// Operator-friendly relay name (used in tracing + audit log).
    #[arg(long, default_value = "portal-relay-local")]
    name: String,

    /// CA directory URL. Reserved for the Phase 4 B3-B5 ACME wiring;
    /// rejected at parse time today because Phase 7 B1 only
    /// materializes self-signed material via [`ProviderSelector::Local`].
    #[arg(long)]
    acme_directory_url: Option<String>,

    /// Operator email for ACME registration. Reserved for the
    /// Phase 4 B3-B5 ACME wiring; rejected at parse time today.
    #[arg(long)]
    contact_email: Option<String>,

    /// Domains the issued cert should cover. Reserved for the
    /// Phase 4 B3-B5 ACME wiring; rejected at parse time today.
    /// Repeatable.
    #[arg(long = "domain")]
    domains: Vec<String>,
}

fn main() -> eyre::Result<()> {
    init_tracing();
    let matches = Cli::command().get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(err) => err.exit(),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    runtime.block_on(async move {
        match cli.command {
            Command::Serve(args) => {
                let serve_matches = matches
                    .subcommand_matches("serve")
                    .ok_or_else(|| eyre!("internal: serve subcommand matches missing"))?;
                reject_acme_flags(serve_matches)?;
                serve(args).await
            }
        }
    })
}

/// Phase 7 B1 only wires [`ProviderSelector::Local`]. Refuse to boot if
/// the operator passed any flag that implies real ACME issuance — we
/// would otherwise silently produce self-signed material under a
/// misleading configuration.
fn reject_acme_flags(matches: &ArgMatches) -> eyre::Result<()> {
    const FLAGS: &[(&str, &str)] = &[
        ("acme_directory_url", "--acme-directory-url"),
        ("contact_email", "--contact-email"),
        ("domains", "--domain"),
    ];
    for (id, display) in FLAGS {
        if matches!(matches.value_source(id), Some(ValueSource::CommandLine)) {
            return Err(eyre!(
                "{display} is reserved for the Phase 4 B3-B5 ACME wiring; \
                 Phase 7 B1 only supports local self-signed mode. Re-run \
                 without {display}.",
            ));
        }
    }
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,portal_relay=info,portal_acme=info"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .try_init();
}

#[tracing::instrument(skip_all, fields(state_dir = %args.state_dir.display(), name = %args.name))]
async fn serve(args: ServeArgs) -> eyre::Result<()> {
    tracing::info!("starting portal-relay");

    // 1. Build the ACME config + manager (local-mode only — see
    //    `reject_acme_flags`). The directory URL + contact email
    //    fields exist on `AcmeConfig` for forward-compat with the
    //    Phase 4 B3-B5 wiring; we plug in safe placeholders.
    let key_dir = KeyDir::new(args.state_dir.join("tls"));
    let directory_url = DirectoryUrl::new(DirectoryUrl::LE_STAGING);
    let contact_email = CompactString::from("operator@example.invalid");
    // Local mode default SAN list — operator-friendly placeholder. The
    // local provider ignores this and bakes its own loopback SANs into
    // the self-signed cert; we still populate it so `AcmeConfig::builder`
    // sees a non-empty `domains` slice for forward-compat.
    let domains: Vec<CompactString> = vec![CompactString::from("localhost")];

    let acme_cfg = AcmeConfig::builder()
        .directory_url(directory_url)
        .contact_email(contact_email)
        .domains(domains)
        .key_dir(key_dir.clone())
        .build();

    let acme_mgr = Arc::new(
        AcmeManager::new(acme_cfg, ProviderSelector::Local)
            .context("construct ACME manager")?,
    );
    let handoff = acme_mgr
        .ensure_certificate()
        .await
        .context("materialize TLS material")?;
    tracing::info!(
        fullchain = %handoff.fullchain.display(),
        private_key = %handoff.private_key.display(),
        mode = ?handoff.mode,
        "TLS material ready",
    );
    acme_mgr
        .start()
        .await
        .context("start ACME manager maintenance loop")?;

    // 2. Build the relay server.
    let server = Server::new();
    server.start().await.context("start relay server")?;
    let status = server.status().await;
    tracing::info!(?status, "relay server started");

    // 3. Wait for SIGINT/SIGTERM (Ctrl+C on Windows).
    let cancel = CancellationToken::new();
    install_signal_handler(cancel.clone());
    cancel.cancelled().await;
    tracing::info!("shutdown signal received");

    // 4. Drain.
    server.shutdown().await;
    acme_mgr.shutdown().await;
    tracing::info!("portal-relay stopped");
    Ok(())
}

/// Install a signal handler that cancels `cancel` on the first SIGINT
/// (Ctrl+C) or SIGTERM (Unix only). Failure to install the SIGTERM
/// stream is non-fatal — we log and still await SIGINT so Ctrl+C
/// continues to work.
fn install_signal_handler(cancel: CancellationToken) {
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        cancel.cancel();
    });
}

/// Resolves on the first SIGINT (Ctrl+C) or, on Unix, SIGTERM.
/// SIGTERM-stream construction failure is best-effort: we log and
/// fall back to SIGINT-only so Ctrl+C still terminates the process.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let sigterm_stream = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        );
        match sigterm_stream {
            Ok(mut sigterm) => {
                tokio::select! {
                    res = tokio::signal::ctrl_c() => {
                        if let Err(err) = res {
                            tracing::warn!(?err, "ctrl_c handler errored");
                        } else {
                            tracing::info!("SIGINT received");
                        }
                    }
                    _ = sigterm.recv() => {
                        tracing::info!("SIGTERM received");
                    }
                }
            }
            Err(err) => {
                tracing::warn!(
                    ?err,
                    "failed to install SIGTERM handler; falling back to SIGINT only",
                );
                if let Err(ctrl_err) = tokio::signal::ctrl_c().await {
                    tracing::warn!(?ctrl_err, "ctrl_c handler errored");
                } else {
                    tracing::info!("SIGINT received");
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::warn!(?err, "ctrl_c handler errored");
        } else {
            tracing::info!("Ctrl+C received");
        }
    }
}
