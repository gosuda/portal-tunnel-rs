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
//! Subsequent commits wire the binary against the existing
//! `portal-relay` library surfaces — admin / SDK / discovery axum
//! routers (Phase 5 B5 / B6, landed), the ECH-aware tenant TLS
//! routing path (Phase 5 B9, landed), the QUIC backhaul `Endpoint`
//! (Phase 3 B2, landed), the embedded frontend bundle (Phase 7 B1,
//! landed), and the TUI subcommand (Phase 5 B10, pending). The
//! library pieces exist; the binary still needs the composition
//! glue.
//!
//! ## Local-only argument policy
//!
//! `Manager::new` currently dispatches via [`ProviderSelector::Local`]
//! only. The three ACME modes (`AcmeCloudflare`, `AcmeRoute53`,
//! `AcmeGcloud`) — backed by the DNS providers landed in Phase 4
//! B3 / B4 / B5 — return [`portal_acme::AcmeError::Config`] until the
//! `instant-acme` client wrapper that drives those providers under
//! [`portal_acme::Manager::ensure_certificate`] lands. To avoid
//! silently producing self-signed material when the operator clearly
//! asked for real ACME issuance, `serve` rejects any of
//! `--acme-directory-url` / `--contact-email` / `--domain` at parse
//! time. Once the instant-acme wrapper + per-provider selection is
//! wired in this binary's follow-up batch, the rejection is replaced
//! by an explicit `--provider <local|cloudflare|route53|gcloud>` flag.

#![forbid(unsafe_code)]

// Phase 7 U8.11 install-script render API — public surface that
// the admin router's forthcoming `/__install.sh` and
// `/__install.ps1` handlers consume. The admin router itself exists
// today as a placeholder constructor in
// `portal_relay::api::build_admin_router`; the actual route handlers
// land with the Phase 5 B8 admin-router-handler wire-up. The
// installer module ships now so the rendering logic + Go-parity
// tests are reviewable in isolation; the handler wire-up is
// one-line per route once the admin handlers are mounted.
#[expect(
    dead_code,
    reason = "handler integration is the next U8.11 follow-up commit \
              once the admin router carries route handlers"
)]
mod installer;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{ArgMatches, CommandFactory, FromArgMatches, Parser, Subcommand, parser::ValueSource};
use compact_str::CompactString;
use eyre::{Context as _, eyre};
use portal_acme::{AcmeConfig, DirectoryUrl, KeyDir, Manager as AcmeManager, ProviderSelector};
use portal_relay::policy::PolicyRuntime;
use portal_relay::state::LeaseRegistry;
use portal_relay::{ConfigLoadError, RelayConfigBundle, Server};
use portal_relay_bin::init::{InitArgs, run_init};
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
    /// Scaffold default `bootstrap.json` + `runtime.json` config files
    /// in the supplied state directory. The files use placeholder key
    /// paths that the operator must replace with real PEM-encoded key
    /// files before running `serve`.
    Init(InitArgs),
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

    /// CA directory URL. Reserved for ACME issuance; rejected at
    /// parse time today because the binary currently only
    /// materializes self-signed material via
    /// [`ProviderSelector::Local`].
    #[arg(long)]
    acme_directory_url: Option<String>,

    /// Operator email for ACME registration. Reserved for ACME
    /// issuance; rejected at parse time today.
    #[arg(long)]
    contact_email: Option<String>,

    /// Domains the issued cert should cover. Reserved for ACME
    /// issuance; rejected at parse time today. Repeatable.
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
            Command::Init(args) => run_init(&args).await,
        }
    })
}

/// The binary currently only wires [`ProviderSelector::Local`].
/// Refuse to boot if the operator passed any flag that implies real
/// ACME issuance — we would otherwise silently produce self-signed
/// material under a misleading configuration.
fn reject_acme_flags(matches: &ArgMatches) -> eyre::Result<()> {
    const FLAGS: &[(&str, &str)] = &[
        ("acme_directory_url", "--acme-directory-url"),
        ("contact_email", "--contact-email"),
        ("domains", "--domain"),
    ];
    for (id, display) in FLAGS {
        if matches!(matches.value_source(id), Some(ValueSource::CommandLine)) {
            return Err(eyre!(
                "{display} is reserved for ACME issuance; this binary \
                 currently only supports local self-signed mode. \
                 Re-run without {display}.",
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

/// Load `state_dir/bootstrap.json` + `state_dir/runtime.json` if
/// BOTH files exist on disk. Returns `Ok(None)` if EITHER file is
/// missing (`std::io::ErrorKind::NotFound`) — the operator has not
/// run `portal-relay init` yet, or has deliberately omitted the
/// runtime file. Returns `Ok(Some(bundle))` on full load, or
/// `Err(_)` for any other error (malformed JSON, permissions, etc.).
async fn load_bundle_if_present(
    state_dir: &std::path::Path,
) -> eyre::Result<Option<RelayConfigBundle>> {
    let bootstrap_path = state_dir.join("bootstrap.json");
    let runtime_path = state_dir.join("runtime.json");

    match RelayConfigBundle::from_files(&bootstrap_path, &runtime_path).await {
        Ok(bundle) => Ok(Some(bundle)),
        Err(ConfigLoadError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(None)
        }
        Err(other) => Err(other).context("loading config bundle"),
    }
}

#[tracing::instrument(skip_all, fields(state_dir = %args.state_dir.display(), name = %args.name))]
async fn serve(args: ServeArgs) -> eyre::Result<()> {
    tracing::info!("starting portal-relay");

    // 1. Build the ACME config + manager (local-mode only — see
    //    `reject_acme_flags`). The directory URL + contact email
    //    fields exist on `AcmeConfig` for forward-compat with the
    //    eventual ACME wiring; we plug in safe placeholders.
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
        AcmeManager::new(acme_cfg, ProviderSelector::Local).context("construct ACME manager")?,
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
    //
    // Opportunistic config-bundle integration: if the operator ran
    // `portal-relay init` (or hand-wrote both files), load the
    // bundle and wire its `ReloadHandle` into `PolicyRuntime` so
    // the iter-128/129 reload-aware reads (`is_ip_banned`,
    // `bps_cap_per_identity`) reflect the on-disk operator config.
    // If either file is missing, fall back to the default
    // `PolicyRuntime` so the iter-119 baseline of `serve` working
    // without `init` first is preserved.
    let bundle = load_bundle_if_present(&args.state_dir).await?;
    let reload_handle: Option<Arc<portal_relay::ReloadHandle>> = bundle.map(|bundle| {
        let bundle_name = bundle.server.name.clone();
        let ip_ban_count = bundle.runtime.ip_ban_list.len();
        let bps_cap = bundle.runtime.bps_per_identity;
        let handle = Arc::new(bundle.into_handle());
        tracing::info!(
            bundle_name = %bundle_name,
            ip_ban_count,
            bps_cap_per_identity = bps_cap,
            "loaded U13 config bundle from state_dir; PolicyRuntime is reload-aware",
        );
        handle
    });

    if reload_handle.is_none() {
        tracing::info!(
            "no bootstrap.json/runtime.json found in state_dir; \
             using default PolicyRuntime (run `portal-relay init` to scaffold)",
        );
    }

    let policy = reload_handle
        .as_ref()
        .map_or_else(PolicyRuntime::new, |handle| {
            PolicyRuntime::new().with_reload_handle(Arc::clone(handle))
        });

    // 2.5. Spawn the optional config-file watcher.
    //
    // Hoare invariant: the watcher only fires when a bundle was
    // loaded — there is no point watching a non-existent
    // runtime.json. The JoinHandle is held for shutdown-time
    // abort; aborting drops the inner debouncer, which signals the
    // OS-level watcher to stop. Spawn-time errors log warn and
    // continue without hot-reload (best-effort, per iter-126's
    // resilience contract).
    #[cfg(feature = "config_file_watch")]
    let watcher_handle: Option<tokio::task::JoinHandle<()>> = match &reload_handle {
        Some(handle) => {
            let runtime_path = args.state_dir.join("runtime.json");
            match portal_relay::watch_runtime_config(Arc::clone(handle), runtime_path.clone()) {
                Ok(jh) => {
                    tracing::info!(
                        runtime_path = %runtime_path.display(),
                        "spawned config_file_watch task; runtime.json edits trigger reload",
                    );
                    Some(jh)
                }
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        runtime_path = %runtime_path.display(),
                        "failed to spawn config_file_watch; continuing without hot-reload",
                    );
                    None
                }
            }
        }
        None => None,
    };

    let server = Server::with_components(LeaseRegistry::new(), policy);
    server.start().await.context("start relay server")?;
    let status = server.status().await;
    tracing::info!(?status, "relay server started");

    // 3. Wait for SIGINT/SIGTERM (Ctrl+C on Windows).
    let cancel = CancellationToken::new();
    install_signal_handler(cancel.clone());
    cancel.cancelled().await;
    tracing::info!("shutdown signal received");

    // 4. Drain.
    //
    // Abort the config-file watcher first AND await its
    // JoinHandle: `abort()` only requests cancellation, so we must
    // await the handle to guarantee the task actually drops its
    // inner debouncer (which signals the OS-level watcher to stop)
    // before the server drains. The await resolves with
    // `Err(JoinError)` whose `is_cancelled()` is true; we discard
    // it.
    #[cfg(feature = "config_file_watch")]
    if let Some(jh) = watcher_handle {
        jh.abort();
        let _ = jh.await;
        tracing::info!("aborted config_file_watch task");
    }
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
    // R9: top-of-`main` runtime entry point. Binary crate composes the task
    // tree at the runtime root; this signal-handler spawn is the canonical
    // "free `tokio::spawn` permitted only at top of main" exception.
    #[expect(
        clippy::disallowed_methods,
        reason = "R9: top-of-main signal handler in binary crate runtime entry"
    )]
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
        let sigterm_stream =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
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
