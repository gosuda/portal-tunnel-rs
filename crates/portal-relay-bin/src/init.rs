//! `portal-relay init` — scaffold default config files in a state dir.
//!
//! First production binary consumer of the U13 config chain: builds a
//! [`RelayServerConfig`] via [`RelayServerConfig::new`] and a
//! [`RuntimeConfig::default`], then serializes both through the
//! workspace serde derives into `bootstrap.json` + `runtime.json`
//! under the operator-supplied state directory.
//!
//! ## Operator-safety invariant
//!
//! `init` refuses to overwrite an existing `bootstrap.json` or
//! `runtime.json` unless `--force` is explicitly set. This guards
//! against the canonical foot-gun of silently clobbering an
//! operator-edited config. The existence check runs *before*
//! `create_dir_all` so a wrong `--state-dir` argument does not leave a
//! stray empty directory behind.
//!
//! Subsequent `portal-relay serve` invocations consume the files via
//! [`portal_relay::RelayConfigBundle::from_files_with_env`] (env-overlay
//! loader; operators set `PORTAL_RELAY_*` env vars to override
//! runtime fields). The serve integration is wired through
//! `crate::load::load_bundle_if_present`.

use std::path::PathBuf;

use clap::Args;
use compact_str::CompactString;
use eyre::{Context as _, eyre};
use portal_relay::{RelayServerConfig, RuntimeConfig};

/// Args for `portal-relay init`.
#[derive(Debug, Args)]
pub struct InitArgs {
    /// State directory to scaffold. The bootstrap.json + runtime.json
    /// files are written here. Created if missing (recursive
    /// `mkdir -p`).
    #[arg(long)]
    pub state_dir: PathBuf,
    /// Overwrite existing bootstrap.json or runtime.json files.
    /// Refuses otherwise (the operator-safety default — silent
    /// overwrite of operator-edited config is a canonical foot-gun).
    #[arg(long)]
    pub force: bool,
}

/// Scaffold default `bootstrap.json` + `runtime.json` files under
/// `args.state_dir`.
///
/// Hoare-invariant: when `args.force` is `false`, the function is a
/// no-op on disk if either target file already exists — the existing
/// file is left untouched, no directory is created, and the caller
/// receives an `Err` naming the conflicting path.
///
/// # Errors
///
/// - The state-dir existence pre-check fails (I/O error other than
///   "not found").
/// - Either target file exists and `args.force` is `false`.
/// - Creating the state directory fails (`mkdir -p`).
/// - Serializing either config to JSON fails.
/// - Writing either file fails.
///
/// # Partial-failure caveat
///
/// The two writes are sequential and non-transactional. If the
/// `bootstrap.json` write succeeds but the `runtime.json` write
/// fails, `bootstrap.json` is left on disk. A subsequent non-`--force`
/// run will refuse on the existing `bootstrap.json`. The operator
/// must remove the stranded file (or rerun with `--force`) before
/// re-init succeeds. Force-backup of overwritten files is
/// out of scope for v0.1.
pub async fn run_init(args: &InitArgs) -> eyre::Result<()> {
    let state_dir = &args.state_dir;
    let bootstrap_path = state_dir.join("bootstrap.json");
    let runtime_path = state_dir.join("runtime.json");

    if !args.force {
        for path in [&bootstrap_path, &runtime_path] {
            if tokio::fs::try_exists(path)
                .await
                .wrap_err_with(|| format!("checking {}", path.display()))?
            {
                return Err(eyre!(
                    "{} already exists. Re-run with `--force` to overwrite.",
                    path.display(),
                ));
            }
        }
    }

    tokio::fs::create_dir_all(state_dir)
        .await
        .wrap_err_with(|| format!("creating state dir {}", state_dir.display()))?;

    let bootstrap = RelayServerConfig::new(
        CompactString::from("portal-relay"),
        state_dir.clone(),
        state_dir.join("api-https.key"),
        state_dir.join("keyless.key"),
        state_dir.join("quic-id.key"),
    );
    let runtime = RuntimeConfig::default();

    let bootstrap_json =
        serde_json::to_string_pretty(&bootstrap).wrap_err("serializing bootstrap config")?;
    let runtime_json =
        serde_json::to_string_pretty(&runtime).wrap_err("serializing runtime config")?;

    tokio::fs::write(&bootstrap_path, bootstrap_json)
        .await
        .wrap_err_with(|| format!("writing {}", bootstrap_path.display()))?;
    tokio::fs::write(&runtime_path, runtime_json)
        .await
        .wrap_err_with(|| format!("writing {}", runtime_path.display()))?;

    println!("Scaffolded relay config in {}:", state_dir.display());
    println!("  - bootstrap.json (replace placeholder *.key paths before `serve`)");
    println!("  - runtime.json (operator-tunable; safe to leave at defaults for v0.1)");
    println!("Next: generate the three trust-boundary keys and update bootstrap.json:");
    println!("  - api-https.key (rustls-acceptable PEM private key)");
    println!("  - keyless.key (PEM private key for tenant keyless oracle)");
    println!("  - quic-id.key (PEM private key for QUIC backhaul identity)");
    println!("Then: portal-relay serve (Phase 7 B1)");

    Ok(())
}
