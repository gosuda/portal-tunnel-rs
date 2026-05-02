mod api;
mod auth;
mod config;
mod policy;
mod relay;
mod state;

use anyhow::Context;
use clap::Parser;
use config::RelayConfig;
use relay::Server;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Run the portal-relay binary entry point. Returns the process exit code.
#[must_use]
pub fn run() -> std::process::ExitCode {
    match run_inner() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = ?err, "portal relay terminated with error");
            std::process::ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn run_inner() -> anyhow::Result<()> {
    init_tracing();

    let cfg = RelayConfig::parse().normalize()?;
    let server = Server::new(cfg).await.context("initialize relay server")?;

    info!(
        api_addr = %server.api_addr(),
        portal_url = %server.portal_url(),
        root_host = %server.root_host(),
        "portal relay starting"
    );

    server.run().await
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}
