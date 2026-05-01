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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cfg = RelayConfig::parse().normalize()?;
    let server = Server::new(cfg).context("initialize relay server")?;

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
