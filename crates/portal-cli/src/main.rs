//! `portal` binary — user-facing client.
//!
//! Phase 7 B2 ships the CLI argument-parsing skeleton:
//! - `portal expose --hostname X --target Y --relay R` parses cleanly.
//! - `portal list` parses cleanly.
//! - The actual expose-flow + lease-listener composes the
//!   [`portal_sdk`] surfaces (`ExposeSession` lifecycle, listener
//!   loop, identity loader); see `portal_sdk`'s lib.rs §Phase 6a
//!   implementation status for the per-unit deferrals.
//!
//! Until those surfaces are composed end-to-end, every subcommand
//! prints the parsed args + a deferral notice and exits 0 —
//! sufficient for the harness to verify the CLI shape.

#![forbid(unsafe_code)]

use clap::{Args, Parser, Subcommand};

/// Top-level CLI.
#[derive(Debug, Parser)]
#[command(name = "portal", version, about = "Portal-tunnel client CLI")]
struct Cli {
    /// Subcommand to invoke.
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Expose a local target through a portal relay.
    Expose(ExposeArgs),
    /// List configured relays + active leases.
    List(ListArgs),
}

#[derive(Debug, Args)]
struct ExposeArgs {
    /// Public hostname to register on the relay.
    #[arg(long)]
    hostname: String,
    /// Local target socket to forward to (e.g., `127.0.0.1:8080`).
    #[arg(long)]
    target: String,
    /// Relay descriptor URL or local file. Repeatable for multi-relay
    /// selection.
    #[arg(long = "relay")]
    relays: Vec<String>,
    /// Reject the connection if the MITM probe disagrees with the
    /// pinned relay identity. Default: true (`--ban-mitm` is the safe
    /// default per SEC-013).
    #[arg(long, default_value_t = true)]
    ban_mitm: bool,
}

#[derive(Debug, Args)]
struct ListArgs {
    /// Filter to a specific hostname.
    #[arg(long)]
    hostname: Option<String>,
}

fn main() {
    init_tracing();
    let cli = Cli::parse();
    match cli.command {
        Command::Expose(args) => run_expose(&args),
        Command::List(args) => run_list(&args),
    }
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,portal_sdk=info"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .try_init();
}

fn run_expose(args: &ExposeArgs) {
    tracing::info!(
        hostname = %args.hostname,
        target = %args.target,
        relays = ?args.relays,
        ban_mitm = args.ban_mitm,
        event_capacity = portal_sdk::DEFAULT_EVENT_CHANNEL_CAPACITY,
        "portal expose parsed args; end-to-end flow not yet composed (deferred)",
    );
    println!(
        "portal expose: parsed --hostname={} --target={} --relays={:?} --ban-mitm={}",
        args.hostname, args.target, args.relays, args.ban_mitm,
    );
    println!(
        "event channel capacity: {}",
        portal_sdk::DEFAULT_EVENT_CHANNEL_CAPACITY
    );
    println!("expose flow not yet composed end-to-end (deferred — see portal_sdk)");
}

fn run_list(args: &ListArgs) {
    tracing::info!(hostname = ?args.hostname, "portal list parsed args");
    println!("portal list: hostname filter = {:?}", args.hostname);
    println!("list flow not yet composed end-to-end (deferred)");
}
