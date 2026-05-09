//! `portal` binary — user-facing client.
//!
//! Wires the expose flow end-to-end:
//! - Loads tenant + protocol identity keys.
//! - Registers with the relay via HTTP challenge-response.
//! - Opens a QUIC connection to the relay.
//! - Forwards accepted TCP streams to the local `--target`.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use compact_str::CompactString;
use portal_sdk::{AcceptedStream, ExposeConfig, ExposeSession, channel};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

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
    /// Path to tenant secp256k1 identity key file.
    #[arg(long)]
    tenant_key_path: PathBuf,
    /// Optional path to persisted ed25519 protocol key.
    #[arg(long)]
    protocol_key_path: Option<PathBuf>,
    /// Relay descriptor file (JSON). Repeatable for multi-relay selection;
    /// the first descriptor is used as the primary relay.
    #[arg(long = "relay")]
    relays: Vec<String>,
    /// HTTPS API base URL (e.g. `https://relay.example.com`).
    #[arg(long, default_value = "https://localhost:8443")]
    api_base_url: String,
    /// Local bind address for the QUIC endpoint.
    #[arg(long, default_value = "0.0.0.0:0")]
    bind_addr: String,
    /// Request UDP datagram surface.
    #[arg(long)]
    udp: bool,
}

#[derive(Debug, Args)]
struct ListArgs {
    /// Filter to a specific hostname.
    #[arg(long)]
    hostname: Option<String>,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.command {
        Command::Expose(args) => run_expose(args).await,
        Command::List(args) => {
            run_list(&args);
            Ok(())
        }
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

async fn run_expose(args: ExposeArgs) -> eyre::Result<()> {
    if args.relays.is_empty() {
        eyre::bail!("at least one --relay descriptor file is required");
    }

    // Parse the first relay descriptor.
    let relay = load_relay_descriptor(&args.relays[0])?;

    let bind_addr: SocketAddr = args.bind_addr.parse()?;

    let config = ExposeConfig {
        relay,
        api_base_url: CompactString::from(args.api_base_url),
        tenant_key_path: args.tenant_key_path,
        protocol_key_path: args.protocol_key_path,
        hostname: CompactString::from(args.hostname),
        udp_enabled: args.udp,
        tcp_enabled: true,
        bind_addr,
    };

    let (event_tx, _event_rx) = channel();
    let (session, mut stream_rx) = ExposeSession::start(config, event_tx).await?;

    tracing::info!(target = %args.target, "expose session active; forwarding streams");

    let target = args.target.clone();
    let forward_cancel = CancellationToken::new();
    let mut join_set = JoinSet::new();

    let receive_cancel = forward_cancel.clone();
    #[expect(
        clippy::disallowed_methods,
        reason = "R9 OR clause: stored JoinHandle (receive_task) + CancellationToken (forward_cancel)"
    )]
    let mut receive_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                () = receive_cancel.cancelled() => break,
                _ = join_set.join_next(), if !join_set.is_empty() => {
                    // Reaped a completed forward task; continue.
                }
                maybe = stream_rx.recv() => {
                    match maybe {
                        Some(stream) => {
                            let t = target.clone();
                            join_set.spawn(async move {
                                if let Err(e) = handle_stream(stream, &t).await {
                                    tracing::warn!(error = %e, "stream forward failed");
                                }
                            });
                        }
                        None => break,
                    }
                }
            }
        }
        join_set
    });

    tokio::select! {
        res = &mut receive_task => {
            let mut join_set = res?;
            join_set.shutdown().await;
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            forward_cancel.cancel();
            let mut join_set = receive_task.await?;
            join_set.shutdown().await;
        }
    }

    session.stop().await;
    Ok(())
}

async fn handle_stream(stream: AcceptedStream, target: &str) -> std::io::Result<()> {
    match stream {
        AcceptedStream::TcpRaw { mut send, mut recv } => {
            let tcp = tokio::net::TcpStream::connect(target).await?;
            let (mut tcp_read, mut tcp_write) = tcp.into_split();

            let (r1, r2) = tokio::join!(
                tokio::io::copy(&mut recv, &mut tcp_write),
                tokio::io::copy(&mut tcp_read, &mut send)
            );
            r1?;
            r2?;
            Ok(())
        }
        AcceptedStream::TcpTls { .. } => {
            tracing::warn!("TCP TLS stream forwarding not yet implemented");
            Ok(())
        }
        _ => {
            tracing::warn!("unknown accepted stream variant");
            Ok(())
        }
    }
}

fn load_relay_descriptor(path: &str) -> eyre::Result<portal_wire::descriptor::RelayDescriptor> {
    let bytes = std::fs::read(path)?;
    let descriptor: portal_wire::descriptor::RelayDescriptor = serde_json::from_slice(&bytes)?;
    Ok(descriptor)
}

fn run_list(args: &ListArgs) {
    tracing::info!(hostname = ?args.hostname, "portal list parsed args");
    println!("portal list: hostname filter = {:?}", args.hostname);
    println!("list flow not yet composed end-to-end (deferred)");
}
