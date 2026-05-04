//! Relay-side TCP port forwarder. Each accept maps to a server-initiated
//! `Channel::TcpProxy::Raw` QUIC stream over the supplied backhaul.

use std::num::NonZeroUsize;
use std::sync::Arc;

use compact_str::CompactString;
use portal_wire::channel::Channel;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::dual_stack::{bind_dual_stack_tcp, canonicalize_socket};
use crate::error::NetError;
use crate::quic::stream::{TcpProxyKind, open_outbound};

/// Default cap on concurrent in-flight forwarders. `NonZeroUsize` so a
/// miswired zero cannot wedge the accept loop on the first permit.
pub const DEFAULT_MAX_CONCURRENT_FORWARDERS: NonZeroUsize = match NonZeroUsize::new(1024) {
    Some(n) => n,
    None => unreachable!(),
};

/// Per-lease TCP forwarder. Construction does not bind; call
/// [`TcpPortRelay::start`] to begin accepting and [`TcpPortRelay::shutdown`]
/// to drain in-flight splices and join all tasks.
pub struct TcpPortRelay {
    identity_key: CompactString,
    port: u16,
    backhaul: Arc<quinn::Connection>,
    cancel: CancellationToken,
    max_forwarders: NonZeroUsize,
    tasks: JoinSet<()>,
}

impl TcpPortRelay {
    /// Build a new relay around `backhaul`. `identity_key` is for tracing
    /// correlation; `port` is the TCP port to bind in [`Self::start`].
    #[must_use]
    pub fn new(identity_key: CompactString, port: u16, backhaul: Arc<quinn::Connection>) -> Self {
        Self {
            identity_key,
            port,
            backhaul,
            cancel: CancellationToken::new(),
            max_forwarders: DEFAULT_MAX_CONCURRENT_FORWARDERS,
            tasks: JoinSet::new(),
        }
    }

    /// Override the concurrent-forwarder cap. Must be called before
    /// [`Self::start`].
    #[must_use]
    pub const fn with_max_forwarders(mut self, max: NonZeroUsize) -> Self {
        self.max_forwarders = max;
        self
    }

    /// Bind a dual-stack TCP listener and spawn the accept loop. The
    /// accept loop watches both the caller-supplied `cancel` and the
    /// internal token fired by [`Self::shutdown`].
    ///
    /// # Errors
    /// Returns [`NetError::BindFailed`] / [`NetError::Io`] on bind failure.
    #[tracing::instrument(skip_all, fields(identity_key = %self.identity_key, port = self.port))]
    pub async fn start(&mut self, cancel: CancellationToken) -> Result<(), NetError> {
        let listener = bind_dual_stack_tcp(
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            self.port,
            false,
        )
        .await?;
        let backhaul = Arc::clone(&self.backhaul);
        let internal = self.cancel.clone();
        let semaphore = Arc::new(Semaphore::new(self.max_forwarders.get()));
        let tracker = TaskTracker::new();
        self.tasks.spawn(async move {
            accept_loop(listener, backhaul, semaphore, tracker, cancel, internal).await;
        });
        Ok(())
    }

    /// Cancel the internal token and join the accept-loop task. In-flight
    /// forwarders observe the same token and unwind by dropping their
    /// directional `JoinSet`, which aborts the per-half copy tasks; the
    /// dropped quinn `SendStream`/`RecvStream` halves issue
    /// finish-or-reset / stop on drop, so this resolves promptly even
    /// when the tenant origin is stalled. Idempotent.
    pub async fn shutdown(&mut self) {
        self.cancel.cancel();
        while let Some(res) = self.tasks.join_next().await {
            if let Err(err) = res {
                tracing::warn!(?err, "tcp port relay accept loop join error");
            }
        }
    }
}

#[tracing::instrument(skip_all)]
async fn accept_loop(
    listener: TcpListener,
    backhaul: Arc<quinn::Connection>,
    semaphore: Arc<Semaphore>,
    tracker: TaskTracker,
    caller_cancel: CancellationToken,
    internal_cancel: CancellationToken,
) {
    'accept: loop {
        tokio::select! {
            biased;
            () = caller_cancel.cancelled() => break 'accept,
            () = internal_cancel.cancelled() => break 'accept,
            res = listener.accept() => match res {
                Ok((tcp, peer)) => {
                    let peer = canonicalize_socket(peer);
                    // Permit acquire is cancellation-aware so saturation
                    // cannot wedge shutdown.
                    let permit = tokio::select! {
                        biased;
                        () = caller_cancel.cancelled() => { drop(tcp); break 'accept; }
                        () = internal_cancel.cancelled() => { drop(tcp); break 'accept; }
                        permit = Arc::clone(&semaphore).acquire_owned() => match permit {
                            Ok(p) => p,
                            Err(err) => {
                                tracing::warn!(?err, "tcp port relay semaphore closed");
                                drop(tcp);
                                break 'accept;
                            }
                        },
                    };
                    let backhaul = Arc::clone(&backhaul);
                    let fwd_caller = caller_cancel.clone();
                    let fwd_internal = internal_cancel.clone();
                    tracker.spawn(async move {
                        if let Err(err) =
                            handle_conn(tcp, peer, backhaul, fwd_caller, fwd_internal).await
                        {
                            tracing::warn!(?peer, ?err, "tcp port forward failed");
                        }
                        drop(permit);
                    });
                }
                Err(err) => {
                    tracing::warn!(?err, "tcp accept error; continuing loop");
                }
            },
        }
    }
    tracker.close();
    tracker.wait().await;
}

#[tracing::instrument(skip_all, fields(peer = ?peer))]
async fn handle_conn(
    tcp: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    backhaul: Arc<quinn::Connection>,
    caller_cancel: CancellationToken,
    internal_cancel: CancellationToken,
) -> Result<(), NetError> {
    use tokio::io::AsyncWriteExt as _;

    let (mut send_q, mut recv_q) =
        open_outbound(&backhaul, Channel::TcpProxy, Some(TcpProxyKind::Raw)).await?;
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    // Each direction is owned by its own spawned task. Cancel propagates
    // by aborting both tasks, which drops the inner stream halves; quinn
    // drop-impls issue finish-or-reset (`SendStream`) and stop
    // (`RecvStream`) so the QUIC peer observes a graceful unwind.
    let mut directions: JoinSet<Result<(), NetError>> = JoinSet::new();
    directions.spawn(async move {
        tokio::io::copy(&mut tcp_read, &mut send_q)
            .await
            .map_err(NetError::Io)?;
        send_q
            .finish()
            .map_err(|e| NetError::Quic(format!("send finish: {e}")))?;
        Ok(())
    });
    directions.spawn(async move {
        tokio::io::copy(&mut recv_q, &mut tcp_write)
            .await
            .map_err(NetError::Io)?;
        tcp_write.shutdown().await.map_err(NetError::Io)?;
        Ok(())
    });

    let drain = async {
        // First-error policy: on the first directional fault (or
        // non-cancel join failure), abort the sibling so the forwarder
        // returns promptly and releases its semaphore permit. A clean
        // EOF on one half lets the other run to natural completion.
        let mut sibling_err: Option<NetError> = None;
        while let Some(res) = directions.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    sibling_err = Some(err);
                    directions.abort_all();
                    // Drain remaining handles so the JoinSet is empty
                    // before we return.
                    while directions.join_next().await.is_some() {}
                    break;
                }
                Err(join_err) if join_err.is_cancelled() => {}
                Err(join_err) => {
                    sibling_err = Some(NetError::Quic(format!("forwarder join: {join_err}")));
                    directions.abort_all();
                    while directions.join_next().await.is_some() {}
                    break;
                }
            }
        }
        sibling_err.map_or(Ok(()), Err)
    };

    tokio::select! {
        biased;
        result = drain => result,
        () = caller_cancel.cancelled() => {
            // Drop `directions` to abort both halves; quinn drops handle
            // the wire-side reset/stop.
            drop(directions);
            Ok(())
        }
        () = internal_cancel.cancelled() => {
            drop(directions);
            Ok(())
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test-only setup parses hard-coded literals"
)]
mod tests {
    use super::*;

    /// R12-canon: every inbound peer must be canonicalized before any
    /// downstream consumer (tracing field, future ACL hook) sees it.
    #[test]
    fn canonicalize_socket_v4_mapped_yields_v4_form() {
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
        let v4_mapped: SocketAddr = "[::ffff:127.0.0.1]:55555".parse().unwrap();
        assert_eq!(
            canonicalize_socket(v4_mapped),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 55555)),
        );
    }
}
