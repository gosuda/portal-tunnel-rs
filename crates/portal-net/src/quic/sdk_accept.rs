//! SDK-side accept loop.
//!
//! Reads server-initiated bidi streams from the relay, dispatches by
//! `Channel` tag, and surfaces typed accepted streams to the caller.
//! Replaces Go's `stream_client.go::ClientStream`.
//!
//! # Scope (B6)
//!
//! TLS termination via `tokio_rustls::server::TlsStream` is **deferred to
//! Phase 5/6a** — the point at which the SDK actually performs TLS
//! handshakes against tenant origin certs. For Batch 6 the
//! [`AcceptedStream::TcpTls`] variant carries the raw QUIC stream pair
//! plus the [`TcpProxyKind`] discriminant; downstream code is responsible
//! for driving the TLS handshake. The `handshake_timeout` field is
//! preserved on [`SdkAcceptor`] so the public API does not need to grow
//! when the wrapping lands. Per R8 (minimalism) we explicitly do not
//! pull `tokio-rustls` into `portal-net` until that work begins.
//!
//! [`SdkAcceptor::run`] consumes `self` (single-shot) — restarting the
//! accept loop requires a fresh acceptor against a fresh
//! `quinn::Connection`. This mirrors Go's `ClientStream::runSession`,
//! which is also single-shot per connection lifetime, and avoids the
//! ambiguity of a re-entrant loop sharing a `JoinSet` across calls.

use std::sync::Arc;
use std::time::Duration;

use quinn::{RecvStream, SendStream};
use rustls::ServerConfig;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::error::NetError;
use crate::quic::stream::{InboundStream, TcpProxyKind, dispatch_inbound};

/// A bidirectional stream pair tagged with its decoded transport mode.
#[non_exhaustive]
pub enum AcceptedStream {
    /// Raw TCP — the SDK forwards bytes directly to the tenant origin
    /// without any further decoding.
    TcpRaw {
        /// QUIC send half spliced to the tenant origin.
        send: SendStream,
        /// QUIC recv half spliced from the tenant origin.
        recv: RecvStream,
    },
    /// Tenant-side TLS — the SDK terminates TLS using the tenant's own
    /// cert/key (passed via `tls_config` to [`SdkAcceptor::run`]). Bytes
    /// arriving on the QUIC stream are encrypted; the caller decrypts
    /// via a `tokio_rustls::server::TlsStream` wrapper that is layered on
    /// in Phase 5/6a.
    ///
    /// The TLS handshake will happen inside the accept loop with a
    /// `handshake_timeout` once that wrapping lands; on timeout the
    /// stream will be closed and no `AcceptedStream` will be emitted.
    /// In B6 the variant only carries the raw stream pair plus the
    /// [`TcpProxyKind`] discriminant.
    TcpTls {
        /// QUIC send half (TLS ciphertext from peer).
        send: SendStream,
        /// QUIC recv half (TLS ciphertext to peer).
        recv: RecvStream,
        /// Decoded sub-discriminant. Always `TcpProxyKind::Tls` for this
        /// variant — preserved here so callers can match exhaustively
        /// against the wire register.
        kind: TcpProxyKind,
    },
}

/// SDK-side accept loop handle.
///
/// Spawn via [`SdkAcceptor::run`]; the loop accepts server-initiated
/// bidi streams from the relay's QUIC connection, dispatches by channel
/// tag, and forwards `AcceptedStream`s into the `accepted` mpsc channel.
pub struct SdkAcceptor {
    conn: quinn::Connection,
    accepted: mpsc::Sender<AcceptedStream>,
    cancel: CancellationToken,
    handshake_timeout: Duration,
}

/// Default per-handshake TLS timeout (mirrors Go's
/// `ClientStream::handshakeTimeout`).
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

impl SdkAcceptor {
    /// Construct a new acceptor. Use [`SdkAcceptor::run`] to spawn the
    /// accept loop; the supplied `accepted` channel receives typed
    /// streams as they are emitted.
    #[must_use]
    pub const fn new(
        conn: quinn::Connection,
        accepted: mpsc::Sender<AcceptedStream>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            conn,
            accepted,
            cancel,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }

    /// Override the per-handshake TLS timeout. The default is 10 seconds.
    #[must_use]
    pub const fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Drive the accept loop. Each accepted bidi stream is dispatched on
    /// its first byte. `Channel::Control` and `Channel::HopRoute` are
    /// rejected with `WireDecode` errors logged at warn level — only
    /// `Channel::TcpProxy` produces an `AcceptedStream`.
    ///
    /// `tls_config` is applied to TLS-tagged streams once Phase 5/6a
    /// layers in `tokio-rustls`. In B6 the parameter is accepted but
    /// not yet consumed; passing `None` is also valid.
    ///
    /// Returns when the underlying QUIC connection closes cleanly or
    /// `cancel` fires. Surfaces a [`NetError::Quic`] when `accept_bi`
    /// reports an abnormal connection error (transport fault, peer
    /// stack-level abort with a non-`NO_ERROR` code, timeout, reset).
    /// Routine shutdown variants are mapped to `Ok(())`:
    /// - `ApplicationClosed` — peer initiated a clean application close.
    /// - `LocallyClosed` — we initiated the close.
    /// - `ConnectionClosed` carrying transport `NO_ERROR` — peer's stack
    ///   issued a graceful transport-level `CONNECTION_CLOSE`. Other
    ///   transport codes (e.g. `INTERNAL_ERROR`, `PROTOCOL_VIOLATION`)
    ///   are abnormal and propagate as errors.
    ///
    /// `self` is consumed because the loop owns the `quinn::Connection`
    /// clone and the `mpsc::Sender`; restart requires constructing a
    /// fresh acceptor against a fresh connection.
    ///
    /// # Errors
    /// Returns [`NetError::Quic`] when `accept_bi` reports an abnormal
    /// connection error. Clean close and cancellation are not errors.
    pub async fn run(self, _tls_config: Option<Arc<ServerConfig>>) -> Result<(), NetError> {
        let mut tasks: JoinSet<()> = JoinSet::new();
        let conn = self.conn.clone();
        let accepted = self.accepted.clone();
        let timeout = self.handshake_timeout;
        let cancel = self.cancel.clone();

        let outcome = loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    tracing::debug!("sdk acceptor cancelled");
                    break Ok(());
                }
                res = conn.accept_bi() => match res {
                    Ok((send, recv)) => {
                        let accepted = accepted.clone();
                        tasks.spawn(async move {
                            if let Err(err) = handle_stream(send, recv, accepted, timeout).await {
                                tracing::warn!(?err, "sdk accept handle_stream failed");
                            }
                        });
                    }
                    Err(err) => {
                        if is_clean_close(&err) {
                            tracing::debug!(?err, "sdk accept_bi clean close; exiting loop");
                            break Ok(());
                        }
                        tracing::warn!(?err, "sdk accept_bi abnormal error; exiting loop");
                        break Err(NetError::Quic(format!("accept_bi: {err}")));
                    }
                },
            }
        };
        tasks.shutdown().await;
        outcome
    }
}

/// Classify a `quinn::ConnectionError` as a routine clean shutdown vs.
/// an abnormal transport-level failure.
///
/// Routine:
/// - `ApplicationClosed` — peer-initiated application-layer close.
/// - `LocallyClosed` — we initiated the close.
/// - `ConnectionClosed` carrying the transport `NO_ERROR` code — peer's
///   stack issued a graceful transport-level close (per RFC 9000
///   §10.2.1, `NO_ERROR` is the documented graceful-shutdown code).
///
/// Everything else — non-`NO_ERROR` transport closes, timeouts, resets,
/// transport faults, locally failed handshakes — is a real error.
fn is_clean_close(err: &quinn::ConnectionError) -> bool {
    match err {
        quinn::ConnectionError::ApplicationClosed(_) | quinn::ConnectionError::LocallyClosed => {
            true
        }
        quinn::ConnectionError::ConnectionClosed(frame) => {
            frame.error_code == quinn::TransportErrorCode::NO_ERROR
        }
        _ => false,
    }
}

#[tracing::instrument(skip_all)]
async fn handle_stream(
    send: SendStream,
    recv: RecvStream,
    accepted: mpsc::Sender<AcceptedStream>,
    _handshake_timeout: Duration,
) -> Result<(), NetError> {
    let inbound = dispatch_inbound(send, recv).await?;
    match inbound {
        InboundStream::TcpProxy { kind, send, recv } => {
            let stream = match kind {
                TcpProxyKind::Raw => AcceptedStream::TcpRaw { send, recv },
                TcpProxyKind::Tls => AcceptedStream::TcpTls { send, recv, kind },
            };
            accepted
                .send(stream)
                .await
                .map_err(|_| NetError::Quic("accepted-stream receiver dropped".to_owned()))?;
            Ok(())
        }
        InboundStream::Control { .. } => Err(NetError::WireDecode(
            "sdk side does not accept Control streams from relay".to_owned(),
        )),
        InboundStream::HopRoute { .. } => Err(NetError::WireDecode(
            "sdk side does not accept HopRoute streams in v0.1".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 10-second default handshake timeout is documented on
    /// [`SdkAcceptor::with_handshake_timeout`] as part of that
    /// method's public contract. This test pins the const that
    /// backs that documented value.
    #[test]
    fn handshake_timeout_default_is_10s() {
        assert_eq!(DEFAULT_HANDSHAKE_TIMEOUT, Duration::from_secs(10));
    }
}
