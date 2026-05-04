//! `DatagramSession`: lifecycle wrapper around a `quinn::Connection`'s
//! datagram surface. Owns the receive loop that decodes inbound
//! `DatagramFrame`s and forwards them to a tokio mpsc channel.

use std::sync::Arc;

use bytes::Bytes;
use portal_wire::datagram::DatagramFrame;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::error::NetError;

/// Send half of the bidirectional datagram channel. Cloning is cheap
/// (single Arc).
#[derive(Clone)]
pub struct DatagramSendHandle {
    inner: Arc<Mutex<Option<quinn::Connection>>>,
}

impl DatagramSendHandle {
    /// Send a `DatagramFrame` over the bound connection.
    ///
    /// # Errors
    /// [`NetError::Quic`] when no connection is bound or the connection
    /// rejects the datagram. [`NetError::WireDecode`] when postcard
    /// encoding fails.
    pub async fn send(&self, frame: &DatagramFrame) -> Result<(), NetError> {
        let bytes = postcard::to_allocvec(frame)
            .map_err(|e| NetError::WireDecode(format!("datagram encode: {e}")))?;
        // Clone the `quinn::Connection` (cheap — it's `Arc`-backed) and
        // release the mutex BEFORE the synchronous `send_datagram` call
        // so concurrent senders are not serialised behind one another.
        let conn = {
            let guard = self.inner.lock().await;
            guard
                .as_ref()
                .ok_or_else(|| {
                    NetError::Quic("no connection bound for datagram send".to_owned())
                })?
                .clone()
        };
        conn.send_datagram(Bytes::from(bytes))
            .map_err(|e| NetError::Quic(format!("send_datagram: {e}")))
    }
}

/// Session lifecycle wrapper. Owns the receive loop in a `JoinSet`,
/// surfaces inbound frames via mpsc, and exposes a clone-able
/// [`DatagramSendHandle`] for outbound traffic.
pub struct DatagramSession {
    incoming: mpsc::Sender<DatagramFrame>,
    conn: Arc<Mutex<Option<quinn::Connection>>>,
    /// `true` (relay default): drop inbound frames when the receiver is
    /// behind. `false` (SDK default): block the receive loop until the
    /// receiver drains, applying back-pressure to the QUIC peer.
    drop_full: bool,
    tasks: JoinSet<()>,
    cancel: CancellationToken,
}

impl DatagramSession {
    /// Construct a fresh session. Returns the session + the receive half
    /// of the inbound mpsc channel.
    #[must_use]
    pub fn new(buffer_size: usize, drop_full: bool) -> (Self, mpsc::Receiver<DatagramFrame>) {
        let (tx, rx) = mpsc::channel(buffer_size);
        let session = Self {
            incoming: tx,
            conn: Arc::new(Mutex::new(None)),
            drop_full,
            tasks: JoinSet::new(),
            cancel: CancellationToken::new(),
        };
        (session, rx)
    }

    /// Get a clone-able send handle for outbound datagrams.
    #[must_use]
    pub fn sender(&self) -> DatagramSendHandle {
        DatagramSendHandle {
            inner: Arc::clone(&self.conn),
        }
    }

    /// Bind a `quinn::Connection`. Replaces any prior connection (closes
    /// the old one with `CONNECTION_CLOSE replaced`). Spawns the receive
    /// loop; the returned [`CancellationToken`] is the per-bind child
    /// token, which fires when the loop exits (peer disconnect, stop,
    /// or master cancel).
    ///
    /// # Errors
    /// Currently infallible; reserved for future config-validation paths.
    pub async fn bind(&mut self, conn: quinn::Connection) -> Result<CancellationToken, NetError> {
        {
            let mut guard = self.conn.lock().await;
            if let Some(old) = guard.replace(conn.clone()) {
                old.close(0u32.into(), b"replaced");
            }
        }

        let bind_cancel = CancellationToken::new();
        let bind_cancel_inner = bind_cancel.clone();
        let parent_cancel = self.cancel.clone();
        let conn_clone = conn.clone();
        let tx = self.incoming.clone();
        let drop_full = self.drop_full;

        self.tasks.spawn(async move {
            recv_loop(conn_clone, tx, drop_full, parent_cancel, bind_cancel_inner.clone()).await;
            bind_cancel_inner.cancel();
        });
        Ok(bind_cancel)
    }

    /// Cancel the master token, join the receive loop, and close the
    /// bound connection. Idempotent.
    pub async fn stop(&mut self) {
        self.cancel.cancel();
        while let Some(res) = self.tasks.join_next().await {
            if let Err(err) = res {
                tracing::warn!(?err, "datagram session recv loop join error");
            }
        }
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.take() {
            conn.close(0u32.into(), b"session stopped");
        }
    }
}

async fn recv_loop(
    conn: quinn::Connection,
    tx: mpsc::Sender<DatagramFrame>,
    drop_full: bool,
    parent_cancel: CancellationToken,
    bind_cancel: CancellationToken,
) {
    use tokio::sync::mpsc::error::TrySendError;

    loop {
        tokio::select! {
            biased;
            () = parent_cancel.cancelled() => break,
            () = bind_cancel.cancelled() => break,
            res = conn.read_datagram() => match res {
                Ok(bytes) => match postcard::from_bytes::<DatagramFrame>(&bytes) {
                    Ok(frame) => {
                        if drop_full {
                            match tx.try_send(frame) {
                                Ok(()) => {}
                                Err(TrySendError::Full(_)) => {
                                    tracing::warn!("inbound datagram dropped — buffer full");
                                }
                                Err(TrySendError::Closed(_)) => {
                                    tracing::debug!("datagram receiver gone");
                                    break;
                                }
                            }
                        } else {
                            // Cancellation-aware blocking send: parent
                            // / bind cancel cannot be starved by a slow
                            // receiver.
                            tokio::select! {
                                biased;
                                () = parent_cancel.cancelled() => break,
                                () = bind_cancel.cancelled() => break,
                                send_res = tx.send(frame) => {
                                    if send_res.is_err() {
                                        tracing::debug!("datagram receiver gone");
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(?e, "malformed datagram dropped");
                    }
                },
                Err(e) => {
                    tracing::debug!(?e, "datagram read error; exiting recv loop");
                    break;
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sending without a prior `bind` returns the documented
    /// `NetError::Quic("no connection bound...")` rather than panicking
    /// or hanging on a dropped connection.
    #[tokio::test]
    async fn send_without_bind_returns_quic_no_connection() {
        let (session, _rx) = DatagramSession::new(4, true);
        let handle = session.sender();
        let frame = DatagramFrame {
            flow_id: 1,
            payload: Bytes::from_static(b"hello"),
        };
        match handle.send(&frame).await {
            Err(NetError::Quic(msg)) => assert!(
                msg.contains("no connection bound"),
                "unexpected message: {msg}",
            ),
            Err(other) => panic!("expected NetError::Quic, got {other:?}"),
            Ok(()) => panic!("send must fail when no connection is bound"),
        }
    }
}
