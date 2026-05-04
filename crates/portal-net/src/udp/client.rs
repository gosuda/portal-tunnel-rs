//! SDK-side datagram client. Wraps a [`DatagramSession`] with `drop_full
//! = false` (back-pressure semantics) per Go's
//! `datagram_client.go::DatagramClient`.

use portal_wire::datagram::DatagramFrame;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::error::NetError;
use crate::udp::session::{DatagramSendHandle, DatagramSession};

/// SDK-side datagram client.
///
/// Owns a [`DatagramSession`] and the receive half of its inbound mpsc
/// channel. [`DatagramClient::bind`] connects the session to a
/// `quinn::Connection`; [`DatagramClient::send`] enqueues outbound
/// frames; [`DatagramClient::accept`] pulls inbound frames.
pub struct DatagramClient {
    session: DatagramSession,
    sender: DatagramSendHandle,
    incoming: mpsc::Receiver<DatagramFrame>,
    bound: bool,
}

impl DatagramClient {
    /// Construct a client with the requested inbound buffer size.
    ///
    /// SDK-side default: `drop_full = false` (block on full receive
    /// buffer to apply back-pressure, matching Go's
    /// `dropIncoming = false`).
    #[must_use]
    pub fn new(buffer_size: usize) -> Self {
        let (session, incoming) = DatagramSession::new(buffer_size, false);
        let sender = session.sender();
        Self {
            session,
            sender,
            incoming,
            bound: false,
        }
    }

    /// Bind the client to a `quinn::Connection`. Returns the per-bind
    /// cancellation token surfaced by [`DatagramSession::bind`].
    ///
    /// # Errors
    /// Currently infallible (forwarded from `DatagramSession::bind`).
    pub fn bind(&mut self, conn: &quinn::Connection) -> Result<CancellationToken, NetError> {
        let token = self.session.bind(conn)?;
        self.bound = true;
        Ok(token)
    }

    /// Receive the next inbound `DatagramFrame`. Returns `None` when the
    /// session has stopped.
    pub async fn accept(&mut self) -> Option<DatagramFrame> {
        self.incoming.recv().await
    }

    /// Send an outbound `DatagramFrame`.
    ///
    /// # Errors
    /// [`NetError::Quic`] when no connection is bound, or when the
    /// underlying `quinn::Connection` rejects the datagram.
    /// [`NetError::WireDecode`] on postcard encode failure.
    pub fn send(&self, frame: &DatagramFrame) -> Result<(), NetError> {
        self.sender.send(frame)
    }

    /// Whether [`DatagramClient::bind`] has been called and
    /// [`DatagramClient::close`] has not since.
    #[must_use]
    pub const fn connected(&self) -> bool {
        self.bound
    }

    /// Cancel the session's master token, drain the receive loop, and
    /// close the bound connection. Idempotent.
    pub async fn close(&mut self) {
        self.session.stop().await;
        self.bound = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn connected_is_false_before_bind() {
        let client = DatagramClient::new(8);
        assert!(!client.connected());
    }

    #[test]
    fn send_without_bind_returns_quic_no_connection() {
        let client = DatagramClient::new(8);
        let frame = DatagramFrame {
            flow_id: 1,
            payload: Bytes::from_static(b"x"),
        };
        let result = client.send(&frame);
        assert!(matches!(result, Err(NetError::Quic(_))));
    }
}
