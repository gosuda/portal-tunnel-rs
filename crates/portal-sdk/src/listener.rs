//! Lease listener — accepts server-initiated streams from the relay.
//!
//! Wraps [`portal_net::SdkAcceptor`] to produce a [`tokio::sync::mpsc`]
//! channel of [`portal_net::AcceptedStream`]s.

use portal_net::{AcceptedStream, SdkAcceptor};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::error::SdkResult;

/// Handle to the listener accept loop.
pub struct Listener {
    cancel: CancellationToken,
    tasks: JoinSet<()>,
}

impl Listener {
    /// Start the accept loop on `conn`.
    ///
    /// Returns a receiver that yields [`AcceptedStream`]s as the relay
    /// opens new bidi streams, and a [`Listener`] handle that can be
    /// used to stop the loop cleanly.
    ///
    /// `cancel` is cloned internally; the returned [`Listener`] must be
    /// kept alive and [`stop`](Self::stop) must be called for clean
    /// shutdown.
    ///
    /// # Errors
    /// Returns [`SdkError::Config`] if the acceptor cannot be constructed.
    pub fn start(
        conn: portal_net::quinn::Connection,
        cancel: CancellationToken,
        buffer: usize,
    ) -> SdkResult<(Self, mpsc::Receiver<AcceptedStream>)> {
        let (tx, rx) = mpsc::channel(buffer);
        let acceptor = SdkAcceptor::new(conn, tx, cancel.clone());
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            if let Err(e) = acceptor.run(None).await {
                tracing::warn!(error = %e, "listener accept loop exited with error");
            }
        });
        Ok((Self { cancel, tasks }, rx))
    }

    /// Signal the accept loop to stop and wait for task termination.
    pub async fn stop(mut self) {
        self.cancel.cancel();
        let () = self.tasks.shutdown().await;
    }
}
