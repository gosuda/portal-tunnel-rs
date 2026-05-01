use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use tokio::time;
use tokio_rustls::server::TlsStream;

const DEFAULT_IDLE_KEEPALIVE: Duration = Duration::from_secs(15);
const DEFAULT_READY_QUEUE_LIMIT: usize = 8;

pub const MARKER_KEEPALIVE: u8 = 0x00;
#[allow(dead_code)]
pub const MARKER_RAW_START: u8 = 0x01;
#[allow(dead_code)]
pub const MARKER_TLS_START: u8 = 0x02;

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("stream ready queue full")]
    QueueFull,
}

pub type ReverseIo = TlsStream<TcpStream>;

pub struct RelayStream {
    ready: Mutex<VecDeque<Arc<ReverseSession>>>,
    notify: Notify,
    ready_limit: usize,
    idle_interval: Duration,
}

impl RelayStream {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            ready: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
            ready_limit: DEFAULT_READY_QUEUE_LIMIT,
            idle_interval: DEFAULT_IDLE_KEEPALIVE,
        })
    }

    pub async fn offer(self: &Arc<Self>, io: ReverseIo) -> Result<(), StreamError> {
        let session = Arc::new(ReverseSession::new(io));
        {
            let mut ready = self.ready.lock().await;
            if ready.len() >= self.ready_limit {
                return Err(StreamError::QueueFull);
            }
            ready.push_back(Arc::clone(&session));
        }
        self.notify.notify_one();

        let idle_interval = self.idle_interval;
        tokio::spawn(async move {
            session.keepalive_loop(idle_interval).await;
        });
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn claim(&self, marker: u8) -> Result<ReverseIo, StreamError> {
        loop {
            if let Some(session) = self.ready.lock().await.pop_front() {
                if let Some(io) = session.activate(marker).await {
                    return Ok(io);
                }
                continue;
            }
            self.notify.notified().await;
        }
    }

    #[allow(dead_code)]
    pub async fn ready_count(&self) -> usize {
        self.ready.lock().await.len()
    }
}

pub struct ReverseSession {
    io: Mutex<Option<ReverseIo>>,
}

impl ReverseSession {
    fn new(io: ReverseIo) -> Self {
        Self {
            io: Mutex::new(Some(io)),
        }
    }

    async fn keepalive_loop(&self, idle_interval: Duration) {
        let mut ticker = time::interval(idle_interval);
        loop {
            ticker.tick().await;
            let mut guard = self.io.lock().await;
            let Some(io) = guard.as_mut() else {
                return;
            };
            if tokio::io::AsyncWriteExt::write_all(io, &[MARKER_KEEPALIVE])
                .await
                .is_err()
            {
                *guard = None;
                return;
            }
        }
    }

    #[allow(dead_code)]
    async fn activate(&self, marker: u8) -> Option<ReverseIo> {
        let mut io = self.io.lock().await.take()?;
        if tokio::io::AsyncWriteExt::write_all(&mut io, &[marker])
            .await
            .is_err()
        {
            return None;
        }
        Some(io)
    }
}
