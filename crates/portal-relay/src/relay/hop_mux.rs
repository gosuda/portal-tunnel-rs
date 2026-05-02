#![allow(dead_code)]

use anyhow::{Context, bail};
use futures_util::future::{BoxFuture, poll_fn};
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, warn};
use yamux::{Config, Connection as YamuxConnection, Mode, Stream as YamuxStream};

pub const HOP_MUX_PORT: u16 = 7778;
pub const MAX_HOP_TOKEN_BYTES: usize = 256;
const DEFAULT_TOKEN_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_STREAM_WINDOW_SIZE: u32 = 16 * 1024 * 1024;

pub(crate) trait HopMuxIo: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T> HopMuxIo for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

pub(crate) type BoxedHopMuxIo = Box<dyn HopMuxIo>;
pub(crate) type StreamHandle = Compat<YamuxStream>;
type YamuxIo = Compat<BoxedHopMuxIo>;

pub(crate) trait HopMuxConnector: Send + Sync + 'static {
    fn connect(&self, overlay_ipv4: &str) -> BoxFuture<'static, anyhow::Result<BoxedHopMuxIo>>;
}

struct TcpHopMuxConnector;

impl HopMuxConnector for TcpHopMuxConnector {
    fn connect(&self, overlay_ipv4: &str) -> BoxFuture<'static, anyhow::Result<BoxedHopMuxIo>> {
        let overlay_ipv4 = overlay_ipv4.trim().to_string();
        Box::pin(async move {
            if overlay_ipv4.is_empty() {
                bail!("next hop overlay ipv4 is required");
            }
            let ip: IpAddr = overlay_ipv4
                .parse()
                .context("next hop overlay ipv4 must be an IP address")?;
            let addr = SocketAddr::new(ip, HOP_MUX_PORT);
            let conn = TcpStream::connect(addr)
                .await
                .with_context(|| format!("connect hop mux peer at {addr}"))?;
            Ok(Box::new(conn) as BoxedHopMuxIo)
        })
    }
}

pub struct HopMux {
    incoming_tx: mpsc::Sender<HopStream>,
    incoming_rx: Mutex<mpsc::Receiver<HopStream>>,
    outbound: Mutex<HashMap<String, OutboundSession>>,
    connector: Arc<dyn HopMuxConnector>,
}

pub struct HopStream {
    pub stream: StreamHandle,
    pub token: String,
    pub remote_addr: String,
}

struct OutboundSession {
    commands: mpsc::Sender<OpenStreamCommand>,
    driver: JoinHandle<()>,
}

struct OpenStreamCommand {
    token: String,
    response: oneshot::Sender<anyhow::Result<StreamHandle>>,
}

impl Drop for OutboundSession {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl HopMux {
    pub fn new() -> Arc<Self> {
        Self::with_connector(Arc::new(TcpHopMuxConnector))
    }

    pub(crate) fn with_connector(connector: Arc<dyn HopMuxConnector>) -> Arc<Self> {
        let (incoming_tx, incoming_rx) = mpsc::channel(256);
        Arc::new(Self {
            incoming_tx,
            incoming_rx: Mutex::new(incoming_rx),
            outbound: Mutex::new(HashMap::new()),
            connector,
        })
    }

    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> anyhow::Result<()> {
        loop {
            let (conn, remote_addr) = listener.accept().await.context("accept hop mux")?;
            let hop_mux = Arc::clone(&self);
            tokio::spawn(async move {
                hop_mux
                    .serve_connection(conn, remote_addr.to_string())
                    .await;
            });
        }
    }

    pub(crate) async fn serve_connection<I>(self: Arc<Self>, conn: I, remote_addr: String)
    where
        I: HopMuxIo,
    {
        debug!(%remote_addr, "hop mux inbound session accepted");
        serve_inbound_session(conn, remote_addr, self.incoming_tx.clone()).await;
    }

    pub async fn accept(&self) -> Option<HopStream> {
        self.incoming_rx.lock().await.recv().await
    }

    pub async fn open_stream(
        &self,
        overlay_ipv4: &str,
        token: &str,
    ) -> anyhow::Result<StreamHandle> {
        let overlay_ipv4 = overlay_ipv4.trim();
        if overlay_ipv4.is_empty() {
            bail!("next hop overlay ipv4 is required");
        }
        let connector = Arc::clone(&self.connector);
        self.open_stream_with_connector(overlay_ipv4, token, move || {
            connector.connect(overlay_ipv4)
        })
        .await
    }

    pub async fn open_stream_with_retry(
        &self,
        overlay_ipv4: &str,
        token: &str,
        timeout: Duration,
        retry_wait: Duration,
    ) -> anyhow::Result<StreamHandle> {
        let mut last_err = None;
        let opened = time::timeout(timeout, async {
            loop {
                match self.open_stream(overlay_ipv4, token).await {
                    Ok(stream) => return Ok(stream),
                    Err(err) => {
                        last_err = Some(err);
                        time::sleep(retry_wait).await;
                    }
                }
            }
        })
        .await;

        match opened {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(err)) => Err(err),
            Err(_) => {
                let message = last_err.map_or_else(|| "timeout".to_string(), |err| err.to_string());
                warn!(
                    overlay_ipv4,
                    timeout_ms = timeout.as_millis(),
                    retry_wait_ms = retry_wait.as_millis(),
                    error = %message,
                    "open next-hop hop mux stream timed out"
                );
                anyhow::bail!("open next hop stream within {timeout:?}: {message}")
            }
        }
    }

    async fn open_stream_to_addr(
        &self,
        session_key: &str,
        addr: SocketAddr,
        token: &str,
    ) -> anyhow::Result<StreamHandle> {
        self.open_stream_with_connector(session_key, token, || async move {
            let conn = TcpStream::connect(addr)
                .await
                .with_context(|| format!("connect hop mux peer at {addr}"))?;
            Ok(Box::new(conn) as BoxedHopMuxIo)
        })
        .await
    }

    pub(crate) async fn open_stream_with_connector<F, Fut>(
        &self,
        session_key: &str,
        token: &str,
        connector: F,
    ) -> anyhow::Result<StreamHandle>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<BoxedHopMuxIo>>,
    {
        let commands = self.session_with_connector(session_key, connector).await?;
        let (response, reply) = oneshot::channel();
        let command = OpenStreamCommand {
            token: token.trim().to_string(),
            response,
        };
        if commands.send(command).await.is_err() {
            self.drop_session(session_key).await;
            bail!("hop mux outbound session closed");
        }
        match reply
            .await
            .context("hop mux outbound stream reply dropped")?
        {
            Ok(stream) => {
                debug!(session_key, "hop mux outbound stream opened");
                Ok(stream)
            }
            Err(err) => {
                self.drop_session(session_key).await;
                Err(err)
            }
        }
    }

    async fn session_with_connector<F, Fut>(
        &self,
        session_key: &str,
        connector: F,
    ) -> anyhow::Result<mpsc::Sender<OpenStreamCommand>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<BoxedHopMuxIo>>,
    {
        let session_key = session_key.trim();
        if session_key.is_empty() {
            bail!("next hop overlay ipv4 is required");
        }
        {
            let mut outbound = self.outbound.lock().await;
            if let Some(existing) = outbound.get(session_key)
                && !existing.driver.is_finished()
            {
                debug!(session_key, "reusing hop mux outbound session");
                return Ok(existing.commands.clone());
            }
            outbound.remove(session_key);
        }

        debug!(session_key, "opening hop mux outbound session");
        let conn = match connector().await {
            Ok(conn) => conn,
            Err(err) => {
                warn!(session_key, error = %err, "open hop mux outbound session failed");
                return Err(err);
            }
        };
        let session = YamuxConnection::new(conn.compat(), hop_yamux_config(), Mode::Client);
        let (commands, command_rx) = mpsc::channel(32);
        let driver_session_key = session_key.to_string();
        let driver = tokio::spawn(async move {
            drive_outbound_session(driver_session_key, session, command_rx).await;
        });
        let candidate = OutboundSession {
            commands: commands.clone(),
            driver,
        };

        let mut outbound = self.outbound.lock().await;
        if let Some(existing) = outbound.get(session_key)
            && !existing.driver.is_finished()
        {
            debug!(session_key, "using concurrent hop mux outbound session");
            return Ok(existing.commands.clone());
        }
        outbound.insert(session_key.to_string(), candidate);
        debug!(session_key, "hop mux outbound session ready");
        Ok(commands)
    }

    async fn drop_session(&self, session_key: &str) {
        self.outbound.lock().await.remove(session_key);
    }
}

pub async fn write_hop_token_frame<W>(writer: &mut W, token: &str) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let token = token.trim();
    if token.is_empty() {
        bail!("next hop token is required");
    }
    let payload = token.as_bytes();
    if payload.len() > MAX_HOP_TOKEN_BYTES {
        bail!("next hop token is too large");
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    writer
        .write_all(&frame)
        .await
        .context("write hop token frame")?;
    writer.flush().await.context("flush hop token frame")?;
    Ok(())
}

pub async fn read_hop_token_frame<R>(reader: &mut R) -> anyhow::Result<String>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    reader
        .read_exact(&mut header)
        .await
        .context("read hop token frame length")?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_HOP_TOKEN_BYTES {
        bail!("invalid hop token frame length");
    }
    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .await
        .context("read hop token frame payload")?;
    let token = String::from_utf8(payload)
        .context("hop token frame payload is not utf8")?
        .trim()
        .to_string();
    if token.is_empty() {
        bail!("next hop token is required");
    }
    Ok(token)
}

async fn serve_inbound_session<I>(conn: I, remote_addr: String, incoming: mpsc::Sender<HopStream>)
where
    I: HopMuxIo,
{
    let conn = Box::new(conn) as BoxedHopMuxIo;
    let mut session = YamuxConnection::new(conn.compat(), hop_yamux_config(), Mode::Server);
    debug!(%remote_addr, "hop mux inbound yamux session started");
    while let Some(result) = poll_fn(|cx| session.poll_next_inbound(cx)).await {
        match result {
            Ok(stream) => {
                debug!(%remote_addr, "hop mux inbound stream opened");
                let incoming = incoming.clone();
                let remote_addr = remote_addr.clone();
                tokio::spawn(async move {
                    handle_inbound_stream(stream.compat(), remote_addr, incoming).await;
                });
            }
            Err(err) => {
                debug!(%remote_addr, error = %err, "hop mux session closed");
                return;
            }
        }
    }
}

async fn handle_inbound_stream(
    mut stream: StreamHandle,
    remote_addr: String,
    incoming: mpsc::Sender<HopStream>,
) {
    let token = match time::timeout(DEFAULT_TOKEN_TIMEOUT, read_hop_token_frame(&mut stream)).await
    {
        Ok(Ok(token)) => token,
        Ok(Err(err)) => {
            debug!(%remote_addr, error = %err, "hop mux token rejected");
            let _ = stream.shutdown().await;
            return;
        }
        Err(_) => {
            debug!(%remote_addr, "hop mux token read timed out");
            let _ = stream.shutdown().await;
            return;
        }
    };

    if incoming
        .send(HopStream {
            stream,
            token,
            remote_addr,
        })
        .await
        .is_err()
    {
        warn!("hop mux stream dropped because accept queue is closed");
    } else {
        debug!("hop mux inbound stream queued");
    }
}

async fn drive_outbound_session(
    session_key: String,
    mut session: YamuxConnection<YamuxIo>,
    mut commands: mpsc::Receiver<OpenStreamCommand>,
) {
    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    let _ = poll_fn(|cx| session.poll_close(cx)).await;
                    debug!(session_key, "outbound hop mux session command channel closed");
                    return;
                };
                handle_outbound_open(&session_key, &mut session, command).await;
            }
            inbound = poll_fn(|cx| session.poll_next_inbound(cx)) => {
                match inbound {
                    Some(Ok(stream)) => {
                        let mut stream = stream.compat();
                        let _ = stream.shutdown().await;
                    }
                    Some(Err(err)) => {
                        debug!(session_key, error = %err, "outbound hop mux session closed");
                        return;
                    }
                    None => {
                        debug!(session_key, "outbound hop mux session closed");
                        return;
                    }
                }
            }
        }
    }
}

async fn handle_outbound_open(
    session_key: &str,
    session: &mut YamuxConnection<YamuxIo>,
    command: OpenStreamCommand,
) {
    let result = async {
        let mut stream = poll_fn(|cx| session.poll_new_outbound(cx))
            .await
            .context("open hop mux stream")?
            .compat();
        write_hop_token_frame(&mut stream, &command.token)
            .await
            .context("write hop mux token frame")?;
        Ok(stream)
    }
    .await;

    if result.is_err() {
        debug!(session_key, "open hop mux outbound stream failed");
    }
    let _ = command.response.send(result);
}

fn hop_yamux_config() -> Config {
    let mut config = Config::default();
    config.set_split_send_size(1200);
    config.set_max_connection_receive_window(None);
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_mux_port_matches_go_default() {
        assert_eq!(HOP_MUX_PORT, 7778);
    }

    #[tokio::test]
    async fn hop_token_frame_matches_go_layout() {
        let mut frame = Vec::new();
        write_hop_token_frame(&mut frame, " hpt_token ")
            .await
            .unwrap();
        assert_eq!(&frame[..4], &[0, 0, 0, 9]);
        assert_eq!(&frame[4..], b"hpt_token");

        let mut reader = frame.as_slice();
        let token = read_hop_token_frame(&mut reader).await.unwrap();
        assert_eq!(token, "hpt_token");
    }

    #[tokio::test]
    async fn hop_token_frame_rejects_invalid_lengths() {
        let mut empty = [0u8; 4].as_slice();
        assert!(read_hop_token_frame(&mut empty).await.is_err());

        let too_large = ((MAX_HOP_TOKEN_BYTES + 1) as u32).to_be_bytes();
        let mut too_large = too_large.as_slice();
        assert!(read_hop_token_frame(&mut too_large).await.is_err());
    }

    #[tokio::test]
    async fn hop_mux_delivers_token_and_bidirectional_stream() {
        let server = HopMux::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(Arc::clone(&server).serve(listener));

        let client = HopMux::new();
        let mut client_stream = client
            .open_stream_to_addr("peer", peer_addr, " hpt_token ")
            .await
            .unwrap();
        let mut hop_stream = time::timeout(Duration::from_secs(2), server.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(hop_stream.token, "hpt_token");
        assert!(!hop_stream.remote_addr.is_empty());

        client_stream.write_all(b"ping").await.unwrap();
        let mut inbound = [0u8; 4];
        hop_stream.stream.read_exact(&mut inbound).await.unwrap();
        assert_eq!(&inbound, b"ping");

        hop_stream.stream.write_all(b"pong").await.unwrap();
        let mut outbound = [0u8; 4];
        client_stream.read_exact(&mut outbound).await.unwrap();
        assert_eq!(&outbound, b"pong");

        server_task.abort();
    }

    #[tokio::test]
    async fn hop_mux_accepts_boxed_non_tcp_transport() {
        let server = HopMux::new();
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server_task =
            tokio::spawn(Arc::clone(&server).serve_connection(server_io, "overlay-peer".into()));

        let client = HopMux::new();
        let mut client_stream = client
            .open_stream_with_connector("overlay-peer", "hpt_overlay", || async move {
                Ok(Box::new(client_io) as BoxedHopMuxIo)
            })
            .await
            .unwrap();

        let mut hop_stream = time::timeout(Duration::from_secs(2), server.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(hop_stream.token, "hpt_overlay");
        assert_eq!(hop_stream.remote_addr, "overlay-peer");

        client_stream.write_all(b"ping").await.unwrap();
        let mut inbound = [0u8; 4];
        hop_stream.stream.read_exact(&mut inbound).await.unwrap();
        assert_eq!(&inbound, b"ping");

        hop_stream.stream.write_all(b"pong").await.unwrap();
        let mut outbound = [0u8; 4];
        client_stream.read_exact(&mut outbound).await.unwrap();
        assert_eq!(&outbound, b"pong");

        server_task.abort();
    }
}
