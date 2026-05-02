use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

const DEFAULT_MAX_PACKET_SIZE: usize = 1350;
const DEFAULT_FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_FLOW_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

pub struct UdpDatagramRuntime {
    port: u16,
    socket: Arc<UdpSocket>,
    state: Arc<Mutex<UdpDatagramState>>,
    tasks: Vec<JoinHandle<()>>,
}

#[derive(Default)]
struct UdpDatagramState {
    conn: Option<quinn::Connection>,
    flow_table: HashMap<u32, FlowState>,
    addr_index: HashMap<SocketAddr, u32>,
    next_flow: u32,
}

struct FlowState {
    client_addr: SocketAddr,
    last_seen: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramFrame {
    pub flow_id: u32,
    pub payload: Vec<u8>,
}

impl UdpDatagramRuntime {
    pub fn start(port: u16) -> anyhow::Result<Self> {
        let std_socket =
            std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))?;
        std_socket.set_nonblocking(true)?;
        let socket = Arc::new(UdpSocket::from_std(std_socket)?);
        let state = Arc::new(Mutex::new(UdpDatagramState {
            next_flow: 1,
            ..UdpDatagramState::default()
        }));

        let tasks = vec![
            tokio::spawn(read_loop(Arc::clone(&socket), Arc::clone(&state))),
            tokio::spawn(cleanup_loop(Arc::clone(&state))),
        ];

        Ok(Self {
            port,
            socket,
            state,
            tasks,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn bind_backhaul(&self, conn: quinn::Connection) {
        let old = {
            let mut state = self.state.lock().expect("udp datagram state lock poisoned");
            state.conn.replace(conn.clone())
        };
        if let Some(old) = old {
            old.close(0u32.into(), b"replaced");
        }

        tokio::spawn(receive_loop(
            conn,
            Arc::clone(&self.socket),
            Arc::clone(&self.state),
        ));
    }
}

impl Drop for UdpDatagramRuntime {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        if let Some(conn) = self
            .state
            .lock()
            .expect("udp datagram state lock poisoned")
            .conn
            .take()
        {
            conn.close(0u32.into(), b"lease stopped");
        }
    }
}

async fn read_loop(socket: Arc<UdpSocket>, state: Arc<Mutex<UdpDatagramState>>) {
    let mut buf = vec![0u8; DEFAULT_MAX_PACKET_SIZE];
    loop {
        let (n, client_addr) = match socket.recv_from(&mut buf).await {
            Ok(packet) => packet,
            Err(err) => {
                warn!(error = %err, "udp relay read loop exiting");
                return;
            }
        };

        let payload = buf[..n].to_vec();
        let (flow_id, conn) = {
            let mut state = state.lock().expect("udp datagram state lock poisoned");
            let flow_id = state.touch_flow(client_addr);
            (flow_id, state.conn.clone())
        };

        let Some(conn) = conn else {
            debug!(%client_addr, flow_id, "dropping udp packet without quic backhaul");
            continue;
        };

        let encoded = encode_datagram(flow_id, &payload);
        if let Err(err) = conn.send_datagram(Bytes::from(encoded)) {
            warn!(%client_addr, flow_id, error = %err, "send udp datagram to quic backhaul failed");
        }
    }
}

async fn receive_loop(
    conn: quinn::Connection,
    socket: Arc<UdpSocket>,
    state: Arc<Mutex<UdpDatagramState>>,
) {
    let conn_id = conn.stable_id();
    loop {
        let data = match conn.read_datagram().await {
            Ok(data) => data,
            Err(err) => {
                clear_connection_if_current(&state, conn_id);
                debug!(error = %err, "quic backhaul datagram receive loop ended");
                return;
            }
        };

        let Some(frame) = decode_datagram(&data) else {
            continue;
        };
        let client_addr = {
            let mut state = state.lock().expect("udp datagram state lock poisoned");
            state.touch_known_flow(frame.flow_id)
        };

        let Some(client_addr) = client_addr else {
            continue;
        };

        if let Err(err) = socket.send_to(&frame.payload, client_addr).await {
            warn!(%client_addr, flow_id = frame.flow_id, error = %err, "udp flow writeback failed");
            forget_flow(&state, frame.flow_id);
        }
    }
}

async fn cleanup_loop(state: Arc<Mutex<UdpDatagramState>>) {
    let mut ticker = tokio::time::interval(DEFAULT_FLOW_CLEANUP_INTERVAL);
    loop {
        ticker.tick().await;
        let now = Instant::now();
        let mut state = state.lock().expect("udp datagram state lock poisoned");
        state.expire_idle_flows(now);
    }
}

fn clear_connection_if_current(state: &Mutex<UdpDatagramState>, conn_id: usize) {
    let mut state = state.lock().expect("udp datagram state lock poisoned");
    if state
        .conn
        .as_ref()
        .map(quinn::Connection::stable_id)
        .is_some_and(|active_id| active_id == conn_id)
    {
        state.conn = None;
    }
}

fn forget_flow(state: &Mutex<UdpDatagramState>, flow_id: u32) {
    let mut state = state.lock().expect("udp datagram state lock poisoned");
    if let Some(flow) = state.flow_table.remove(&flow_id) {
        state.addr_index.remove(&flow.client_addr);
    }
}

impl UdpDatagramState {
    fn touch_flow(&mut self, client_addr: SocketAddr) -> u32 {
        let now = Instant::now();
        if let Some(flow_id) = self.addr_index.get(&client_addr).copied() {
            if let Some(flow) = self.flow_table.get_mut(&flow_id) {
                flow.last_seen = now;
                return flow_id;
            }
            self.addr_index.remove(&client_addr);
        }

        let flow_id = self.next_flow;
        self.next_flow = self.next_flow.checked_add(1).unwrap_or(1);
        self.flow_table.insert(
            flow_id,
            FlowState {
                client_addr,
                last_seen: now,
            },
        );
        self.addr_index.insert(client_addr, flow_id);
        flow_id
    }

    fn touch_known_flow(&mut self, flow_id: u32) -> Option<SocketAddr> {
        let flow = self.flow_table.get_mut(&flow_id)?;
        flow.last_seen = Instant::now();
        Some(flow.client_addr)
    }

    fn expire_idle_flows(&mut self, now: Instant) {
        let expired: Vec<u32> = self
            .flow_table
            .iter()
            .filter_map(|(flow_id, flow)| {
                (now.duration_since(flow.last_seen) > DEFAULT_FLOW_IDLE_TIMEOUT).then_some(*flow_id)
            })
            .collect();
        for flow_id in expired {
            if let Some(flow) = self.flow_table.remove(&flow_id) {
                self.addr_index.remove(&flow.client_addr);
            }
        }
    }
}

pub fn encode_datagram(flow_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut value = u64::from(flow_id);
    let mut out = Vec::with_capacity(5 + payload.len());
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out.extend_from_slice(payload);
    out
}

pub fn decode_datagram(data: &[u8]) -> Option<DatagramFrame> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (idx, byte) in data.iter().copied().enumerate() {
        value |= u64::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            let flow_id = u32::try_from(value).ok()?;
            return Some(DatagramFrame {
                flow_id,
                payload: data[idx + 1..].to_vec(),
            });
        }
        shift += 7;
        if shift >= 35 {
            return None;
        }
    }
    None
}

#[derive(Debug, serde::Deserialize)]
pub struct QuicBackhaulControlMessage {
    pub access_token: String,
}

#[derive(Debug, serde::Serialize)]
pub struct QuicBackhaulControlResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

pub async fn read_control_message(
    recv: &mut quinn::RecvStream,
) -> anyhow::Result<QuicBackhaulControlMessage> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut body = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            if !body.is_empty() {
                match serde_json::from_slice::<QuicBackhaulControlMessage>(&body) {
                    Ok(mut msg) => {
                        msg.access_token = msg.access_token.trim().to_string();
                        if msg.access_token.is_empty() {
                            anyhow::bail!("quic backhaul access token is required");
                        }
                        return Ok(msg);
                    }
                    Err(err) if err.is_eof() => {}
                    Err(err) => return Err(err).context("decode quic backhaul control message"),
                }
            }

            if body.len() > 4096 {
                anyhow::bail!("quic backhaul control message too large");
            }
            let n = recv
                .read(&mut buf)
                .await
                .context("read quic backhaul control stream")?
                .context("quic backhaul control stream closed")?;
            body.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .context("quic backhaul control read timed out")?
}

pub async fn write_control_response(
    send: &mut quinn::SendStream,
    response: &QuicBackhaulControlResponse,
) -> anyhow::Result<()> {
    let body = serde_json::to_vec(response).context("encode quic backhaul control response")?;
    send.write_all(&body)
        .await
        .context("write quic backhaul control response")?;
    send.write_all(b"\n")
        .await
        .context("write quic backhaul control newline")?;
    send.finish()
        .context("finish quic backhaul control response")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_codec_matches_go_uvarint_layout() {
        assert_eq!(encode_datagram(1, b"abc"), b"\x01abc");
        assert_eq!(encode_datagram(300, b"x"), b"\xac\x02x");

        assert_eq!(
            decode_datagram(b"\xac\x02x"),
            Some(DatagramFrame {
                flow_id: 300,
                payload: b"x".to_vec(),
            })
        );
        assert_eq!(decode_datagram(b""), None);
        assert_eq!(decode_datagram(b"\x80"), None);
    }
}
