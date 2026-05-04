//! Relay-side UDP listener: per-source flow-id assignment + bidirectional
//! routing over a backhaul-bound `DatagramSession`.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use compact_str::CompactString;
use papaya::HashMap;
use portal_wire::datagram::DatagramFrame;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::dual_stack::{bind_dual_stack_udp, canonicalize_socket};
use crate::error::NetError;
use crate::udp::session::DatagramSendHandle;

/// Per-flow state: canonical peer address + last-seen instant.
#[derive(Clone, Copy)]
struct FlowState {
    peer: SocketAddr,
    last_seen: Instant,
}

/// Idle-flow expiry threshold (mirrors Go's `defaultIdleFlowTimeout`).
const FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Cleanup-tick interval (mirrors Go's `defaultCleanupInterval`).
const FLOW_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

/// Relay-side UDP listener.
pub struct UdpRelay {
    identity_key: CompactString,
    port: u16,
    sender: DatagramSendHandle,
    flows: Arc<HashMap<u32, FlowState>>,
    addr_index: Arc<HashMap<SocketAddr, u32>>,
    next_flow: Arc<AtomicU32>,
    cancel: CancellationToken,
    tasks: JoinSet<()>,
}

impl UdpRelay {
    /// Construct a new UDP relay. `sender` comes from a [`crate::udp::DatagramSession`]
    /// already bound to the backhaul.
    #[must_use]
    pub fn new(identity_key: CompactString, port: u16, sender: DatagramSendHandle) -> Self {
        Self {
            identity_key,
            port,
            sender,
            flows: Arc::new(HashMap::new()),
            addr_index: Arc::new(HashMap::new()),
            next_flow: Arc::new(AtomicU32::new(1)),
            cancel: CancellationToken::new(),
            tasks: JoinSet::new(),
        }
    }

    /// Bind a dual-stack UDP socket and spawn the read / dispatch /
    /// cleanup tasks. The accept loop runs until either the
    /// caller-supplied `cancel` fires OR the internal token (cancelled
    /// by [`Self::shutdown`]) fires.
    ///
    /// `inbound_rx` is the receive half of a [`crate::udp::DatagramSession`]'s
    /// mpsc channel; the dispatch loop reads decoded frames and routes
    /// them back to the original UDP source.
    ///
    /// # Errors
    /// Returns [`NetError::BindFailed`] / [`NetError::Io`] on bind failure.
    #[tracing::instrument(skip_all, fields(identity_key = %self.identity_key, port = self.port))]
    pub async fn start(
        &mut self,
        inbound_rx: mpsc::Receiver<DatagramFrame>,
        cancel: CancellationToken,
    ) -> Result<(), NetError> {
        let std_socket = bind_dual_stack_udp(IpAddr::V6(Ipv6Addr::UNSPECIFIED), self.port, false)?;
        std_socket.set_nonblocking(true).map_err(NetError::Io)?;
        let socket = Arc::new(UdpSocket::from_std(std_socket).map_err(NetError::Io)?);

        let merged = MergedCancel::new(cancel, self.cancel.clone());

        let read_socket = Arc::clone(&socket);
        let read_flows = Arc::clone(&self.flows);
        let read_index = Arc::clone(&self.addr_index);
        let read_next = Arc::clone(&self.next_flow);
        let read_sender = self.sender.clone();
        let read_cancel = merged.clone();
        self.tasks.spawn(async move {
            read_loop(
                read_socket,
                read_flows,
                read_index,
                read_next,
                read_sender,
                read_cancel,
            )
            .await;
        });

        let dispatch_socket = Arc::clone(&socket);
        let dispatch_flows = Arc::clone(&self.flows);
        let dispatch_cancel = merged.clone();
        self.tasks.spawn(async move {
            dispatch_loop(dispatch_socket, dispatch_flows, inbound_rx, dispatch_cancel).await;
        });

        let cleanup_flows = Arc::clone(&self.flows);
        let cleanup_index = Arc::clone(&self.addr_index);
        let cleanup_cancel = merged;
        self.tasks.spawn(async move {
            cleanup_loop(cleanup_flows, cleanup_index, cleanup_cancel).await;
        });

        Ok(())
    }

    /// Cancel the internal token and join all spawned tasks. Idempotent.
    pub async fn shutdown(&mut self) {
        self.cancel.cancel();
        while let Some(res) = self.tasks.join_next().await {
            if let Err(err) = res {
                tracing::warn!(?err, "udp relay task join error");
            }
        }
    }

    /// Snapshot the current flow count (metrics / tests).
    #[must_use]
    pub fn flow_count(&self) -> usize {
        self.flows.pin().len()
    }
}

/// Wraps two `CancellationToken`s and exposes a single `cancelled()`
/// future that fires when EITHER is cancelled. Cheap to clone.
#[derive(Clone)]
struct MergedCancel {
    a: CancellationToken,
    b: CancellationToken,
}

impl MergedCancel {
    const fn new(a: CancellationToken, b: CancellationToken) -> Self {
        Self { a, b }
    }

    async fn cancelled(&self) {
        tokio::select! {
            biased;
            () = self.a.cancelled() => {}
            () = self.b.cancelled() => {}
        }
    }
}

/// Look up or assign a `flow_id` for the canonicalized peer address.
///
/// Publication order is `FlowState` BEFORE `addr_index`: a concurrent
/// reader that observes a new index entry is guaranteed to find a
/// matching live flow (no observer ever sees a "stale" id that is
/// merely about-to-be-installed).
///
/// The function loops until it can return a `(peer, id)` pairing where
/// the index points at a live flow. Each iteration either returns or
/// makes the table state strictly more consistent — there is no bounded
/// retry budget because the contention space is bounded by the number
/// of concurrent peers, not by an empirical retry count.
///
/// 1. Probe `addr_index` for an existing id.
/// 2. If present and the flow is live: refresh `last_seen` and return.
/// 3. If present but the flow is missing: cleanup raced ahead of us.
///    Purge the stale entry only if it still names the observed id,
///    then loop and re-allocate.
/// 4. If absent: allocate a candidate id, install the `FlowState` first
///    (so any reader observing our index sees a backing flow), then
///    `try_insert` the index. On index conflict (a concurrent winner
///    already published their own id), retire our flow and loop so we
///    reuse the winner's id rather than leaking a phantom flow.
fn touch_flow(
    flows: &HashMap<u32, FlowState>,
    addr_index: &HashMap<SocketAddr, u32>,
    next_flow: &AtomicU32,
    peer: SocketAddr,
) -> u32 {
    let now = Instant::now();

    loop {
        let idx = addr_index.pin();
        if let Some(&id) = idx.get(&peer) {
            let pin = flows.pin();
            if let Some(state) = pin.get(&id) {
                pin.insert(
                    id,
                    FlowState {
                        peer: state.peer,
                        last_seen: now,
                    },
                );
                return id;
            }
            // Stale index entry — flow was purged but addr_index lingered.
            // Drop only if it still names `id` (don't trample a concurrent
            // re-allocation that just published a different id), then loop.
            let _ = idx.remove_if(&peer, |_, &v| v == id);
            continue;
        }

        let candidate = next_flow.fetch_add(1, Ordering::Relaxed);
        let pin = flows.pin();
        pin.insert(
            candidate,
            FlowState {
                peer,
                last_seen: now,
            },
        );
        if idx.try_insert(peer, candidate).is_ok() {
            return candidate;
        }
        // A concurrent winner already published their index entry. Retire
        // the unreachable flow we just installed (only if it still belongs
        // to us) and loop so we reuse THEIR id instead of leaking a
        // phantom flow.
        let _ = pin.remove_if(&candidate, |_, state| state.peer == peer);
    }
}

async fn read_loop(
    socket: Arc<UdpSocket>,
    flows: Arc<HashMap<u32, FlowState>>,
    addr_index: Arc<HashMap<SocketAddr, u32>>,
    next_flow: Arc<AtomicU32>,
    sender: DatagramSendHandle,
    cancel: MergedCancel,
) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            res = socket.recv_from(&mut buf) => match res {
                Ok((n, peer)) => {
                    let peer = canonicalize_socket(peer);
                    let flow_id = touch_flow(&flows, &addr_index, &next_flow, peer);
                    let frame = DatagramFrame {
                        flow_id,
                        payload: Bytes::copy_from_slice(&buf[..n]),
                    };
                    if let Err(err) = sender.send(&frame) {
                        tracing::warn!(?err, ?peer, "udp→backhaul forward failed");
                    }
                }
                Err(err) => {
                    tracing::warn!(?err, "udp recv_from error; continuing");
                }
            },
        }
    }
}

async fn dispatch_loop(
    socket: Arc<UdpSocket>,
    flows: Arc<HashMap<u32, FlowState>>,
    mut inbound_rx: mpsc::Receiver<DatagramFrame>,
    cancel: MergedCancel,
) {
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            opt = inbound_rx.recv() => match opt {
                Some(frame) => {
                    let peer = {
                        let pin = flows.pin();
                        pin.get(&frame.flow_id).map(|s| s.peer)
                    };
                    let Some(peer) = peer else {
                        tracing::debug!(flow_id = frame.flow_id, "dispatch frame for unknown flow");
                        continue;
                    };
                    if let Err(err) = socket.send_to(&frame.payload, peer).await {
                        tracing::warn!(?err, ?peer, "udp send_to failed");
                    }
                }
                None => break,
            },
        }
    }
}

async fn cleanup_loop(
    flows: Arc<HashMap<u32, FlowState>>,
    addr_index: Arc<HashMap<SocketAddr, u32>>,
    cancel: MergedCancel,
) {
    let mut ticker = tokio::time::interval(FLOW_CLEANUP_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            _ = ticker.tick() => {
                let now = Instant::now();
                let pin = flows.pin();
                let idx_pin = addr_index.pin();
                let mut to_drop: Vec<(u32, SocketAddr)> = Vec::new();
                #[expect(
                    clippy::explicit_iter_loop,
                    reason = "papaya HashMapRef does not implement IntoIterator for &Self"
                )]
                for (id, state) in pin.iter() {
                    if now.duration_since(state.last_seen) > FLOW_IDLE_TIMEOUT {
                        to_drop.push((*id, state.peer));
                    }
                }
                for (id, peer) in to_drop {
                    pin.remove(&id);
                    // Conditional remove: only drop the index entry if it
                    // still names the id we're purging. A concurrent
                    // touch_flow may have re-allocated this peer to a new
                    // id between our snapshot and now; an unconditional
                    // remove would orphan that fresh allocation. Symmetric
                    // with touch_flow's stale-index repair pattern.
                    let _ = idx_pin.remove_if(&peer, |_, &v| v == id);
                }
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only setup")]
mod tests {
    use super::*;

    #[test]
    fn touch_flow_assigns_distinct_ids_for_distinct_peers() {
        let flows = HashMap::new();
        let idx = HashMap::new();
        let next = AtomicU32::new(1);
        let p1: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let p2: SocketAddr = "127.0.0.1:1001".parse().unwrap();
        assert_ne!(
            touch_flow(&flows, &idx, &next, p1),
            touch_flow(&flows, &idx, &next, p2),
        );
    }

    #[test]
    fn touch_flow_returns_same_id_for_same_peer() {
        let flows = HashMap::new();
        let idx = HashMap::new();
        let next = AtomicU32::new(1);
        let p: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        assert_eq!(
            touch_flow(&flows, &idx, &next, p),
            touch_flow(&flows, &idx, &next, p),
        );
    }

    /// R12-canon: v4-mapped-v6 and bare v4 peers must collapse to the
    /// same flow once `canonicalize_socket` has been applied.
    #[test]
    fn touch_flow_canonicalizes_v4_mapped() {
        let flows = HashMap::new();
        let idx = HashMap::new();
        let next = AtomicU32::new(1);
        let v4_mapped: SocketAddr = "[::ffff:1.2.3.4]:5000".parse().unwrap();
        let v4: SocketAddr = "1.2.3.4:5000".parse().unwrap();
        assert_eq!(
            touch_flow(&flows, &idx, &next, canonicalize_socket(v4_mapped)),
            touch_flow(&flows, &idx, &next, canonicalize_socket(v4)),
        );
    }
}
