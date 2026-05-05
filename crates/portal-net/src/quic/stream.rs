//! Per-stream `Channel`-tag dispatch.
//!
//! Wire shape (single source: portal-wire `ChannelCodec`):
//! `[tag:u8][len:u32_be][payload:len]`. The first frame on a fresh QUIC
//! bidirectional stream carries the `Channel` discriminant; subsequent
//! framing depends on the channel.
//!
//! Phase 3 reads the `Channel` tag as a single 1-byte prefix in front of
//! channel-specific framing — Control rides length-prefixed postcard
//! `Envelope` payloads (see [`crate::quic::control`]), `TcpProxy` rides
//! a 1-byte [`TcpProxyKind`] sub-discriminant followed by raw bytes,
//! `HopRoute` is reserved for Phase 6b.
//!
//! - **`Control`** — frames are length-prefixed postcard `Envelope` payloads
//!   exchanged via [`tokio_util::codec::Framed`]. Caller wraps the resulting
//!   stream pair in [`crate::quic::control`] for the handshake.
//! - **`TcpProxy`** — first frame is a 1-byte sub-discriminant
//!   ([`TcpProxyKind::Raw`] / [`TcpProxyKind::Tls`]); after that the stream
//!   is raw bytes spliced into the tenant origin.
//! - **`HopRoute`** — first frame is a `HopRouteHeader` (Phase 6b reserved).
//!   For Phase 3 we accept the header bytes opaquely (declared by Phase 1
//!   when overlay lands) and surface them to the caller for forwarding.
//! - **`UdpDatagram`** — invalid as a stream channel (UDP rides QUIC
//!   datagrams, not bidirectional streams). Dispatch returns `WireDecode`.

use portal_wire::channel::Channel;
use portal_wire::error::Error as WireError;
use quinn::{RecvStream, SendStream};

use crate::error::NetError;

/// Re-export of [`portal_wire::channel::TcpProxyKind`] — the sub-discriminant
/// byte that follows a [`Channel::TcpProxy`] tag on the first frame of a TCP
/// proxy stream. The discriminant byte values are owned by `portal-wire`
/// (Phase 1 wire register); `portal-net` is a pure consumer.
pub use portal_wire::channel::TcpProxyKind;

/// Outcome of [`dispatch_inbound`]: a typed view of the next stream the
/// peer opened, with channel-specific framing already adapted on top of the
/// raw quinn stream pair.
#[non_exhaustive]
pub enum InboundStream {
    /// Control-plane stream. Framing is length-prefixed postcard envelopes;
    /// the caller wraps in `Framed<_, ControlCodec>` for the handshake.
    Control {
        /// Server-side send half of the bidirectional QUIC stream.
        send: SendStream,
        /// Server-side recv half of the bidirectional QUIC stream.
        recv: RecvStream,
    },
    /// TCP proxy with the sub-kind already read from the wire.
    TcpProxy {
        /// Whether the origin-side stream is raw TCP or TLS.
        kind: TcpProxyKind,
        /// Server-side send half of the bidirectional QUIC stream.
        send: SendStream,
        /// Server-side recv half of the bidirectional QUIC stream.
        recv: RecvStream,
    },
    /// Multi-hop overlay (Phase 6b reserved). Phase 3 surfaces the raw
    /// stream pair so a future overlay layer can consume it; we do NOT
    /// parse the `HopRouteHeader` here — it is a Phase 6b decision.
    HopRoute {
        /// Server-side send half of the bidirectional QUIC stream.
        send: SendStream,
        /// Server-side recv half of the bidirectional QUIC stream.
        recv: RecvStream,
    },
}

/// Read the first 1-byte channel tag from `recv`, then any channel-specific
/// sub-discriminant bytes, returning a typed `InboundStream` ready for
/// channel-specific consumption.
///
/// # Errors
/// Returns [`NetError::Io`] on a truncated stream;
/// [`NetError::WireDecode`] on an unknown / forbidden channel tag (e.g.,
/// `Channel::UdpDatagram` is not a valid stream channel) or
/// `LegacyKeepaliveByte` (legacy 0x00 marker).
pub async fn dispatch_inbound(
    send: SendStream,
    mut recv: RecvStream,
) -> Result<InboundStream, NetError> {
    use tokio::io::AsyncReadExt as _;

    // tokio AsyncReadExt::read_u8 returns io::Error directly; the
    // `#[from]` path on NetError::Io preserves the original ErrorKind for
    // caller-side EOF / reset discrimination (which `Error::other(e)`
    // would re-kind to ErrorKind::Other and lose).
    let tag_byte = recv.read_u8().await.map_err(NetError::Io)?;
    let channel = Channel::try_from(tag_byte).map_err(|e: WireError| {
        NetError::WireDecode(format!("channel tag {tag_byte:#04x}: {e}"))
    })?;
    match channel {
        Channel::Control => Ok(InboundStream::Control { send, recv }),
        Channel::TcpProxy => {
            let kind_byte = recv.read_u8().await.map_err(NetError::Io)?;
            let kind = TcpProxyKind::try_from(kind_byte).map_err(|e: WireError| {
                NetError::WireDecode(format!("tcp-proxy kind {kind_byte:#04x}: {e}"))
            })?;
            Ok(InboundStream::TcpProxy { kind, send, recv })
        }
        Channel::HopRoute => Ok(InboundStream::HopRoute { send, recv }),
        Channel::UdpDatagram => Err(NetError::WireDecode(
            "UdpDatagram is not a stream channel — UDP rides QUIC datagrams".to_owned(),
        )),
    }
}

/// Validate the channel/`tcp_kind` argument pair for an outbound stream
/// open before any side effect occurs. Single owner of the rule set —
/// [`open_outbound`] and the unit tests both delegate here.
///
/// Rules:
/// - `Channel::UdpDatagram` is rejected (UDP rides QUIC datagrams, not
///   bidirectional streams) — symmetric with [`dispatch_inbound`].
/// - `Channel::TcpProxy` requires a `tcp_kind` sub-discriminant; absence
///   is a programmer error and is rejected before opening.
/// - `Channel::Control` and `Channel::HopRoute` MUST NOT carry a
///   `tcp_kind` — that byte slot is `TcpProxy`-only.
///
/// # Errors
/// Returns [`NetError::WireDecode`] for any invalid combination so callers
/// can surface a single error class to higher layers.
fn validate_open_outbound_args(
    channel: Channel,
    tcp_kind: Option<TcpProxyKind>,
) -> Result<(), NetError> {
    match (channel, tcp_kind) {
        (Channel::UdpDatagram, _) => Err(NetError::WireDecode(
            "UdpDatagram is not a stream channel — UDP rides QUIC datagrams".to_owned(),
        )),
        (Channel::TcpProxy, None) => Err(NetError::WireDecode(
            "TcpProxy stream requires TcpProxyKind sub-discriminant".to_owned(),
        )),
        (Channel::Control | Channel::HopRoute, Some(_)) => Err(NetError::WireDecode(format!(
            "{channel:?} stream does not accept a TcpProxyKind sub-discriminant",
        ))),
        (Channel::Control | Channel::HopRoute, None) | (Channel::TcpProxy, Some(_)) => Ok(()),
    }
}

/// Open a server-initiated bidirectional QUIC stream and write the channel
/// tag prefix. For `Channel::TcpProxy`, also writes the sub-kind byte.
///
/// All channel/`tcp_kind` validation happens **before** any side effect
/// (`open_bi` / writes) via the private `validate_open_outbound_args`
/// helper, so a misuse never leaves a half-formed stream on the wire
/// that the peer would have to time out.
///
/// # Errors
/// Returns [`NetError::WireDecode`] when the channel/`tcp_kind` combination
/// is invalid (no stream is opened);
/// [`NetError::Quic`] on stream-open failure;
/// [`NetError::Io`] on tag-write failure (after a stream was opened — caller
/// is expected to drop the stream pair on error to surface the local error
/// to the peer as a stream reset).
pub async fn open_outbound(
    conn: &quinn::Connection,
    channel: Channel,
    tcp_kind: Option<TcpProxyKind>,
) -> Result<(SendStream, RecvStream), NetError> {
    use tokio::io::AsyncWriteExt as _;

    validate_open_outbound_args(channel, tcp_kind)?;

    let (mut send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| NetError::Quic(format!("open_bi: {e}")))?;
    send.write_u8(channel as u8).await.map_err(NetError::Io)?;
    if let (Channel::TcpProxy, Some(kind)) = (channel, tcp_kind) {
        send.write_u8(kind as u8).await.map_err(NetError::Io)?;
    }
    Ok((send, recv))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests for the I/O paths in stream.rs require a live quinn connection
    // (open_bi) which ALSO requires server config + spki-pinned client
    // config. We exercise the dispatch_inbound + open_outbound round-trip
    // via integration tests that spin up a same-process server + client
    // endpoint. The unit-test layer here covers only the pure conversion
    // paths that don't need a runtime — namely the type re-export and the
    // pre-side-effect validation in open_outbound.

    #[test]
    fn re_exported_tcp_proxy_kind_matches_wire_register() {
        // Identity check: the re-export resolves to the same wire-register
        // type and the byte values match what `portal-wire` declares.
        let raw: portal_wire::channel::TcpProxyKind = TcpProxyKind::Raw;
        let tls: portal_wire::channel::TcpProxyKind = TcpProxyKind::Tls;
        assert_eq!(raw as u8, 0x01);
        assert_eq!(tls as u8, 0x02);
    }

    #[test]
    fn open_outbound_rejects_udp_datagram() {
        let result = validate_open_outbound_args(Channel::UdpDatagram, None);
        assert!(matches!(result, Err(NetError::WireDecode(_))));
        let result = validate_open_outbound_args(Channel::UdpDatagram, Some(TcpProxyKind::Raw));
        assert!(matches!(result, Err(NetError::WireDecode(_))));
    }

    #[test]
    fn open_outbound_requires_tcp_kind_for_tcp_proxy() {
        let result = validate_open_outbound_args(Channel::TcpProxy, None);
        assert!(matches!(result, Err(NetError::WireDecode(_))));
    }

    #[test]
    fn open_outbound_rejects_unexpected_tcp_kind_on_non_tcp_channels() {
        for channel in [Channel::Control, Channel::HopRoute] {
            let result = validate_open_outbound_args(channel, Some(TcpProxyKind::Tls));
            assert!(
                matches!(result, Err(NetError::WireDecode(_))),
                "expected rejection for {channel:?} with TcpProxyKind",
            );
        }
    }

    #[test]
    fn open_outbound_accepts_valid_combinations() {
        for channel in [Channel::Control, Channel::HopRoute] {
            assert!(validate_open_outbound_args(channel, None).is_ok());
        }
        for kind in [TcpProxyKind::Raw, TcpProxyKind::Tls] {
            assert!(validate_open_outbound_args(Channel::TcpProxy, Some(kind)).is_ok());
        }
    }
}
