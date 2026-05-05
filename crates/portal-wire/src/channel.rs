//! QUIC stream channel tag and [`ChannelCodec`].

use std::convert::TryFrom;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::error::Error;
use crate::limits;

/// First byte on a multiplexed QUIC stream payload framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Channel {
    /// Control-plane; optional [`crate::routed_hostname::RoutedHostname`] in first frame.
    Control = 0x01,
    /// TCP port relay.
    TcpProxy = 0x02,
    /// UDP datagram session.
    UdpDatagram = 0x03,
    /// Multi-hop overlay (reserved parsing path for Phase 6b).
    HopRoute = 0x04,
}

impl Channel {
    /// SEC-014 max payload for this channel.
    #[must_use]
    pub const fn max_payload(self) -> usize {
        match self {
            Self::Control => limits::CONTROL_MAX,
            Self::TcpProxy => limits::TCP_PROXY_MAX,
            Self::UdpDatagram => limits::UDP_DATAGRAM_MAX,
            Self::HopRoute => limits::HOP_ROUTE_MAX,
        }
    }
}

impl TryFrom<u8> for Channel {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Err(Error::LegacyKeepaliveByte),
            0x01 => Ok(Self::Control),
            0x02 => Ok(Self::TcpProxy),
            0x03 => Ok(Self::UdpDatagram),
            0x04 => Ok(Self::HopRoute),
            other => Err(Error::UnknownChannelTag(other)),
        }
    }
}

/// Sub-discriminant byte that follows a [`Channel::TcpProxy`] tag.
///
/// Appears on the first frame of a TCP proxy stream. The byte values are
/// part of the wire register (Phase 1) — a single source of truth for
/// both the relay-side dispatcher and the SDK-side opener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TcpProxyKind {
    /// Raw TCP forwarding (no origin-side TLS termination).
    Raw = 0x01,
    /// TLS forwarding (origin-side TLS termination).
    Tls = 0x02,
}

impl TryFrom<u8> for TcpProxyKind {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Raw),
            0x02 => Ok(Self::Tls),
            other => Err(Error::UnknownTcpProxyKind(other)),
        }
    }
}

/// Framing: `[tag:u8][len:u32_be][payload:len]`.
#[derive(Debug, Default, Clone, Copy)]
pub struct ChannelCodec;

impl Decoder for ChannelCodec {
    type Item = (Channel, Bytes);
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 5 {
            return Ok(None);
        }
        let tag = src[0];
        let channel = Channel::try_from(tag)?;
        let len = u32::from_be_bytes([src[1], src[2], src[3], src[4]]) as usize;
        if len > channel.max_payload() {
            return Err(Error::FrameTooLarge);
        }
        if src.len() < 5 + len {
            return Ok(None);
        }
        src.advance(5);
        let payload = src.split_to(len).freeze();
        Ok(Some((channel, payload)))
    }
}

impl Encoder<(Channel, Bytes)> for ChannelCodec {
    type Error = Error;

    fn encode(
        &mut self,
        (channel, payload): (Channel, Bytes),
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        if payload.len() > channel.max_payload() {
            return Err(Error::FrameTooLarge);
        }
        dst.reserve(5 + payload.len());
        dst.put_u8(channel as u8);
        dst.put_u32(u32::try_from(payload.len()).map_err(|_| Error::FrameTooLarge)?);
        dst.put_slice(&payload);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "codec round-trip exercises infallible paths"
    )]

    use super::*;

    #[test]
    fn round_trip_control_empty() {
        let mut codec = ChannelCodec;
        let mut buf = BytesMut::new();
        codec
            .encode((Channel::Control, Bytes::new()), &mut buf)
            .unwrap();
        let (ch, pl) = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(ch, Channel::Control);
        assert!(pl.is_empty());
    }

    #[test]
    fn legacy_zero_rejected() {
        let mut buf = BytesMut::from(&[0x00_u8, 0, 0, 0, 0][..]);
        let mut codec = ChannelCodec;
        let e = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(e, Error::LegacyKeepaliveByte));
    }

    #[test]
    fn tcp_proxy_kind_round_trips() {
        for kind in [TcpProxyKind::Raw, TcpProxyKind::Tls] {
            let byte = kind as u8;
            let back = TcpProxyKind::try_from(byte).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn tcp_proxy_kind_rejects_unknown_byte() {
        let result = TcpProxyKind::try_from(0xff);
        assert!(matches!(result, Err(Error::UnknownTcpProxyKind(0xff))));
    }
}
