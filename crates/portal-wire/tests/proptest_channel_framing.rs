//! U17 — `ChannelCodec` framing round-trip and oversized rejection.
#![expect(clippy::unwrap_used, reason = "proptest surfaces failures via panic")]

use bytes::{BufMut, Bytes, BytesMut};
use portal_wire::Error;
use portal_wire::channel::{Channel, ChannelCodec};
use proptest::prelude::*;
use tokio_util::codec::{Decoder, Encoder};

fn channel_strategy() -> impl Strategy<Value = Channel> {
    prop_oneof![
        Just(Channel::Control),
        Just(Channel::TcpProxy),
        Just(Channel::UdpDatagram),
        Just(Channel::HopRoute),
    ]
}

proptest! {
    #[test]
    fn channel_framing_roundtrip_identity(
        channel in channel_strategy(),
        payload in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let max = channel.max_payload();
        let payload: Vec<u8> = payload.into_iter().take(max).collect();
        let payload = Bytes::from(payload);

        let mut codec = ChannelCodec;
        let mut buf = BytesMut::new();
        codec.encode((channel, payload.clone()), &mut buf).unwrap();
        let (ch2, pl2) = codec.decode(&mut buf).unwrap().unwrap();
        prop_assert_eq!(ch2, channel);
        prop_assert_eq!(pl2, payload);
    }

    #[test]
    fn channel_encode_rejects_oversized_payload(
        channel in channel_strategy(),
        extra in 1usize..64usize,
    ) {
        let max = channel.max_payload();
        let len = max.saturating_add(extra);
        let payload = Bytes::from(vec![0x5Au8; len]);
        let mut codec = ChannelCodec;
        let mut buf = BytesMut::new();
        let e = codec.encode((channel, payload), &mut buf).unwrap_err();
        prop_assert!(matches!(e, Error::FrameTooLarge));
    }

    #[test]
    fn channel_decode_rejects_oversized_length_field(
        channel in channel_strategy(),
        extra in 1usize..1024usize,
    ) {
        let max = channel.max_payload();
        let proclaimed = max.saturating_add(extra);
        let proclaimed_u32 = u32::try_from(proclaimed).unwrap_or(u32::MAX);

        let mut buf = BytesMut::new();
        buf.put_u8(channel as u8);
        buf.put_u32(proclaimed_u32);

        let mut codec = ChannelCodec;
        let e = codec.decode(&mut buf).unwrap_err();
        prop_assert!(matches!(e, Error::FrameTooLarge));
    }
}
