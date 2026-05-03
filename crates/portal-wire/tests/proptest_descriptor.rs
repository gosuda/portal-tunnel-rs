//! U17 — `RelayDescriptor` canonical signing input invariant under address reordering.
#![expect(clippy::unwrap_used, reason = "proptest surfaces failures via panic")]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use portal_wire::descriptor::RelayDescriptor;
use proptest::prelude::*;

fn socket_v4_strategy() -> impl Strategy<Value = SocketAddrV4> {
    (any::<[u8; 4]>(), any::<u16>())
        .prop_map(|(oct, port)| SocketAddrV4::new(Ipv4Addr::from(oct), port))
}

fn socket_v6_strategy() -> impl Strategy<Value = SocketAddrV6> {
    (any::<[u8; 16]>(), any::<u16>(), any::<u32>())
        .prop_map(|(oct, port, flow)| SocketAddrV6::new(Ipv6Addr::from(oct), port, flow, 0))
}

proptest! {
    #[test]
    fn relay_descriptor_canonical_bytes_invariant_under_address_shuffle(
        identity_key in prop::array::uniform32(any::<u8>()),
        mut v4 in prop::collection::vec(socket_v4_strategy(), 0..16),
        mut v6 in prop::collection::vec(socket_v6_strategy(), 0..8),
    ) {
        v4.sort_by_key(|s| (s.ip().to_bits(), s.port()));
        v6.sort_by_key(|s| (s.ip().to_bits(), s.port()));

        let mut rev_v4 = v4.clone();
        rev_v4.reverse();
        let mut rev_v6 = v6.clone();
        rev_v6.reverse();

        let sorted = RelayDescriptor {
            identity_key,
            addresses_v4: v4,
            addresses_v6: v6,
        };
        let shuffled = RelayDescriptor {
            identity_key,
            addresses_v4: rev_v4,
            addresses_v6: rev_v6,
        };

        prop_assume!(sorted.canonical_signing_input().is_ok());
        prop_assert_eq!(
            sorted.canonical_signing_input().unwrap(),
            shuffled.canonical_signing_input().unwrap()
        );
    }
}
