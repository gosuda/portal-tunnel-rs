//! Canonical signing input length bound for [`portal_wire::descriptor::RelayDescriptor`].
#![expect(clippy::unwrap_used, reason = "proptest surfaces failures via panic")]

use std::net::{Ipv4Addr, SocketAddrV4};

use portal_wire::descriptor::RelayDescriptor;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn descriptor_inner_under_cap(addr_octet in 1u8..255u8) {
        let d = RelayDescriptor {
            identity_key: [addr_octet; 32],
            addresses_v4: vec![SocketAddrV4::new(Ipv4Addr::new(addr_octet, 2, 3, 4), 443)],
            addresses_v6: vec![],
        };
        let inner = postcard::to_stdvec(&d).unwrap();
        prop_assert!(inner.len() <= portal_wire::limits::RELAY_DESCRIPTOR_CANON_MAX);
        prop_assert!(!d.canonical_signing_input().unwrap().is_empty());
    }
}
