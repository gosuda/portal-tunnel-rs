//! U17 — `HopRoute` canonical signing determinism + postcard round-trip.
#![expect(clippy::unwrap_used, reason = "proptest surfaces failures via panic")]

use compact_str::CompactString;
use jiff::Timestamp;
use portal_wire::hop::HopRoute;
use proptest::prelude::*;

proptest! {
    #[test]
    fn hop_route_canonical_deterministic_and_postcard_roundtrip(
        route_id in any::<u64>(),
        next_hop in prop::array::uniform32(any::<u8>()),
        public_hostname in "[a-z0-9.-]{1,64}",
        route_hostname in "[a-z0-9.-]{1,64}",
        hostname_hash in "[a-f0-9]{8,64}",
        ech_config_list in prop::collection::vec(any::<u8>(), 0..128),
        match_token in "[a-zA-Z0-9_-]{1,64}",
        first_seen_at in proptest::option::of(-377_705_116_800i64..=253_402_300_799i64)
            .prop_filter_map("valid timestamp", |opt| {
                opt.map_or(Some(None), |ts| Timestamp::from_second(ts).ok().map(Some))
            }),
    ) {
        let h = HopRoute {
            route_id,
            next_hop,
            public_hostname: CompactString::from(public_hostname),
            route_hostname: CompactString::from(route_hostname),
            hostname_hash,
            ech_config_list,
            match_token,
            first_seen_at,
        };
        let c1 = h.canonical_signing_input().unwrap();
        let c2 = h.canonical_signing_input().unwrap();
        prop_assert_eq!(&c1, &c2);

        let bytes = postcard::to_stdvec(&h).unwrap();
        let back: HopRoute = postcard::from_bytes(&bytes).unwrap();
        prop_assert_eq!(&h, &back);

        let c_back = back.canonical_signing_input().unwrap();
        prop_assert_eq!(&c1, &c_back, "postcard round-trip must preserve canonical signing input");
    }
}
