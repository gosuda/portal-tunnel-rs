//! U17 — `HopRoute` canonical signing determinism + postcard round-trip.
#![expect(clippy::unwrap_used, reason = "proptest surfaces failures via panic")]

use portal_wire::hop::HopRoute;
use proptest::prelude::*;

proptest! {
    #[test]
    fn hop_route_canonical_deterministic_and_postcard_roundtrip(
        route_id in any::<u64>(),
        next_hop in prop::array::uniform32(any::<u8>()),
    ) {
        let h = HopRoute { route_id, next_hop };
        let c1 = h.canonical_signing_input().unwrap();
        let c2 = h.canonical_signing_input().unwrap();
        prop_assert_eq!(c1, c2);

        let bytes = postcard::to_stdvec(&h).unwrap();
        let back: HopRoute = postcard::from_bytes(&bytes).unwrap();
        prop_assert_eq!(h, back);
    }
}
