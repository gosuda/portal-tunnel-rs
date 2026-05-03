//! U17 — `ReputationDelta` postcard round-trip + canonical signing determinism.
#![expect(clippy::unwrap_used, reason = "proptest surfaces failures via panic")]

use portal_wire::reputation::{ReasonCode, ReputationDelta};
use proptest::prelude::*;

proptest! {
    #[test]
    fn reputation_delta_postcard_roundtrip_and_canonical_stable(
        identity in prop::array::uniform32(any::<u8>()),
        score_delta in any::<i32>(),
        decay_window_secs in any::<u64>(),
        reason in any::<u16>(),
        signed_by in prop::array::uniform32(any::<u8>()),
    ) {
        let d = ReputationDelta {
            identity_pubkey: identity,
            score_delta,
            decay_window_secs,
            reason_code: ReasonCode(reason),
            signed_by_relay_pubkey: signed_by,
        };
        let c1 = d.canonical_signing_input().unwrap();
        let c2 = d.canonical_signing_input().unwrap();
        prop_assert_eq!(c1, c2);

        let bytes = postcard::to_stdvec(&d).unwrap();
        let back: ReputationDelta = postcard::from_bytes(&bytes).unwrap();
        prop_assert_eq!(d, back);
    }
}
