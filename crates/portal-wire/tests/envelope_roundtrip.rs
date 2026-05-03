//! Postcard round-trip for [`portal_wire::envelope::Envelope`].
#![expect(clippy::unwrap_used, reason = "proptest surfaces failures via panic")]

use bytes::Bytes;
use jiff::Timestamp;
use portal_wire::envelope::{Audience, Claims, Envelope, Purpose};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn envelope_postcard_roundtrip(
        payload in prop::collection::vec(any::<u8>(), 0..512),
        sig_byte in any::<u8>(),
    ) {
        let mut sig = [sig_byte; 64];
        sig[0] ^= 1;
        let env = Envelope {
            payload: Bytes::from(payload),
            sig,
            claims: Claims {
                nonce: [9; 16],
                not_before: Timestamp::UNIX_EPOCH,
                not_after: Timestamp::UNIX_EPOCH,
                audience: Audience::RelayApiSdk,
                purpose: Purpose::LeaseAccess,
            },
        };
        let bytes = env.to_bytes().unwrap();
        let back = Envelope::from_bytes(&bytes).unwrap();
        prop_assert_eq!(env, back);
    }
}
