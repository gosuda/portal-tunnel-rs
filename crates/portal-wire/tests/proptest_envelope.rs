//! U17 — `Envelope` postcard round-trip (behavioral gate).
#![expect(clippy::unwrap_used, reason = "proptest surfaces failures via panic")]

use bytes::Bytes;
use jiff::Timestamp;
use portal_wire::envelope::{Audience, Claims, Envelope, Purpose};
use proptest::prelude::*;

fn audience_strategy() -> impl Strategy<Value = Audience> {
    prop_oneof![
        Just(Audience::RelayApiAdmin),
        Just(Audience::RelayApiSdk),
        Just(Audience::RelayApiDiscovery),
        Just(Audience::Keyless),
        Just(Audience::HopForward),
    ]
}

fn purpose_strategy() -> impl Strategy<Value = Purpose> {
    prop_oneof![
        Just(Purpose::Register),
        Just(Purpose::Renew),
        Just(Purpose::Unregister),
        Just(Purpose::HopAttest),
        Just(Purpose::KeylessSign),
        Just(Purpose::DiscoveryAnnounce),
        Just(Purpose::LeaseAccess),
    ]
}

fn timestamp_pair() -> impl Strategy<Value = (Timestamp, Timestamp)> {
    (-86_400i64..86_400i64, -86_400i64..86_400i64).prop_map(|(before_s, after_s)| {
        let not_before = Timestamp::from_second(before_s).unwrap_or(Timestamp::UNIX_EPOCH);
        let not_after = Timestamp::from_second(after_s).unwrap_or(Timestamp::UNIX_EPOCH);
        (not_before, not_after)
    })
}

proptest! {
    #[test]
    fn envelope_postcard_roundtrip(
        payload in prop::collection::vec(any::<u8>(), 0..1024),
        sig in prop::collection::vec(any::<u8>(), 64).prop_map(|v| {
            let mut a = [0u8; 64];
            a.copy_from_slice(&v);
            a
        }),
        nonce in prop::array::uniform16(any::<u8>()),
        (not_before, not_after) in timestamp_pair(),
        audience in audience_strategy(),
        purpose in purpose_strategy(),
    ) {
        let env = Envelope {
            payload: Bytes::from(payload),
            sig,
            claims: Claims {
                nonce,
                not_before,
                not_after,
                audience,
                purpose,
            },
        };
        let bytes = env.to_bytes().unwrap();
        let back = Envelope::from_bytes(&bytes).unwrap();
        prop_assert_eq!(env, back);
    }
}
