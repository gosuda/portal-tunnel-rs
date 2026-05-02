use chrono::Duration as ChronoDuration;
use rand_core::{OsRng, RngCore};

use super::DEFAULT_LEASE_TTL;

pub(super) fn lease_ttl(seconds: i64) -> ChronoDuration {
    if seconds > 0 {
        return ChronoDuration::seconds(seconds);
    }
    ChronoDuration::from_std(DEFAULT_LEASE_TTL).expect("static duration must convert")
}

pub(super) fn random_id(prefix: &str) -> String {
    let mut buf = [0u8; 8];
    OsRng.fill_bytes(&mut buf);
    format!("{prefix}{}", hex::encode(buf))
}

pub(super) fn random_nonce() -> String {
    let mut buf = [0u8; 8];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

pub(super) fn is_zero(value: &u16) -> bool {
    *value == 0
}
