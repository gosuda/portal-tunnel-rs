// PRE: src_ip is the request's remote IP (may be empty → "<unknown>").
// INVARIANT: new buckets start full (tokens = BURST); buckets at capacity → deny without creating.
// POST: returns true iff the request is within rate; consumes 1 token on true.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const RATE_PER_MINUTE: f64 = 30.0;
const BURST: f64 = 60.0;
const PRUNE_INTERVAL: Duration = Duration::from_secs(600);
const BUCKET_IDLE_TTL: Duration = Duration::from_secs(1800);
const MAX_BUCKET_COUNT: usize = 65536;

struct AnnounceBucket {
    tokens: f64,
    last_update: Instant,
}

struct Inner {
    buckets: HashMap<String, AnnounceBucket>,
    last_prune: Instant,
}

pub struct AnnounceLimiter {
    inner: Mutex<Inner>,
}

impl AnnounceLimiter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                buckets: HashMap::new(),
                last_prune: Instant::now(),
            }),
        }
    }

    #[must_use]
    pub fn allow(&self, src_ip: &str) -> bool {
        let key = if src_ip.is_empty() {
            "<unknown>"
        } else {
            src_ip
        };
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("announce limiter lock poisoned");

        // Prune idle buckets on schedule
        if now.duration_since(inner.last_prune) >= PRUNE_INTERVAL {
            inner
                .buckets
                .retain(|_, b| now.duration_since(b.last_update) < BUCKET_IDLE_TTL);
            inner.last_prune = now;
        }

        // Get or create bucket; use contains_key to avoid NLL borrow-checker conflict
        if !inner.buckets.contains_key(key) && inner.buckets.len() >= MAX_BUCKET_COUNT {
            return false;
        }
        let bucket = inner
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| AnnounceBucket {
                tokens: BURST,
                last_update: now,
            });

        // Token replenishment (token bucket algorithm)
        let elapsed_secs = now.duration_since(bucket.last_update).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed_secs * RATE_PER_MINUTE / 60.0).min(BURST);
        bucket.last_update = now;

        // Consume one token
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl Default for AnnounceLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allows_within_burst() {
        let limiter = AnnounceLimiter::new();
        for i in 0..60 {
            assert!(limiter.allow("1.2.3.4"), "call {i} should be allowed");
        }
    }

    #[test]
    fn test_denies_after_burst() {
        let limiter = AnnounceLimiter::new();
        for _ in 0..60 {
            let _ = limiter.allow("1.2.3.4");
        }
        assert!(!limiter.allow("1.2.3.4"), "61st call should be denied");
    }

    #[test]
    fn test_different_ips_independent() {
        let limiter = AnnounceLimiter::new();
        // Exhaust one IP
        for _ in 0..60 {
            let _ = limiter.allow("1.1.1.1");
        }
        assert!(!limiter.allow("1.1.1.1"), "1.1.1.1 should be exhausted");
        // Other IP should still be allowed
        assert!(
            limiter.allow("2.2.2.2"),
            "2.2.2.2 should be independent and allowed"
        );
    }

    #[test]
    fn test_unknown_key_for_empty_ip() {
        let limiter = AnnounceLimiter::new();
        // Should not panic, uses "<unknown>" key
        assert!(
            limiter.allow(""),
            "empty ip should be allowed via <unknown> key"
        );
    }
}
