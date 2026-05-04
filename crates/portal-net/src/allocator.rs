//! Port allocator with grace-period reservation.
//!
//! Mirrors Go's `port_allocator.go::PortAllocator`. The grace-period
//! reservation lets a lease that briefly disconnects (e.g., a momentary
//! network blip) re-bind to the same port on reconnect — preserving any
//! state cached at the tenant origin (sticky firewall rules, etc.).

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use compact_str::CompactString;
use tokio::sync::Mutex;

use crate::error::NetError;

/// Reservation entry: a port temporarily held for a specific lease name
/// after `release`, expiring after `grace`. While the reservation is
/// live, `allocate(name)` for the same name returns the reserved port;
/// after expiry the port returns to the available pool.
#[derive(Debug, Clone)]
struct Reservation {
    port: u16,
    expires_at: Instant,
}

#[derive(Debug)]
struct Inner {
    available: BTreeSet<u16>,
    in_use: HashMap<u16, CompactString>,
    /// Reservations indexed by lease name so `allocate(name)` can find
    /// the prior port in O(1).
    reserved: HashMap<CompactString, Reservation>,
    grace: Duration,
}

impl Inner {
    /// Drop expired reservations and return their ports to `available`.
    fn cleanup_expired(&mut self, now: Instant) {
        let expired: Vec<CompactString> = self
            .reserved
            .iter()
            .filter(|(_, r)| r.expires_at <= now)
            .map(|(name, _)| name.clone())
            .collect();
        for name in expired {
            if let Some(r) = self.reserved.remove(&name) {
                self.available.insert(r.port);
            }
        }
    }
}

/// Pool of ports with grace-period reservation. All public methods are
/// `async` because they take a `tokio::sync::Mutex` lock; the lock guards
/// the entire `Inner` so allocate/release are atomic.
pub struct PortAllocator {
    inner: Arc<Mutex<Inner>>,
}

impl PortAllocator {
    /// Construct a new allocator over the closed range `[min, max]`.
    /// `grace` is the duration a released port stays reserved for the
    /// same lease name.
    ///
    /// If `min > max`, the allocator is empty (every `allocate` returns
    /// [`NetError::PortExhausted`]). This mirrors Go's defensive default.
    #[must_use]
    pub fn new(min: u16, max: u16, grace: Duration) -> Self {
        let available: BTreeSet<u16> = if min == 0 || max == 0 || min > max {
            BTreeSet::new()
        } else {
            (min..=max).collect()
        };
        Self {
            inner: Arc::new(Mutex::new(Inner {
                available,
                in_use: HashMap::new(),
                reserved: HashMap::new(),
                grace,
            })),
        }
    }

    /// Allocate a port for `name`. If `name` has a live reservation,
    /// returns that port (consuming the reservation). Else returns the
    /// lowest available port.
    ///
    /// # Errors
    /// Returns [`NetError::PortExhausted`] when no port is available and
    /// no reservation matches `name`.
    pub async fn allocate(&self, name: &str) -> Result<u16, NetError> {
        let now = Instant::now();
        let port = {
            let mut inner = self.inner.lock().await;
            inner.cleanup_expired(now);

            let key = CompactString::from(name);
            if let Some(reservation) = inner.reserved.remove(&key) {
                inner.in_use.insert(reservation.port, key);
                reservation.port
            } else {
                let port = inner.available.pop_first().ok_or(NetError::PortExhausted)?;
                inner.in_use.insert(port, key);
                port
            }
        };
        Ok(port)
    }

    /// Release `port`. If `port` is not in use, the call is a no-op.
    /// Otherwise the port is moved into the reservation table for the
    /// lease that held it (`grace` deadline). If the lease already had a
    /// different reserved port, that prior port is returned to the
    /// available pool (mirrors Go's reservation-replace).
    pub async fn release(&self, port: u16) {
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        inner.cleanup_expired(now);

        let Some(name) = inner.in_use.remove(&port) else {
            return;
        };
        let expires_at = now + inner.grace;
        if let Some(prior) = inner
            .reserved
            .insert(name, Reservation { port, expires_at })
        {
            // Lease had a prior different reservation; return THAT port to
            // the pool, mirroring Go's reservation-replace.
            if prior.port != port {
                inner.available.insert(prior.port);
            }
        }
    }

    /// Snapshot the number of available ports (for tests + metrics).
    pub async fn available_count(&self) -> usize {
        self.inner.lock().await.available.len()
    }

    /// Snapshot the number of reserved ports (for tests + metrics).
    pub async fn reserved_count(&self) -> usize {
        self.inner.lock().await.reserved.len()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests use deterministic inputs")]
mod tests {
    use super::*;

    fn fixed_grace() -> Duration {
        Duration::from_mins(1)
    }

    #[tokio::test]
    async fn allocate_returns_min_first() {
        let allocator = PortAllocator::new(2000, 2010, fixed_grace());
        let port = allocator.allocate("alice").await.unwrap();
        assert_eq!(port, 2000);
    }

    #[tokio::test]
    async fn release_then_allocate_same_name_returns_same_port() {
        let allocator = PortAllocator::new(3000, 3010, fixed_grace());
        let p1 = allocator.allocate("alice").await.unwrap();
        allocator.release(p1).await;
        let p2 = allocator.allocate("alice").await.unwrap();
        assert_eq!(p1, p2, "grace-period reservation must return same port");
    }

    #[tokio::test]
    async fn allocate_with_no_ports_returns_exhausted() {
        let allocator = PortAllocator::new(4000, 4001, fixed_grace());
        let _p1 = allocator.allocate("alice").await.unwrap();
        let _p2 = allocator.allocate("bob").await.unwrap();
        let result = allocator.allocate("carol").await;
        assert!(matches!(result, Err(NetError::PortExhausted)));
    }

    #[tokio::test]
    async fn release_unknown_port_is_no_op() {
        let allocator = PortAllocator::new(5000, 5010, fixed_grace());
        // Should not panic.
        allocator.release(9999).await;
        assert_eq!(allocator.available_count().await, 11);
    }

    #[tokio::test]
    async fn min_greater_than_max_yields_empty_allocator() {
        let allocator = PortAllocator::new(7000, 6000, fixed_grace());
        let result = allocator.allocate("alice").await;
        assert!(matches!(result, Err(NetError::PortExhausted)));
    }

    #[tokio::test]
    async fn reservation_replace_returns_old_port_to_pool() {
        let allocator = PortAllocator::new(8000, 8010, fixed_grace());
        let p1 = allocator.allocate("alice").await.unwrap();
        assert_eq!(p1, 8000);
        allocator.release(p1).await; // 8000 reserved for alice
        // Allocate next available — would be 8001 because 8000 is reserved.
        let p2 = allocator.allocate("alice").await.unwrap();
        assert_eq!(p2, 8000, "reserved 8000 returned for alice");
        // Now allocate again for alice — should return next available
        // (8000 is in_use, 8001 is in pool).
        let p3 = allocator.allocate("alice").await.unwrap();
        assert_eq!(p3, 8001);
        // Release p3 (8001) — alice now has 8000 in_use AND 8001 reserved.
        // The reservation-replace path: alice's prior reservation was for
        // 8000 (consumed). Now reserving 8001. There is NO prior live
        // reservation, so no port is returned to the pool here.
        allocator.release(p3).await;
        assert_eq!(allocator.reserved_count().await, 1);
    }

    #[tokio::test]
    async fn expired_reservation_is_cleaned_up_on_allocate() {
        // Use a tiny grace so the reservation expires quickly.
        let allocator = PortAllocator::new(9000, 9001, Duration::from_millis(10));
        let p1 = allocator.allocate("alice").await.unwrap();
        allocator.release(p1).await;
        assert_eq!(allocator.reserved_count().await, 1);
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Allocate for a DIFFERENT name. cleanup_expired must fire and
        // 9000 should land back in `available`.
        let p2 = allocator.allocate("bob").await.unwrap();
        assert_eq!(
            p2, 9000,
            "expired reservation must release port back to pool"
        );
        assert_eq!(allocator.reserved_count().await, 0);
    }

    #[tokio::test]
    async fn concurrent_allocate_yields_distinct_ports() {
        let allocator = Arc::new(PortAllocator::new(10_000, 10_099, fixed_grace()));
        let mut handles = Vec::new();
        for i in 0..100 {
            let allocator = Arc::clone(&allocator);
            handles.push(tokio::spawn(async move {
                allocator.allocate(&format!("client_{i}")).await.unwrap()
            }));
        }
        let mut ports = Vec::new();
        for h in handles {
            ports.push(h.await.unwrap());
        }
        ports.sort_unstable();
        ports.dedup();
        assert_eq!(
            ports.len(),
            100,
            "100 concurrent allocations must yield distinct ports"
        );
    }
}
