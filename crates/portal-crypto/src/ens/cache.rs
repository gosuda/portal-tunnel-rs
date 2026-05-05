//! TTL-cache decoration over a [`BoxedEnsResolver`].
//!
//! [`CachedEnsResolver`] memoizes both forward (`name → address`) and
//! reverse (`address → Option<name>`) ENS lookups behind a configurable
//! time-to-live.  It is the v0.1 mitigation for upstream-RPC throttling
//! when an ENS-gated policy check fires inside a hot path: at the relay
//! engine's default sustained quota (~50 RPS / identity), an
//! un-cached gate would generate ~50 ENS calls/sec/identity to Infura /
//! Alchemy / Cloudflare and be throttled within seconds.
//!
//! # Semantics
//!
//! * Cache hit on a fresh entry returns the cached value without
//!   touching the inner resolver.
//! * Cache miss or stale entry calls the inner resolver, stores the
//!   result, and returns it.
//! * Inner-resolver errors are **not** cached: a failed lookup retries
//!   on the next call, so a transient ENS-RPC flake at lookup time does
//!   not poison the cache for the full TTL.
//! * Reverse-direction `Ok(None)` **is** cached: the absence of a
//!   reverse record is a stable property of the address until the
//!   operator registers one, and not caching it would defeat the cache
//!   for the common case (most addresses have no reverse record).
//!
//! # Eviction
//!
//! v0.1 ships **lazy** eviction only — stale entries are overwritten
//! on the next access for the same key, but never proactively swept.
//! The worst-case in-memory bound is the number of distinct identities
//! the relay has decided about; an active cleanup loop and an LRU /
//! size cap are out of scope for this iteration.
//!
//! # Default TTL
//!
//! [`DEFAULT_ENS_CACHE_TTL`] is 5 minutes — the v0.1 trade-off
//! between staleness on operator-driven name transfers and upstream
//! RPC pressure.  Override via [`CachedEnsResolver::new`].
//!
//! # Opt-in
//!
//! Caching is opt-in: callers explicitly wrap a [`BoxedEnsResolver`]
//! in [`CachedEnsResolver`].  The bare [`BoxedEnsResolver`] does not
//! auto-cache.
//!
//! # Status
//!
//! This is a v0.1 lazy-eviction TTL cache, not a production-grade or
//! battle-tested caching layer.  It is sufficient for the engine-side
//! Sybil-gating bypass and is shaped for that single use site.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::EthAddress;
use crate::ens::{BoxedEnsResolver, EnsError};

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/// Default TTL for [`CachedEnsResolver::with_default_ttl`] (5 minutes).
pub const DEFAULT_ENS_CACHE_TTL: Duration = Duration::from_mins(5);

// ---------------------------------------------------------------------------
// Internal entry shape
// ---------------------------------------------------------------------------

struct CacheEntry<T> {
    value: T,
    inserted_at: Instant,
}

impl<T> CacheEntry<T> {
    fn is_fresh(&self, ttl: Duration) -> bool {
        self.inserted_at.elapsed() < ttl
    }
}

// ---------------------------------------------------------------------------
// CachedEnsResolver
// ---------------------------------------------------------------------------

/// TTL-cache decoration over a [`BoxedEnsResolver`].
///
/// Two independent direction caches sit in front of the inner resolver:
///
/// * Forward: `name → EthAddress`.
/// * Reverse: `EthAddress → Option<String>`.
///
/// Both caches use [`parking_lot::RwLock<HashMap<_, _>>`].  A sync lock
/// is correct here because the cache lookup itself is non-blocking;
/// the inner resolver's `await` is the blocking part and **must** run
/// with no cache guard held — see the per-method invariant below.
///
/// `CachedEnsResolver` is the outermost layer: it does **not**
/// implement [`crate::EnsResolver`], so it cannot be re-wrapped in
/// another [`BoxedEnsResolver`].  This is deliberate; the v0.1 use
/// site does not need it.
pub struct CachedEnsResolver {
    inner: BoxedEnsResolver,
    forward: RwLock<HashMap<String, CacheEntry<EthAddress>>>,
    /// Keyed by the raw 20-byte representation of [`EthAddress`] so
    /// the cache does not need [`EthAddress`] to derive [`Hash`]; the
    /// trade-off is one stack copy per lookup of a 20-byte key, which
    /// is the minimum viable shape (no `EthAddress` derive churn,
    /// no extra newtype).
    reverse: RwLock<HashMap<[u8; 20], CacheEntry<Option<String>>>>,
    ttl: Duration,
}

impl core::fmt::Debug for CachedEnsResolver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CachedEnsResolver")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl CachedEnsResolver {
    /// Wrap `inner` with a TTL cache.
    ///
    /// Use [`Self::with_default_ttl`] for the workspace default of
    /// 5 minutes ([`DEFAULT_ENS_CACHE_TTL`]).
    #[must_use]
    pub fn new(inner: BoxedEnsResolver, ttl: Duration) -> Self {
        Self {
            inner,
            forward: RwLock::new(HashMap::new()),
            reverse: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    /// Wrap `inner` with the workspace-default 5-minute TTL.
    #[must_use]
    pub fn with_default_ttl(inner: BoxedEnsResolver) -> Self {
        Self::new(inner, DEFAULT_ENS_CACHE_TTL)
    }

    /// Cached forward resolution (name → address).
    ///
    /// On cache hit (fresh entry) the cached value is returned and
    /// the inner resolver is **not** called.  On miss or stale entry
    /// the inner resolver runs, the result is stored, and the value
    /// is returned to the caller.
    ///
    /// Errors from the inner resolver are **not** cached — a failed
    /// lookup retries on the next call.
    ///
    /// # Invariant
    ///
    /// The cache read guard is dropped **before** awaiting the inner
    /// resolver.  Holding a [`parking_lot::RwLock`] guard across an
    /// `.await` is unsound under tokio's multi-threaded scheduler
    /// (the guard is `!Send`) and would also serialize all lookups
    /// behind the slowest one.  The two scoped blocks below are
    /// load-bearing — preserve them on any future refactor.
    ///
    /// # Errors
    ///
    /// Returns whatever [`crate::EnsResolver::resolve`] returned on
    /// the underlying call (typically [`EnsError::NameNotFound`] or
    /// [`EnsError::Rpc`]).
    pub async fn resolve(&self, name: &str) -> Result<EthAddress, EnsError> {
        {
            let cache = self.forward.read();
            if let Some(entry) = cache.get(name)
                && entry.is_fresh(self.ttl)
            {
                return Ok(entry.value);
            }
        } // <-- read guard dropped here, BEFORE the await below.

        let addr = self.inner.resolve(name).await?;

        {
            let mut cache = self.forward.write();
            cache.insert(
                name.to_owned(),
                CacheEntry {
                    value: addr,
                    inserted_at: Instant::now(),
                },
            );
        }

        Ok(addr)
    }

    /// Cached reverse resolution (address → optional name).
    ///
    /// `Ok(None)` **is** cached — the absence of a reverse record is
    /// a stable property of the address until its operator registers
    /// one, and not caching it would defeat the cache for the common
    /// case (most Ethereum addresses have no reverse record).
    ///
    /// Errors from the inner resolver are **not** cached.
    ///
    /// # Invariant
    ///
    /// Same guard-dropped-before-await rule as
    /// [`Self::resolve`]; see that method's docs.
    ///
    /// # Errors
    ///
    /// Returns whatever
    /// [`crate::EnsResolver::resolve_reverse`] returned on the
    /// underlying call (typically [`EnsError::Rpc`] for transport
    /// errors).
    pub async fn resolve_reverse(&self, addr: EthAddress) -> Result<Option<String>, EnsError> {
        let key = *addr.as_bytes();

        {
            let cache = self.reverse.read();
            if let Some(entry) = cache.get(&key)
                && entry.is_fresh(self.ttl)
            {
                return Ok(entry.value.clone());
            }
        } // <-- read guard dropped here, BEFORE the await below.

        let name = self.inner.resolve_reverse(addr).await?;

        {
            let mut cache = self.reverse.write();
            cache.insert(
                key,
                CacheEntry {
                    value: name.clone(),
                    inserted_at: Instant::now(),
                },
            );
        }

        Ok(name)
    }

    /// Test-only accessor for the configured TTL.
    ///
    /// Exposed under `cfg(test)` to let unit tests assert that
    /// [`Self::with_default_ttl`] uses [`DEFAULT_ENS_CACHE_TTL`].
    #[cfg(test)]
    pub(crate) const fn ttl(&self) -> Duration {
        self.ttl
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "test helpers — panics are acceptable in #[cfg(test)]"
    )]

    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;
    use crate::ens::EnsResolver;

    // -----------------------------------------------------------------------
    // Counting test fake
    // -----------------------------------------------------------------------

    /// Test fake that returns deterministic results and counts calls
    /// per direction.  Lives in this module's test scope rather than
    /// reusing the `MockEnsResolver` from `alloy_resolver.rs` because
    /// that fake is private to its own `mod tests` and not reachable
    /// across sibling modules.
    struct CountingEnsResolver {
        forward_calls: Arc<AtomicUsize>,
        reverse_calls: Arc<AtomicUsize>,
        forward_addr: EthAddress,
        reverse_name: Option<String>,
        /// When `true`, forward calls return `EnsError::NameNotFound`;
        /// the test flips this back to `false` to verify error retries.
        forward_should_fail: Arc<AtomicBool>,
    }

    impl CountingEnsResolver {
        fn new(forward_addr: EthAddress, reverse_name: Option<String>) -> Self {
            Self {
                forward_calls: Arc::new(AtomicUsize::new(0)),
                reverse_calls: Arc::new(AtomicUsize::new(0)),
                forward_addr,
                reverse_name,
                forward_should_fail: Arc::new(AtomicBool::new(false)),
            }
        }

        fn forward_counter(&self) -> Arc<AtomicUsize> {
            Arc::clone(&self.forward_calls)
        }

        fn reverse_counter(&self) -> Arc<AtomicUsize> {
            Arc::clone(&self.reverse_calls)
        }

        fn fail_flag(&self) -> Arc<AtomicBool> {
            Arc::clone(&self.forward_should_fail)
        }
    }

    impl EnsResolver for CountingEnsResolver {
        #[expect(
            clippy::manual_async_fn,
            reason = "explicit impl Future + Send return is required to satisfy the trait's Send bound"
        )]
        fn resolve<'a>(
            &'a self,
            name: &'a str,
        ) -> impl Future<Output = Result<EthAddress, EnsError>> + Send + 'a {
            async move {
                self.forward_calls.fetch_add(1, Ordering::SeqCst);
                if self.forward_should_fail.load(Ordering::SeqCst) {
                    return Err(EnsError::NameNotFound(name.to_owned()));
                }
                Ok(self.forward_addr)
            }
        }

        #[expect(
            clippy::manual_async_fn,
            reason = "explicit impl Future + Send return is required to satisfy the trait's Send bound"
        )]
        fn resolve_reverse(
            &self,
            _addr: EthAddress,
        ) -> impl Future<Output = Result<Option<String>, EnsError>> + Send + '_ {
            async move {
                self.reverse_calls.fetch_add(1, Ordering::SeqCst);
                Ok(self.reverse_name.clone())
            }
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn fixed_addr(byte: u8) -> EthAddress {
        EthAddress::new([byte; 20])
    }

    // -----------------------------------------------------------------------
    // Forward direction
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn forward_cache_hit_avoids_inner_call() {
        let inner = CountingEnsResolver::new(fixed_addr(0xAA), None);
        let counter = inner.forward_counter();
        let cache = CachedEnsResolver::new(BoxedEnsResolver::new(inner), Duration::from_mins(1));

        let _ = cache.resolve("foo.eth").await.expect("first call resolves");
        let _ = cache
            .resolve("foo.eth")
            .await
            .expect("second call resolves from cache");

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "second forward call must be served from cache"
        );
    }

    #[tokio::test]
    async fn forward_cache_miss_calls_inner() {
        let inner = CountingEnsResolver::new(fixed_addr(0xBB), None);
        let counter = inner.forward_counter();
        let cache = CachedEnsResolver::new(BoxedEnsResolver::new(inner), Duration::from_mins(1));

        let _ = cache.resolve("foo.eth").await.expect("first name resolves");
        let _ = cache
            .resolve("bar.eth")
            .await
            .expect("second name resolves");

        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "distinct names must each hit the inner resolver"
        );
    }

    #[tokio::test]
    async fn forward_cache_expires_after_ttl() {
        let inner = CountingEnsResolver::new(fixed_addr(0xCC), None);
        let counter = inner.forward_counter();
        let cache = CachedEnsResolver::new(BoxedEnsResolver::new(inner), Duration::from_millis(50));

        let _ = cache.resolve("foo.eth").await.expect("first call resolves");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = cache
            .resolve("foo.eth")
            .await
            .expect("second call resolves after TTL");

        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "stale entry must trigger a re-fetch"
        );
    }

    #[tokio::test]
    async fn forward_inner_error_is_not_cached() {
        let inner = CountingEnsResolver::new(fixed_addr(0xDD), None);
        let counter = inner.forward_counter();
        let fail = inner.fail_flag();
        fail.store(true, Ordering::SeqCst);

        let cache = CachedEnsResolver::new(BoxedEnsResolver::new(inner), Duration::from_mins(1));

        let err = cache
            .resolve("foo.eth")
            .await
            .expect_err("first call should fail");
        assert!(
            matches!(err, EnsError::NameNotFound(_)),
            "expected NameNotFound, got {err:?}",
        );

        // Flip the inner to success: the second call must hit the inner
        // again (error not cached) and succeed.
        fail.store(false, Ordering::SeqCst);
        let addr = cache
            .resolve("foo.eth")
            .await
            .expect("second call should succeed because errors are not cached");
        assert_eq!(addr, fixed_addr(0xDD));
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "inner must be called twice — errors are not cached",
        );
    }

    // -----------------------------------------------------------------------
    // Reverse direction
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn reverse_cache_hit_avoids_inner_call() {
        let inner = CountingEnsResolver::new(fixed_addr(0xEE), Some("foo.eth".to_owned()));
        let counter = inner.reverse_counter();
        let cache = CachedEnsResolver::new(BoxedEnsResolver::new(inner), Duration::from_mins(1));

        let addr = fixed_addr(0x11);
        let _ = cache
            .resolve_reverse(addr)
            .await
            .expect("first reverse resolves");
        let _ = cache
            .resolve_reverse(addr)
            .await
            .expect("second reverse from cache");

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "second reverse call must be served from cache"
        );
    }

    #[tokio::test]
    async fn reverse_cache_caches_none() {
        let inner = CountingEnsResolver::new(fixed_addr(0xEE), None);
        let counter = inner.reverse_counter();
        let cache = CachedEnsResolver::new(BoxedEnsResolver::new(inner), Duration::from_mins(1));

        let addr = fixed_addr(0x22);
        let first = cache
            .resolve_reverse(addr)
            .await
            .expect("first reverse resolves");
        let second = cache
            .resolve_reverse(addr)
            .await
            .expect("second reverse from cache");

        assert_eq!(first, None);
        assert_eq!(second, None);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "Ok(None) must be cached so the absence of a reverse record \
             does not defeat the cache for the common case",
        );
    }

    #[tokio::test]
    async fn reverse_cache_miss_for_distinct_addresses() {
        let inner = CountingEnsResolver::new(fixed_addr(0xEE), Some("foo.eth".to_owned()));
        let counter = inner.reverse_counter();
        let cache = CachedEnsResolver::new(BoxedEnsResolver::new(inner), Duration::from_mins(1));

        let _ = cache
            .resolve_reverse(fixed_addr(0x33))
            .await
            .expect("first addr resolves");
        let _ = cache
            .resolve_reverse(fixed_addr(0x44))
            .await
            .expect("second addr resolves");

        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "distinct addresses must each hit the inner resolver"
        );
    }

    #[tokio::test]
    async fn reverse_cache_expires_after_ttl() {
        let inner = CountingEnsResolver::new(fixed_addr(0xEE), Some("foo.eth".to_owned()));
        let counter = inner.reverse_counter();
        let cache = CachedEnsResolver::new(BoxedEnsResolver::new(inner), Duration::from_millis(50));

        let addr = fixed_addr(0x55);
        let _ = cache
            .resolve_reverse(addr)
            .await
            .expect("first reverse resolves");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = cache
            .resolve_reverse(addr)
            .await
            .expect("second reverse after TTL");

        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "stale reverse entry must trigger a re-fetch"
        );
    }

    // -----------------------------------------------------------------------
    // Constructor / TTL shape
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn with_default_ttl_uses_5_minutes() {
        let inner = CountingEnsResolver::new(fixed_addr(0xFF), None);
        let cache = CachedEnsResolver::with_default_ttl(BoxedEnsResolver::new(inner));

        assert_eq!(
            cache.ttl(),
            DEFAULT_ENS_CACHE_TTL,
            "with_default_ttl must use the workspace 5-minute default"
        );
        assert_eq!(
            DEFAULT_ENS_CACHE_TTL,
            Duration::from_mins(5),
            "DEFAULT_ENS_CACHE_TTL contract: 5 minutes"
        );
    }
}
