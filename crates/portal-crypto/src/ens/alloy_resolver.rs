//! ENS resolver trait and alloy-backed production implementation.
//!
//! [`EnsResolver`] is the Send-bounded async trait that callers hold.
//! [`AlloyEnsResolver`] is the production implementation backed by an HTTP
//! JSON-RPC endpoint via `alloy-ens`.
//!
//! # Example
//!
//! ```rust,no_run
//! use portal_crypto::{AlloyEnsResolver, EnsResolver};
//!
//! # async fn run() -> Result<(), portal_crypto::EnsError> {
//! let resolver = AlloyEnsResolver::from_rpc_url("https://mainnet.infura.io/v3/KEY").await?;
//! let addr = resolver.resolve("vitalik.eth").await?;
//! println!("{addr}");
//! # Ok(())
//! # }
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use alloy::network::Ethereum;
use alloy::providers::{ProviderBuilder, RootProvider};
use alloy_ens::ProviderEnsExt as _;
use thiserror::Error;

use crate::EthAddress;

// ---------------------------------------------------------------------------
// EnsError
// ---------------------------------------------------------------------------

/// Errors that can occur during ENS name resolution.
///
/// This type is `#[non_exhaustive]` so that future alloy API changes can
/// introduce new mapping categories without breaking existing match arms.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum EnsError {
    /// The name was not found in the ENS registry (no resolver registered).
    #[error("ENS name not found: {0}")]
    NameNotFound(String),

    /// An RPC or contract error occurred while resolving the name.
    #[error("ENS RPC error: {0}")]
    Rpc(String),

    /// The resolved address bytes could not be interpreted as a valid address.
    #[error("ENS resolved an invalid address")]
    InvalidAddress,
}

// ---------------------------------------------------------------------------
// EnsResolver trait
// ---------------------------------------------------------------------------

/// Async ENS name resolver.
///
/// This trait is `Send + Sync`-bounded so implementations can be held across
/// `.await` points in tokio multi-threaded schedulers and shared via `Arc`.
/// The production implementation is [`AlloyEnsResolver`]; tests inject a mock.
///
/// Note: `trait_variant` was evaluated for generating a paired non-Send
/// local variant, but its proc-macro-generated code triggers
/// `clippy::future_not_send` at a span outside the reach of item-level
/// `#[expect]` attributes, causing the `-D warnings` gate to fail.  The trait
/// is therefore defined directly with the `Send + Sync` bounds callers require.
///
/// Two directions are exposed:
///
/// * [`Self::resolve`] — forward (`name → address`).
/// * [`Self::resolve_reverse`] — reverse (`address → Option<name>`).
///
/// # Object safety
///
/// This trait is **not object-safe** because its methods return
/// `impl Future`. Callers must hold the concrete type, or wrap any
/// `EnsResolver` impl in [`BoxedEnsResolver`] for dynamic dispatch
/// (which routes through a crate-sealed inner trait that returns
/// `Pin<Box<dyn Future<...> + Send>>`).
pub trait EnsResolver: Send + Sync {
    /// Resolve an ENS name to an Ethereum address.
    ///
    /// Returns [`EnsError::NameNotFound`] if the name has no registered
    /// resolver, or [`EnsError::Rpc`] on any transport / contract error.
    ///
    /// The explicit `impl Future + Send + 'a` return constrains the future to
    /// be `Send`, which is required for use in tokio multi-threaded schedulers.
    /// `async fn` syntax is intentionally not used in the trait declaration
    /// because it cannot express the `Send` auto-trait bound on the returned
    /// future.  Implementors must suppress `clippy::manual_async_fn` on their
    /// impl bodies.
    fn resolve<'a>(
        &'a self,
        name: &'a str,
    ) -> impl Future<Output = Result<EthAddress, EnsError>> + Send + 'a;

    /// Reverse-resolve an Ethereum address to its primary ENS name
    /// (the name configured via the `addr.reverse` resolver).
    ///
    /// Returns `Ok(Some(name))` when the address has a reverse record.
    /// Returns `Ok(None)` when no reverse record is registered — this is
    /// the **expected** result for the majority of Ethereum addresses;
    /// callers must NOT treat it as an error.  Returns
    /// [`EnsError::Rpc`] only on actual transport / contract failures,
    /// never on "no reverse record".
    ///
    /// This is the inverse of [`Self::resolve`]: forward resolution
    /// answers "what address does `vitalik.eth` map to?", reverse
    /// resolution answers "is `0xd8dA…` ENS-named, and if so, by what
    /// name?".
    ///
    /// Note: this method returns whatever name the reverse-resolver
    /// claims; it does not forward-verify that the returned name
    /// resolves back to `addr`.  Security-sensitive callers (e.g. the
    /// R10 Sybil-gating bypass at
    /// `crates/portal-relay/src/policy/reputation.rs`) should perform
    /// that round-trip themselves via [`Self::resolve`] before treating
    /// the name as authoritative.
    ///
    /// The returned future's lifetime is elided to `&self`'s lifetime;
    /// `addr` is an owned [`EthAddress`] so no extra borrow is captured.
    fn resolve_reverse(
        &self,
        addr: EthAddress,
    ) -> impl Future<Output = Result<Option<String>, EnsError>> + Send + '_;
}

// ---------------------------------------------------------------------------
// BoxedEnsResolver — dyn-dispatch adapter
// ---------------------------------------------------------------------------

/// Object-safe sibling of [`EnsResolver`] that returns a boxed future.
///
/// Sealed at the crate boundary: external crates implement [`EnsResolver`] and
/// reach [`BoxedEnsResolver`] only through [`BoxedEnsResolver::new`] /
/// [`BoxedEnsResolver::from_arc`], never by impl-ing this trait directly.
/// The trait is declared `pub` because the enclosing `ens` module is
/// `pub(crate)` in `lib.rs`, which already caps visibility at the crate
/// root; an explicit inner `pub(crate)` would only fire
/// `clippy::redundant_pub_crate`.  The blanket
/// `impl<T: EnsResolver + ?Sized>` below routes every existing resolver
/// through `Box::pin` so an `Arc<dyn ObjectSafeEnsResolver>` is usable
/// wherever dynamic dispatch is required.
pub trait ObjectSafeEnsResolver: Send + Sync {
    fn resolve_boxed<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<EthAddress, EnsError>> + Send + 'a>>;

    fn resolve_reverse_boxed<'a>(
        &'a self,
        addr: EthAddress,
    ) -> Pin<Box<dyn Future<Output = Result<Option<String>, EnsError>> + Send + 'a>>;
}

impl<T: EnsResolver + ?Sized> ObjectSafeEnsResolver for T {
    fn resolve_boxed<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<EthAddress, EnsError>> + Send + 'a>> {
        Box::pin(self.resolve(name))
    }

    fn resolve_reverse_boxed<'a>(
        &'a self,
        addr: EthAddress,
    ) -> Pin<Box<dyn Future<Output = Result<Option<String>, EnsError>> + Send + 'a>> {
        Box::pin(self.resolve_reverse(addr))
    }
}

/// Type-erased, dyn-dispatch-friendly wrapper around any [`EnsResolver`].
///
/// `BoxedEnsResolver` exists because [`EnsResolver`]'s methods return
/// `impl Future`, which makes the trait itself non-object-safe.  This
/// newtype routes both [`Self::resolve`] (forward) and
/// [`Self::resolve_reverse`] (reverse) through a crate-sealed
/// `ObjectSafeEnsResolver` inner adapter so callers that need to hold
/// an `Arc<dyn ...>`-shaped resolver (for example, code paths that
/// select one of several resolvers at runtime) can do so without
/// re-shaping their surface around generics.
///
/// Cloning is cheap: it bumps the inner `Arc` refcount.  No consumer in
/// the workspace currently holds a `BoxedEnsResolver`; this type is the
/// dyn-dispatch adapter, available for future call sites that need it.
#[derive(Clone)]
pub struct BoxedEnsResolver(Arc<dyn ObjectSafeEnsResolver>);

impl BoxedEnsResolver {
    /// Wrap any [`EnsResolver`] impl for dynamic dispatch.
    pub fn new<R: EnsResolver + 'static>(resolver: R) -> Self {
        Self(Arc::new(resolver))
    }

    /// Wrap an already-`Arc`'d resolver without re-allocating.
    pub fn from_arc<R: EnsResolver + 'static>(resolver: Arc<R>) -> Self {
        Self(resolver)
    }

    /// Resolve an ENS name through dynamic dispatch.
    ///
    /// Returns the same `Pin<Box<dyn Future...>>` shape that
    /// `tokio::spawn` and similar consumers expect.
    #[must_use = "futures do nothing unless awaited"]
    pub fn resolve<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<EthAddress, EnsError>> + Send + 'a>> {
        self.0.resolve_boxed(name)
    }

    /// Reverse-resolve through dynamic dispatch.
    ///
    /// Same `Ok(Some(name))` / `Ok(None)` / `Err(Rpc)` semantics as
    /// [`EnsResolver::resolve_reverse`].
    #[must_use = "futures do nothing unless awaited"]
    pub fn resolve_reverse<'a>(
        &'a self,
        addr: EthAddress,
    ) -> Pin<Box<dyn Future<Output = Result<Option<String>, EnsError>> + Send + 'a>> {
        self.0.resolve_reverse_boxed(addr)
    }
}

impl core::fmt::Debug for BoxedEnsResolver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BoxedEnsResolver").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// AlloyEnsResolver — production implementation
// ---------------------------------------------------------------------------

/// Production ENS resolver backed by an Ethereum JSON-RPC endpoint.
///
/// Wraps a `RootProvider<Ethereum>` behind an `Arc` so the underlying
/// `reqwest` HTTP connection pool is reused across calls.  Cloning the
/// resolver clones the `Arc`, sharing the same pool.
///
/// The mainnet ENS Universal Resolver address
/// (`0xeeeeeeee14d718c2b47d9923deab1335e144eeee`) is used by `alloy-ens`
/// automatically; the RPC endpoint must point at Ethereum mainnet.
#[derive(Clone, Debug)]
pub struct AlloyEnsResolver {
    provider: Arc<RootProvider<Ethereum>>,
}

impl AlloyEnsResolver {
    /// Construct an [`AlloyEnsResolver`] from a pre-built `RootProvider`.
    ///
    /// This constructor is intended for tests that inject a provider backed
    /// by a mock or wiremock server.  Production callers should prefer
    /// [`AlloyEnsResolver::from_rpc_url`].
    #[must_use]
    pub const fn new(provider: Arc<RootProvider<Ethereum>>) -> Self {
        Self { provider }
    }

    /// Build an [`AlloyEnsResolver`] from an HTTP(S) RPC URL string.
    ///
    /// Creates a `RootProvider<Ethereum>` with the `reqwest` HTTP transport
    /// and wraps it in an `Arc`.  Returns [`EnsError::Rpc`] if the URL
    /// cannot be parsed or the transport cannot be initialised.
    ///
    /// # Errors
    ///
    /// Returns [`EnsError::Rpc`] on URL-parse failure or transport error.
    pub async fn from_rpc_url(url: &str) -> Result<Self, EnsError> {
        let provider: RootProvider<Ethereum> = ProviderBuilder::new()
            .disable_recommended_fillers()
            .connect(url)
            .await
            .map_err(|e| EnsError::Rpc(format!("transport error: {e}")))?;
        Ok(Self {
            provider: Arc::new(provider),
        })
    }
}

impl EnsResolver for AlloyEnsResolver {
    #[expect(
        clippy::manual_async_fn,
        reason = "explicit impl Future + Send return is required to satisfy the trait's Send bound"
    )]
    fn resolve<'a>(
        &'a self,
        name: &'a str,
    ) -> impl Future<Output = Result<EthAddress, EnsError>> + Send + 'a {
        async move {
            let alloy_addr = self
                .provider
                .resolve_name(name)
                .await
                .map_err(|e| match e {
                    alloy_ens::EnsError::ResolverNotFound(_) => {
                        EnsError::NameNotFound(name.to_owned())
                    }
                    other => EnsError::Rpc(other.to_string()),
                })?;

            // alloy `Address` is `FixedBytes<20>` (newtype chain:
            // `Address` → `.0` = `FixedBytes<20>` → `.0.0` = `[u8; 20]`).
            Ok(EthAddress::new(alloy_addr.0.0))
        }
    }

    #[expect(
        clippy::manual_async_fn,
        reason = "explicit impl Future + Send return is required to satisfy the trait's Send bound"
    )]
    fn resolve_reverse(
        &self,
        addr: EthAddress,
    ) -> impl Future<Output = Result<Option<String>, EnsError>> + Send + '_ {
        async move {
            let alloy_addr = alloy::primitives::Address::from(addr.as_bytes());
            match self.provider.lookup_address(&alloy_addr).await {
                // Resolver registered but no name set → no reverse record.
                Ok(name) if name.is_empty() => Ok(None),
                Ok(name) => Ok(Some(name)),
                // No reverse-registrar resolver for this address →
                // no reverse record (the EXPECTED state for most addresses).
                Err(alloy_ens::EnsError::ResolverNotFound(_)) => Ok(None),
                // Genuine transport / contract failure.
                Err(other) => Err(EnsError::Rpc(other.to_string())),
            }
        }
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

    use super::*;

    // -----------------------------------------------------------------------
    // Mock resolver for trait-level unit testing
    // -----------------------------------------------------------------------

    /// A test-only mock that returns a pre-programmed address or error.
    ///
    /// The forward-resolution fields (`addr`, `not_found_name`) and the
    /// reverse-resolution fields (`reverse_addr`, `reverse_name`) are
    /// independent: a mock built via [`Self::resolves_to`] has no reverse
    /// record, and a mock built via [`Self::reverse_resolves_to`] returns
    /// `EnsError::NameNotFound` on forward lookups (the default for an
    /// unset `addr`).
    struct MockEnsResolver {
        addr: Option<EthAddress>,
        not_found_name: String,
        reverse_addr: Option<EthAddress>,
        reverse_name: String,
    }

    impl MockEnsResolver {
        fn resolves_to(addr: EthAddress) -> Self {
            Self {
                addr: Some(addr),
                not_found_name: String::new(),
                reverse_addr: None,
                reverse_name: String::new(),
            }
        }

        fn fails_with_not_found(name: &str) -> Self {
            Self {
                addr: None,
                not_found_name: name.to_owned(),
                reverse_addr: None,
                reverse_name: String::new(),
            }
        }

        fn reverse_resolves_to(addr: EthAddress, name: &str) -> Self {
            Self {
                addr: None,
                not_found_name: String::new(),
                reverse_addr: Some(addr),
                reverse_name: name.to_owned(),
            }
        }
    }

    impl EnsResolver for MockEnsResolver {
        #[expect(
            clippy::manual_async_fn,
            reason = "explicit impl Future + Send return is required to satisfy the trait's Send bound"
        )]
        fn resolve<'a>(
            &'a self,
            _name: &'a str,
        ) -> impl Future<Output = Result<EthAddress, EnsError>> + Send + 'a {
            async move {
                self.addr.map_or_else(
                    || Err(EnsError::NameNotFound(self.not_found_name.clone())),
                    Ok,
                )
            }
        }

        #[expect(
            clippy::manual_async_fn,
            reason = "explicit impl Future + Send return is required to satisfy the trait's Send bound"
        )]
        fn resolve_reverse(
            &self,
            addr: EthAddress,
        ) -> impl Future<Output = Result<Option<String>, EnsError>> + Send + '_ {
            async move {
                match self.reverse_addr {
                    Some(known) if known == addr => Ok(Some(self.reverse_name.clone())),
                    _ => Ok(None),
                }
            }
        }
    }

    /// Helper: parse a hex address string (with or without `0x` prefix) into
    /// an `EthAddress`.  Test-only.
    ///
    /// # Panics
    ///
    /// Panics if the input is not exactly 40 hex chars (after stripping `0x`).
    fn parse_addr_hex(s: &str) -> EthAddress {
        let hex = s.strip_prefix("0x").unwrap_or(s);
        assert_eq!(hex.len(), 40, "address must be 40 hex chars");
        let mut bytes = [0u8; 20];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            // to_digit(16) returns 0–15; both nibbles are guaranteed to fit u8.
            let hi = u8::try_from(
                (chunk[0] as char)
                    .to_digit(16)
                    .expect("valid hex nibble in address string"),
            )
            .expect("hex nibble 0–15 fits in u8");
            let lo = u8::try_from(
                (chunk[1] as char)
                    .to_digit(16)
                    .expect("valid hex nibble in address string"),
            )
            .expect("hex nibble 0–15 fits in u8");
            bytes[i] = (hi << 4) | lo;
        }
        EthAddress::new(bytes)
    }

    // -----------------------------------------------------------------------
    // Trait-level unit tests via mock
    // -----------------------------------------------------------------------

    /// Resolving a known name via a mock resolver returns the correct address.
    #[tokio::test]
    async fn mock_resolver_resolves_known_name() {
        // vitalik.eth → 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
        let expected = parse_addr_hex("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        let resolver = MockEnsResolver::resolves_to(expected);

        let got = resolver
            .resolve("vitalik.eth")
            .await
            .expect("should resolve");
        assert_eq!(
            format!("{got}"),
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            "resolved address must match EIP-55 checksum form"
        );
    }

    /// Resolving a name that has no resolver in the registry returns
    /// `EnsError::NameNotFound`.
    #[tokio::test]
    async fn mock_resolver_returns_not_found() {
        let resolver = MockEnsResolver::fails_with_not_found("nxdomain.eth");
        let err = resolver
            .resolve("nxdomain.eth")
            .await
            .expect_err("should return error");
        assert!(
            matches!(err, EnsError::NameNotFound(_)),
            "expected NameNotFound, got {err:?}"
        );
    }

    /// `EnsError` converts into `PortalCryptoError::Ens` via `#[from]`.
    #[test]
    fn ens_error_converts_to_portal_crypto_error() {
        use crate::PortalCryptoError;
        let ens_err = EnsError::NameNotFound("test.eth".to_owned());
        let crypto_err: PortalCryptoError = ens_err.into();
        assert!(
            matches!(crypto_err, PortalCryptoError::Ens(_)),
            "expected PortalCryptoError::Ens, got {crypto_err:?}"
        );
    }

    /// A bad RPC URL causes `from_rpc_url` to return `EnsError::Rpc`.
    #[tokio::test]
    async fn from_rpc_url_bad_url_returns_rpc_error() {
        let err = AlloyEnsResolver::from_rpc_url("not://a valid url !!!")
            .await
            .expect_err("bad URL should fail");
        assert!(
            matches!(err, EnsError::Rpc(_)),
            "expected Rpc error for bad URL, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // BoxedEnsResolver — dyn-dispatch adapter
    // -----------------------------------------------------------------------

    /// Wrapping a working mock resolver in `BoxedEnsResolver::new` round-trips
    /// the resolved address through the `Arc<dyn ObjectSafeEnsResolver>` indirection.
    #[tokio::test]
    async fn boxed_resolver_round_trips_resolves_to_address() {
        let expected = parse_addr_hex("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        let inner = MockEnsResolver::resolves_to(expected);
        let resolver = BoxedEnsResolver::new(inner);

        let got = resolver
            .resolve("vitalik.eth")
            .await
            .expect("boxed resolver should resolve");
        assert_eq!(
            got, expected,
            "BoxedEnsResolver must propagate the inner resolver's address"
        );
    }

    /// Wrapping a not-found mock resolver propagates `EnsError::NameNotFound`
    /// through the dyn-dispatch boundary unchanged.
    #[tokio::test]
    async fn boxed_resolver_round_trips_name_not_found() {
        let inner = MockEnsResolver::fails_with_not_found("missing.eth");
        let resolver = BoxedEnsResolver::new(inner);

        let err = resolver
            .resolve("missing.eth")
            .await
            .expect_err("boxed resolver should surface the not-found error");
        match err {
            EnsError::NameNotFound(name) => assert_eq!(name, "missing.eth"),
            other => panic!("expected NameNotFound(\"missing.eth\"), got {other:?}"),
        }
    }

    /// Cloning a `BoxedEnsResolver` produces a second handle that resolves
    /// successfully and returns the same address as the original.
    ///
    /// This test deliberately does NOT claim to verify shared `Arc` identity:
    /// proving that strictly would require either pointer-identity introspection
    /// on the inner `Arc<dyn ...>` (which the spec disallows because of
    /// `Arc::ptr_eq` ambiguity on `dyn`) or extra test-only API surface, which
    /// would violate the smallest-diff guideline.  The weaker shape here is
    /// exactly the fallback the spec sanctions: "just call `.resolve(...)` on
    /// both clones and assert both return the expected value."
    #[tokio::test]
    async fn boxed_resolver_clone_returns_same_address_on_both_handles() {
        let expected = parse_addr_hex("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        let resolver = BoxedEnsResolver::new(MockEnsResolver::resolves_to(expected));
        let clone = resolver.clone();

        let got_orig = resolver
            .resolve("vitalik.eth")
            .await
            .expect("original handle should resolve");
        let got_clone = clone
            .resolve("vitalik.eth")
            .await
            .expect("cloned handle should resolve");

        assert_eq!(got_orig, expected);
        assert_eq!(got_clone, expected);
    }

    // -----------------------------------------------------------------------
    // resolve_reverse — mock-only unit tests
    // -----------------------------------------------------------------------

    /// A mock configured with `reverse_resolves_to` returns `Ok(Some(name))`
    /// when queried for the matching address.
    #[tokio::test]
    async fn mock_resolve_reverse_returns_name_when_configured() {
        let addr = parse_addr_hex("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        let resolver = MockEnsResolver::reverse_resolves_to(addr, "vitalik.eth");

        let got = resolver
            .resolve_reverse(addr)
            .await
            .expect("reverse resolution must not error");
        assert_eq!(got, Some("vitalik.eth".to_owned()));
    }

    /// Querying an address other than the one configured returns `Ok(None)`,
    /// not an error.
    #[tokio::test]
    async fn mock_resolve_reverse_returns_none_for_unconfigured_address() {
        let known = parse_addr_hex("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        let other = parse_addr_hex("0000000000000000000000000000000000000001");
        let resolver = MockEnsResolver::reverse_resolves_to(known, "vitalik.eth");

        let got = resolver
            .resolve_reverse(other)
            .await
            .expect("reverse resolution for other address must not error");
        assert_eq!(got, None);
    }

    /// A mock built via the forward-only `resolves_to` constructor has no
    /// reverse data and therefore returns `Ok(None)` for any reverse query.
    #[tokio::test]
    async fn mock_resolve_reverse_returns_none_when_no_reverse_configured() {
        let addr = parse_addr_hex("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        let resolver = MockEnsResolver::resolves_to(addr);

        let got = resolver
            .resolve_reverse(addr)
            .await
            .expect("reverse resolution must not error");
        assert_eq!(got, None);
    }

    /// `BoxedEnsResolver::resolve_reverse` round-trips through the
    /// dyn-dispatch indirection to the underlying mock.
    #[tokio::test]
    async fn boxed_resolver_round_trips_resolve_reverse() {
        let addr = parse_addr_hex("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
        let inner = MockEnsResolver::reverse_resolves_to(addr, "vitalik.eth");
        let boxed = BoxedEnsResolver::new(inner);

        let got = boxed
            .resolve_reverse(addr)
            .await
            .expect("boxed reverse resolution must not error");
        assert_eq!(got, Some("vitalik.eth".to_owned()));
    }

    // -----------------------------------------------------------------------
    // Live network test — manual only, skipped in CI
    // -----------------------------------------------------------------------

    /// Live ENS resolution against a public Ethereum RPC.
    ///
    /// Run manually with:
    /// ```text
    /// cargo nextest run -p portal-crypto --run-ignored only -- live_ens
    /// ```
    #[tokio::test]
    #[ignore = "manual run via cargo nextest run -p portal-crypto --run-ignored only -- live_ens"]
    async fn live_ens_vitalik_eth() {
        let resolver = AlloyEnsResolver::from_rpc_url("https://ethereum.reth.rs/rpc")
            .await
            .expect("failed to build AlloyEnsResolver");
        let addr = resolver
            .resolve("vitalik.eth")
            .await
            .expect("live ENS resolution failed");
        // vitalik.eth → 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
        assert_eq!(
            format!("{addr}"),
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        );
    }
}
