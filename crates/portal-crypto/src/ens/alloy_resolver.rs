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
/// # Object safety
///
/// This trait is **not object-safe** because `resolve` returns
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
}

impl<T: EnsResolver + ?Sized> ObjectSafeEnsResolver for T {
    fn resolve_boxed<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<EthAddress, EnsError>> + Send + 'a>> {
        Box::pin(self.resolve(name))
    }
}

/// Type-erased, dyn-dispatch-friendly wrapper around any [`EnsResolver`].
///
/// `BoxedEnsResolver` exists because [`EnsResolver::resolve`] returns
/// `impl Future`, which makes the trait itself non-object-safe.  This
/// newtype routes calls through a crate-sealed `ObjectSafeEnsResolver`
/// inner adapter so callers that need to hold an `Arc<dyn ...>`-shaped
/// resolver (for example, code paths that select one of several
/// resolvers at runtime) can do so without re-shaping their surface
/// around generics.
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
    struct MockEnsResolver {
        addr: Option<EthAddress>,
        not_found_name: String,
    }

    impl MockEnsResolver {
        fn resolves_to(addr: EthAddress) -> Self {
            Self {
                addr: Some(addr),
                not_found_name: String::new(),
            }
        }

        fn fails_with_not_found(name: &str) -> Self {
            Self {
                addr: None,
                not_found_name: name.to_owned(),
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
