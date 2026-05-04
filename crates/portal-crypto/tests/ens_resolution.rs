//! ENS resolution integration tests.
//!
//! # Implementation decision: mock-impl path
//!
//! Alloy's JSON-RPC transport applies its own framing (JSON-RPC 2.0 batch
//! requests, provider polling, EIP-1898 block tags) that does not map cleanly
//! to wiremock's HTTP-level request matchers without re-implementing a
//! substantial subset of the alloy transport layer.  Rather than adding that
//! complexity and fragility, this file takes the **mock-impl** path described
//! in the B8 spec:
//!
//! - A minimal `MockEnsResolver` implements the [`portal_crypto::EnsResolver`]
//!   trait in-process, returning a pre-programmed address.
//! - The live-network test is retained as an `#[ignore]`-gated case that can be
//!   run manually against `https://cloudflare-eth.com`.
//!
//! This mirrors the pattern already established in
//! `crates/portal-crypto/src/ens/alloy_resolver.rs` (the `mock_resolver_*`
//! unit tests there) but promotes it to a crate-level integration test so the
//! public `EnsResolver` trait contract is exercised through the crate boundary.
//!
//! Phase 2 B8 / U13 integration gate.

use std::future::Future;

use portal_crypto::{AlloyEnsResolver, EnsError, EnsResolver, EthAddress};

// ---------------------------------------------------------------------------
// Inline mock resolver
// ---------------------------------------------------------------------------

/// Parse a hex address string (with or without `0x` prefix) into an
/// [`EthAddress`].  Returns `Err` if the string is not exactly 40 hex chars
/// after stripping the optional `0x`.
fn parse_addr_hex(s: &str) -> Result<EthAddress, String> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if hex.len() != 40 {
        return Err(format!("expected 40 hex chars, got {}", hex.len()));
    }
    let mut bytes = [0u8; 20];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        bytes[i] = (hi << 4) | lo;
    }
    Ok(EthAddress::new(bytes))
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex char: {b:#x}")),
    }
}

/// In-process mock that returns a pre-programmed address for any name.
struct MockEnsResolver {
    result: Result<EthAddress, EnsError>,
}

impl MockEnsResolver {
    const fn resolves_to(addr: EthAddress) -> Self {
        Self { result: Ok(addr) }
    }

    fn not_found(name: &str) -> Self {
        Self {
            result: Err(EnsError::NameNotFound(name.to_owned())),
        }
    }
}

impl EnsResolver for MockEnsResolver {
    fn resolve<'a>(
        &'a self,
        _name: &'a str,
    ) -> impl Future<Output = Result<EthAddress, EnsError>> + Send + 'a {
        let result = match &self.result {
            Ok(addr) => Ok(*addr),
            Err(EnsError::NameNotFound(n)) => Err(EnsError::NameNotFound(n.clone())),
            Err(EnsError::Rpc(m)) => Err(EnsError::Rpc(m.clone())),
            Err(EnsError::InvalidAddress) => Err(EnsError::InvalidAddress),
            // `EnsError` is `#[non_exhaustive]`; this arm handles any future variants.
            Err(_) => Err(EnsError::Rpc("unknown mock error".to_owned())),
        };
        async move { result }
    }
}

// ---------------------------------------------------------------------------
// Integration tests via mock
// ---------------------------------------------------------------------------

/// Resolving "vitalik.eth" via a mock resolver returns the expected address
/// and its `Display` form matches the EIP-55 checksum.
#[tokio::test]
async fn mock_ens_resolves_vitalik_eth() -> Result<(), Box<dyn std::error::Error>> {
    // vitalik.eth → 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
    let expected = parse_addr_hex("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045")?;
    let resolver = MockEnsResolver::resolves_to(expected);

    let addr = resolver.resolve("vitalik.eth").await?;

    assert_eq!(
        format!("{addr}"),
        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        "Display must emit EIP-55 checksum form"
    );
    Ok(())
}

/// Resolving a name with no registry entry returns `EnsError::NameNotFound`.
#[tokio::test]
async fn mock_ens_not_found_returns_correct_variant() -> Result<(), Box<dyn std::error::Error>> {
    let resolver = MockEnsResolver::not_found("nxdomain.eth");
    let err = resolver
        .resolve("nxdomain.eth")
        .await
        .err()
        .ok_or("expected Err, got Ok")?;

    assert!(
        matches!(err, EnsError::NameNotFound(_)),
        "expected NameNotFound, got {err:?}"
    );
    Ok(())
}

/// A bad RPC URL causes `AlloyEnsResolver::from_rpc_url` to return
/// `EnsError::Rpc`, testing the production constructor's error path.
#[tokio::test]
async fn alloy_from_rpc_url_bad_url_returns_rpc_error() {
    let result = AlloyEnsResolver::from_rpc_url("not://a valid url !!!").await;
    assert!(
        matches!(result, Err(EnsError::Rpc(_))),
        "expected Rpc error for malformed URL, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Live-network test (manual only)
// ---------------------------------------------------------------------------

/// Live ENS resolution of "vitalik.eth" against Cloudflare's public Ethereum
/// JSON-RPC endpoint.
///
/// Run manually:
/// ```text
/// cargo nextest run -p portal-crypto --run-ignored only -- live_ens_cloudflare
/// ```
#[tokio::test]
#[ignore = "manual run only — requires live Ethereum RPC: cargo nextest run -p portal-crypto --run-ignored only -- live_ens_cloudflare"]
async fn live_ens_cloudflare() -> Result<(), Box<dyn std::error::Error>> {
    let resolver = AlloyEnsResolver::from_rpc_url("https://cloudflare-eth.com").await?;
    let addr = resolver.resolve("vitalik.eth").await?;
    assert_eq!(
        format!("{addr}"),
        "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
    );
    Ok(())
}
