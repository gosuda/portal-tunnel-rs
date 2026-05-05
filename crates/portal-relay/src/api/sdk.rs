//! SDK trust-boundary endpoint handlers.
//!
//! ## Endpoints
//!
//! - `GET /v1/sdk/domain` — bootstrap-time deployment-constant
//!   identity surface. Returns the relay's protocol/release version
//!   pair so the SDK can pin the wire surface it is talking to before
//!   it has any keys to authenticate. No state extraction; no rate
//!   limit; no authentication. CORS header
//!   `Access-Control-Allow-Origin: *` per Go upstream
//!   (`portal-tunnel/portal/api_server.go:238`).
//!
//! ## Trust boundary
//!
//! The SDK router is reachable from any client; handlers register
//! their own per-endpoint authentication policies. `GET /v1/sdk/domain`
//! is intentionally unauthenticated — it is the SDK's bootstrap
//! handshake before any lease, key, or signed material exists.
//!
//! Subsequent handlers (`/v1/sdk/register-challenge`, `/v1/sdk/register`,
//! `/v1/sdk/renew`, `/v1/sdk/unregister`, `/v1/sdk/connect`) land in
//! follow-up commits.

use axum::Json;
use axum::http::{HeaderMap, HeaderValue, header};
use serde::Serialize;

use crate::api::envelope::{ApiDataEnvelope, ApiError, ok};

/// Wire body for `GET /v1/sdk/domain`.
///
/// Both fields are populated from `env!("CARGO_PKG_VERSION")` in v0.1
/// because the relay binary is the canonical version source. The
/// fields are kept as separate identifiers (rather than collapsed to a
/// single `version`) to mirror Go upstream's `types.DomainResponse`
/// shape — the discriminator is preserved for forward-compat so a
/// future relay can decouple wire-protocol version (`protocol_version`)
/// from binary build-tag (`release_version`) without a wire break.
///
/// `#[non_exhaustive]` blocks struct-literal construction from
/// downstream Rust crates; it does NOT guarantee JSON-wire
/// compatibility — a strict-decoder client that rejects unknown
/// keys would still break on a field addition.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct DomainBody {
    /// Wire-protocol version. v0.1 collapses to `CARGO_PKG_VERSION`;
    /// future releases may decouple from `release_version`.
    pub protocol_version: &'static str,
    /// Relay binary release version. v0.1 collapses to
    /// `CARGO_PKG_VERSION`; future releases may decouple from
    /// `protocol_version`.
    pub release_version: &'static str,
}

/// `GET /v1/sdk/domain` — deployment-constant relay identity.
///
/// Returns the relay's protocol/release version pair as a constant
/// JSON body wrapped in [`ApiDataEnvelope`]. The response carries an
/// `Access-Control-Allow-Origin: *` header so a browser-resident SDK
/// (origin-bound JS) can fetch the bootstrap surface before negotiating
/// any further authentication.
///
/// ## CORS approach
///
/// `tower-http` is not a workspace dependency in v0.1 (see
/// `crates/portal-relay/Cargo.toml`), so the header is set per-handler
/// via [`HeaderMap`] on a tuple-`IntoResponse` return shape. A
/// follow-up slice that needs broader CORS coverage (preflight, vary,
/// allow-methods) should adopt `tower_http::cors::CorsLayer` at the
/// router level rather than fan out per-handler header insertion.
///
/// # Errors
///
/// Infallible. The signature returns
/// `Result<…, ApiError>` for envelope uniformity with the rest of the
/// API surface; the `Err` arm is unreachable in v0.1.
#[tracing::instrument(name = "sdk.domain", skip_all)]
pub async fn domain_handler() -> Result<(HeaderMap, Json<ApiDataEnvelope<DomainBody>>), ApiError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    Ok((
        headers,
        ok(DomainBody {
            protocol_version: env!("CARGO_PKG_VERSION"),
            release_version: env!("CARGO_PKG_VERSION"),
        }),
    ))
}
