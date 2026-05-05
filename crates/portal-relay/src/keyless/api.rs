//! Keyless mTLS sign endpoint — axum [`Router`] + handler + the
//! locally-constructed [`rustls::ServerConfig`] that pins this
//! surface to its own R2 trust boundary.
//!
//! ## R2 trust-boundary discipline
//!
//! The [`rustls::ServerConfig`] built by
//! [`build_keyless_server_config`] is the **third** distinct
//! `ServerConfig` instance in the workspace, alongside the
//! api-https config (`crate::api::*`) and the QUIC backhaul config
//! (`portal_net`).  This module's config MUST live entirely inside
//! `keyless::api`; it MUST NOT alias into `state/` or `listeners/`.
//! The `pub` constructors here are the single point of contact
//! between the keyless trust boundary and the rest of the relay.
//!
//! ## Endpoint shape
//!
//! - `POST` [`KEYLESS_SIGN_PATH`] (`/v1/keyless/sign`) — body is a
//!   JSON-encoded [`SignRequest`]; success replies are
//!   `{"data": SignResponse}`; failures are
//!   `{"error": KeylessErrorBody}` per the workspace HTTP envelope
//!   convention.
//!
//! ## Handler order (matches plan U3 §Approach)
//!
//! 1. Run [`KeylessPolicy::validate`] against the request +
//!    connecting subject — this enforces SEC-004 protections (known
//!    key id, scheme match, payload budget, per-tenant rate limit).
//! 2. Build the SEC-007 [`canonical_signing_input`].
//! 3. `bridge.sign(scheme, canonical_message).await` — the bridge
//!    routes the actual signing call onto a blocking-pool worker.
//! 4. Wrap the resulting signature bytes in a [`SignResponse`] and
//!    return.
//!
//! Each error path maps to a typed [`KeylessError`] which carries
//! into a stable wire code via [`error_status`].
//!
//! ## What this module does NOT own
//!
//! - **Listener bind.**  Spinning up the actual TCP socket +
//!   `tokio_rustls::TlsAcceptor` + connection-accept loop is the
//!   relay top-level `main`'s responsibility (Phase 5 / U16
//!   server-orchestrator). This module surfaces the
//!   `rustls::ServerConfig` and the `Router` so the orchestrator can
//!   assemble them; we deliberately do not ship a "run me" helper
//!   that hides the lifecycle.
//! - **Operator config.**  `KeylessConfig` — the figment-loaded knob
//!   surface — lands at a later unit; for now the only public knob
//!   is `KEYLESS_SIGN_PATH`.

use std::sync::Arc;

use axum::Router;
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, http};
use compact_str::CompactString;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::keyless::bridge::Bridge;
use crate::keyless::error::KeylessError;
use crate::keyless::policy::KeylessPolicy;
use crate::keyless::wire::{KeylessErrorBody, SignRequest, SignResponse, canonical_signing_input};

/// Stable URL path for the keyless sign endpoint.
pub const KEYLESS_SIGN_PATH: &str = "/v1/keyless/sign";

// ---------------------------------------------------------------------------
// KeylessApiState — what the handler needs at request time
// ---------------------------------------------------------------------------

/// Axum router state for the keyless surface.
///
/// Cheap-clone: holds an `Arc`-cloneable [`KeylessPolicy`] + a
/// [`Bridge`] (mpsc sender clone) + a function pointer to the
/// connection-subject extractor.
#[derive(Clone)]
pub struct KeylessApiState {
    /// The validation pipeline + per-tenant rate limiter.
    pub policy: KeylessPolicy,
    /// The async-bridge handle to the worker pool.  Cloning
    /// duplicates the mpsc sender; the queue depth is shared.
    pub bridge: Bridge,
    /// Connecting client's mTLS-validated subject extractor.
    ///
    /// The relay's TLS-listener layer attaches the validated client
    /// certificate's subject string into request extensions before
    /// the handler runs (see [`SubjectExtension`]); the policy's
    /// per-tenant rate limit keys on whatever this returns.
    ///
    /// Held as a function pointer rather than a closure so the
    /// state stays trivially `Clone + Send + Sync`.
    pub subject_extractor: SubjectExtractor,
}

impl core::fmt::Debug for KeylessApiState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeylessApiState")
            .field("policy", &self.policy)
            .field("bridge", &self.bridge)
            .finish_non_exhaustive()
    }
}

/// Connection-subject extractor function pointer.
///
/// Pulls the connecting tenant's subject out of an axum request.
/// The default ([`subject_from_extension`]) reads a
/// [`SubjectExtension`] inserted by the listener layer; integration
/// tests can plug in a fixed-string extractor for hermeticity.
pub type SubjectExtractor =
    fn(&http::request::Parts, &std::net::SocketAddr) -> Option<CompactString>;

/// Default [`SubjectExtractor`].
///
/// Returns the value of any [`SubjectExtension`] set on the
/// request's extensions map, or `None` if the listener layer did
/// not attach one (which happens when the connection somehow
/// bypassed mTLS — the handler treats `None` as
/// `unauthorized`).
#[must_use]
pub fn subject_from_extension(
    parts: &http::request::Parts,
    _peer: &std::net::SocketAddr,
) -> Option<CompactString> {
    parts
        .extensions
        .get::<SubjectExtension>()
        .map(|s| s.0.clone())
}

/// Request-extension wrapper for the connecting tenant's
/// mTLS-validated subject.
///
/// The listener / TLS-acceptance layer is expected to insert one of
/// these into every request's extensions before passing the request
/// to the keyless router.  The default subject extractor
/// ([`subject_from_extension`]) reads this back out.
#[derive(Debug, Clone)]
pub struct SubjectExtension(pub CompactString);

// ---------------------------------------------------------------------------
// build_keyless_router — the axum surface
// ---------------------------------------------------------------------------

/// Construct the keyless mTLS sign router.
///
/// Routes:
/// - `POST` [`KEYLESS_SIGN_PATH`] → `sign_handler` (private; see
///   `keyless::api`'s sole `POST` handler).
///
/// The router carries [`KeylessApiState`] as its state; the caller
/// owns the lifecycle of the [`KeylessPolicy`] and the [`Bridge`].
#[must_use]
#[expect(
    clippy::double_must_use,
    reason = "wrapper-fn boundary contract: `axum::Router` is `#[must_use]` \
              but constructor-return shape re-affirms it here"
)]
#[expect(
    clippy::disallowed_methods,
    reason = "Phase 7 U8.8 utoipa coverage gate names \
              `utoipa_axum::OpenApiRouter::route` for library-crate route \
              registration. The keyless surface is the third trust boundary \
              (R2) and is intentionally absent from the public OpenAPI \
              surface — it is an mTLS-only oracle for tenant-cert use, not \
              part of the discoverable api-https / sdk / discovery API. \
              Adopting utoipa-axum here would require importing the crate \
              for a single non-discoverable route. Recorded as a follow-up \
              gap in the U3 implementation report; reachable only via the \
              keyless mTLS ServerConfig built locally to this module."
)]
pub fn build_keyless_router(state: KeylessApiState) -> Router {
    // Bound-to-var rebind shape per `docs/utoipa-coverage-policy.md`
    // §Enforcement note 2: this is the documented escape from the
    // ast-grep belt-and-suspenders gate, which only matches the
    // chained-builder shape `Router::new().route(...)`. Clippy's
    // `disallowed_methods` still resolves the `r.route(...)` call by
    // DefId — that is the load-bearing primary gate, and the
    // `#[expect(clippy::disallowed_methods, ...)]` above carries the
    // R2/U8.8 carve-out justification. Keeping ast-grep silent here
    // is correct: this file is exercising the policy's documented
    // escape procedure for a non-discoverable surface, not bypassing
    // a real R7 violation.
    let r = Router::new();
    let r = r.route(KEYLESS_SIGN_PATH, post(sign_handler));
    r.with_state(state)
}

// ---------------------------------------------------------------------------
// sign_handler — the U3 four-step pipeline
// ---------------------------------------------------------------------------

/// `POST` [`KEYLESS_SIGN_PATH`] handler.
///
/// On success returns `{"data": SignResponse}` with status 200.
/// On any [`KeylessError`] returns `{"error": KeylessErrorBody}`
/// with the wire code + HTTP status spelled out in
/// [`error_status`].
///
/// The `key_id` and `scheme` fields are populated on the current
/// span via `Span::record` *after* JSON decode — the request body
/// is not available as an argument to `#[instrument]`, so we
/// declare the fields with `Empty` placeholders and fill them in
/// once the decoded `SignRequest` is in hand.
#[tracing::instrument(
    skip_all,
    fields(
        key_id = tracing::field::Empty,
        scheme = tracing::field::Empty,
    ),
)]
async fn sign_handler(
    State(state): State<KeylessApiState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    request: http::Request<axum::body::Body>,
) -> Result<Json<KeylessDataEnvelope<SignResponse>>, KeylessHandlerError> {
    let (parts, body) = request.into_parts();

    // 1. Pull the mTLS-validated subject out of the request.
    let Some(subject) = (state.subject_extractor)(&parts, &peer) else {
        return Err(KeylessHandlerError(KeylessError::UnknownKeyId(
            "no mTLS subject on request — connection bypassed the keyless verifier".to_owned(),
        )));
    };

    // 2. Read + decode the JSON body.  Bound the body read at the
    //    JSON-encoded ceiling: the canonical wire is `Vec<u8>`
    //    serialised as a JSON array of integers (the inverse JSON
    //    expansion is up to ~5 bytes per byte for pathological
    //    inputs — `255,` per element).  We multiply the keyless
    //    payload budget by 8 to give comfortable headroom over
    //    boundary-inclusive 8 KiB payloads + the surrounding
    //    SignRequest envelope overhead, while still capping the
    //    read at a finite value (the policy validation layer
    //    enforces the actual SEC-014 budget on the *decoded* bytes).
    const BODY_READ_LIMIT_MULT: usize = 8;
    let body_read_limit =
        portal_wire::limits::KEYLESS_PAYLOAD_BUDGET.saturating_mul(BODY_READ_LIMIT_MULT);
    let body_bytes = match axum::body::to_bytes(body, body_read_limit).await {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::debug!(error = %err, "keyless: body read failed");
            return Err(KeylessHandlerError(KeylessError::PayloadTooLarge {
                observed: body_read_limit + 1,
                budget: portal_wire::limits::KEYLESS_PAYLOAD_BUDGET,
            }));
        }
    };
    let req: SignRequest = match serde_json::from_slice(&body_bytes) {
        Ok(req) => req,
        Err(err) => {
            tracing::debug!(error = %err, "keyless: json decode failed");
            return Err(KeylessHandlerError(KeylessError::SchemeMismatch(format!(
                "request body could not be decoded as SignRequest: {err}"
            ))));
        }
    };

    // Now that the request is decoded, fill in the span's
    // `key_id` / `scheme` fields the `#[instrument]` attribute
    // declared with `Empty` placeholders.
    let span = tracing::Span::current();
    span.record("key_id", tracing::field::display(&req.key_id));
    span.record("scheme", req.scheme.as_u16());

    // 3. Run the SEC-004 validation pipeline.
    let _known_key = state.policy.validate(subject.as_str(), &req)?;

    // 4. Build the SEC-007 canonical signing input.
    let canonical = canonical_signing_input(&req).map_err(|err| {
        tracing::error!(error = %err, "keyless: canonical encoding failed");
        KeylessHandlerError(KeylessError::SignFailed(format!(
            "canonical encoding failed: {err}"
        )))
    })?;

    // 5. Hand off to the bridge.  Backpressure surfaces as a typed
    //    `KeylessError` which `error_status` maps to 503 / 429 / 5xx.
    let signature = state.bridge.sign(req.scheme.to_rustls(), canonical).await?;

    // 6. Wrap in the success envelope.
    Ok(Json(KeylessDataEnvelope {
        data: SignResponse {
            signature,
            scheme: req.scheme,
        },
    }))
}

// ---------------------------------------------------------------------------
// Response envelopes
// ---------------------------------------------------------------------------

/// `{"data": T}` success envelope for the keyless surface.
///
/// Defined locally rather than re-using
/// [`crate::api::ApiDataEnvelope`] because the keyless trust
/// boundary is independent (R2) — re-using the api-https envelope
/// would create a cross-trust-boundary type alias and complicate
/// the future task of differentiating envelopes per surface.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeylessDataEnvelope<T> {
    /// The success payload.
    pub data: T,
}

/// `{"error": KeylessErrorBody}` failure envelope for the keyless
/// surface.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeylessErrorEnvelope {
    /// The error body.
    pub error: KeylessErrorBody,
}

/// Newtype wrapper around [`KeylessError`] that implements
/// [`IntoResponse`] using the keyless-flavoured wire envelope.
///
/// Local to this module — the api-https surface uses
/// [`crate::api::ApiError`]; the keyless surface owns its own wire
/// codes (R2).
#[derive(Debug)]
pub struct KeylessHandlerError(pub KeylessError);

impl From<KeylessError> for KeylessHandlerError {
    fn from(err: KeylessError) -> Self {
        Self(err)
    }
}

impl IntoResponse for KeylessHandlerError {
    fn into_response(self) -> Response {
        let (status, code, message) = error_status(&self.0);
        let body = KeylessErrorEnvelope {
            error: KeylessErrorBody {
                code: CompactString::new(code),
                message,
            },
        };
        (status, Json(body)).into_response()
    }
}

/// `KeylessError` → `(http_status, wire_code, message)` mapping.
///
/// Single source of truth for the keyless wire-error catalogue;
/// integration test `keyless_mtls_round_trip.rs` asserts each
/// variant's mapping.
#[must_use]
pub fn error_status(err: &KeylessError) -> (StatusCode, &'static str, String) {
    match err {
        KeylessError::UnknownKeyId(_) => (
            StatusCode::BAD_REQUEST,
            "unknown_key_id",
            "unknown key id".to_owned(),
        ),
        KeylessError::SchemeMismatch(_) => (
            StatusCode::BAD_REQUEST,
            "scheme_mismatch",
            "scheme does not match the loaded key".to_owned(),
        ),
        KeylessError::PayloadTooLarge { budget, .. } => (
            StatusCode::BAD_REQUEST,
            "payload_too_large",
            format!("payload exceeds the {budget}-byte keyless budget"),
        ),
        KeylessError::RateLimited => (
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "per-tenant rate limit exceeded".to_owned(),
        ),
        KeylessError::RoutingContextMismatch(_) => (
            // SEC-015: explicit security-policy refusal — 403 (NOT 400)
            // signals authorisation failure, not input-shape complaint.
            StatusCode::FORBIDDEN,
            "routing_context_mismatch",
            "routed hostname does not authorise the requested cert subject".to_owned(),
        ),
        KeylessError::QueueFull => (
            StatusCode::SERVICE_UNAVAILABLE,
            "bridge_queue_full",
            "keyless bridge is at capacity".to_owned(),
        ),
        KeylessError::BridgeClosed => (
            StatusCode::SERVICE_UNAVAILABLE,
            "bridge_closed",
            "keyless bridge is shutting down".to_owned(),
        ),
        // Sign-time + loader-time failures all surface as
        // `internal` so a future code-path that accidentally
        // surfaces a loader-only variant at the handler returns a
        // sane wire code instead of a 500 with no body.  Merged
        // into a single arm to avoid identical-bodies clippy
        // duplication.
        KeylessError::SignFailed(_)
        | KeylessError::WorkerPanic
        | KeylessError::MalformedPem(_)
        | KeylessError::UnsupportedAlgorithm(_)
        | KeylessError::InvalidKey(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal keyless error".to_owned(),
        ),
    }
}

// ---------------------------------------------------------------------------
// build_keyless_server_config — the local rustls::ServerConfig
// ---------------------------------------------------------------------------

/// Build the keyless surface's [`rustls::ServerConfig`] with mTLS
/// client-cert verification.
///
/// `client_ca_roots` is the pinned tenant CA bundle that the
/// `WebPkiClientVerifier` will use to validate connecting client
/// certs.  `server_cert_chain` + `server_private_key` are the
/// keyless surface's own server identity (tenant-facing).
///
/// **R2 boundary.**  The returned `ServerConfig` MUST be consumed
/// inside the keyless module's listener wiring; do not stash it
/// anywhere reachable from `state/` or `listeners/`.
///
/// # Errors
///
/// Returns [`KeylessApiBuildError`] when the supplied roots are
/// empty or the `CryptoProvider` rejects the supplied server cert
/// / private key (e.g. mismatched algorithm, malformed key).
pub fn build_keyless_server_config(
    client_ca_roots: RootCertStore,
    server_cert_chain: Vec<CertificateDer<'static>>,
    server_private_key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, KeylessApiBuildError> {
    if client_ca_roots.is_empty() {
        return Err(KeylessApiBuildError::EmptyClientRoots);
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(client_ca_roots), provider.clone())
            .build()
            .map_err(|e| KeylessApiBuildError::Verifier(e.to_string()))?;

    let cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| KeylessApiBuildError::Tls(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_cert_chain, server_private_key)
        .map_err(|e| KeylessApiBuildError::Tls(e.to_string()))?;
    Ok(cfg)
}

/// Errors emitted by [`build_keyless_server_config`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeylessApiBuildError {
    /// The supplied `client_ca_roots` was empty — a verifier with
    /// no roots would accept any client cert, which is the exact
    /// failure mode mTLS exists to prevent.
    #[error("client CA root store is empty — refusing to build a verifier with no trust anchors")]
    EmptyClientRoots,
    /// The webpki client-cert verifier builder rejected the inputs.
    #[error("client cert verifier: {0}")]
    Verifier(String),
    /// rustls server config builder rejected the inputs.
    #[error("rustls server config: {0}")]
    Tls(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test-only setup")]
mod tests {
    use super::*;

    #[test]
    fn error_status_maps_each_variant() {
        // Spot-check the mapping table — the integration test asserts
        // the wire-side observable form, this guards the table itself
        // against accidental reorder.
        assert_eq!(
            error_status(&KeylessError::UnknownKeyId("x".into())).1,
            "unknown_key_id"
        );
        assert_eq!(
            error_status(&KeylessError::SchemeMismatch("x".into())).1,
            "scheme_mismatch"
        );
        assert_eq!(
            error_status(&KeylessError::PayloadTooLarge {
                observed: 9000,
                budget: 8192
            })
            .1,
            "payload_too_large"
        );
        assert_eq!(error_status(&KeylessError::RateLimited).1, "rate_limited");
        assert_eq!(
            error_status(&KeylessError::QueueFull).1,
            "bridge_queue_full"
        );
        assert_eq!(error_status(&KeylessError::BridgeClosed).1, "bridge_closed");
        assert_eq!(
            error_status(&KeylessError::RoutingContextMismatch("x".into())).1,
            "routing_context_mismatch"
        );
        assert_eq!(
            error_status(&KeylessError::RoutingContextMismatch("x".into())).0,
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn error_status_assigns_correct_http_codes() {
        assert_eq!(
            error_status(&KeylessError::UnknownKeyId("x".into())).0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            error_status(&KeylessError::RateLimited).0,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            error_status(&KeylessError::QueueFull).0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            error_status(&KeylessError::WorkerPanic).0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn build_keyless_server_config_refuses_empty_roots() {
        // Generate a throwaway server cert via rcgen and feed an
        // empty root store: the builder must refuse.
        // (Hermetic — the rcgen call is the only crypto here.)
        // We cannot reach into rcgen from a unit test without a
        // dev-dep declaration; instead, exercise the early-exit path
        // by passing an empty root store + dummy cert/key bytes that
        // would otherwise fail at `with_single_cert`.  The empty-root
        // arm fires first.
        let roots = RootCertStore::empty();
        // Use a placeholder DER body — never reached because the
        // empty-roots check fires first.
        let dummy_cert = CertificateDer::from(vec![0u8; 1]);
        // Same for the key — never reached.
        let dummy_key =
            PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(vec![0u8; 1]));
        let err = build_keyless_server_config(roots, vec![dummy_cert], dummy_key)
            .expect_err("empty roots must be refused");
        assert!(matches!(err, KeylessApiBuildError::EmptyClientRoots));
    }
}
