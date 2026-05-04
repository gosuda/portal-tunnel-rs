//! API response envelope + typed error.
//!
//! Wire shape: every API response is `{"data": T}` on success or
//! `{"error": {"code": "...", "message": "..."}}` on failure. The
//! [`ApiError`] enum is canonicalized in this module so handlers
//! return `ApiResult<T>` and the framework lifts to the right HTTP
//! status code via [`IntoResponse`].
//!
//! ## Phase 5 B6 scope
//!
//! Lands the envelope shape, the 19 `ApiErrorCode` variants from Go's
//! `types.APIErrorCode*`, and `From<RelayError> for ApiError`. Per-
//! surface state types (`AdminState`, `SdkState`, `DiscoveryState`)
//! are stub-typed here; subsequent batches fill in the field set as
//! handlers land.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::error::RelayError;

/// API error code mirroring Go's `types.APIErrorCode*` enum. Each
/// variant maps to (a) a stable wire string and (b) an HTTP status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApiErrorCode {
    /// Feature gated behind v0.2 / Phase 6b (e.g., hop-route in v0.1).
    FeatureUnavailable,
    /// Hostname already held by another identity.
    HostnameConflict,
    /// Source IP is in the policy ban list.
    IpBanned,
    /// Lease is unknown.
    LeaseNotFound,
    /// Lease registration was rejected by policy.
    LeaseRejected,
    /// Transport pair (UDP / TCP / hop) does not match registration.
    TransportMismatch,
    /// Request lacks valid authentication.
    Unauthorized,
    /// UDP datagram surface is disabled by policy.
    UdpDisabled,
    /// UDP capacity exhausted.
    UdpCapacityExceeded,
    /// UDP port pool exhausted.
    UdpPortExhausted,
    /// TCP port surface is disabled by policy.
    TcpPortDisabled,
    /// TCP port capacity exhausted.
    TcpPortCapacityExceeded,
    /// TCP port pool exhausted.
    TcpPortExhausted,
    /// Rate limit exceeded.
    RateLimited,
    /// Request body or headers were malformed.
    InvalidRequest,
    /// Internal server error (5xx).
    Internal,
    /// HTTP/1.1 hijack is not supported by the underlying transport.
    HijackUnsupported,
    /// HTTP/1.1 hijack failed mid-flight.
    HijackFailed,
    /// Endpoint requires HTTP/1.1.
    Http11Only,
}

impl ApiErrorCode {
    /// Stable wire string used in the `error.code` JSON field.
    #[must_use]
    pub const fn wire_code(self) -> &'static str {
        match self {
            Self::FeatureUnavailable => "feature_unavailable",
            Self::HostnameConflict => "hostname_conflict",
            Self::IpBanned => "ip_banned",
            Self::LeaseNotFound => "lease_not_found",
            Self::LeaseRejected => "lease_rejected",
            Self::TransportMismatch => "transport_mismatch",
            Self::Unauthorized => "unauthorized",
            Self::UdpDisabled => "udp_disabled",
            Self::UdpCapacityExceeded => "udp_capacity_exceeded",
            Self::UdpPortExhausted => "udp_port_exhausted",
            Self::TcpPortDisabled => "tcp_port_disabled",
            Self::TcpPortCapacityExceeded => "tcp_port_capacity_exceeded",
            Self::TcpPortExhausted => "tcp_port_exhausted",
            Self::RateLimited => "rate_limited",
            Self::InvalidRequest => "invalid_request",
            Self::Internal => "internal",
            Self::HijackUnsupported => "hijack_unsupported",
            Self::HijackFailed => "hijack_failed",
            Self::Http11Only => "http11_only",
        }
    }

    /// HTTP status code paired with this variant.
    #[must_use]
    pub const fn http_status(self) -> StatusCode {
        match self {
            Self::HostnameConflict | Self::TransportMismatch => StatusCode::CONFLICT,
            Self::IpBanned | Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::LeaseNotFound => StatusCode::NOT_FOUND,
            Self::LeaseRejected
            | Self::UdpDisabled
            | Self::TcpPortDisabled
            | Self::HijackUnsupported => StatusCode::FORBIDDEN,
            Self::FeatureUnavailable
            | Self::UdpCapacityExceeded
            | Self::UdpPortExhausted
            | Self::TcpPortCapacityExceeded
            | Self::TcpPortExhausted => StatusCode::SERVICE_UNAVAILABLE,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::InvalidRequest | Self::Http11Only => StatusCode::BAD_REQUEST,
            Self::Internal | Self::HijackFailed => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Wire shape of a non-success response: `{"error": {...}}`.
#[derive(Debug, Clone, Serialize)]
pub struct ApiErrorBody {
    /// Stable wire code (see [`ApiErrorCode::wire_code`]).
    pub code: &'static str,
    /// Human-readable message. MUST NOT echo internal state or
    /// secret material.
    pub message: String,
}

/// Envelope around the wire-shape error.
#[derive(Debug, Clone, Serialize)]
pub struct ApiErrorEnvelope {
    /// The error body.
    pub error: ApiErrorBody,
}

/// Wire shape of a successful response: `{"data": T}`.
#[derive(Debug, Clone, Serialize)]
pub struct ApiDataEnvelope<T> {
    /// The success payload.
    pub data: T,
}

/// Typed API error returned by handlers.
#[derive(Debug, Clone)]
pub struct ApiError {
    /// Discriminant + status mapping.
    pub code: ApiErrorCode,
    /// Human-readable message.
    pub message: String,
}

impl ApiError {
    /// Construct with a static message.
    #[must_use]
    pub fn new(code: ApiErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Convenience constructor for [`ApiErrorCode::Internal`] when
    /// surfacing an internal failure to the wire — strips the
    /// concrete error string in favor of a constant message so
    /// internal state does not leak.
    #[must_use]
    pub fn internal() -> Self {
        Self::new(ApiErrorCode::Internal, "internal error")
    }

    /// Convenience constructor for [`ApiErrorCode::Unauthorized`].
    #[must_use]
    pub fn unauthorized() -> Self {
        Self::new(ApiErrorCode::Unauthorized, "unauthorized")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ApiErrorEnvelope {
            error: ApiErrorBody {
                code: self.code.wire_code(),
                message: self.message,
            },
        };
        (self.code.http_status(), Json(body)).into_response()
    }
}

impl From<RelayError> for ApiError {
    fn from(err: RelayError) -> Self {
        // Map crate-level errors to wire codes. The mapping is
        // deliberately narrow: most `RelayError` variants surface as
        // `Internal` because they carry implementation detail that
        // must not reach the wire. The `Config` variant is mapped to
        // `InvalidRequest` only when its origin is request-validation
        // — but the current crate uses `Config` more broadly, so we
        // keep it on `Internal` for now and let downstream batches
        // tighten the mapping when handler-specific errors surface.
        match err {
            RelayError::Config(_)
            | RelayError::Io(_)
            | RelayError::Net(_)
            | RelayError::Crypto(_)
            | RelayError::Wire(_)
            | RelayError::Keyless(_) => Self::internal(),
        }
    }
}

/// Crate-wide handler return type.
pub type ApiResult<T> = Result<Json<ApiDataEnvelope<T>>, ApiError>;

/// Wrap a value in the success envelope.
#[must_use]
#[expect(
    clippy::double_must_use,
    reason = "wrapper-fn boundary contract: `Json<T>` is `#[must_use]` \
              but the handler-return shape re-affirms it here"
)]
pub const fn ok<T: Serialize>(value: T) -> Json<ApiDataEnvelope<T>> {
    Json(ApiDataEnvelope { data: value })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_code_round_trip() {
        for code in [
            ApiErrorCode::FeatureUnavailable,
            ApiErrorCode::HostnameConflict,
            ApiErrorCode::IpBanned,
            ApiErrorCode::LeaseNotFound,
            ApiErrorCode::LeaseRejected,
            ApiErrorCode::TransportMismatch,
            ApiErrorCode::Unauthorized,
            ApiErrorCode::UdpDisabled,
            ApiErrorCode::UdpCapacityExceeded,
            ApiErrorCode::UdpPortExhausted,
            ApiErrorCode::TcpPortDisabled,
            ApiErrorCode::TcpPortCapacityExceeded,
            ApiErrorCode::TcpPortExhausted,
            ApiErrorCode::RateLimited,
            ApiErrorCode::InvalidRequest,
            ApiErrorCode::Internal,
            ApiErrorCode::HijackUnsupported,
            ApiErrorCode::HijackFailed,
            ApiErrorCode::Http11Only,
        ] {
            // Wire codes must be lowercase snake_case + non-empty.
            // Digits are permitted (e.g., `http11_only`).
            let wire = code.wire_code();
            assert!(!wire.is_empty(), "wire code must be non-empty");
            assert!(
                wire.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "wire code {wire} must be lowercase_snake (digits permitted)",
            );
        }
    }

    #[test]
    fn http_status_categorisation_is_consistent() {
        assert_eq!(
            ApiErrorCode::Unauthorized.http_status(),
            StatusCode::UNAUTHORIZED,
        );
        assert_eq!(
            ApiErrorCode::HostnameConflict.http_status(),
            StatusCode::CONFLICT,
        );
        assert_eq!(
            ApiErrorCode::RateLimited.http_status(),
            StatusCode::TOO_MANY_REQUESTS,
        );
        assert_eq!(
            ApiErrorCode::Internal.http_status(),
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    #[test]
    fn relay_error_to_api_error_is_internal() {
        let relay_err = RelayError::Config("internal state thing".to_owned());
        let api_err: ApiError = relay_err.into();
        assert_eq!(api_err.code, ApiErrorCode::Internal);
        // Body MUST NOT carry the original string.
        assert_eq!(api_err.message, "internal error");
    }

    #[test]
    fn into_response_uses_correct_status() {
        let err = ApiError::new(ApiErrorCode::LeaseNotFound, "no such lease");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
