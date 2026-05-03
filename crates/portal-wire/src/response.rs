//! JSON HTTP response wrapper for admin/SDK surfaces.

use serde::{Deserialize, Serialize};

/// `{ "data": T }`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataResponse<T> {
    /// Successful payload.
    pub data: T,
}

/// `{ "error": { "code", "message" } }`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Machine-readable and human-readable error body.
    pub error: ApiErrorBody,
}

/// Error body for an [`ErrorResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiErrorBody {
    /// Stable error code (`snake_case`).
    pub code: String,
    /// Operator-facing message.
    pub message: String,
}
