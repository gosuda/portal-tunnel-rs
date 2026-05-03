//! Relay-server library — lease lifecycle, axum API surface, policy engine,
//! discovery, overlay, keyless oracle.
//!
//! Owner: server-side trust boundaries (`SecretBox<ApiHttpsKey>`,
//! `SecretBox<KeylessSigningKey>`) per R2 (Phase 5+6b, U6/U7b).
