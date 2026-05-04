//! QUIC transport primitives.

// `pub mod` (not `pub(crate)`) is intentional: clippy::redundant_pub_crate fires
// because `quic` itself is declared `pub(crate)` in `lib.rs`, making an inner
// `pub(crate)` redundant. Visibility is already capped at the crate root.
pub mod identity;
