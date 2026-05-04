//! QUIC transport primitives.

pub mod endpoint;
pub mod identity;
pub mod verifier;

pub use endpoint::{Endpoint, EndpointRole};
pub use verifier::SpkiPinVerifier;
