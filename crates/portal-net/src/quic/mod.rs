//! QUIC transport primitives.

pub mod control;
pub mod endpoint;
pub mod identity;
pub mod stream;
pub mod verifier;

pub use control::{
    build_control_claims, recv_control_envelope, send_control_envelope, verify_control_envelope,
};
pub use endpoint::{Endpoint, EndpointRole};
pub use stream::{InboundStream, TcpProxyKind, dispatch_inbound, open_outbound};
pub use verifier::SpkiPinVerifier;
