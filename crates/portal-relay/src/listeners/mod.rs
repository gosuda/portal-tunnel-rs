//! Dual-stack v4+v6 listener helpers + R12-canon entry point for
//! policy / api / discovery modules in this crate.

pub mod canonicalize;
pub mod dual_stack;
pub mod tls_serve;

pub use canonicalize::canonicalize_source;
pub use dual_stack::{bind_dual_stack_tcp, bind_dual_stack_udp};
pub use tls_serve::serve_tls_router;
