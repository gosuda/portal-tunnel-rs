//! Dual-stack bind helpers re-exported from `portal_net::dual_stack`.
//!
//! Phase 5 U3's spec calls for a single-owner R12 helper at
//! `portal-relay/src/listeners/`; the workspace decision is to keep
//! `portal-net` as the single owner of the bind primitive and surface
//! it here under the portal-relay namespace so consumers within this
//! crate use a consistent path.

pub use portal_net::dual_stack::{bind_dual_stack_tcp, bind_dual_stack_udp};
