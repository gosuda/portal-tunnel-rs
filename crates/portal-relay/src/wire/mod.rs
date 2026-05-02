// INVARIANT: All wire-protocol-frozen constants in this crate live exclusively
// under this module. Any protocol literal outside wire/ is a bug.
pub mod alpn;
pub mod envelope;
pub mod jwt;
pub mod markers;
pub mod paths;
