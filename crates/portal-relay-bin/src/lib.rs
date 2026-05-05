//! `portal-relay-bin` library surface.
//!
//! The binary crate's testable subcommand logic lives behind a thin
//! library target so integration tests under `tests/` can drive
//! `init` directly without spawning a subprocess. The binary entry
//! point in `src/main.rs` consumes the same module.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod init;
