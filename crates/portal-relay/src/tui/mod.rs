//! Relay-side R15 v0.1 status TUI surfaces.
//!
//! Terminal setup and CLI wiring live in `portal-relay-bin`; this module owns
//! library-renderable views and cancelable watch-loop helpers.

pub mod status;

pub use status::{
    BpsAggregate, IdentityHealth, Lifecycle, RecentEvent, StatusSnapshot, StatusView, TuiError,
    run, run_with_terminal,
};
