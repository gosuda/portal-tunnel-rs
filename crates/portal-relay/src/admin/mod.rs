//! Shared admin surface types.
//!
//! Distinct from [`crate::api::admin`], which carries the HTTP handlers for
//! the admin trust-boundary router. This module holds frontend-neutral admin
//! action and view primitives consumed by TUI surfaces.

pub mod action;
pub mod view;

pub use action::{Action, ApprovalMode};
pub use view::View;
