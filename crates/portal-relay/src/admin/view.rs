//! Shared rendering trait for admin TUI views.

use ratatui::{Frame, layout::Rect};

/// Synchronous renderer implemented by admin TUI views.
///
/// Rendering is intentionally not async: views receive already-materialized
/// snapshots and draw them into the supplied ratatui frame.
pub trait View<S> {
    /// Render `snapshot` into `area`.
    fn render(&self, frame: &mut Frame<'_>, area: Rect, snapshot: &S);
}
