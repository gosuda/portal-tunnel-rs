//! Testable helpers for the `portal-relay tui` subcommand.

use portal_relay::tui::StatusSnapshot;

/// Initial v0.1 status snapshot rendered by `portal-relay tui`.
///
/// Runtime status watch plumbing is intentionally deferred to the later
/// server-status source; until then the binary renders the library's stopped
/// default snapshot so operators can launch and inspect the TUI shell without
/// implying a live relay is attached.
#[must_use]
pub fn initial_tui_snapshot() -> StatusSnapshot {
    StatusSnapshot::default()
}

#[cfg(test)]
mod tests {
    use portal_relay::tui::Lifecycle;

    use super::*;

    #[test]
    fn initial_tui_snapshot_is_stopped_default() {
        let snapshot = initial_tui_snapshot();

        assert_eq!(snapshot.lifecycle, Lifecycle::Stopped);
        assert!(snapshot.recent_events.is_empty());
        assert_eq!(snapshot.lease_count, 0);
        assert_eq!(snapshot.identity_health.approved, 0);
        assert_eq!(snapshot.identity_health.pending, 0);
        assert_eq!(snapshot.identity_health.denied, 0);
        assert_eq!(snapshot.identity_health.banned, 0);
        assert_eq!(snapshot.bps.inbound, 0);
        assert_eq!(snapshot.bps.outbound, 0);
    }
}
