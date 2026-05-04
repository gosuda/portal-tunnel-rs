//! Tunnel state + event types consumed by `portal-cli`'s R15 v0.1
//! Tunnel TUI default mode.
//!
//! `portal-sdk` deliberately does NOT depend on `ratatui` — the SDK
//! publishes plain structs through a `tokio::sync::broadcast`
//! channel; the CLI crate owns all rendering. This boundary lets
//! the SDK be reused in non-TUI contexts (programmatic API
//! consumers, tests, embedded integrations) without dragging the
//! TUI runtime in.

use std::net::SocketAddr;

use compact_str::CompactString;
use jiff::Timestamp;
use tokio::sync::broadcast;

/// Coarse-grained tunnel lifecycle phase. Mirrors the Go SDK's
/// `TunnelStatus` enum but extends with `Backoff` for the
/// reconnect-after-failure window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TunnelState {
    /// Not started yet.
    Idle,
    /// Resolving + verifying relay descriptors.
    Discovering,
    /// Dialing the chosen relay.
    Connecting,
    /// Connected; lease is active and healthy.
    Active,
    /// Connection lost; in exponential-backoff between dials.
    Backoff,
    /// Operator-initiated stop or fatal error; tunnel is shut down.
    Stopped,
}

/// Per-event payload published on the broadcast channel.
///
/// Variants are kept narrow + non-exhaustive so subsequent batches
/// can extend the surface without breaking downstream consumers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TunnelEvent {
    /// Lifecycle transitioned to a new state.
    #[non_exhaustive]
    StateChanged {
        /// Previous state.
        from: TunnelState,
        /// New state.
        to: TunnelState,
        /// Wall-clock timestamp of the transition.
        at: Timestamp,
    },
    /// Outbound dial attempt against a specific relay address.
    #[non_exhaustive]
    DialAttempt {
        /// Relay identity-key hex (cosmetic — actual auth uses SPKI pin).
        relay_id: CompactString,
        /// Resolved socket addr the dial targeted.
        addr: SocketAddr,
        /// Wall-clock timestamp.
        at: Timestamp,
    },
    /// Lease was issued by the relay.
    #[non_exhaustive]
    LeaseIssued {
        /// Hostname allocated by the relay.
        hostname: CompactString,
        /// Lease expiry timestamp.
        expires_at: Timestamp,
    },
    /// Lease was renewed.
    #[non_exhaustive]
    LeaseRenewed {
        /// Hostname.
        hostname: CompactString,
        /// New expiry.
        expires_at: Timestamp,
    },
    /// Lease was lost (expired, revoked, or relay closed).
    #[non_exhaustive]
    LeaseLost {
        /// Hostname.
        hostname: CompactString,
        /// Optional human-readable reason.
        reason: CompactString,
    },
    /// MITM probe failed against the chosen relay — connection is
    /// being torn down.
    #[non_exhaustive]
    MitmDetected {
        /// Relay identity-key hex.
        relay_id: CompactString,
        /// Probe-failure description.
        reason: CompactString,
    },
    /// Eclipse picker warning — the supplied relay set is below
    /// the diversity floor but operator override permitted the
    /// dial. Surfaces so the CLI can render a banner.
    #[non_exhaustive]
    EclipseWarning {
        /// Number of distinct ASN bins observed.
        asn_bins: usize,
        /// Number of relays in the set.
        relay_count: usize,
    },
    /// Operator-visible audit message (typically a `tracing::info`
    /// echoed onto the bus for the TUI default mode).
    #[non_exhaustive]
    Audit {
        /// Span name + message body (compact for the TUI's narrow column).
        message: CompactString,
        /// Wall-clock timestamp.
        at: Timestamp,
    },
}

/// Default broadcast channel capacity.
///
/// Sized so the TUI default mode (single subscriber drained on each
/// frame at 30Hz) never loses events under normal load while
/// allowing brief subscriber stalls without blocking the SDK's emit
/// loop.
pub const DEFAULT_EVENT_CHANNEL_CAPACITY: usize = 256;

/// Convenience constructor: a fresh `(sender, receiver)` pair with
/// the documented default capacity.
#[must_use]
pub fn channel() -> (broadcast::Sender<TunnelEvent>, broadcast::Receiver<TunnelEvent>) {
    broadcast::channel(DEFAULT_EVENT_CHANNEL_CAPACITY)
}

/// Convenience constructor with a caller-chosen capacity. Panics
/// only if `capacity == 0`.
///
/// # Panics
/// Panics on `capacity == 0` (broadcast channels require a positive
/// capacity).
#[must_use]
pub fn channel_with_capacity(
    capacity: usize,
) -> (broadcast::Sender<TunnelEvent>, broadcast::Receiver<TunnelEvent>) {
    assert!(capacity > 0, "channel capacity must be > 0");
    broadcast::channel(capacity)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only setup")]
mod tests {
    use super::*;

    fn fixed_now() -> Timestamp {
        Timestamp::from_second(1_778_155_200).unwrap()
    }

    #[tokio::test]
    async fn channel_default_capacity_round_trip() {
        let (tx, mut rx) = channel();
        let event = TunnelEvent::StateChanged {
            from: TunnelState::Idle,
            to: TunnelState::Discovering,
            at: fixed_now(),
        };
        tx.send(event).unwrap();
        let received = rx.recv().await.unwrap();
        assert!(matches!(
            received,
            TunnelEvent::StateChanged {
                from: TunnelState::Idle,
                to: TunnelState::Discovering,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn channel_with_capacity_zero_panics() {
        let result = std::panic::catch_unwind(|| channel_with_capacity(0));
        assert!(result.is_err(), "capacity 0 must panic");
    }

    #[tokio::test]
    async fn multiple_subscribers_each_receive_event() {
        let (tx, mut rx1) = channel();
        let mut rx2 = tx.subscribe();
        let event = TunnelEvent::Audit {
            message: "hello".into(),
            at: fixed_now(),
        };
        tx.send(event).unwrap();
        let _ = rx1.recv().await.unwrap();
        let _ = rx2.recv().await.unwrap();
    }

    #[test]
    fn tunnel_state_is_copy() {
        // Compile-time invariant: TunnelState is Copy so consumers
        // can stash the discriminant without ceremony.
        fn assert_copy<T: Copy>() {}
        assert_copy::<TunnelState>();
    }
}
