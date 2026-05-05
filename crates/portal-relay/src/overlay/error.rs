//! Error type for the overlay subsystem (Phase 6b/B).
//!
//! Phase 6b/B U6 ships the loader-side variants surfaced by the
//! [`crate::overlay::wg_device::WgDevice`] trait + its
//! [`crate::overlay::wg_device::DefguardAdapter`] implementation:
//! `DeviceInit`, `IpcSet`, `PeerConfig`, `IoError`. The variant set is
//! `#[non_exhaustive]` so the U7 `netstack` + `Overlay` orchestrator
//! arms (smoltcp poll-loop join failure, hop-mux bind failure, peer-sync
//! collision, etc.) are not breaking changes when they land.

use std::io;

use thiserror::Error;

/// Errors produced by the overlay subsystem (`WgDevice` adapter,
/// netstack, hop-mux, peer-sync).
///
/// Phase 6b/B U6 — the U6 commit emits only `DeviceInit`, `PeerConfig`,
/// and `IoError`. `IpcSet` is reserved for a future fork-pick whose
/// configuration surface goes through a wg-config-string IPC channel
/// (`defguard_boringtun`'s `noise::Tunn` API does not — see ADR-0014's
/// fork-swap note); the variant is declared at U6 time so callers'
/// match arms remain stable across the secondary swap path.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum OverlayError {
    /// The userspace `WireGuard` device handle could not be constructed.
    /// Wraps the fork-side construction-time failure as a string so the
    /// fork's typed error never leaks across the sealed-trait boundary
    /// (per ADR-0014's "fork swap is one file" goal).
    ///
    /// Phase 6b/B U6 — emitted by
    /// [`crate::overlay::wg_device::DefguardAdapter::new`] when the
    /// supplied private key is malformed or the rate-limiter init fails.
    #[error("device init: {0}")]
    DeviceInit(String),

    /// A wg-config-string IPC application failed.
    ///
    /// Reserved for a future fork-pick whose configuration surface is
    /// the wg-quick / wg-userspace IPC channel
    /// (`set=1\nprivate_key=...\n...`). `defguard_boringtun`'s
    /// `noise::Tunn` API does not exercise this variant at U6 time —
    /// peer mutation goes through `apply_peers` directly. The variant
    /// is declared so the trait's error surface is stable across the
    /// secondary swap path documented in ADR-0015.
    #[error("ipc set: {0}")]
    IpcSet(String),

    /// A peer-config entry was rejected: malformed public key length,
    /// CIDR out of range, or any other validation failure that occurs
    /// before the peer enters the routing table.
    ///
    /// Phase 6b/B U6 — emitted by
    /// [`crate::overlay::wg_device::WgDevice::apply_peers`] (the trait
    /// method that `DefguardAdapter` implements) when the supplied
    /// [`crate::overlay::wg_device::PeerConfig`] fails pre-flight
    /// validation. The routing table is unchanged on this error
    /// (atomic-swap discipline — no partial peer-set updates).
    #[error("peer config: {0}")]
    PeerConfig(String),

    /// A standard library I/O error pass-through (filesystem or
    /// socket).  Reserved for the U7 hop-mux + netstack code paths
    /// that bind a real UDP socket; the U6 adapter does not exercise
    /// this variant directly because `noise::Tunn` does not own a
    /// socket (see ADR-0014 §"safe public API" + the U6 adapter's
    /// rustdoc for the divergence note).
    #[error("io: {0}")]
    IoError(#[from] io::Error),

    /// A trait method was invoked before its U7 wiring landed.
    ///
    /// Phase 6b/B U6 ships [`crate::overlay::wg_device::WgDevice`]'s
    /// trait shape only — the cleartext-IP packet I/O methods
    /// (`read_packet` / `write_packet`) cannot perform real work
    /// until U7's `overlay::netstack` integration wires them to the
    /// smoltcp `Interface` egress / ingress queues.  Calling them at
    /// U6 returns this variant so a misuse is observable at the wire
    /// rather than masked by a silent no-op success.
    #[error("not yet implemented: {0}")]
    NotYetImplemented(&'static str),
}
