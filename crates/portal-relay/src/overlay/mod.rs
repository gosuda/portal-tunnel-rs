//! Overlay subsystem (Phase 6b/B) — sealed `WgDevice` trait + the
//! adapter that wraps the chosen userspace `WireGuard` fork
//! (`defguard_boringtun`, per ADR-0015).
//!
//! ## Phase 6b/B implementation status
//!
//! Phase 6b/B lands incrementally per
//! `docs/plans/2026-05-04-007-feat-portal-relay-overlay-keyless-plan.md`.
//!
//! - **U5 (landed)** — ADR-0014 (overlay architecture) + ADR-0015
//!   (fork pick) + workspace dep declaration.
//! - **U6 (landed)** — sealed [`wg_device::WgDevice`] trait +
//!   [`wg_device::DefguardAdapter`] + [`wg_device::PeerConfig`] +
//!   [`error::OverlayError`].  The trait shape is wired but the
//!   cleartext-IP packet I/O methods return
//!   [`error::OverlayError::NotYetImplemented`] until U7 lands the
//!   smoltcp wiring.
//! - **U7 (deferred)** — `overlay::netstack` (smoltcp interface +
//!   poll loop), `overlay::peer_sync` (greenfield
//!   `RelayDescriptor` → `Vec<PeerConfig>` translation), and
//!   `overlay::Overlay` (orchestrator).  The U7 commit also wires
//!   `WgDevice::read_packet` / `WgDevice::write_packet` to real
//!   smoltcp socket I/O.
//!
//! ## Architecture pointer
//!
//! See ADR-0014 §"Sealed `WgDevice` trait isolates fork choice" for
//! the rationale that sealed-trait + smoltcp + QUIC-on-smoltcp-UDP
//! hop-mux is the chosen overlay shape; ADR-0015 §"Decision" pins
//! `defguard_boringtun` as the v0.1 primary fork.

pub mod error;
pub mod wg_device;

pub use error::OverlayError;
pub use wg_device::{AllowedIp, DefguardAdapter, PeerConfig, WgDevice};
