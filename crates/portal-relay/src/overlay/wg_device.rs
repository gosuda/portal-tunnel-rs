//! Sealed [`WgDevice`] trait + the [`DefguardAdapter`] implementation
//! that wraps `defguard_boringtun = 0.6.5` per ADR-0014 / ADR-0015.
//!
//! ## Trait shape (per ADR-0014)
//!
//! `WgDevice` exposes four operations a userspace `WireGuard` data plane
//! must support for the overlay subsystem to drive it:
//!
//! - [`WgDevice::apply_peers`] — atomic peer-set replacement.
//! - [`WgDevice::read_packet`] / [`WgDevice::write_packet`] — packet
//!   I/O across the WG cryptographic boundary (cleartext IP packets
//!   on the tunnel-interface side; ciphertext UDP datagrams on the
//!   network side). Phase 6b/B U7 (`overlay::netstack`) owns the
//!   smoltcp wiring of these methods.  At U6 the methods return
//!   [`OverlayError::NotYetImplemented`] — a misuse is observable at
//!   the wire rather than masked by a silent no-op success.
//! - [`WgDevice::close`] — terminal lifecycle hook.
//!
//! The trait is sealed so only the in-crate adapter implements it.
//! Switching to the secondary fork (`NepTUN`, post-license-review per
//! ADR-0015) requires editing this single file plus the
//! `[workspace.dependencies]` entry; nothing else in `portal-relay`
//! depends on the fork's typed surface.
//!
//! ## Divergence from the plan-named "device" abstraction
//!
//! ADR-0014's `WgDevice` framing names a single device handle that
//! owns the peer set. **`defguard_boringtun`'s public API does not ship
//! a multi-peer device type at U6 land time:** the crate's `device`
//! sub-module is feature-gated behind the `device` Cargo feature and
//! pulls in `socket2` + a per-peer UDP `socket2::Socket`, which would
//! bind real OS ports and contradict the smoltcp-in-process design
//! ADR-0014 commits to. The portable surface is `noise::Tunn`, a
//! per-peer `WireGuard` state machine that does not own a socket.
//!
//! Per the plan's option B, [`DefguardAdapter`] is itself the device:
//! it owns a [`std::collections::HashMap`] of validated peer-state
//! entries keyed by peer public key, plus a routing table (one entry
//! per allowed-IP) the U7 netstack will consult to dispatch outbound
//! packets to the right peer's `noise::Tunn::encapsulate`. The atomic
//! swap discipline is preserved — `apply_peers` validates every entry
//! before mutating the in-memory state, so a single rejected peer
//! leaves the previous peer set untouched.
//!
//! Per-peer `noise::Tunn` instances are NOT constructed at U6 land
//! time. The static private key + the shared
//! [`defguard_boringtun::noise::rate_limiter::RateLimiter`] are
//! reconstructed at U7 land time alongside their only consumers (the
//! per-peer `Tunn::new` calls in the smoltcp-bridged
//! encapsulate/decapsulate path) — the workspace `dead_code`
//! discipline disallows holding them at U6 with no U6-time reader.
//! The validated peer map this adapter writes at U6 carries every
//! `PeerConfig` field `WireGuard` configures (allowed-IPs, endpoint,
//! keepalive, pre-shared key) so U7's `Tunn::new` call has full
//! peer state available without a re-apply round-trip.
//!
//! ## Hard gates upheld
//!
//! - **`unsafe_code = "forbid"` (workspace-wide).** No `unsafe` is
//!   required to consume `noise::Tunn` — the crate's public API is
//!   fully safe at 0.6.5 (per ADR-0015's matrix).
//! - **License (Apache-2.0 OR MIT).** `defguard_boringtun` composes
//!   with the workspace's MIT distribution without a legal-review
//!   gate (per ADR-0015 §Decision).

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use defguard_boringtun::x25519;
use parking_lot::RwLock;
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};

use super::error::OverlayError;

/// The sealed module that prevents external implementations of
/// [`WgDevice`]. Per ADR-0014, only the in-crate adapter for the
/// chosen fork (per ADR-0015) implements this marker.
mod sealed {
    /// Sealed marker — re-implemented per swap of the fork-pick
    /// adapter (ADR-0015 secondary→primary path).
    pub trait Sealed {}
}

/// Sealed trait that abstracts the userspace `WireGuard` data plane.
///
/// Phase 6b/B U6 — implemented in-crate by [`DefguardAdapter`]. The
/// U7 `overlay::netstack` integration consumes this trait, not the
/// concrete adapter type, so the fork swap is one file (per ADR-0014).
///
/// The trait is `Send + Sync` because the U7 netstack will share the
/// device between the smoltcp poll-loop task and the hop-mux send/recv
/// tasks.
pub trait WgDevice: sealed::Sealed + Send + Sync {
    /// Atomically replace the peer set. The supplied slice describes
    /// the desired final peer set; peers absent from the slice are
    /// removed from the device, peers present are inserted-or-updated.
    ///
    /// # Errors
    ///
    /// Returns [`OverlayError::PeerConfig`] if any entry fails
    /// pre-flight validation (malformed public key, zero allowed-IPs,
    /// CIDR out of range, etc.). The previous peer set is preserved
    /// on error.
    fn apply_peers(&self, peers: &[PeerConfig]) -> Result<(), OverlayError>;

    /// Read one cleartext IP packet from the `WireGuard` tunnel
    /// interface side.
    ///
    /// # Errors
    ///
    /// Phase 6b/B U6 — returns [`OverlayError::NotYetImplemented`];
    /// the U7 `overlay::netstack` integration owns the smoltcp wiring
    /// + the eventual error surface (`IoError` for socket failures).
    fn read_packet(&self, buf: &mut [u8]) -> Result<usize, OverlayError>;

    /// Write one cleartext IP packet into the `WireGuard` tunnel
    /// interface for encapsulation + transmission.
    ///
    /// # Errors
    ///
    /// Phase 6b/B U6 — returns [`OverlayError::NotYetImplemented`];
    /// see [`WgDevice::read_packet`].
    fn write_packet(&self, packet: &[u8]) -> Result<(), OverlayError>;

    /// Close the device — drop all peer state.  Takes `Box<Self>`
    /// so the call is object-safe (`dyn WgDevice` consumers in U7
    /// hold the device behind a smart pointer; an owned-`self`
    /// receiver would break object safety).  The boxed device is
    /// consumed so the trait object cannot be re-used post-close.
    ///
    /// # Errors
    ///
    /// Returns [`OverlayError`] if a fork-side teardown step fails;
    /// the U6 adapter never produces an error here (the destructor
    /// is infallible).
    fn close(self: Box<Self>) -> Result<(), OverlayError>;
}

/// One peer entry consumed by [`WgDevice::apply_peers`].
///
/// This is the curated greenfield shape — the U7 `peer_sync` module
/// converts greenfield `RelayDescriptor` (from `portal-wire`) into
/// `Vec<PeerConfig>` for the apply call. The shape is intentionally
/// fork-neutral so the secondary swap (ADR-0015) does not ripple.
///
/// Not `Clone`: `SecretBox<[u8; 32]>` deliberately does not implement
/// `Clone` (the `secrecy` crate gates `SecretBox::clone` behind a
/// `CloneableSecret` marker the keyless module's R2 discipline does
/// not opt in for `[u8; 32]`).  Callers that need an additional copy
/// rebuild the `PeerConfig` from the source descriptor.
#[derive(Debug)]
pub struct PeerConfig {
    /// Peer's `WireGuard` X25519 static public key (32 bytes).
    pub public_key: [u8; 32],

    /// Allowed-IPs entries (IP + CIDR length). Both IPv4 and IPv6
    /// entries are first-class — R12 carriage requirement.
    pub allowed_ips: Vec<AllowedIp>,

    /// Optional remote endpoint. Phase 6b/B U7 hop-mux passes this
    /// through to the smoltcp UDP send path; the U6 adapter records
    /// it without further validation.
    pub endpoint: Option<SocketAddr>,

    /// Optional persistent-keepalive interval in seconds
    /// (`WireGuard`'s `PersistentKeepalive` knob).
    pub persistent_keepalive_secs: Option<u16>,

    /// Optional pre-shared key (`WireGuard`'s `PresharedKey`).  Wrapped
    /// in [`secrecy::SecretBox`] so accidental `Debug` output does not
    /// expose the bytes.
    pub preshared_key: Option<SecretBox<[u8; 32]>>,
}

/// One allowed-IP entry — IP address + CIDR prefix length.
///
/// Both v4 and v6 are first-class (R12). The constructor enforces
/// the prefix-length range matches the address family (≤ 32 for v4,
/// ≤ 128 for v6) so the routing-table insert site does not need to
/// re-check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AllowedIp {
    addr: IpAddr,
    prefix_len: u8,
}

impl AllowedIp {
    /// Construct an [`AllowedIp`].
    ///
    /// # Errors
    ///
    /// Returns [`OverlayError::PeerConfig`] if `prefix_len` exceeds
    /// the family-appropriate maximum (32 for IPv4, 128 for IPv6).
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Self, OverlayError> {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(OverlayError::PeerConfig(format!(
                "prefix length {prefix_len} exceeds family maximum {max}",
            )));
        }
        Ok(Self { addr, prefix_len })
    }

    /// The base IP address of this allowed-IP entry.
    #[must_use]
    pub const fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The CIDR prefix length (0..=32 for v4, 0..=128 for v6).
    #[must_use]
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
}

/// In-crate validated state for a single `WireGuard` peer.
///
/// Holds every configurable peer attribute the `WireGuard` wire
/// understands so a successful [`WgDevice::apply_peers`] never
/// silently drops endpoint / keepalive / pre-shared-key state.  Each
/// field has a U6-time accessor on [`DefguardAdapter`] so the
/// workspace `dead_code` discipline is upheld:
///
/// - `allowed_ips` — consumed by [`DefguardAdapter::registered_allowed_ips`]
///   (also the U7 routing-table consumer).
/// - `endpoint` — consumed by [`DefguardAdapter::peer_endpoint`].
/// - `persistent_keepalive_secs` — consumed by
///   [`DefguardAdapter::peer_persistent_keepalive_secs`].
/// - `preshared_key` — consumed by
///   [`DefguardAdapter::peer_has_preshared_key`] (the bytes
///   themselves never leave the adapter — only their presence is
///   observable across the U6 surface).
struct PeerState {
    allowed_ips: Vec<AllowedIp>,
    endpoint: Option<SocketAddr>,
    persistent_keepalive_secs: Option<u16>,
    preshared_key: Option<SecretBox<[u8; 32]>>,
}

/// Adapter that wraps `defguard_boringtun = 0.6.5` behind the sealed
/// [`WgDevice`] trait.
///
/// See the module-level rustdoc for the divergence note (option B
/// peer-set + routing-table-inside-the-adapter shape) and the hard
/// gates this adapter upholds (`unsafe_code = "forbid"`, MIT-compatible
/// license).
///
/// Phase 6b/B U6 records only the static public key + the validated
/// peer map.  The static private key + the shared
/// [`defguard_boringtun::noise::rate_limiter::RateLimiter`] are
/// constructed at U7 land time alongside their only consumers (the
/// per-peer `noise::Tunn` instances built when the smoltcp-bridged
/// encapsulate/decapsulate path goes live).
pub struct DefguardAdapter {
    /// Static public key bytes.  Held so the U7 `peer_sync` self-skip
    /// check can compare a candidate peer's public key against the
    /// adapter's own without rederiving it.
    static_public_bytes: [u8; 32],
    /// Map of peer public key → validated peer state.  Read on every
    /// packet dispatch (U7 hot path); written only on `apply_peers`.
    peers: RwLock<HashMap<[u8; 32], PeerState>>,
}

impl DefguardAdapter {
    /// Construct a new adapter over the supplied X25519 static private
    /// key.
    ///
    /// Returns [`OverlayError::DeviceInit`] if the supplied private
    /// key is malformed (the typed `[u8; 32]` surface enforces
    /// length, but the validation site is in place for the
    /// secondary-swap path where the key surface may change).
    ///
    /// Phase 6b/B U6 derives + records only the corresponding public
    /// key.  U7 expands the constructor to also build + retain the
    /// shared `RateLimiter` (because U7 is when the per-peer
    /// `noise::Tunn` instances that consume it are built).
    ///
    /// # Errors
    ///
    /// Returns [`OverlayError::DeviceInit`] if construction fails
    /// (currently unreachable behind the `[u8; 32]` typed surface;
    /// the validation site is reserved for the secondary-swap path).
    ///
    /// The `SecretBox` argument is taken by value so the caller's
    /// trust-boundary discipline (R2) hands ownership of the secret
    /// to this constructor — the `secrecy` crate zeroises the inner
    /// bytes when the box is dropped.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "ownership transfer is the R2 trust-boundary contract; the `SecretBox` is dropped + zeroised inside the constructor"
    )]
    pub fn new(static_private_bytes: SecretBox<[u8; 32]>) -> Result<Self, OverlayError> {
        let static_private = x25519::StaticSecret::from(*static_private_bytes.expose_secret());
        let static_public_bytes = *x25519::PublicKey::from(&static_private).as_bytes();
        Ok(Self {
            static_public_bytes,
            peers: RwLock::new(HashMap::new()),
        })
    }

    /// Construct an adapter with a freshly-generated WG static private
    /// key.  Intended for unit tests + the U7 orchestrator's first-run
    /// init path; production deployments load the key from disk via
    /// `portal-crypto`.
    ///
    /// # Errors
    ///
    /// Returns [`OverlayError::DeviceInit`] if the underlying
    /// constructor fails (currently unreachable; see [`Self::new`]).
    pub fn with_random_key() -> Result<Self, OverlayError> {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self::new(SecretBox::new(Box::new(bytes)))
    }

    /// Test-only observation hook: the routing-table entries
    /// currently registered, in deterministic sorted order
    /// (by address, then prefix length).
    ///
    /// Phase 6b/B U6 — the unit tests assert R12 IPv6 carriage and
    /// the v4 happy-path via this getter. The U7 netstack consumes
    /// the same routing table via the typed lookup in
    /// `route_destination` (forthcoming) — tests should NOT poke at
    /// this for non-assertion purposes.
    #[must_use]
    pub fn registered_allowed_ips(&self) -> Vec<(IpAddr, u8)> {
        let mut entries: Vec<(IpAddr, u8)> = {
            let peers = self.peers.read();
            peers
                .values()
                .flat_map(|p| p.allowed_ips.iter().map(|ip| (ip.addr, ip.prefix_len)))
                .collect()
        };
        entries.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        entries
    }

    /// The static public key derived from the configured static
    /// private key.  Useful for logging + the U7 self-skip check
    /// (`peer_sync` drops a peer entry whose public key matches the
    /// adapter's own).
    #[must_use]
    pub const fn static_public_bytes(&self) -> [u8; 32] {
        self.static_public_bytes
    }

    /// The endpoint configured for the peer with the given public
    /// key, or `None` if the peer is not registered or did not
    /// declare an endpoint.
    ///
    /// Phase 6b/B U6 — observable so [`WgDevice::apply_peers`]
    /// faithfully preserves the `WireGuard` transport state across an
    /// apply.  U7's hop-mux consumes this through the same accessor.
    #[must_use]
    pub fn peer_endpoint(&self, public_key: &[u8; 32]) -> Option<SocketAddr> {
        self.peers.read().get(public_key).and_then(|p| p.endpoint)
    }

    /// The persistent-keepalive interval (seconds) configured for
    /// the peer with the given public key, or `None` if the peer is
    /// not registered or did not declare a keepalive.
    ///
    /// Phase 6b/B U6 — observable so [`WgDevice::apply_peers`]
    /// faithfully preserves the `WireGuard` `PersistentKeepalive`
    /// knob.  U7's timer-wiring path consumes this through the same
    /// accessor.
    #[must_use]
    pub fn peer_persistent_keepalive_secs(&self, public_key: &[u8; 32]) -> Option<u16> {
        self.peers
            .read()
            .get(public_key)
            .and_then(|p| p.persistent_keepalive_secs)
    }

    /// Whether a pre-shared key is configured for the peer with the
    /// given public key.  Returns `false` if the peer is not
    /// registered.
    ///
    /// Phase 6b/B U6 — observable so [`WgDevice::apply_peers`]
    /// faithfully preserves the `WireGuard` `PresharedKey` knob.  The
    /// bytes themselves never cross this surface (R2 trust-boundary
    /// discipline) — only their *presence* is reported, which is
    /// sufficient for an apply round-trip test.  U7's `Tunn::new`
    /// consumes the inner secret via a private accessor that lives
    /// alongside the per-peer `Tunn` construction.
    #[must_use]
    pub fn peer_has_preshared_key(&self, public_key: &[u8; 32]) -> bool {
        self.peers
            .read()
            .get(public_key)
            .is_some_and(|p| p.preshared_key.is_some())
    }

    /// Validate one [`PeerConfig`] entry without mutating state.
    fn validate_peer(peer: &PeerConfig) -> Result<(), OverlayError> {
        // The 32-byte length is enforced by the typed `[u8; 32]`
        // surface; the small-subgroup check below refuses every
        // forbidden low-order Curve25519 public key (RFC 7748 §5 +
        // the published small-subgroup-attack literature).  A peer
        // with one of these keys would yield a deterministic shared
        // secret of zero — refused here so the routing-table insert
        // site sees only well-formed keys.
        if X25519_FORBIDDEN_LOW_ORDER_KEYS.contains(&peer.public_key) {
            return Err(OverlayError::PeerConfig(
                "peer public key is a forbidden low-order Curve25519 point".to_owned(),
            ));
        }
        if peer.allowed_ips.is_empty() {
            return Err(OverlayError::PeerConfig(
                "peer must declare at least one allowed_ip".to_owned(),
            ));
        }
        Ok(())
    }
}

/// The forbidden low-order Curve25519 public keys exactly as
/// enumerated by libsodium's reference implementation.
///
/// Source — primary, byte-identical:
/// `libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c`,
/// function `has_small_order`, the `static const unsigned char
/// blocklist[7][32]` table.  The seven entries are the only points
/// libsodium rejects; this adapter mirrors that exact set so the
/// validation surface is auditable against an upstream primary
/// source rather than a derived literature claim.
///
/// Each entry's role:
///
/// 1. `[0; 32]` — the identity element on the Montgomery curve
///    (a peer presenting it yields a zero shared secret).
/// 2. `[1, 0, …]` — order-1 representative.
/// 3. `e0eb7a7c…00` — order-8 generator (the sodium blocklist's
///    canonical 32-byte little-endian encoding).
/// 4. `5f9c95bc…57` — the conjugate order-8 generator.
/// 5. `ec ff…7f` — `p - 1` (mod p reduces to `-1`, an order-2
///    representative).
/// 6. `ed ff…7f` — `p` (≡ 0 mod p; identity again under the
///    standard reduction, listed so a peer cannot bypass the
///    `[0; 32]` check by sending the unreduced encoding).
/// 7. `ee ff…7f` — `p + 1` (≡ 1 mod p; mirrors entry 2 under the
///    standard reduction).
const X25519_FORBIDDEN_LOW_ORDER_KEYS: [[u8; 32]; 7] = [
    [0u8; 32],
    [
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

impl sealed::Sealed for DefguardAdapter {}

impl WgDevice for DefguardAdapter {
    fn apply_peers(&self, peers: &[PeerConfig]) -> Result<(), OverlayError> {
        // Pre-flight validate every entry first so a malformed
        // mid-slice peer leaves the previous peer set untouched
        // (atomic-swap discipline).
        for peer in peers {
            Self::validate_peer(peer)?;
        }

        // Build the new peer map.  Last-write-wins on duplicate
        // public keys within the input slice — matches WireGuard
        // wg-config-string semantics.  Every configured field is
        // preserved (allowed-IPs, endpoint, keepalive, pre-shared key)
        // so an apply never silently drops transport or security
        // state.
        let mut new_peers: HashMap<[u8; 32], PeerState> = HashMap::with_capacity(peers.len());
        for peer in peers {
            let preshared_key = peer
                .preshared_key
                .as_ref()
                .map(|k| SecretBox::new(Box::new(*k.expose_secret())));
            let state = PeerState {
                allowed_ips: peer.allowed_ips.clone(),
                endpoint: peer.endpoint,
                persistent_keepalive_secs: peer.persistent_keepalive_secs,
                preshared_key,
            };
            new_peers.insert(peer.public_key, state);
        }

        {
            let mut guard = self.peers.write();
            *guard = new_peers;
        }
        Ok(())
    }

    fn read_packet(&self, _buf: &mut [u8]) -> Result<usize, OverlayError> {
        Err(OverlayError::NotYetImplemented(
            "WgDevice::read_packet — wired in Phase 6b/B U7 (overlay::netstack)",
        ))
    }

    fn write_packet(&self, _packet: &[u8]) -> Result<(), OverlayError> {
        Err(OverlayError::NotYetImplemented(
            "WgDevice::write_packet — wired in Phase 6b/B U7 (overlay::netstack)",
        ))
    }

    fn close(self: Box<Self>) -> Result<(), OverlayError> {
        // Drop the boxed device — the destructor runs the peer map
        // + rate-limiter teardown.  `Box<Self>` consumption keeps the
        // call site object-safe.
        drop(self);
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test-only setup")]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    /// Phase 6b/B U6 test scenario 1: construct adapter with a
    /// generated WG private key + listen port → device handle is
    /// live; `apply_peers(&[])` is a no-op success.
    ///
    /// Note: `noise::Tunn`'s constructor does NOT bind a UDP socket,
    /// so there is no "listen port" parameter at the U6 surface (see
    /// the module-level divergence rustdoc). The U7 hop-mux owns the
    /// smoltcp UDP bind. The test exercises the actual U6 surface.
    #[test]
    fn construct_and_apply_empty_peer_list() {
        let adapter =
            DefguardAdapter::with_random_key().expect("adapter construction must succeed");
        adapter
            .apply_peers(&[])
            .expect("empty peer list is a no-op success");
        assert!(
            adapter.registered_allowed_ips().is_empty(),
            "no peers means no routing-table entries"
        );
    }

    /// Phase 6b/B U6 test scenario 2: `apply_peers` with one IPv4
    /// peer → routing table contains `<v4-prefix>/32`.
    #[test]
    fn apply_peers_ipv4_routing_table() {
        let adapter = DefguardAdapter::with_random_key().expect("construction");
        let peer_pub = [1u8; 32];
        let allowed =
            AllowedIp::new(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1)), 32).expect("v4/32 is valid");
        let peer = PeerConfig {
            public_key: peer_pub,
            allowed_ips: vec![allowed],
            endpoint: None,
            persistent_keepalive_secs: None,
            preshared_key: None,
        };
        adapter
            .apply_peers(&[peer])
            .expect("v4 peer apply succeeds");
        let entries = adapter.registered_allowed_ips();
        assert_eq!(entries.len(), 1, "exactly one allowed-IP entry");
        assert_eq!(entries[0], (IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1)), 32));
    }

    /// Phase 6b/B U6 test scenario 3 (R12 carriage assertion):
    /// `apply_peers` with one IPv6 peer → routing table contains
    /// `<v6-prefix>/128`.
    #[test]
    fn apply_peers_ipv6_routing_table_r12() {
        let adapter = DefguardAdapter::with_random_key().expect("construction");
        let peer_pub = [2u8; 32];
        let v6_addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let allowed = AllowedIp::new(IpAddr::V6(v6_addr), 128).expect("v6/128 is valid");
        let peer = PeerConfig {
            public_key: peer_pub,
            allowed_ips: vec![allowed],
            endpoint: None,
            persistent_keepalive_secs: None,
            preshared_key: None,
        };
        adapter
            .apply_peers(&[peer])
            .expect("v6 peer apply succeeds");
        let entries = adapter.registered_allowed_ips();
        assert_eq!(entries.len(), 1, "exactly one allowed-IP entry");
        assert_eq!(entries[0], (IpAddr::V6(v6_addr), 128));
    }

    /// Phase 6b/B U6 test scenario 4: `apply_peers` with a malformed
    /// peer public key (the all-zero X25519 small-subgroup point —
    /// the first libsodium blocklist entry) →
    /// `Err(OverlayError::PeerConfig)`; routing table unchanged.
    #[test]
    fn apply_peers_rejects_malformed_public_key() {
        let adapter = DefguardAdapter::with_random_key().expect("construction");
        // Seed with a valid v4 peer first so we can assert the routing
        // table is preserved across the failed apply.
        let make_valid_peer = || PeerConfig {
            public_key: [3u8; 32],
            allowed_ips: vec![
                AllowedIp::new(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 2)), 32).expect("valid"),
            ],
            endpoint: None,
            persistent_keepalive_secs: None,
            preshared_key: None,
        };
        adapter
            .apply_peers(&[make_valid_peer()])
            .expect("seed apply");
        let baseline = adapter.registered_allowed_ips();
        assert_eq!(baseline.len(), 1);

        let bad_peer = PeerConfig {
            public_key: [0u8; 32],
            allowed_ips: vec![
                AllowedIp::new(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 3)), 32).expect("valid"),
            ],
            endpoint: None,
            persistent_keepalive_secs: None,
            preshared_key: None,
        };
        let err = adapter
            .apply_peers(&[make_valid_peer(), bad_peer])
            .expect_err("all-zero public key must be refused");
        assert!(
            matches!(err, OverlayError::PeerConfig(_)),
            "expected PeerConfig variant, got {err:?}",
        );
        assert_eq!(
            adapter.registered_allowed_ips(),
            baseline,
            "routing table preserved across the failed apply (atomic-swap)",
        );
    }

    /// Phase 6b/B U6 test scenario 4 (CIDR-out-of-range edge): the
    /// `AllowedIp::new` constructor refuses a v4 prefix > 32.
    #[test]
    fn allowed_ip_refuses_oversized_prefix_for_v4() {
        let err = AllowedIp::new(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1)), 33)
            .expect_err("v4 prefix > 32 must be refused");
        assert!(
            matches!(err, OverlayError::PeerConfig(_)),
            "expected PeerConfig variant, got {err:?}",
        );
    }

    /// Phase 6b/B U6 test scenario 4 (allowed-IPs cardinality edge):
    /// a peer with zero allowed-IPs is refused so the routing table
    /// never carries a peer that cannot route.
    #[test]
    fn apply_peers_rejects_empty_allowed_ips() {
        let adapter = DefguardAdapter::with_random_key().expect("construction");
        let peer = PeerConfig {
            public_key: [4u8; 32],
            allowed_ips: vec![],
            endpoint: None,
            persistent_keepalive_secs: None,
            preshared_key: None,
        };
        let err = adapter
            .apply_peers(&[peer])
            .expect_err("zero allowed_ips must be refused");
        assert!(matches!(err, OverlayError::PeerConfig(_)));
    }

    /// Phase 6b/B U6 test scenario 5 (in-use port) — **DEFERRED to
    /// U7**.  `noise::Tunn::new` does NOT bind a UDP socket, so the
    /// `DeviceInit::in-use port` case has no surface at the U6
    /// adapter.  The U7 hop-mux (smoltcp UDP socket via the quinn
    /// adapter) is where the in-use-port assertion fires.  The
    /// `OverlayError::DeviceInit` variant is declared at U6 time so
    /// the U7 commit does not break callers' match arms.
    #[test]
    fn device_init_variant_is_declared() {
        // Compile-time check that the variant exists (U7 emits it).
        let err: OverlayError = OverlayError::DeviceInit("placeholder".to_owned());
        assert!(matches!(err, OverlayError::DeviceInit(_)));
    }

    /// Phase 6b/B U6 — `read_packet` / `write_packet` are explicit
    /// not-yet-implemented at U6 time.  Calling them surfaces the
    /// `NotYetImplemented` variant; U7 wires them to smoltcp.
    #[test]
    fn packet_io_returns_not_yet_implemented() {
        let adapter = DefguardAdapter::with_random_key().expect("construction");
        let mut buf = [0u8; 64];
        let read_err = adapter.read_packet(&mut buf).expect_err("U6 stub");
        assert!(matches!(read_err, OverlayError::NotYetImplemented(_)));
        let write_err = adapter.write_packet(&buf).expect_err("U6 stub");
        assert!(matches!(write_err, OverlayError::NotYetImplemented(_)));
    }

    /// Sanity: the static public key derives from the supplied
    /// private key (X25519 base-point multiplication).  Two adapters
    /// constructed from the same private bytes must yield the same
    /// public bytes.
    #[test]
    fn static_public_is_deterministic_from_private() {
        let bytes = [7u8; 32];
        let a = DefguardAdapter::new(SecretBox::new(Box::new(bytes))).expect("construction a");
        let b = DefguardAdapter::new(SecretBox::new(Box::new(bytes))).expect("construction b");
        assert_eq!(a.static_public_bytes(), b.static_public_bytes());
    }

    /// Mixed v4/v6 peer set → routing table carries both families.
    /// Reinforces R12: v6 lives alongside v4, not as a follow-up.
    #[test]
    fn apply_peers_carries_v4_and_v6_simultaneously() {
        let adapter = DefguardAdapter::with_random_key().expect("construction");
        let v4_peer = PeerConfig {
            public_key: [10u8; 32],
            allowed_ips: vec![
                AllowedIp::new(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 4)), 32).expect("valid"),
            ],
            endpoint: None,
            persistent_keepalive_secs: None,
            preshared_key: None,
        };
        let v6_peer = PeerConfig {
            public_key: [11u8; 32],
            allowed_ips: vec![
                AllowedIp::new(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)), 128)
                    .expect("valid"),
            ],
            endpoint: None,
            persistent_keepalive_secs: None,
            preshared_key: None,
        };
        adapter
            .apply_peers(&[v4_peer, v6_peer])
            .expect("mixed v4/v6 peers apply");
        let entries = adapter.registered_allowed_ips();
        assert_eq!(entries.len(), 2);
        // After sort-by-addr-then-prefix: v4 sorts before v6.
        assert_eq!(entries[0].0, IpAddr::V4(Ipv4Addr::new(10, 9, 0, 4)));
        assert_eq!(entries[0].1, 32);
        assert_eq!(
            entries[1].0,
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
        );
        assert_eq!(entries[1].1, 128);
    }

    /// Apply replaces (not merges) the prior peer set.
    #[test]
    fn apply_peers_replaces_prior_set() {
        let adapter = DefguardAdapter::with_random_key().expect("construction");
        let first = PeerConfig {
            public_key: [20u8; 32],
            allowed_ips: vec![
                AllowedIp::new(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 5)), 32).expect("valid"),
            ],
            endpoint: None,
            persistent_keepalive_secs: None,
            preshared_key: None,
        };
        let second = PeerConfig {
            public_key: [21u8; 32],
            allowed_ips: vec![
                AllowedIp::new(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 6)), 32).expect("valid"),
            ],
            endpoint: None,
            persistent_keepalive_secs: None,
            preshared_key: None,
        };
        adapter.apply_peers(&[first]).expect("first apply");
        adapter.apply_peers(&[second]).expect("second apply");
        let entries = adapter.registered_allowed_ips();
        assert_eq!(entries.len(), 1, "second apply replaced (not merged)");
        assert_eq!(entries[0].0, IpAddr::V4(Ipv4Addr::new(10, 9, 0, 6)));
    }

    /// `close` consumes `Box<Self>` (terminal lifecycle, object-safe).
    #[test]
    fn close_consumes_self() {
        let adapter = DefguardAdapter::with_random_key().expect("construction");
        Box::new(adapter).close().expect("close succeeds");
    }

    /// `dyn WgDevice::close` is callable through a trait object —
    /// the `Box<Self>` receiver keeps `WgDevice` object-safe and the
    /// U7 netstack will hold the device as `Box<dyn WgDevice>`.
    #[test]
    fn close_is_object_safe() {
        let adapter: Box<dyn WgDevice> =
            Box::new(DefguardAdapter::with_random_key().expect("construction"));
        adapter.close().expect("dyn-WgDevice close succeeds");
    }

    /// Phase 6b/B U6 — every entry in libsodium's blocklist is
    /// rejected by [`DefguardAdapter::apply_peers`].  Each test
    /// constructs a peer with the blocklist entry as its public key
    /// and a valid v4 allowed-IP; the apply MUST fail with
    /// `OverlayError::PeerConfig` so a peer presenting any small-
    /// order Curve25519 point cannot enter the routing table.
    ///
    /// Note: the blocklist constant lives in this file
    /// (`X25519_FORBIDDEN_LOW_ORDER_KEYS`) and is sourced byte-
    /// identically from libsodium's
    /// `crypto_scalarmult_curve25519_ref10_has_small_order` — a
    /// primary upstream cryptographic reference.  This test is the
    /// per-entry verification gate the security review required.
    #[test]
    fn apply_peers_rejects_each_libsodium_blocklist_entry() {
        let valid_allowed_ip = AllowedIp::new(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 99)), 32)
            .expect("valid v4/32 allowed-ip");
        for (idx, blocked_key) in X25519_FORBIDDEN_LOW_ORDER_KEYS.iter().enumerate() {
            let adapter = DefguardAdapter::with_random_key().expect("construction");
            let peer = PeerConfig {
                public_key: *blocked_key,
                allowed_ips: vec![valid_allowed_ip],
                endpoint: None,
                persistent_keepalive_secs: None,
                preshared_key: None,
            };
            let err = adapter
                .apply_peers(&[peer])
                .expect_err("blocklist entry must be refused");
            assert!(
                matches!(err, OverlayError::PeerConfig(_)),
                "entry {idx}: expected PeerConfig variant, got {err:?}",
            );
            assert!(
                adapter.registered_allowed_ips().is_empty(),
                "entry {idx}: routing table must remain empty after refused apply",
            );
        }
    }

    /// Sanity: the blocklist is exactly the seven libsodium entries
    /// (no silent additions or deletions).
    #[test]
    fn libsodium_blocklist_cardinality_is_seven() {
        assert_eq!(
            X25519_FORBIDDEN_LOW_ORDER_KEYS.len(),
            7,
            "the blocklist must be byte-identical with libsodium's seven entries",
        );
    }

    /// `apply_peers` preserves every configurable peer attribute —
    /// endpoint, persistent-keepalive, pre-shared key — across the
    /// apply.  Regression guard for "the apply silently drops
    /// transport / security state" (an earlier draft narrowed
    /// `PeerState` to allowed-IPs only).
    #[test]
    fn apply_peers_preserves_endpoint_keepalive_and_preshared_key() {
        use std::net::SocketAddrV4;
        let adapter = DefguardAdapter::with_random_key().expect("construction");
        let peer_pub = [42u8; 32];
        let endpoint = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 7), 51820));
        let psk_bytes = [0xa5u8; 32];
        let peer = PeerConfig {
            public_key: peer_pub,
            allowed_ips: vec![
                AllowedIp::new(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 7)), 32).expect("valid"),
            ],
            endpoint: Some(endpoint),
            persistent_keepalive_secs: Some(25),
            preshared_key: Some(SecretBox::new(Box::new(psk_bytes))),
        };
        adapter.apply_peers(&[peer]).expect("apply");

        assert_eq!(
            adapter.peer_endpoint(&peer_pub),
            Some(endpoint),
            "endpoint preserved across apply",
        );
        assert_eq!(
            adapter.peer_persistent_keepalive_secs(&peer_pub),
            Some(25),
            "keepalive preserved across apply",
        );
        assert!(
            adapter.peer_has_preshared_key(&peer_pub),
            "pre-shared key presence preserved across apply",
        );
    }

    /// Per-peer accessors return `None` / `false` for an unknown
    /// public key (no panics, no leaks across the boundary).
    #[test]
    fn per_peer_accessors_handle_unknown_keys() {
        let adapter = DefguardAdapter::with_random_key().expect("construction");
        let unknown = [0xffu8; 32];
        assert!(adapter.peer_endpoint(&unknown).is_none());
        assert!(adapter.peer_persistent_keepalive_secs(&unknown).is_none());
        assert!(!adapter.peer_has_preshared_key(&unknown));
    }
}
