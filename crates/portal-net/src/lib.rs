//! Transport layer — QUIC backhaul, TCP/UDP relay, datagram session.
//!
//! Owner: transport sockets and the QUIC trust boundary (`SecretBox<QuicIdentityKey>`)
//! per R2 (Phase 3, U4).
