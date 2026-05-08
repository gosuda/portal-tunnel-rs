//! Expose round-trip test — blocked on `portal-sdk::expose`.
//!
//! This test documents the full three-trust-boundary e2e flow
//! (admin HTTPS API -> keyless mTLS -> QUIC datagram -> demo
//! target).  It cannot run until Phase 6a U6 lands the
//! `portal-sdk::expose` session lifecycle.

#[tokio::test]
#[ignore = "blocked on portal-sdk::expose (Phase 6a U6)"]
async fn expose_reaches_demo_target() {
    panic!("blocked on portal-sdk::expose (Phase 6a U6)");
}
