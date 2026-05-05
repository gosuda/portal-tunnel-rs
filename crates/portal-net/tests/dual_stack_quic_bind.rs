//! Behavioral gate 3 — R12 dual-stack invariant for QUIC.
//!
//! A server endpoint bound on `[::]:0` (IPv6 wildcard) MUST accept QUIC
//! connections from a v4-loopback client (`127.0.0.1`). This pins the
//! `IPV6_V6ONLY = false` socket option that `bind_dual_stack_udp`
//! installs for QUIC endpoints by default.
//!
//! The matching socket-level invariant is asserted directly in
//! `dual_stack::tests::bind_dual_stack_udp_default_is_dual_stack`, but
//! quinn does not expose the underlying socket so the only way to
//! observe the kernel-side dual-stack acceptance at the `Endpoint`
//! layer is to actually drive a v4 connect against a v6-bound listener.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::time::Duration;

use portal_net::{Endpoint, generate_quic_identity_key, quic_identity_verifying_key};

#[tokio::test]
async fn server_on_v6_wildcard_accepts_v4_client() {
    let _ = tracing_subscriber::fmt::try_init();

    let server_key = generate_quic_identity_key();
    let pinned = quic_identity_verifying_key(&server_key);
    let server = Endpoint::server("[::]:0".parse().unwrap(), server_key).unwrap();
    let server_local = server.local_addr().unwrap();
    assert!(
        server_local.is_ipv6(),
        "server must bind v6 with IPV6_V6ONLY=false, got: {server_local:?}",
    );

    // Reach the server via 127.0.0.1 — the dual-stack socket should
    // accept this through the v4-mapped path.
    let v4_addr: SocketAddr = format!("127.0.0.1:{}", server_local.port())
        .parse()
        .unwrap();

    let client = Endpoint::client("[::]:0".parse().unwrap(), pinned).unwrap();
    let connecting = client
        .connect(v4_addr, "v4-via-dual-stack.invalid")
        .expect("client.connect on v4 addr");

    #[expect(
        clippy::disallowed_methods,
        reason = "test code per R9: server-accept handle awaited via timeout at end of test"
    )]
    let server_accept = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap().unwrap();
        let _conn = incoming.await.expect("server accept v4-mapped client");
    });

    let conn = tokio::time::timeout(Duration::from_secs(5), connecting)
        .await
        .expect("client connect within 5s")
        .expect("client connection completes against v4 addr");
    drop(conn);
    tokio::time::timeout(Duration::from_secs(5), server_accept)
        .await
        .expect("server accept task joins within 5s")
        .expect("server accept task did not panic");
}
