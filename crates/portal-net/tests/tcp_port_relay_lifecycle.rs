//! Behavioral gate 2 — TCP port relay lifecycle (U7 connection-establishment slice).
//!
//! ## Scope and deferral (READ FIRST)
//!
//! This test does **NOT** assert TCP byte forwarding through the QUIC
//! backhaul. Per the U11 plan (`docs/plans/2026-05-04-003-feat-portal-net-plan.md`,
//! lines ~720-780, "TCP forwarding test is partial — connection-establishment
//! only is acceptable"), the full byte-splice integration requires
//! `TcpPortRelay::start` to surface its OS-picked `SocketAddr` so a TCP
//! client can dial it deterministically. Adding a `local_addr()`
//! accessor extends the relay's public surface and is out of scope for
//! Batch 7. The byte-splice round-trip (TCP client -> relay listener
//! -> QUIC stream -> `SdkAcceptor::TcpRaw` -> response back) lands in
//! Phase 5 alongside the lease-allocation pipeline, where the
//! `RelayDescriptor` advertises the bound port back to the SDK and the
//! test harness reads the port from the descriptor.
//!
//! ## What this test asserts
//!
//! 1. Server + client `Endpoint`s complete the SPKI-pinned QUIC
//!    handshake on loopback.
//! 2. `TcpPortRelay::new` accepts an `Arc<quinn::Connection>` from the
//!    server side without panicking.
//! 3. `TcpPortRelay::start` binds a dual-stack TCP listener on port 0
//!    without error against a live QUIC backhaul.
//! 4. `TcpPortRelay::shutdown` cancels the accept loop and joins
//!    within budget after `cancel_relay.cancel()`.
//!
//! Companion behavioral gate `quic_backhaul_roundtrip` covers the
//! `open_outbound` -> `dispatch_inbound` -> `SdkAcceptor::TcpRaw` byte
//! path that the relay's `handle_conn` invokes; the missing piece for
//! a true end-to-end gate is solely the relay's local-port discovery.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use compact_str::CompactString;
use portal_net::tcp::TcpPortRelay;
use portal_net::{Endpoint, generate_quic_identity_key, quic_identity_verifying_key};
use tokio_util::sync::CancellationToken;

/// Connection-establishment-only slice. Name is deliberately scoped to
/// "starts and shuts down cleanly" — no claim of byte forwarding. See
/// the module rustdoc for the deferral rationale.
#[tokio::test]
async fn tcp_port_relay_starts_and_shuts_down_against_live_quic_backhaul() {
    let _ = tracing_subscriber::fmt::try_init();

    // 1. Set up server + client QUIC endpoints on loopback.
    let server_key = generate_quic_identity_key();
    let pinned = quic_identity_verifying_key(&server_key);
    let server = Endpoint::server("127.0.0.1:0".parse().unwrap(), server_key).unwrap();
    let server_addr = server.local_addr().unwrap();
    let client = Endpoint::client("[::]:0".parse().unwrap(), pinned).unwrap();

    // 2. Server-side: accept the QUIC connection in the background.
    let server_handle = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap().unwrap();
        let conn = incoming.await.expect("server connection completes");
        Arc::new(conn)
    });

    // 3. Client-side: connect.
    let connecting = client.connect(server_addr, "tcp-relay-test.invalid").unwrap();
    let client_conn = tokio::time::timeout(Duration::from_secs(5), connecting)
        .await
        .expect("client connect within 5s")
        .expect("client connection completes");

    // 4. Server got the connection.
    let server_conn = tokio::time::timeout(Duration::from_secs(5), server_handle)
        .await
        .expect("server task joins within 5s")
        .expect("server task did not panic");

    // 5. Spawn TcpPortRelay on the server side, port 0 (OS-picked).
    let mut relay = TcpPortRelay::new(
        CompactString::from("test-lease"),
        0,
        Arc::clone(&server_conn),
    );

    let cancel_relay = CancellationToken::new();
    relay
        .start(cancel_relay.clone())
        .await
        .expect("relay starts cleanly");

    // 6. Shut down the relay; the internal cancel + accept-loop join
    //    must complete within budget.
    cancel_relay.cancel();
    tokio::time::timeout(Duration::from_secs(5), relay.shutdown())
        .await
        .expect("relay shuts down within 5s");

    // 7. Tear down QUIC. Dropping the Arc<Connection>s after the relay
    //    has shut down ensures no use-after-free of the backhaul ref.
    drop(client_conn);
    drop(server_conn);
}
