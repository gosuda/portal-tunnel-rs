//! Behavioral gate 1 — in-process QUIC backhaul round-trip.
//!
//! Validates the full B2-B3-B6 stack: server `Endpoint::server`, client
//! `Endpoint::client` with `SpkiPinVerifier`, ALPN portal/2 negotiation,
//! `open_outbound` + `dispatch_inbound` round-trip on a `TcpProxy::Raw`
//! stream, and bidirectional byte forwarding through the SDK acceptor.
//!
//! This test replaces the unit-level "I/O is hard to test in isolation"
//! placeholders left in `quic::stream` and `quic::sdk_accept`: those
//! modules cannot exercise their `open_bi` / `accept_bi` paths without a
//! live quinn `Connection`, and a live connection requires the full
//! ALPN + SPKI-pin handshake to be wired up. The integration harness
//! here is the smallest fixture that hits all three layers at once.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use portal_net::quic::sdk_accept::{AcceptedStream, SdkAcceptor};
use portal_net::quic::stream::{TcpProxyKind, open_outbound};
use portal_net::{Endpoint, generate_quic_identity_key, quic_identity_verifying_key};
use portal_wire::channel::Channel;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Per-direction read cap. Both halves of the round-trip exchange a
/// 4-byte payload (`b"ping"` / `b"pong"`); 64 bytes is loose enough to
/// catch a regression that accidentally writes extra framing without
/// being so generous that an unbounded write stalls the test.
const READ_CAP: usize = 64;

#[tokio::test]
async fn quic_backhaul_round_trip_tcp_proxy_raw() {
    let _ = tracing_subscriber::fmt::try_init();

    // Server endpoint generates its own identity; client pins the
    // server's verifying key.
    let server_key = generate_quic_identity_key();
    let pinned = quic_identity_verifying_key(&server_key);
    let server = Endpoint::server("127.0.0.1:0".parse().unwrap(), server_key).unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = Endpoint::client("[::]:0".parse().unwrap(), pinned).unwrap();

    // Drive server-side accept in the background.
    let server_handle = tokio::spawn(async move {
        let incoming = server
            .accept()
            .await
            .expect("server should yield an Incoming")
            .expect("incoming present");
        let conn = incoming.await.expect("server connection completes");
        // Open a server-initiated TcpProxy::Raw stream and send "ping",
        // then read the SDK side's "pong" response.
        let (mut send, mut recv) =
            open_outbound(&conn, Channel::TcpProxy, Some(TcpProxyKind::Raw))
                .await
                .unwrap();
        send.write_all(b"ping").await.unwrap();
        send.finish().unwrap();
        // quinn::RecvStream::read_to_end takes a size cap and returns
        // the buffered bytes directly; this is distinct from tokio's
        // AsyncReadExt::read_to_end signature.
        let reply = recv.read_to_end(READ_CAP).await.unwrap();
        assert_eq!(reply, b"pong", "server should receive client's pong");
        conn.close(0u32.into(), b"test done");
    });

    // Drive client-side: connect, then run SdkAcceptor with a 1-shot mpsc
    // receiver, on first AcceptedStream echo "pong" back.
    let connecting = client
        .connect(server_addr, "test-relay.invalid")
        .expect("client.connect");
    let conn = connecting.await.expect("client connection completes");

    let (tx, mut rx) = mpsc::channel(1);
    let cancel = CancellationToken::new();
    let acceptor = SdkAcceptor::new(conn.clone(), tx, cancel.clone());
    let acc_handle = tokio::spawn(async move { acceptor.run(None).await });

    let stream = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("AcceptedStream within 5s")
        .expect("AcceptedStream is Some");
    match stream {
        AcceptedStream::TcpRaw { mut send, mut recv } => {
            // Read until peer half-closes (quinn's inherent
            // read_to_end terminates on `finish()` from the peer).
            let got = recv.read_to_end(READ_CAP).await.unwrap();
            assert_eq!(got, b"ping");
            send.write_all(b"pong").await.unwrap();
            send.finish().unwrap();
        }
        AcceptedStream::TcpTls { .. } => {
            panic!("expected TcpRaw, got TcpTls");
        }
        // `AcceptedStream` is `#[non_exhaustive]` per the wire-register
        // forward-compat contract. Future variants would constitute a
        // dispatch regression for this test, since we explicitly wrote
        // `Channel::TcpProxy` + `TcpProxyKind::Raw` on the wire.
        _ => panic!("unexpected AcceptedStream variant for TcpProxy::Raw"),
    }

    // Wind down: server initiated the connection close already; the
    // acceptor loop should observe ApplicationClosed and exit cleanly.
    //
    // Both joins are bounded with explicit timeouts: a stalled QUIC
    // close or a hung accept loop must fail the test, not hang CI.
    tokio::time::timeout(Duration::from_secs(5), server_handle)
        .await
        .expect("server task joins within 5s")
        .expect("server task did not panic");
    cancel.cancel();
    let acc_result = tokio::time::timeout(Duration::from_secs(2), acc_handle)
        .await
        .expect("acceptor task joins within 2s after cancel")
        .expect("acceptor task did not panic");
    acc_result.expect("SdkAcceptor::run returns Ok on clean shutdown");
}

