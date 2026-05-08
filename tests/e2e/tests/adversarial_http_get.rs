//! Adversarial tests for the e2e raw-TCP HTTP helper.
//!
//! Violates assumptions in `http_get` to ensure the harness
//! handles malformed or misbehaving servers without silent
//! corruption or panics.

use e2e::http_get;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    reason = "test mock server: short-lived helper task"
)]
#[expect(
    clippy::expect_used,
    reason = "test-only mock server setup: unrecoverable on failure"
)]
async fn http_get_reports_404_without_panic() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock server");
    let addr = listener.local_addr().expect("local_addr").to_string();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .await
            .expect("mock write");
    });

    let result = http_get(&addr, "/missing").await;
    let (status, body) = match result {
        Ok(v) => v,
        Err(e) => panic!("http_get failed: {e}"),
    };
    assert_eq!(status, 404);
    assert!(body.is_empty());
}

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    reason = "test mock server: short-lived helper task"
)]
#[expect(
    clippy::expect_used,
    reason = "test-only mock server setup: unrecoverable on failure"
)]
async fn http_get_rejects_malformed_status_line() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock server");
    let addr = listener.local_addr().expect("local_addr").to_string();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        stream
            .write_all(b"garbage\r\n\r\n")
            .await
            .expect("mock write");
    });

    let result = http_get(&addr, "/").await;
    assert!(
        result.is_err(),
        "malformed status line should yield an error, not silent 0"
    );
}

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    reason = "test mock server: short-lived helper task"
)]
#[expect(
    clippy::expect_used,
    reason = "test-only mock server setup: unrecoverable on failure"
)]
async fn http_get_reads_body_via_eof_when_no_content_length() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock server");
    let addr = listener.local_addr().expect("local_addr").to_string();
    let payload = "hello without length";

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let response = format!("HTTP/1.1 200 OK\r\n\r\n{payload}");
        stream
            .write_all(response.as_bytes())
            .await
            .expect("mock write");
        stream.shutdown().await.expect("mock shutdown");
    });

    let result = http_get(&addr, "/").await;
    let (status, body) = match result {
        Ok(v) => v,
        Err(e) => panic!("http_get failed: {e}"),
    };
    assert_eq!(status, 200);
    assert_eq!(body, payload);
}

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    reason = "test mock server: short-lived helper task"
)]
#[expect(
    clippy::expect_used,
    reason = "test-only mock server setup: unrecoverable on failure"
)]
async fn http_get_rejects_empty_response() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock server");
    let addr = listener.local_addr().expect("local_addr").to_string();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        drop(stream);
    });

    let result = http_get(&addr, "/").await;
    assert!(
        result.is_err(),
        "empty response should yield an error, not silent 0"
    );
}
