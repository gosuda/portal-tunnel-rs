//! Single-process e2e harness (Phase 7 U8.5).
//!
//! Boots an in-process [`portal_relay::Server`], mounts the admin
//! and SDK trust-boundary routers on ephemeral TCP listeners,
//! and spawns the `portal-demo` binary as a downstream target.
//! The full expose round-trip is blocked on `portal-sdk::expose`
//! (Phase 6a U6); tests for that path are `#[ignore]`.

use std::net::SocketAddr;
use std::process::Stdio;

use portal_crypto::ed25519_from_seed_for_test;
use portal_relay::Server;
use portal_relay::policy::ReputationEngine;
use tokio::io::{AsyncBufReadExt, AsyncReadExt};
use tokio::net::TcpListener;
use tokio::process::Child;

/// Test harness holding the relay server, demo child, and listener
/// addresses.
pub struct Harness {
    server: Server,
    admin_addr: SocketAddr,
    sdk_addr: SocketAddr,
    demo_addr: SocketAddr,
    demo_child: Child,
    admin_handle: tokio::task::JoinHandle<()>,
    sdk_handle: tokio::task::JoinHandle<()>,
}

impl Harness {
    /// Boot the harness.
    ///
    /// # Panics
    /// Panics if listener bind or `portal-demo` spawn fails.
    #[expect(
        clippy::expect_used,
        reason = "test-only harness boot: unrecoverable on failure"
    )]
    #[expect(
        clippy::disallowed_methods,
        reason = "test runtime: axum serve tasks stored in Harness for shutdown"
    )]
    pub async fn boot() -> Self {
        // 1. Build server with required SDK dependencies.
        let server = Server::new()
            .with_reputation_engine(ReputationEngine::new())
            .with_relay_protocol_key(ed25519_from_seed_for_test([0xE2u8; 32]));

        server.start().await.expect("server start");

        // 2. Admin router on ephemeral TCP.
        let admin_listener = TcpListener::bind("127.0.0.1:0").await.expect("admin bind");
        let admin_addr = admin_listener.local_addr().expect("admin local_addr");
        let admin_router = server.admin_router();
        let admin_handle = tokio::spawn(async move {
            let _ = axum::serve(admin_listener, admin_router.into_make_service()).await;
        });

        // 3. SDK router on ephemeral TCP.
        let sdk_listener = TcpListener::bind("127.0.0.1:0").await.expect("sdk bind");
        let sdk_addr = sdk_listener.local_addr().expect("sdk local_addr");
        let sdk_state = server.sdk_state();
        let sdk_router = portal_relay::api::build_sdk_router(sdk_state);
        let sdk_handle = tokio::spawn(async move {
            let _ = axum::serve(sdk_listener, sdk_router.into_make_service()).await;
        });

        // 4. Spawn portal-demo binary.
        let demo_bin = find_portal_demo();
        let mut demo_child = tokio::process::Command::new(&demo_bin)
            .arg("--bind")
            .arg("127.0.0.1:0")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn portal-demo");

        // Wait for demo to print its listening line (bounded).
        let stdout = demo_child.stdout.take().expect("demo stdout");
        let mut reader = tokio::io::BufReader::new(stdout).lines();
        let demo_addr = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while let Ok(Some(line)) = reader.next_line().await {
                if let Some(rest) = line.strip_prefix("portal-demo: listening on ") {
                    return Some(rest.parse::<SocketAddr>().expect("demo addr parse"));
                }
            }
            None
        })
        .await
        .expect("portal-demo startup timed out")
        .expect("portal-demo did not emit listening line");

        // 5. Wait for axum servers to be ready (retry with backoff).
        wait_for_ok(&admin_addr.to_string(), "/v1/admin/health", 5).await;
        wait_for_ok(&sdk_addr.to_string(), "/v1/sdk/domain", 5).await;

        Self {
            server,
            admin_addr,
            sdk_addr,
            demo_addr,
            demo_child,
            admin_handle,
            sdk_handle,
        }
    }

    /// Admin listener address.
    #[must_use]
    pub const fn admin_addr(&self) -> SocketAddr {
        self.admin_addr
    }

    /// SDK listener address.
    #[must_use]
    pub const fn sdk_addr(&self) -> SocketAddr {
        self.sdk_addr
    }

    /// Demo listener address.
    #[must_use]
    pub const fn demo_addr(&self) -> SocketAddr {
        self.demo_addr
    }

    /// Graceful shutdown.
    pub async fn shutdown(mut self) {
        self.server.shutdown().await;
        let _ = self.demo_child.start_kill();
        let _ = self.demo_child.wait().await;
        self.admin_handle.abort();
        self.sdk_handle.abort();
    }
}

/// Retry `http_get` until a non-zero status is returned or `secs`
/// elapse.
async fn wait_for_ok(addr: &str, path: &str, secs: u64) {
    let deadline = std::time::Duration::from_secs(secs);
    tokio::time::timeout(deadline, async {
        loop {
            if let Ok((status, _)) = http_get(addr, path).await
                && status != 0
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("server at {addr} did not become ready within {secs}s"));
}

#[expect(clippy::expect_used, reason = "test-only harness boot")]
fn find_portal_demo() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_portal-demo") {
        return path.into();
    }
    let mut path = std::env::current_exe().expect("current_exe");
    path.pop(); // deps/ or release/deps/
    path.pop(); // debug/ or release/
    path.push("portal-demo");
    path
}

/// Minimal HTTP/1.1 GET helper over raw TCP.
///
/// # Errors
///
/// Returns `std::io::Error` on TCP connect, write, or read failure.
///
/// Returns `(status_code, body)`.
pub async fn http_get(addr: &str, path: &str) -> std::io::Result<(u16, String)> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    let stream = TcpStream::connect(addr).await?;
    let (reader, mut writer) = stream.into_split();
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    writer.write_all(request.as_bytes()).await?;

    let mut buf_reader = BufReader::new(reader);
    let mut status_line = String::new();
    buf_reader.read_line(&mut status_line).await?;

    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    let mut content_length = None;
    loop {
        let mut line = String::new();
        buf_reader.read_line(&mut line).await?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some(v) = line
            .strip_prefix("Content-Length: ")
            .or_else(|| line.strip_prefix("content-length: "))
        {
            content_length = v.trim().parse::<usize>().ok();
        }
    }

    let body = if let Some(len) = content_length {
        let mut buf = vec![0u8; len];
        buf_reader.read_exact(&mut buf).await?;
        String::from_utf8_lossy(&buf).into_owned()
    } else {
        let mut buf = Vec::new();
        buf_reader.read_to_end(&mut buf).await?;
        String::from_utf8_lossy(&buf).into_owned()
    };

    Ok((status, body))
}
