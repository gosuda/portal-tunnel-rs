//! `portal-demo` — minimal HTTP echo target used by the
//! portal-tunnel e2e harness as the tenant origin.
//!
//! Listens on a configurable address (default `127.0.0.1:0` so the
//! OS picks a free port) and replies to every TCP connection with a
//! tiny HTTP/1.1 response containing either `--body` or the request
//! body's first 1 KiB.
//!
//! Deliberately HTTP/1.1 plain-text — the relay's TCP forwarder is
//! transparent so origin-side TLS is the relay's choice. The e2e
//! harness wraps this in TLS via the relay if the test asks for it.

#![forbid(unsafe_code)]

use std::net::SocketAddr;

use clap::Parser;
use eyre::{Context as _, eyre};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};

const MAX_BODY_ECHO_BYTES: usize = 1024;
const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;

#[derive(Debug, Parser)]
#[command(name = "portal-demo", version, about = "Portal-tunnel e2e demo target")]
struct Args {
    /// Bind address (use `127.0.0.1:0` for an OS-allocated port).
    #[arg(long, default_value = "127.0.0.1:0")]
    bind: SocketAddr,
    /// Optional response body to echo for every request. If omitted,
    /// echoes up to the first 1 KiB of the inbound request body.
    #[arg(long)]
    body: Option<String>,
}

fn main() -> eyre::Result<()> {
    init_tracing();
    let args = Args::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    runtime.block_on(serve(args))
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .try_init();
}

async fn serve(args: Args) -> eyre::Result<()> {
    let listener = TcpListener::bind(args.bind)
        .await
        .context("bind listener")?;
    let local = listener
        .local_addr()
        .context("read local listener address")?;
    println!("portal-demo: listening on {local}");
    tracing::info!(addr = %local, "portal-demo accept loop starting");

    loop {
        tokio::select! {
            biased;
            res = tokio::signal::ctrl_c() => {
                if let Err(err) = res {
                    tracing::warn!(?err, "ctrl_c handler errored");
                }
                tracing::info!("portal-demo shutdown signal received");
                break;
            }
            res = listener.accept() => match res {
                Ok((stream, peer)) => {
                    let body_override = args.body.clone();
                    // R9: top-of-main connection handler in binary crate
                    // runtime entry. portal-demo is a sample binary whose
                    // accept loop runs at runtime-root level.
                    #[expect(
                        clippy::disallowed_methods,
                        reason = "R9: top-of-main connection handler in binary crate runtime entry"
                    )]
                    tokio::spawn(async move {
                        if let Err(err) = handle(stream, peer, body_override).await {
                            tracing::warn!(?peer, ?err, "portal-demo connection error");
                        }
                    });
                }
                Err(err) => {
                    tracing::warn!(?err, "accept error; continuing");
                }
            }
        }
    }
    Ok(())
}

async fn handle(
    stream: TcpStream,
    peer: SocketAddr,
    body_override: Option<String>,
) -> eyre::Result<()> {
    tracing::debug!(?peer, "portal-demo accepted connection");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let request_line = read_line_limited(&mut reader, MAX_HEADER_LINE_BYTES)
        .await?
        .ok_or_else(|| eyre!("empty HTTP request line"))?;
    validate_request_line(&request_line)?;

    let content_length = read_headers(&mut reader).await?;

    let body = if let Some(body) = body_override {
        body.into_bytes()
    } else if let Some(content_length) = content_length.filter(|len| *len > 0) {
        read_bounded_body(&mut reader, content_length).await?
    } else {
        format!("portal-demo echo: {request_line}").into_bytes()
    };

    let response = response_bytes(&body);
    write_half
        .write_all(&response)
        .await
        .context("write response")?;
    write_half.shutdown().await.context("shutdown write half")?;
    Ok(())
}

fn validate_request_line(request_line: &str) -> eyre::Result<()> {
    if request_line.trim().is_empty() {
        return Err(eyre!("empty HTTP request line"));
    }
    let mut parts = request_line.split_ascii_whitespace();
    let method = parts.next().ok_or_else(|| eyre!("missing HTTP method"))?;
    let target = parts.next().ok_or_else(|| eyre!("missing HTTP target"))?;
    let version = parts.next().ok_or_else(|| eyre!("missing HTTP version"))?;
    if parts.next().is_some() {
        return Err(eyre!("too many fields in HTTP request line"));
    }
    if method.is_empty() || target.is_empty() || version != "HTTP/1.1" {
        return Err(eyre!("malformed HTTP/1.1 request line"));
    }
    Ok(())
}

async fn read_headers<R>(reader: &mut BufReader<R>) -> eyre::Result<Option<usize>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut content_length: Option<usize> = None;
    let mut total_header_bytes = 0_usize;
    loop {
        let Some(header) = read_line_limited(reader, MAX_HEADER_LINE_BYTES).await? else {
            break;
        };
        total_header_bytes = total_header_bytes
            .checked_add(header.len())
            .ok_or_else(|| eyre!("HTTP headers too large"))?;
        if total_header_bytes > MAX_HEADER_BYTES {
            return Err(eyre!("HTTP headers exceed {MAX_HEADER_BYTES} bytes"));
        }
        if header == "\r\n" || header == "\n" {
            break;
        }
        if let Some(parsed) = parse_content_length_header(&header)? {
            if content_length.is_some_and(|existing| existing != parsed) {
                return Err(eyre!("conflicting Content-Length headers"));
            }
            content_length = Some(parsed);
        }
    }
    Ok(content_length)
}

async fn read_line_limited<R>(
    reader: &mut BufReader<R>,
    max_len: usize,
) -> eyre::Result<Option<String>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let n = reader.read(&mut byte).await.context("read line byte")?;
        if n == 0 {
            if bytes.is_empty() {
                return Ok(None);
            }
            return Err(eyre!("unexpected EOF while reading HTTP line"));
        }
        bytes.push(byte[0]);
        if bytes.len() > max_len {
            return Err(eyre!("HTTP line exceeds {max_len} bytes"));
        }
        if byte[0] == b'\n' {
            break;
        }
    }
    String::from_utf8(bytes)
        .map(Some)
        .context("HTTP line is not valid UTF-8")
}

async fn read_bounded_body<R>(
    reader: &mut BufReader<R>,
    content_length: usize,
) -> eyre::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    if content_length > MAX_BODY_ECHO_BYTES {
        return Err(eyre!(
            "request body length {content_length} exceeds {MAX_BODY_ECHO_BYTES}-byte echo cap",
        ));
    }
    let mut buf = vec![0_u8; content_length];
    reader.read_exact(&mut buf).await.context("read body")?;
    Ok(buf)
}

fn parse_content_length_header(header: &str) -> eyre::Result<Option<usize>> {
    let Some((name, value)) = header.split_once(':') else {
        return Ok(None);
    };
    if !name.trim().eq_ignore_ascii_case("content-length") {
        return Ok(None);
    }
    let value = value.trim();
    if value.is_empty() {
        return Err(eyre!("empty Content-Length header"));
    }
    let parsed = value.parse::<usize>().context("parse Content-Length")?;
    Ok(Some(parsed))
}

fn response_bytes(body: &[u8]) -> Vec<u8> {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
        len = body.len(),
    );
    let mut response = header.into_bytes();
    response.extend_from_slice(body);
    response
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test-only assertions")]
mod tests {
    use super::*;

    #[test]
    fn parses_content_length_case_insensitively() {
        assert_eq!(
            parse_content_length_header("content-length: 3\r\n").unwrap(),
            Some(3)
        );
        assert_eq!(
            parse_content_length_header("CONTENT-LENGTH: 4\r\n").unwrap(),
            Some(4)
        );
        assert_eq!(
            parse_content_length_header("Content-Length: 5\r\n").unwrap(),
            Some(5)
        );
    }

    #[test]
    fn ignores_non_content_length_headers() {
        assert_eq!(
            parse_content_length_header("Host: example.test\r\n").unwrap(),
            None
        );
    }

    #[test]
    fn rejects_invalid_content_length() {
        assert!(parse_content_length_header("Content-Length: nope\r\n").is_err());
    }

    #[test]
    fn rejects_empty_request_line() {
        assert!(validate_request_line("").is_err());
        assert!(validate_request_line("\r\n").is_err());
    }

    #[test]
    fn rejects_non_http11_request_line() {
        assert!(validate_request_line("GET / HTTP/1.0\r\n").is_err());
    }

    #[tokio::test]
    async fn rejects_oversized_body() {
        let bytes = vec![b'a'; MAX_BODY_ECHO_BYTES + 1];
        let mut reader = BufReader::new(bytes.as_slice());
        let result = read_bounded_body(&mut reader, MAX_BODY_ECHO_BYTES + 1).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_oversized_header_line() {
        let mut bytes = vec![b'a'; MAX_HEADER_LINE_BYTES + 1];
        bytes.push(b'\n');
        let mut reader = BufReader::new(bytes.as_slice());
        let result = read_line_limited(&mut reader, MAX_HEADER_LINE_BYTES).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_oversized_total_headers() {
        let mut bytes = Vec::new();
        for _ in 0..=(MAX_HEADER_BYTES / 4) {
            bytes.extend_from_slice(b"X: a\n");
        }
        bytes.extend_from_slice(b"\r\n");
        let mut reader = BufReader::new(bytes.as_slice());
        let result = read_headers(&mut reader).await;
        assert!(result.is_err());
    }

    #[test]
    fn response_preserves_raw_body_bytes() {
        let body = [0xff, 0x00, b'a', b'\n'];
        let response = response_bytes(&body);
        let boundary = b"\r\n\r\n";
        let start = response
            .windows(boundary.len())
            .position(|window| window == boundary)
            .unwrap()
            + boundary.len();
        assert_eq!(&response[start..], body);
    }
}
