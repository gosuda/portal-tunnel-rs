use std::time::Duration;

use anyhow::Context;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use tokio::net::TcpStream;
use tokio::time;
use tracing::debug;

use crate::auth::identity::normalize_hostname;
use crate::relay::bridge::{
    RelayMetrics, copy_bidirectional_with_metrics, copy_bidirectional_with_policy_and_metrics,
};
use crate::relay::hop_mux::HopMux;
use crate::relay::leases::LeaseRegistry;
use crate::relay::stream::MARKER_TLS_START;

const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CLIENT_HELLO_BYTES: usize = 16 * 1024;
const NEXT_HOP_OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const NEXT_HOP_OPEN_RETRY_WAIT: Duration = Duration::from_millis(250);

pub async fn handle_public_ingress(
    mut public: TcpStream,
    leases: &LeaseRegistry,
    hop_mux: Option<Arc<HopMux>>,
    api_addr: SocketAddr,
    root_host: &str,
    metrics: Arc<RelayMetrics>,
) -> anyhow::Result<()> {
    let client_hello = read_client_hello(&mut public).await?;
    let server_name = extract_sni(&client_hello).context("client hello does not contain sni")?;
    if server_name == normalize_hostname(root_host) {
        return forward_root_host_to_api(public, client_hello, api_addr, metrics.as_ref()).await;
    }

    let Some(target) = leases.lookup_stream(&server_name) else {
        if let Some(next_hop) = leases.lookup_next_hop(&server_name) {
            let hop_mux = hop_mux.context("next-hop forwarding runtime unavailable")?;
            let mut next = hop_mux
                .open_stream_with_retry(
                    &next_hop.overlay_ipv4,
                    &next_hop.token,
                    NEXT_HOP_OPEN_TIMEOUT,
                    NEXT_HOP_OPEN_RETRY_WAIT,
                )
                .await?;
            next.write_all(&client_hello)
                .await
                .context("replay client hello to next hop")?;
            let _ = copy_bidirectional_with_metrics(&mut public, &mut next, metrics.as_ref()).await;
            return Ok(());
        }
        debug!(%server_name, "no lease route for sni");
        return Ok(());
    };
    let mut reverse = target
        .stream
        .claim(MARKER_TLS_START)
        .await
        .context("claim reverse session")?;
    reverse
        .write_all(&client_hello)
        .await
        .context("replay client hello to reverse session")?;
    let _ = copy_bidirectional_with_policy_and_metrics(
        &mut public,
        &mut reverse,
        &target.policy,
        &target.identity_key,
        Some(metrics.as_ref()),
    )
    .await;
    Ok(())
}

async fn forward_root_host_to_api(
    mut public: TcpStream,
    client_hello: Vec<u8>,
    api_addr: SocketAddr,
    metrics: &RelayMetrics,
) -> anyhow::Result<()> {
    let mut api = TcpStream::connect(api_addr)
        .await
        .with_context(|| format!("connect root-host fallback api listener at {api_addr}"))?;
    api.write_all(&client_hello)
        .await
        .context("replay client hello to api listener")?;
    let _ = copy_bidirectional_with_metrics(&mut public, &mut api, metrics).await;
    Ok(())
}

async fn read_client_hello(public: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    time::timeout(CLIENT_HELLO_TIMEOUT, async {
        let mut buf = Vec::with_capacity(2048);
        let mut chunk = [0u8; 1024];
        loop {
            let n = public.read(&mut chunk).await.context("read client hello")?;
            if n == 0 {
                anyhow::bail!("connection closed before client hello");
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > MAX_CLIENT_HELLO_BYTES {
                anyhow::bail!("client hello too large");
            }
            if complete_tls_record_len(&buf).is_some_and(|len| buf.len() >= len) {
                return Ok(buf);
            }
        }
    })
    .await
    .context("client hello timeout")?
}

fn complete_tls_record_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 5 {
        return None;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    Some(5 + record_len)
}

fn extract_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return None;
    }
    let record = &buf[5..5 + record_len];
    // TLS handshake_type.client_hello (RFC 5246 §7.4) — NOT a portal-tunnel marker; do not unify with wire::markers::*
    if record.len() < 4 || record[0] != 0x01 {
        return None;
    }
    let handshake_len =
        ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | record[3] as usize;
    if record.len() < 4 + handshake_len {
        return None;
    }
    let mut pos = 4;
    pos += 2; // legacy version
    pos += 32; // random
    if pos >= record.len() {
        return None;
    }
    let session_id_len = record[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > record.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;
    if pos >= record.len() {
        return None;
    }
    let compression_len = record[pos] as usize;
    pos += 1 + compression_len;
    if pos + 2 > record.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2;
    let extensions_end = pos.checked_add(extensions_len)?;
    if extensions_end > record.len() {
        return None;
    }

    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let ext_len = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
        pos += 4;
        let ext_end = pos.checked_add(ext_len)?;
        if ext_end > extensions_end {
            return None;
        }
        if ext_type == 0 {
            return parse_server_name_extension(&record[pos..ext_end]);
        }
        pos = ext_end;
    }
    None
}

fn parse_server_name_extension(ext: &[u8]) -> Option<String> {
    if ext.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
    if ext.len() < 2 + list_len {
        return None;
    }
    let mut pos = 2;
    let end = 2 + list_len;
    while pos + 3 <= end {
        let name_type = ext[pos];
        let name_len = u16::from_be_bytes([ext[pos + 1], ext[pos + 2]]) as usize;
        pos += 3;
        let name_end = pos.checked_add(name_len)?;
        if name_end > end {
            return None;
        }
        if name_type == 0 {
            return std::str::from_utf8(&ext[pos..name_end])
                .ok()
                .map(normalize_hostname)
                .filter(|host| !host.is_empty());
        }
        pos = name_end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_tls_record() {
        assert!(extract_sni(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }
}
