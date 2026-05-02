#[cfg(test)]
use std::cmp;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;
#[cfg(test)]
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time;

use crate::policy::PolicyRuntime;

const COPY_BUF_SIZE: usize = 16 * 1024;

#[derive(Default)]
pub struct RelayMetrics {
    active_connections: AtomicI64,
    tcp_bytes: AtomicI64,
    tcp_load: Mutex<TcpLoadState>,
}

#[derive(Default)]
struct TcpLoadState {
    at: Option<DateTime<Utc>>,
    bytes: i64,
}

impl RelayMetrics {
    fn begin_connection(&self) -> RelayConnectionGuard<'_> {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        RelayConnectionGuard { metrics: self }
    }

    pub fn active_connection_count(&self) -> i64 {
        self.active_connections.load(Ordering::Relaxed)
    }

    pub fn current_tcp_bps(&self, now: DateTime<Utc>) -> f64 {
        let total_bytes = self.tcp_bytes.load(Ordering::Relaxed);
        let mut load = self.tcp_load.lock().expect("relay metrics lock poisoned");
        let Some(previous_at) = load.at else {
            load.at = Some(now);
            load.bytes = total_bytes;
            return 0.0;
        };

        let elapsed = now.signed_duration_since(previous_at);
        let Ok(elapsed) = elapsed.to_std() else {
            return 0.0;
        };
        if elapsed.is_zero() {
            return 0.0;
        }

        let bps = (total_bytes - load.bytes) as f64 / elapsed.as_secs_f64();
        load.at = Some(now);
        load.bytes = total_bytes;
        bps
    }

    fn record_tcp_bytes(&self, bytes: u64) {
        let bytes = i64::try_from(bytes).unwrap_or(i64::MAX);
        self.tcp_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

struct RelayConnectionGuard<'a> {
    metrics: &'a RelayMetrics,
}

impl Drop for RelayConnectionGuard<'_> {
    fn drop(&mut self) {
        self.metrics
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
pub async fn copy_bidirectional_with_policy<A, B>(
    a: &mut A,
    b: &mut B,
    policy: &PolicyRuntime,
    identity_key: &str,
) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    copy_bidirectional_with_policy_and_metrics(a, b, policy, identity_key, None).await
}

pub async fn copy_bidirectional_with_policy_and_metrics<A, B>(
    a: &mut A,
    b: &mut B,
    policy: &PolicyRuntime,
    identity_key: &str,
    metrics: Option<&RelayMetrics>,
) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let _active = metrics.map(|metrics| metrics.begin_connection());
    if policy.identity_status(identity_key, "").bps <= 0 {
        if let Some(metrics) = metrics {
            return copy_bidirectional_counting(a, b, metrics).await;
        }
        return tokio::io::copy_bidirectional(a, b).await;
    }

    let (mut ar, mut aw) = io::split(a);
    let (mut br, mut bw) = io::split(b);
    tokio::try_join!(
        throttled_copy_with_policy(&mut ar, &mut bw, policy, identity_key, metrics),
        throttled_copy_with_policy(&mut br, &mut aw, policy, identity_key, metrics)
    )
}

pub async fn copy_bidirectional_with_metrics<A, B>(
    a: &mut A,
    b: &mut B,
    metrics: &RelayMetrics,
) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let _active = metrics.begin_connection();
    copy_bidirectional_counting(a, b, metrics).await
}

async fn copy_bidirectional_counting<A, B>(
    a: &mut A,
    b: &mut B,
    metrics: &RelayMetrics,
) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = io::split(a);
    let (mut br, mut bw) = io::split(b);
    tokio::try_join!(
        counting_copy(&mut ar, &mut bw, metrics),
        counting_copy(&mut br, &mut aw, metrics)
    )
}

async fn counting_copy<R, W>(
    reader: &mut R,
    writer: &mut W,
    metrics: &RelayMetrics,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut copied = 0u64;
    let mut buf = vec![0u8; COPY_BUF_SIZE];

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.shutdown().await?;
            return Ok(copied);
        }
        writer.write_all(&buf[..n]).await?;
        copied += n as u64;
        metrics.record_tcp_bytes(n as u64);
    }
}

async fn throttled_copy_with_policy<R, W>(
    reader: &mut R,
    writer: &mut W,
    policy: &PolicyRuntime,
    identity_key: &str,
    metrics: Option<&RelayMetrics>,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut copied = 0u64;
    let mut buf = vec![0u8; COPY_BUF_SIZE];

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.shutdown().await?;
            return Ok(copied);
        }

        let mut data = &buf[..n];
        while !data.is_empty() {
            let reservation = policy.reserve_identity_bps(identity_key, data.len());
            if !reservation.wait.is_zero() {
                time::sleep(reservation.wait).await;
                continue;
            }
            let chunk_size = reservation.chunk_size.min(data.len()).max(1);
            writer.write_all(&data[..chunk_size]).await?;
            copied += chunk_size as u64;
            if let Some(metrics) = metrics {
                metrics.record_tcp_bytes(chunk_size as u64);
            }
            data = &data[chunk_size..];
        }
    }
}

#[cfg(test)]
pub async fn copy_bidirectional_with_bps<A, B>(
    a: &mut A,
    b: &mut B,
    bps: i64,
) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    if bps <= 0 {
        return tokio::io::copy_bidirectional(a, b).await;
    }

    let bytes_per_second = bps as u64;
    let (mut ar, mut aw) = io::split(a);
    let (mut br, mut bw) = io::split(b);
    tokio::try_join!(
        throttled_copy_fixed(&mut ar, &mut bw, bytes_per_second),
        throttled_copy_fixed(&mut br, &mut aw, bytes_per_second)
    )
}

#[cfg(test)]
async fn throttled_copy_fixed<R, W>(
    reader: &mut R,
    writer: &mut W,
    bytes_per_second: u64,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut copied = 0u64;
    let mut buf = vec![0u8; cmp::min(COPY_BUF_SIZE, bytes_per_second.max(1) as usize)];
    let started = time::Instant::now();

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.shutdown().await?;
            return Ok(copied);
        }
        writer.write_all(&buf[..n]).await?;
        writer.flush().await?;
        copied += n as u64;
        throttle_after_copy(started, copied, bytes_per_second).await;
    }
}

#[cfg(test)]
async fn throttle_after_copy(started: time::Instant, copied: u64, bytes_per_second: u64) {
    let expected = Duration::from_secs_f64(copied as f64 / bytes_per_second as f64);
    let elapsed = started.elapsed();
    if expected > elapsed {
        time::sleep(expected - elapsed).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use chrono::TimeZone;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::Instant;

    use super::*;
    use crate::policy::PolicyRuntime;

    #[tokio::test]
    async fn bps_limit_slows_bridge_copy() {
        let (mut left_client, mut left_bridge) = tokio::io::duplex(4096);
        let (mut right_bridge, mut right_client) = tokio::io::duplex(4096);

        let started = Instant::now();
        let bridge = tokio::spawn(async move {
            copy_bidirectional_with_bps(&mut left_bridge, &mut right_bridge, 1024)
                .await
                .unwrap();
        });

        left_client.write_all(&vec![7u8; 2048]).await.unwrap();
        left_client.shutdown().await.unwrap();
        right_client.shutdown().await.unwrap();

        let mut out = Vec::new();
        right_client.read_to_end(&mut out).await.unwrap();
        bridge.await.unwrap();

        assert_eq!(out.len(), 2048);
        assert!(started.elapsed() >= Duration::from_millis(1500));
    }

    #[tokio::test]
    async fn policy_bps_limit_is_shared_across_directions() {
        let temp_path = std::env::temp_dir().join("portal-policy-shared-bps-test");
        let policy = Arc::new(PolicyRuntime::load(&temp_path, false, false).unwrap());
        policy.set_identity_bps("demo", 1024);

        let (mut left_client, mut left_bridge) = tokio::io::duplex(4096);
        let (mut right_bridge, mut right_client) = tokio::io::duplex(4096);

        let policy_for_bridge = Arc::clone(&policy);
        let started = Instant::now();
        let bridge = tokio::spawn(async move {
            copy_bidirectional_with_policy(
                &mut left_bridge,
                &mut right_bridge,
                &policy_for_bridge,
                "demo",
            )
            .await
            .unwrap();
        });

        left_client.write_all(&vec![1u8; 1024]).await.unwrap();
        right_client.write_all(&vec![2u8; 1024]).await.unwrap();
        left_client.shutdown().await.unwrap();
        right_client.shutdown().await.unwrap();

        let mut left_out = Vec::new();
        let mut right_out = Vec::new();
        left_client.read_to_end(&mut left_out).await.unwrap();
        right_client.read_to_end(&mut right_out).await.unwrap();
        bridge.await.unwrap();

        assert_eq!(left_out.len(), 1024);
        assert_eq!(right_out.len(), 1024);
        assert!(started.elapsed() >= Duration::from_millis(1500));
    }

    #[tokio::test]
    async fn zero_bps_uses_unlimited_bridge_copy() {
        let (mut left_client, mut left_bridge) = tokio::io::duplex(4096);
        let (mut right_bridge, mut right_client) = tokio::io::duplex(4096);

        let bridge = tokio::spawn(async move {
            copy_bidirectional_with_bps(&mut left_bridge, &mut right_bridge, 0)
                .await
                .unwrap();
        });

        left_client.write_all(b"hello").await.unwrap();
        left_client.shutdown().await.unwrap();
        right_client.shutdown().await.unwrap();

        let mut out = Vec::new();
        right_client.read_to_end(&mut out).await.unwrap();
        bridge.await.unwrap();

        assert_eq!(out, b"hello");
    }

    #[tokio::test]
    async fn relay_metrics_track_active_connections_and_tcp_bps() {
        let metrics = Arc::new(RelayMetrics::default());
        let start = Utc.timestamp_opt(10, 0).unwrap();
        assert_eq!(metrics.current_tcp_bps(start), 0.0);

        let (mut left_client, mut left_bridge) = tokio::io::duplex(4096);
        let (mut right_bridge, mut right_client) = tokio::io::duplex(4096);

        let bridge_metrics = Arc::clone(&metrics);
        let bridge = tokio::spawn(async move {
            copy_bidirectional_with_metrics(&mut left_bridge, &mut right_bridge, &bridge_metrics)
                .await
                .unwrap();
        });
        time::timeout(Duration::from_secs(2), async {
            while metrics.active_connection_count() != 1 {
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        left_client.write_all(&vec![7u8; 1024]).await.unwrap();
        left_client.shutdown().await.unwrap();
        right_client.shutdown().await.unwrap();

        let mut out = Vec::new();
        right_client.read_to_end(&mut out).await.unwrap();
        bridge.await.unwrap();

        assert_eq!(out.len(), 1024);
        assert_eq!(metrics.active_connection_count(), 0);
        assert_eq!(
            metrics.current_tcp_bps(start + chrono::Duration::seconds(2)),
            512.0
        );
    }
}
