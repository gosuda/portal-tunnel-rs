use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::policy::PolicyRuntime;
use crate::relay::bridge::{RelayMetrics, copy_bidirectional_with_policy_and_metrics};
use crate::relay::stream::RelayStream;
use crate::wire::markers::RAW_TCP;

pub struct TcpPortRuntime {
    port: u16,
    task: JoinHandle<()>,
}

impl TcpPortRuntime {
    pub fn start(
        port: u16,
        stream: Arc<RelayStream>,
        identity_key: String,
        policy: Arc<PolicyRuntime>,
        metrics: Arc<RelayMetrics>,
    ) -> anyhow::Result<Self> {
        let std_listener =
            std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))?;
        std_listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(std_listener)?;
        let task = tokio::spawn(async move {
            accept_loop(listener, stream, identity_key, policy, metrics).await;
        });
        Ok(Self { port, task })
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for TcpPortRuntime {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn accept_loop(
    listener: TcpListener,
    stream: Arc<RelayStream>,
    identity_key: String,
    policy: Arc<PolicyRuntime>,
    metrics: Arc<RelayMetrics>,
) {
    loop {
        match listener.accept().await {
            Ok((conn, remote_addr)) => {
                let stream = Arc::clone(&stream);
                let identity_key = identity_key.clone();
                let policy = Arc::clone(&policy);
                let metrics = Arc::clone(&metrics);
                tokio::spawn(async move {
                    if let Err(err) =
                        bridge_tcp_conn(conn, stream, &identity_key, &policy, &metrics).await
                    {
                        debug!(%remote_addr, error = %err, "tcp port connection closed");
                    }
                });
            }
            Err(err) => {
                warn!(error = %err, "tcp port accept loop exiting");
                return;
            }
        }
    }
}

async fn bridge_tcp_conn(
    mut public: TcpStream,
    stream: Arc<RelayStream>,
    identity_key: &str,
    policy: &PolicyRuntime,
    metrics: &RelayMetrics,
) -> anyhow::Result<()> {
    let mut reverse = stream.claim(RAW_TCP).await?;
    let _ = copy_bidirectional_with_policy_and_metrics(
        &mut public,
        &mut reverse,
        policy,
        identity_key,
        Some(metrics),
    )
    .await;
    Ok(())
}
