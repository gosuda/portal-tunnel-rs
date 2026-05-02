use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::Duration;

use anyhow::Context;
use chrono::Utc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing::{debug, error, info, warn};

use crate::api;
use crate::api::admin::AdminState;
use crate::api::frontend::FrontendState;
use crate::config::RelayConfig;
use crate::policy::PolicyRuntime;
use crate::relay::bridge::{
    RelayMetrics, copy_bidirectional_with_metrics, copy_bidirectional_with_policy_and_metrics,
};
use crate::relay::discovery::{DISCOVERY_POLL_INTERVAL, DiscoveryState};
use crate::relay::hop_mux::{HopMux, HopMuxConnector, HopStream};
use crate::relay::leases::{HopRelayTarget, LeaseRegistry, LeaseRegistryConfig};
use crate::relay::overlay::{OverlayConfig, OverlayPeer, OverlayRuntime};
use crate::relay::sni::handle_public_ingress;
use crate::relay::udp_datagram::{
    QuicBackhaulControlResponse, read_control_message, write_control_response,
};
use crate::state::acme::AcmeManager;
use crate::state::identity::{RelayIdentity, load_or_create_relay_identity};
use crate::state::tls_material::{KeylessSigner, load_or_create_tls_material};
use crate::wire::markers::TLS_ACTIVATE;
use crate::wire::paths::PATH_SDK_CONNECT;

const REGISTRY_JANITOR_INTERVAL: Duration = Duration::from_secs(5);
const HOP_OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const HOP_OPEN_RETRY_WAIT: Duration = Duration::from_millis(250);

/// Process-lifetime cap on outstanding reservation vouchers (Go parity: 100-slot semaphore).
pub const MAX_VOUCHER_BUDGET: u32 = 100;

/// Bounded counter that mediates issuance of reservation vouchers under [`MAX_VOUCHER_BUDGET`].
///
/// Enforces a checked acquire/release contract so callers cannot accidentally desync the
/// in-flight count: every successful [`acquire`] MUST be paired with exactly one [`release`].
/// A dropped [`VoucherBudgetGuard`] releases automatically.
///
/// [`acquire`]: VoucherBudget::acquire
/// [`release`]: VoucherBudget::release
#[derive(Debug)]
pub struct VoucherBudget {
    in_flight: AtomicU32,
    capacity: u32,
}

impl VoucherBudget {
    pub const fn new(capacity: u32) -> Self {
        Self {
            in_flight: AtomicU32::new(0),
            capacity,
        }
    }

    /// Reserves one budget slot, returning a guard that releases on drop. Returns `None` when
    /// the cap is reached (no slot is taken in that case — the failed `fetch_add` is undone).
    pub fn acquire(self: &Arc<Self>) -> Option<VoucherBudgetGuard> {
        let prev = self
            .in_flight
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if prev >= self.capacity {
            self.in_flight
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
        Some(VoucherBudgetGuard {
            budget: Arc::clone(self),
            released: false,
        })
    }

    fn release(&self) {
        self.in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(test)]
    pub fn in_flight(&self) -> u32 {
        self.in_flight.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// RAII guard returned by [`VoucherBudget::acquire`]. Releases the slot on drop, or earlier via
/// [`VoucherBudgetGuard::release`] if the caller wants explicit hand-off semantics.
#[derive(Debug)]
pub struct VoucherBudgetGuard {
    budget: Arc<VoucherBudget>,
    released: bool,
}

impl VoucherBudgetGuard {
    /// Releases the slot eagerly. Subsequent drops are no-ops.
    /// Kept for API symmetry with [`consume`](Self::consume); the same effect is achieved by
    /// dropping the guard, which the test suite exercises.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "API symmetry with consume(); production sites currently use Drop/consume only"
        )
    )]
    pub fn release(mut self) {
        self.released = true;
        self.budget.release();
    }

    /// Permanently consumes the slot for the lifetime of the process. The slot is NOT released
    /// on drop after this call. Use this when an operation has succeeded and the issuance
    /// should count against the process-lifetime budget (Go parity for `POST /admin/reserve`).
    pub fn consume(mut self) {
        self.released = true;
    }
}

impl Drop for VoucherBudgetGuard {
    fn drop(&mut self) {
        if !self.released {
            self.budget.release();
        }
    }
}

pub struct AppState {
    pub root_host: String,
    pub portal_host: String,
    pub portal_url: String,
    pub relay_identity: Arc<RelayIdentity>,
    pub leases: Arc<LeaseRegistry>,
    pub keyless_signer: KeylessSigner,
    pub admin: Arc<AdminState>,
    pub frontend: Option<Arc<FrontendState>>,
    pub discovery: Option<Arc<DiscoveryState>>,
    pub overlay: Option<Arc<OverlayRuntime>>,
    pub hop_mux: Option<Arc<HopMux>>,
    pub metrics: Arc<RelayMetrics>,
    pub voucher_budget: Arc<VoucherBudget>,
}

pub struct Server {
    cfg: RelayConfig,
    identity: RelayIdentity,
    api_addr: SocketAddr,
    sni_addr: SocketAddr,
    tls_acceptor: TlsAcceptor,
    quic_config: Option<quinn::ServerConfig>,
    acme_manager: Option<AcmeManager>,
    state: Arc<AppState>,
}

impl Server {
    pub async fn new(cfg: RelayConfig) -> anyhow::Result<Self> {
        let root_host = cfg.root_host()?;
        let identity =
            load_or_create_relay_identity(&cfg.identity_path, &root_host, cfg.discovery_enabled)
                .context("load or create relay identity")?;
        let acme_manager = cfg
            .acme_cloudflare_config(&root_host)
            .map(AcmeManager::new)
            .transpose()
            .context("configure acme manager")?;
        if let Some(manager) = &acme_manager {
            manager
                .ensure_certificate()
                .await
                .context("ensure acme tls certificate")?;
        }
        let tls_material = load_or_create_tls_material(&cfg.identity_path, &root_host)
            .context("load or create api tls material")?;
        let api_addr = cfg.api_listen_addr();
        let sni_addr = cfg.sni_listen_addr();
        let quic_config = if cfg.udp_enabled {
            Some(tls_material.quic_config)
        } else {
            None
        };
        let tls_acceptor = TlsAcceptor::from(Arc::new(tls_material.config));
        let policy = Arc::new(
            PolicyRuntime::load_with_landing_default(
                &cfg.identity_path,
                cfg.udp_enabled,
                cfg.tcp_enabled,
                cfg.landing_page_enabled,
            )
            .context("load admin policy state")?,
        );
        policy
            .set_proxy_trust(cfg.trust_proxy_headers, &cfg.trusted_proxy_cidrs)
            .context("configure proxy trust policy")?;
        let admin = Arc::new(
            AdminState::new(identity.admin_secret_key.clone(), Arc::clone(&policy))
                .context("initialize admin auth")?,
        );
        let metrics = Arc::new(RelayMetrics::default());
        let overlay = if cfg.discovery_enabled {
            let overlay_config = OverlayConfig::from_identity(&identity, cfg.wireguard_port)
                .context("configure wireguard overlay")?;
            Some(Arc::new(
                OverlayRuntime::new(overlay_config)
                    .await
                    .context("initialize wireguard overlay runtime")?,
            ))
        } else {
            None
        };
        let hop_mux = overlay.as_ref().map(|overlay| {
            let connector: Arc<dyn HopMuxConnector> =
                Arc::clone(overlay) as Arc<dyn HopMuxConnector>;
            HopMux::with_connector(connector)
        });
        let leases = Arc::new(LeaseRegistry::new(LeaseRegistryConfig {
            root_host: root_host.clone(),
            relay: identity.clone(),
            issuer: cfg.portal_url.clone(),
            sni_port: cfg.sni_port,
            udp_enabled: cfg.udp_enabled,
            tcp_enabled: cfg.tcp_enabled,
            min_port: cfg.min_port,
            max_port: cfg.max_port,
            policy,
            metrics: Arc::clone(&metrics),
        }));
        let overlay_info = overlay.as_ref().map(|overlay| overlay.discovery_info());
        let discovery = cfg.discovery_enabled.then(|| {
            Arc::new(DiscoveryState::new_with_metrics_and_overlay(
                identity.clone(),
                cfg.portal_url.clone(),
                cfg.bootstraps.clone(),
                cfg.udp_enabled,
                cfg.tcp_enabled,
                Arc::clone(&metrics),
                overlay_info,
            ))
        });
        let frontend = cfg
            .frontend_dist
            .as_ref()
            .map(|path| FrontendState::new(path))
            .transpose()
            .context("initialize frontend static serving")?
            .map(Arc::new);
        info!(
            portal_url = %cfg.portal_url,
            root_host = %identity.name,
            api_addr = %api_addr,
            sni_addr = %sni_addr,
            discovery_enabled = cfg.discovery_enabled,
            overlay_enabled = overlay.is_some(),
            hop_mux_enabled = hop_mux.is_some(),
            udp_enabled = cfg.udp_enabled,
            tcp_enabled = cfg.tcp_enabled,
            min_port = cfg.min_port,
            max_port = cfg.max_port,
            wireguard_port = cfg.wireguard_port,
            frontend_enabled = frontend.is_some(),
            trust_proxy_headers = cfg.trust_proxy_headers,
            bootstrap_count = cfg.bootstraps.len(),
            acme_dns_provider = %cfg.acme_dns_provider,
            "relay runtime configured"
        );
        let state = Arc::new(AppState {
            root_host: identity.name.clone(),
            portal_host: root_host,
            portal_url: cfg.portal_url.clone(),
            relay_identity: Arc::new(identity.clone()),
            leases,
            keyless_signer: tls_material.keyless_signer,
            admin,
            frontend,
            discovery,
            overlay,
            hop_mux,
            metrics,
            voucher_budget: Arc::new(VoucherBudget::new(MAX_VOUCHER_BUDGET)),
        });

        Ok(Self {
            cfg,
            identity,
            api_addr,
            sni_addr,
            tls_acceptor,
            quic_config,
            acme_manager,
            state,
        })
    }

    pub fn api_addr(&self) -> SocketAddr {
        self.api_addr
    }

    pub fn portal_url(&self) -> &str {
        &self.cfg.portal_url
    }

    pub fn root_host(&self) -> &str {
        &self.identity.name
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        info!(
            api_addr = %self.api_addr,
            sni_addr = %self.sni_addr,
            discovery_enabled = self.state.discovery.is_some(),
            overlay_enabled = self.state.overlay.is_some(),
            hop_mux_enabled = self.state.hop_mux.is_some(),
            "relay server run loop starting"
        );
        let api_listener = TcpListener::bind(self.api_addr)
            .await
            .with_context(|| format!("listen api on {}", self.api_addr))?;
        let sni_listener = TcpListener::bind(self.sni_addr)
            .await
            .with_context(|| format!("listen sni on {}", self.sni_addr))?;
        let api_local_addr = api_listener
            .local_addr()
            .context("read api listener address")?;
        let sni_local_addr = sni_listener
            .local_addr()
            .context("read sni listener address")?;
        self.state.leases.set_sni_port(sni_local_addr.port());
        info!(api_addr = %api_local_addr, "api listener ready");
        info!(sni_addr = %sni_local_addr, "sni listener ready");

        let quic_task = self.start_quic_backhaul_listener()?;
        let acme_task = self
            .acme_manager
            .take()
            .map(|manager| AbortOnDrop(manager.start_maintenance()));
        let janitor_task = start_registry_janitor(Arc::clone(&self.state.leases));
        let overlay_hop_mux_task = match (&self.state.overlay, &self.state.hop_mux) {
            (Some(overlay), Some(hop_mux)) => Some(
                start_overlay_hop_mux_listener(Arc::clone(overlay), Arc::clone(hop_mux)).await?,
            ),
            _ => None,
        };
        let discovery_task = self.state.discovery.as_ref().map(|discovery| {
            start_discovery_refresher(
                Arc::clone(discovery),
                self.state.overlay.as_ref().map(Arc::clone),
            )
        });
        let hop_mux_task = self.state.hop_mux.as_ref().map(|hop_mux| {
            start_hop_mux_accept_loop(
                Arc::clone(hop_mux),
                Arc::clone(&self.state.leases),
                Arc::clone(&self.state.metrics),
            )
        });

        loop {
            tokio::select! {
                accept = api_listener.accept() => {
                    let (stream, remote_addr) = accept.context("accept api connection")?;
                    let acceptor = self.tls_acceptor.clone();
                    let state = Arc::clone(&self.state);

                    tokio::spawn(async move {
                        let tls_stream = match acceptor.accept(stream).await {
                            Ok(stream) => stream,
                            Err(err) => {
                                error!(%remote_addr, error = %err, "api tls handshake failed");
                                return;
                            }
                        };

                        if let Err(err) = handle_api_connection(tls_stream, state, remote_addr).await {
                            error!(%remote_addr, error = %err, "api http connection failed");
                        }
                    });
                }
                accept = sni_listener.accept() => {
                    let (stream, remote_addr) = accept.context("accept sni connection")?;
                    let leases = Arc::clone(&self.state.leases);
                    let hop_mux = self.state.hop_mux.as_ref().map(Arc::clone);
                    let root_host = self.state.portal_host.clone();
                    let metrics = Arc::clone(&self.state.metrics);
                    tokio::spawn(async move {
                        if let Err(err) = handle_public_ingress(stream, &leases, hop_mux, api_local_addr, &root_host, metrics).await {
                            debug!(%remote_addr, error = %err, "public ingress closed");
                        }
                    });
                }
                signal = tokio::signal::ctrl_c() => {
                    signal.context("install ctrl-c handler")?;
                    info!("shutdown signal received");
                    if let Some(task) = &quic_task {
                        task.abort();
                    }
                    if let Some(task) = &acme_task {
                        task.abort();
                    }
                    janitor_task.abort();
                    if let Some(task) = &discovery_task {
                        task.abort();
                    }
                    if let Some(task) = &overlay_hop_mux_task {
                        task.abort();
                    }
                    if let Some(task) = &hop_mux_task {
                        task.abort();
                    }
                    return Ok(());
                }
            }
        }
    }

    fn start_quic_backhaul_listener(&mut self) -> anyhow::Result<Option<JoinHandle<()>>> {
        let Some(config) = self.quic_config.take() else {
            return Ok(None);
        };
        let endpoint = quinn::Endpoint::server(config, self.sni_addr)
            .with_context(|| format!("listen quic backhaul on {}", self.sni_addr))?;
        let local_addr = endpoint
            .local_addr()
            .context("read quic backhaul local address")?;
        self.state.leases.set_sni_port(local_addr.port());
        info!(quic_addr = %local_addr, "quic backhaul listener ready");

        let leases = Arc::clone(&self.state.leases);
        Ok(Some(tokio::spawn(async move {
            run_quic_backhaul_listener(endpoint, leases).await;
        })))
    }
}

struct AbortOnDrop(JoinHandle<()>);

impl AbortOnDrop {
    fn abort(&self) {
        self.0.abort();
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn start_registry_janitor(leases: Arc<LeaseRegistry>) -> AbortOnDrop {
    AbortOnDrop(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(REGISTRY_JANITOR_INTERVAL);
        loop {
            ticker.tick().await;
            let stats = leases.cleanup_expired(Utc::now());
            if !stats.is_empty() {
                debug!(
                    challenges = stats.challenges,
                    leases = stats.leases,
                    hop_routes = stats.hop_routes,
                    "cleaned expired registry records"
                );
            }
        }
    }))
}

async fn start_overlay_hop_mux_listener(
    overlay: Arc<OverlayRuntime>,
    hop_mux: Arc<HopMux>,
) -> anyhow::Result<AbortOnDrop> {
    Ok(AbortOnDrop(overlay.start_hop_mux_listener(hop_mux).await?))
}

fn start_discovery_refresher(
    discovery: Arc<DiscoveryState>,
    overlay: Option<Arc<OverlayRuntime>>,
) -> AbortOnDrop {
    AbortOnDrop(tokio::spawn(async move {
        info!(
            overlay_enabled = overlay.is_some(),
            interval_secs = DISCOVERY_POLL_INTERVAL.as_secs(),
            "relay discovery refresher started"
        );
        let mut ticker = tokio::time::interval(DISCOVERY_POLL_INTERVAL);
        loop {
            ticker.tick().await;
            match discovery.refresh_once().await {
                Ok(stats) => {
                    if stats.polled > 0 || stats.announced > 0 || stats.failures > 0 {
                        info!(
                            polled = stats.polled,
                            announced = stats.announced,
                            failures = stats.failures,
                            "relay discovery refresh completed"
                        );
                    }
                }
                Err(err) => {
                    warn!(error = %err, "relay discovery refresh failed");
                }
            }
            if let Some(overlay) = &overlay {
                sync_overlay_peers(&discovery, overlay).await;
            }
        }
    }))
}

async fn sync_overlay_peers(discovery: &Arc<DiscoveryState>, overlay: &Arc<OverlayRuntime>) {
    let mut peers = Vec::new();
    for desc in discovery.overlay_peers(Utc::now()) {
        match OverlayPeer::from_descriptor(&desc) {
            Ok(peer) => peers.push(peer),
            Err(err) => {
                warn!(
                    relay = %desc.api_https_addr,
                    error = %err,
                    "relay discovery overlay peer rejected"
                );
            }
        }
    }
    let discovered_peer_count = peers.len();

    match overlay.sync_peers(&peers).await {
        Ok(stats) => {
            for warning in &stats.warnings {
                warn!(warning = %warning, "overlay peer sync warning");
            }
            if stats.changed() {
                info!(
                    discovered_peer_count,
                    added = stats.added,
                    updated = stats.updated,
                    removed = stats.removed,
                    unchanged = stats.unchanged,
                    "overlay peers synced"
                );
            }
        }
        Err(err) => {
            warn!(error = %err, "overlay peer sync failed");
        }
    }
}

fn start_hop_mux_accept_loop(
    hop_mux: Arc<HopMux>,
    leases: Arc<LeaseRegistry>,
    metrics: Arc<RelayMetrics>,
) -> AbortOnDrop {
    AbortOnDrop(tokio::spawn(async move {
        while let Some(stream) = hop_mux.accept().await {
            let remote_addr = stream.remote_addr.clone();
            let leases = Arc::clone(&leases);
            let hop_mux = Arc::clone(&hop_mux);
            let metrics = Arc::clone(&metrics);
            tokio::spawn(async move {
                if let Err(err) = handle_hop_mux_stream(stream, leases, hop_mux, metrics).await {
                    warn!(%remote_addr, error = %err, "hop mux stream closed");
                }
            });
        }
    }))
}

async fn handle_hop_mux_stream(
    mut stream: HopStream,
    leases: Arc<LeaseRegistry>,
    hop_mux: Arc<HopMux>,
    metrics: Arc<RelayMetrics>,
) -> anyhow::Result<()> {
    match leases
        .lookup_hop_token(&stream.token)
        .context("hop token not found")?
    {
        HopRelayTarget::Direct(target) => {
            let mut reverse = target
                .stream
                .claim(TLS_ACTIVATE)
                .await
                .context("claim reverse session")?;
            let _ = copy_bidirectional_with_policy_and_metrics(
                &mut stream.stream,
                &mut reverse,
                &target.policy,
                &target.identity_key,
                Some(metrics.as_ref()),
            )
            .await;
        }
        HopRelayTarget::NextHop(target) => {
            debug!(
                remote_addr = %stream.remote_addr,
                next_overlay_ipv4 = %target.overlay_ipv4,
                "hop mux stream matched next-hop relay target"
            );
            let mut next = hop_mux
                .open_stream_with_retry(
                    &target.overlay_ipv4,
                    &target.token,
                    HOP_OPEN_TIMEOUT,
                    HOP_OPEN_RETRY_WAIT,
                )
                .await?;
            let _ =
                copy_bidirectional_with_metrics(&mut stream.stream, &mut next, metrics.as_ref())
                    .await;
        }
    }
    Ok(())
}

struct ParsedRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn handle_api_connection(
    mut io: TlsStream<tokio::net::TcpStream>,
    state: Arc<AppState>,
    remote_addr: SocketAddr,
) -> anyhow::Result<()> {
    let req = read_http_request(&mut io).await?;
    let client_ip = state
        .admin
        .policy
        .extract_client_ip(remote_addr, &req.headers);
    if req.method == "GET" && req.path == PATH_SDK_CONNECT {
        handle_sdk_connect(io, state, req, remote_addr, client_ip).await?;
        return Ok(());
    }

    let method = req.method.clone();
    let path = req.path.clone();
    let reply = api::handle_request(
        Arc::clone(&state),
        &method,
        &path,
        &req.headers,
        client_ip.clone(),
        req.body,
    )
    .await;
    log_api_rejection(&method, &path, reply.status, remote_addr, &client_ip);
    write_http_response(&mut io, reply.status, &reply.headers, &reply.body, true).await?;
    Ok(())
}

async fn handle_sdk_connect(
    mut io: TlsStream<tokio::net::TcpStream>,
    state: Arc<AppState>,
    req: ParsedRequest,
    remote_addr: SocketAddr,
    client_ip: String,
) -> anyhow::Result<()> {
    let token = header_value(&req.headers, "x-portal-access-token").unwrap_or_default();
    match state.leases.admit_connect(&token) {
        Ok(stream) => {
            io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")
                .await
                .context("write sdk connect response")?;
            stream.offer(io).await.context("queue reverse session")?;
        }
        Err(err) => {
            let reply = api::api_error_reply(err.status_code(), err.api_code(), &err.to_string());
            warn!(
                method = %req.method,
                path = %PATH_SDK_CONNECT,
                status = reply.status.as_u16(),
                error_code = %err.api_code(),
                remote_addr = %remote_addr,
                client_ip = %client_ip,
                error = %err,
                "api request rejected"
            );
            write_http_response(&mut io, reply.status, &reply.headers, &reply.body, true).await?;
        }
    }
    Ok(())
}

fn log_api_rejection(
    method: &str,
    path: &str,
    status: hyper::StatusCode,
    remote_addr: SocketAddr,
    client_ip: &str,
) {
    if status.as_u16() < 400 {
        return;
    }
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    let sdk_or_relay_api =
        path.starts_with("/sdk/") || path.starts_with("/discovery") || path == "/v1/sign";
    if status.as_u16() >= 500 || sdk_or_relay_api {
        warn!(
            method = %method,
            path = %path,
            status = status.as_u16(),
            remote_addr = %remote_addr,
            client_ip = %client_ip,
            "api request rejected"
        );
    } else {
        debug!(
            method = %method,
            path = %path,
            status = status.as_u16(),
            remote_addr = %remote_addr,
            client_ip = %client_ip,
            "api request rejected"
        );
    }
}

async fn read_http_request(
    io: &mut TlsStream<tokio::net::TcpStream>,
) -> anyhow::Result<ParsedRequest> {
    let mut header = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    let header_end;
    loop {
        let n = io.read(&mut buf).await.context("read http request")?;
        if n == 0 {
            anyhow::bail!("connection closed before request");
        }
        header.extend_from_slice(&buf[..n]);
        if header.len() > 16 * 1024 {
            anyhow::bail!("http request header too large");
        }
        if let Some(pos) = find_header_end(&header) {
            header_end = pos;
            break;
        }
    }

    let mut body = header.split_off(header_end + 4);
    let head =
        String::from_utf8(header[..header_end].to_vec()).context("http header is not utf8")?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().context("missing request line")?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default().to_string();
    let path = request_parts.next().unwrap_or_default().to_string();
    if method.is_empty() || path.is_empty() {
        anyhow::bail!("invalid request line");
    }
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    let content_length = header_value(&headers, "content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    while body.len() < content_length {
        let n = io.read(&mut buf).await.context("read http request body")?;
        if n == 0 {
            anyhow::bail!("connection closed before request body");
        }
        body.extend_from_slice(&buf[..n]);
    }
    body.truncate(content_length);

    Ok(ParsedRequest {
        method,
        path,
        headers,
        body,
    })
}

async fn write_http_response(
    io: &mut TlsStream<tokio::net::TcpStream>,
    status: hyper::StatusCode,
    headers: &[(String, String)],
    body: &[u8],
    close: bool,
) -> anyhow::Result<()> {
    let reason = status.canonical_reason().unwrap_or("");
    let mut response = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\n",
        status.as_u16(),
        reason,
        body.len()
    );
    if close {
        response.push_str("Connection: close\r\n");
    }
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    io.write_all(response.as_bytes()).await?;
    io.write_all(body).await?;
    io.flush().await?;
    Ok(())
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

async fn run_quic_backhaul_listener(endpoint: quinn::Endpoint, leases: Arc<LeaseRegistry>) {
    while let Some(incoming) = endpoint.accept().await {
        let leases = Arc::clone(&leases);
        tokio::spawn(async move {
            if let Err(err) = handle_quic_backhaul_conn(incoming, leases).await {
                debug!(error = %err, "quic backhaul connection closed");
            }
        });
    }
}

async fn handle_quic_backhaul_conn(
    incoming: quinn::Incoming,
    leases: Arc<LeaseRegistry>,
) -> anyhow::Result<()> {
    let remote_addr = incoming.remote_address();
    let conn = incoming.await.context("accept quic backhaul connection")?;
    let (mut send, mut recv) = match tokio::time::timeout(Duration::from_secs(10), conn.accept_bi())
        .await
        .context("quic backhaul control stream accept timed out")?
    {
        Ok(stream) => stream,
        Err(err) => {
            conn.close(1u32.into(), b"control stream accept failed");
            return Err(err).context("accept quic backhaul control stream");
        }
    };

    let control = match read_control_message(&mut recv).await {
        Ok(control) => control,
        Err(err) => {
            conn.close(1u32.into(), b"control read failed");
            return Err(err);
        }
    };

    let runtime = match leases.admit_datagram(&control.access_token) {
        Ok(runtime) => runtime,
        Err(err) => {
            let code = err.api_code().to_string();
            let _ = write_control_response(
                &mut send,
                &QuicBackhaulControlResponse {
                    ok: false,
                    error: code,
                },
            )
            .await;
            conn.close(1u32.into(), err.to_string().as_bytes());
            return Ok(());
        }
    };

    runtime.bind_backhaul(conn);
    write_control_response(
        &mut send,
        &QuicBackhaulControlResponse {
            ok: true,
            error: String::new(),
        },
    )
    .await?;
    info!(%remote_addr, "quic backhaul connected");
    Ok(())
}

#[cfg(test)]
mod voucher_budget_tests {
    use super::{MAX_VOUCHER_BUDGET, VoucherBudget};
    use std::sync::Arc;

    #[test]
    fn release_returns_slot_to_budget() {
        let budget = Arc::new(VoucherBudget::new(2));
        let g1 = budget.acquire().expect("first acquire succeeds");
        assert_eq!(budget.in_flight(), 1);
        g1.release();
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn drop_returns_slot_to_budget() {
        let budget = Arc::new(VoucherBudget::new(2));
        {
            let _g = budget.acquire().expect("acquire");
            assert_eq!(budget.in_flight(), 1);
        }
        assert_eq!(budget.in_flight(), 0);
    }

    #[test]
    fn consume_permanently_holds_slot() {
        let budget = Arc::new(VoucherBudget::new(2));
        let g = budget.acquire().expect("acquire");
        g.consume();
        // Slot is not released by drop after consume; in-flight remains 1.
        assert_eq!(budget.in_flight(), 1);
    }

    #[test]
    fn capacity_is_enforced_and_failed_acquire_does_not_burn_slot() {
        let budget = Arc::new(VoucherBudget::new(2));
        let _g1 = budget.acquire().expect("first");
        let _g2 = budget.acquire().expect("second");
        assert!(budget.acquire().is_none(), "third acquire must fail");
        // The failed acquire must not have permanently incremented the in-flight counter.
        assert_eq!(budget.in_flight(), 2);
    }

    #[test]
    fn consume_exhausts_budget_after_max_issuances() {
        let budget = Arc::new(VoucherBudget::new(MAX_VOUCHER_BUDGET));
        for _ in 0..MAX_VOUCHER_BUDGET {
            budget
                .acquire()
                .expect("within capacity")
                .consume();
        }
        assert_eq!(budget.in_flight(), MAX_VOUCHER_BUDGET);
        assert!(
            budget.acquire().is_none(),
            "budget must be exhausted after consuming MAX_VOUCHER_BUDGET slots"
        );
    }
}
