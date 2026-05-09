//! `ExposeSession` — client-side tunnel lifecycle.
//!
//! 1. Load tenant + protocol identity keys.
//! 2. Connect to relay via QUIC.
//! 3. HTTP register-challenge → sign SIWE → register.
//! 4. Spawn listener accept loop.
//! 5. Emit lifecycle events.

use std::net::SocketAddr;
use std::path::PathBuf;

use compact_str::CompactString;
use jiff::Timestamp;
use portal_crypto::{
    evm_address_from_pubkey, sign_eip191_personal, tenant_public_key,
    verifying_key as protocol_verifying_key_inner,
};
use portal_net::quic::endpoint::Endpoint;
use portal_wire::api::{
    RegisterChallengeRequest, RegisterChallengeResponse, RegisterRequest, RegisterResponse,
};
use portal_wire::descriptor::RelayDescriptor;
use secrecy::SecretBox;
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::error::{SdkError, SdkResult};
use crate::events::{TunnelEvent, TunnelState};
use crate::identity::{generate_protocol_key, load_protocol_key, load_tenant_key};
use crate::listener::Listener;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for an [`ExposeSession`].
#[derive(Debug, Clone)]
pub struct ExposeConfig {
    /// Relay to connect to.
    pub relay: RelayDescriptor,
    /// HTTPS API base URL (e.g. `https://relay.example.com`).
    pub api_base_url: CompactString,
    /// Path to the tenant secp256k1 identity key file.
    pub tenant_key_path: PathBuf,
    /// Optional path to a persisted ed25519 protocol key.
    /// If `None`, an ephemeral key is generated.
    pub protocol_key_path: Option<PathBuf>,
    /// Hostname to register.
    pub hostname: CompactString,
    /// Request UDP datagram surface.
    pub udp_enabled: bool,
    /// Request TCP port surface.
    pub tcp_enabled: bool,
    /// Local bind address for the QUIC endpoint.
    pub bind_addr: SocketAddr,
}

impl Default for ExposeConfig {
    fn default() -> Self {
        Self {
            relay: RelayDescriptor {
                identity_key: [0; 32],
                addresses_v4: Vec::new(),
                addresses_v6: Vec::new(),
            },
            api_base_url: CompactString::const_new("https://localhost"),
            tenant_key_path: PathBuf::from("/dev/null"),
            protocol_key_path: None,
            hostname: CompactString::default(),
            udp_enabled: false,
            tcp_enabled: true,
            bind_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
        }
    }
}

// ---------------------------------------------------------------------------
// Session handle
// ---------------------------------------------------------------------------

/// Owned handle to an active expose session.
pub struct ExposeSession {
    cancel: CancellationToken,
    tasks: JoinSet<SdkResult<()>>,
    event_tx: broadcast::Sender<TunnelEvent>,
    listener: Option<Listener>,
}

impl ExposeSession {
    /// Start the session.
    ///
    /// # Errors
    /// Returns [`SdkError::Config`] on missing/invalid configuration,
    /// [`SdkError::Crypto`] on key load failure,
    /// [`SdkError::Net`] on QUIC connection failure,
    /// [`SdkError::Lease`] on registration rejection.
    pub async fn start(
        config: ExposeConfig,
        event_tx: broadcast::Sender<TunnelEvent>,
    ) -> SdkResult<Self> {
        let cancel = CancellationToken::new();
        let mut tasks = JoinSet::new();

        // Load tenant key.
        let tenant_key = load_tenant_key(&config.tenant_key_path)?;

        // Load or generate protocol key.
        let protocol_key = match &config.protocol_key_path {
            Some(path) => load_protocol_key(path)?,
            None => generate_protocol_key()?,
        };

        // Emit Discovering.
        let _ = event_tx.send(TunnelEvent::StateChanged {
            from: TunnelState::Idle,
            to: TunnelState::Discovering,
            at: Timestamp::now(),
        });

        // Build HTTP client.
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| SdkError::Config(format!("http client: {e}")))?;

        // Derive EVM address from tenant key.
        let pk = tenant_public_key(&tenant_key).map_err(|e| SdkError::Crypto(e.to_string()))?;
        let eth_address = evm_address_from_pubkey(&pk).to_string();

        // Encode ed25519 pubkey as base64.
        let ed25519_pubkey = protocol_verifying_key_inner(&protocol_key);
        let ed25519_pk_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            ed25519_pubkey.to_bytes(),
        );

        // Perform HTTP registration.
        let register_resp = register(
            &http,
            &config.api_base_url,
            &eth_address,
            &ed25519_pk_b64,
            &tenant_key,
            &config.hostname,
            config.udp_enabled,
            config.tcp_enabled,
        )
        .await?;

        // Pick a relay address (prefer IPv4, fall back to IPv6).
        let relay_addr = pick_relay_addr(&config.relay).ok_or_else(|| {
            SdkError::Net(portal_net::NetError::Connect("no relay address".to_owned()))
        })?;

        // Emit Connecting.
        let _ = event_tx.send(TunnelEvent::DialAttempt {
            relay_id: CompactString::from(hex_encode(&config.relay.identity_key)),
            addr: relay_addr,
            at: Timestamp::now(),
        });
        let _ = event_tx.send(TunnelEvent::StateChanged {
            from: TunnelState::Discovering,
            to: TunnelState::Connecting,
            at: Timestamp::now(),
        });

        // Connect QUIC.
        let endpoint = Endpoint::client(config.bind_addr, ed25519_pubkey).map_err(SdkError::Net)?;
        let conn = endpoint
            .connect(relay_addr, &hex_encode(&config.relay.identity_key))
            .map_err(SdkError::Net)?
            .await
            .map_err(|e| {
                SdkError::Net(portal_net::NetError::Connect(format!("quic connect: {e}")))
            })?;

        // Emit Active.
        let _ = event_tx.send(TunnelEvent::StateChanged {
            from: TunnelState::Connecting,
            to: TunnelState::Active,
            at: Timestamp::now(),
        });
        let _ = event_tx.send(TunnelEvent::LeaseIssued {
            hostname: register_resp.hostname.clone(),
            expires_at: register_resp.expires_at,
        });

        // Spawn listener accept loop.
        let listener_cancel = cancel.child_token();
        let (listener, mut stream_rx) = Listener::start(conn, listener_cancel, 64)?;

        // Spawn stream consumer task (v0.1: acknowledges streams; TLS
        // termination + tenant forwarding is Phase 5/6a integration).
        let stream_cancel = cancel.child_token();
        tasks.spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    () = stream_cancel.cancelled() => break Ok(()),
                    maybe = stream_rx.recv() => {
                        match maybe {
                            Some(_stream) => {
                                tracing::debug!("accepted stream from relay");
                            }
                            None => break Ok(()),
                        }
                    }
                }
            }
        });

        Ok(Self {
            cancel,
            tasks,
            event_tx,
            listener: Some(listener),
        })
    }

    /// Stop the session and wait for all tasks to finish.
    pub async fn stop(mut self) {
        self.cancel.cancel();
        if let Some(listener) = self.listener.take() {
            listener.stop().await;
        }
        while let Some(res) = self.tasks.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!(error = %e, "expose task returned error"),
                Err(e) => tracing::warn!(error = ?e, "expose task panicked"),
            }
        }
        let _ = self.event_tx.send(TunnelEvent::StateChanged {
            from: TunnelState::Active,
            to: TunnelState::Stopped,
            at: Timestamp::now(),
        });
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// POST register-challenge → sign SIWE → POST register.
#[expect(clippy::too_many_arguments, reason = "wire protocol registration flow")]
async fn register(
    http: &reqwest::Client,
    base_url: &CompactString,
    eth_address: &str,
    ed25519_pk: &str,
    tenant_key: &SecretBox<portal_crypto::TenantSecp256k1Key>,
    hostname: &CompactString,
    udp_enabled: bool,
    tcp_enabled: bool,
) -> SdkResult<RegisterResponse> {
    // 1. Issue challenge.
    let challenge_req = RegisterChallengeRequest {
        eth_address: eth_address.to_owned(),
        ed25519_pk: ed25519_pk.to_owned(),
        reported_ip: None,
        udp_enabled,
        tcp_enabled,
        hop_token: String::new(),
        hostname: hostname.to_string(),
        metadata: String::new(),
        ttl: 0,
        route_hostname: CompactString::default(),
        hostname_hash: String::new(),
    };

    let challenge_url = format!("{base_url}/v1/sdk/register-challenge");
    let challenge_resp: RegisterChallengeResponse = http
        .post(&challenge_url)
        .json(&challenge_req)
        .send()
        .await
        .map_err(|e| SdkError::Lease(format!("challenge request: {e}")))?
        .json()
        .await
        .map_err(|e| SdkError::Lease(format!("challenge response: {e}")))?;

    // 2. Sign SIWE message with tenant key (EIP-191 personal sign).
    let signature = sign_eip191_personal(challenge_resp.siwe_message.as_bytes(), tenant_key)
        .map_err(|e| SdkError::Crypto(e.to_string()))?;
    let signature_hex = format!("0x{}", hex_encode(&signature));

    // 3. Consume challenge → mint lease.
    let register_req = RegisterRequest {
        challenge_id: challenge_resp.challenge_id,
        siwe_message_text: challenge_resp.siwe_message,
        siwe_signature: signature_hex,
        hostname: hostname.clone(),
        metadata: String::new(),
        route_hostname: CompactString::default(),
        hostname_hash: String::new(),
    };

    let register_url = format!("{base_url}/v1/sdk/register");
    let register_resp: RegisterResponse = http
        .post(&register_url)
        .json(&register_req)
        .send()
        .await
        .map_err(|e| SdkError::Lease(format!("register request: {e}")))?
        .json()
        .await
        .map_err(|e| SdkError::Lease(format!("register response: {e}")))?;

    Ok(register_resp)
}

/// Pick the first available relay address (IPv4 preferred, IPv6 fallback).
fn pick_relay_addr(descriptor: &RelayDescriptor) -> Option<SocketAddr> {
    descriptor
        .addresses_v4
        .first()
        .copied()
        .map(SocketAddr::from)
        .or_else(|| {
            descriptor
                .addresses_v6
                .first()
                .copied()
                .map(SocketAddr::from)
        })
}

/// Encode bytes as lowercase hex (no `0x` prefix).
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
