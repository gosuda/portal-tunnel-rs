use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use hyper::StatusCode;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::{debug, warn};
use url::Url;

use crate::api::ApiReply;
use crate::relay::leases::{LeaseRegistry, LeaseView};

const THUMBNAIL_PREFIX: &str = "/thumbnail/";
const CACHE_CONTROL: &str = "public, max-age=300";
const JPEG_CONTENT_TYPE: &str = "image/jpeg";
const QUEUE_SIZE: usize = 32;
const CACHE_CAPACITY: usize = 128;
const LAST_ATTEMPT_CAPACITY: usize = 256;
const COOLDOWN: Duration = Duration::from_secs(30);
const NAVIGATION_SETTLE: Duration = Duration::from_secs(1);
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(not(test))]
const CAPTURE_TASK_TIMEOUT: Duration = Duration::from_secs(120);
#[cfg(test)]
const CAPTURE_TASK_TIMEOUT: Duration = Duration::from_millis(50);
const VIEWPORT_WIDTH: u64 = 1280;
const VIEWPORT_HEIGHT: u64 = 720;
const JPEG_QUALITY: u8 = 80;
const MAX_THUMBNAIL_BYTES: usize = 256 * 1024;

pub fn thumbnail_hostname(path: &str) -> Option<String> {
    let raw = path.strip_prefix(THUMBNAIL_PREFIX)?;
    Some(raw.trim().to_ascii_lowercase())
}

pub fn thumbnail_not_found() -> ApiReply {
    ApiReply {
        status: StatusCode::NOT_FOUND,
        headers: Vec::new(),
        body: Vec::new(),
    }
}

pub struct ThumbnailService {
    backend: Arc<dyn ThumbnailBackend>,
    inner: Mutex<ThumbnailState>,
    queue: Arc<Semaphore>,
}

struct ThumbnailState {
    cache: HashMap<String, Vec<u8>>,
    cache_order: VecDeque<String>,
    pending: HashSet<String>,
    last_attempt: HashMap<String, Instant>,
    last_attempt_order: VecDeque<String>,
}

enum PrefetchDecision {
    Start(OwnedSemaphorePermit),
    Skip,
}

impl ThumbnailService {
    pub fn new(headless_shell_url: String) -> Self {
        Self::with_backend(Arc::new(HeadlessShellBackend::new(headless_shell_url)))
    }

    pub fn with_backend(backend: Arc<dyn ThumbnailBackend>) -> Self {
        Self {
            backend,
            inner: Mutex::new(ThumbnailState {
                cache: HashMap::new(),
                cache_order: VecDeque::new(),
                pending: HashSet::new(),
                last_attempt: HashMap::new(),
                last_attempt_order: VecDeque::new(),
            }),
            queue: Arc::new(Semaphore::new(QUEUE_SIZE)),
        }
    }

    pub async fn handle_get(
        self: &Arc<Self>,
        leases: Arc<LeaseRegistry>,
        hostname: String,
    ) -> ApiReply {
        if hostname.is_empty() {
            return thumbnail_not_found();
        }
        if !leases.thumbnail_eligible(&hostname) {
            self.remove(&hostname).await;
            return thumbnail_not_found();
        }
        if let Some(body) = self.cached(&hostname).await {
            return jpeg_reply(body);
        }
        self.prefetch_if_needed(leases, hostname).await;
        thumbnail_not_found()
    }

    pub async fn prefetch_public_leases(
        self: &Arc<Self>,
        leases: Arc<LeaseRegistry>,
        views: &[LeaseView],
    ) {
        for lease in views {
            if !lease.metadata.thumbnail.trim().is_empty() || lease.hostname.trim().is_empty() {
                self.remove(&lease.hostname).await;
                continue;
            }
            self.prefetch_if_needed(Arc::clone(&leases), lease.hostname.clone())
                .await;
        }
    }

    async fn cached(&self, hostname: &str) -> Option<Vec<u8>> {
        self.inner.lock().await.cache.get(hostname).cloned()
    }

    async fn remove(&self, hostname: &str) {
        let hostname = hostname.trim().to_ascii_lowercase();
        if hostname.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().await;
        inner.cache.remove(&hostname);
        inner.cache_order.retain(|candidate| candidate != &hostname);
        inner.pending.remove(&hostname);
    }

    async fn prefetch_if_needed(self: &Arc<Self>, leases: Arc<LeaseRegistry>, hostname: String) {
        let hostname = hostname.trim().to_ascii_lowercase();
        if hostname.is_empty() {
            return;
        }
        let permit = match self.mark_pending(&hostname).await {
            PrefetchDecision::Start(permit) => permit,
            PrefetchDecision::Skip => return,
        };

        let service = Arc::clone(self);
        tokio::spawn(async move {
            let result = if leases.thumbnail_eligible(&hostname) {
                let backend = Arc::clone(&service.backend);
                let capture_hostname = hostname.clone();
                let capture = tokio::spawn(async move { backend.capture(&capture_hostname).await });
                let mut capture = CaptureTask::new(capture);
                if let Ok(result) = tokio::time::timeout(CAPTURE_TASK_TIMEOUT, capture.join()).await { Some(result) } else {
                    capture.abort_and_wait().await;
                    None
                }
            } else {
                service.remove(&hostname).await;
                drop(permit);
                return;
            };
            drop(permit);

            match result {
                Some(Ok(Ok(jpeg))) => {
                    let mut inner = service.inner.lock().await;
                    inner.insert_cache(hostname.clone(), jpeg);
                    inner.pending.remove(&hostname);
                }
                Some(Ok(Err(err))) => {
                    warn!(%hostname, error = %err, "thumbnail capture failed");
                    service.clear_pending(&hostname).await;
                }
                Some(Err(err)) => {
                    warn!(%hostname, error = %err, "thumbnail capture task failed");
                    service.clear_pending(&hostname).await;
                }
                None => {
                    warn!(%hostname, "thumbnail capture timed out");
                    service.clear_pending(&hostname).await;
                }
            }
        });
    }

    async fn mark_pending(&self, hostname: &str) -> PrefetchDecision {
        let mut inner = self.inner.lock().await;
        if inner.cache.contains_key(hostname) || inner.pending.contains(hostname) {
            return PrefetchDecision::Skip;
        }
        let now = Instant::now();
        if inner
            .last_attempt
            .get(hostname)
            .is_some_and(|previous| now.duration_since(*previous) < COOLDOWN)
        {
            return PrefetchDecision::Skip;
        }
        let Ok(permit) = Arc::clone(&self.queue).try_acquire_owned() else {
            return PrefetchDecision::Skip;
        };
        inner.insert_last_attempt(hostname.to_string(), now);
        inner.pending.insert(hostname.to_string());
        PrefetchDecision::Start(permit)
    }

    async fn clear_pending(&self, hostname: &str) {
        self.inner.lock().await.pending.remove(hostname);
    }
}

struct CaptureTask {
    handle: Option<JoinHandle<anyhow::Result<Vec<u8>>>>,
}

impl CaptureTask {
    fn new(handle: JoinHandle<anyhow::Result<Vec<u8>>>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    async fn join(&mut self) -> Result<anyhow::Result<Vec<u8>>, tokio::task::JoinError> {
        self.handle.take().expect("capture task joined once").await
    }

    async fn abort_and_wait(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
            let _ = handle.await;
        }
    }
}

impl Drop for CaptureTask {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl ThumbnailState {
    fn insert_cache(&mut self, hostname: String, jpeg: Vec<u8>) {
        if !self.cache.contains_key(&hostname) {
            self.cache_order.push_back(hostname.clone());
        }
        self.cache.insert(hostname, jpeg);
        self.enforce_cache_capacity();
    }

    fn insert_last_attempt(&mut self, hostname: String, attempted_at: Instant) {
        if !self.last_attempt.contains_key(&hostname) {
            self.last_attempt_order.push_back(hostname.clone());
        }
        self.last_attempt.insert(hostname, attempted_at);
        self.enforce_last_attempt_capacity();
    }

    fn enforce_cache_capacity(&mut self) {
        while self.cache.len() > CACHE_CAPACITY {
            let Some(oldest) = self.cache_order.pop_front() else {
                break;
            };
            self.cache.remove(&oldest);
        }
    }

    fn enforce_last_attempt_capacity(&mut self) {
        while self.last_attempt.len() > LAST_ATTEMPT_CAPACITY {
            let Some(oldest) = self.last_attempt_order.pop_front() else {
                break;
            };
            self.last_attempt.remove(&oldest);
        }
    }
}

pub trait ThumbnailBackend: Send + Sync + 'static {
    fn capture<'a>(
        &'a self,
        hostname: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send + 'a>>;
}

struct HeadlessShellBackend {
    base_url: String,
    client: reqwest::Client,
}

impl HeadlessShellBackend {
    fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    async fn web_socket_url(&self) -> anyhow::Result<String> {
        let mut url = Url::parse(&self.base_url).context("parse HEADLESS_SHELL_URL")?;
        url.set_path("/json/version");
        url.set_query(None);
        url.set_fragment(None);
        let version = self
            .client
            .get(url)
            .send()
            .await
            .context("request headless-shell version")?
            .error_for_status()
            .context("headless-shell version status")?
            .json::<HeadlessVersion>()
            .await
            .context("decode headless-shell version")?;
        if version.web_socket_debugger_url.trim().is_empty() {
            bail!("headless-shell version missing webSocketDebuggerUrl");
        }
        Ok(version.web_socket_debugger_url)
    }
}

impl ThumbnailBackend for HeadlessShellBackend {
    fn capture<'a>(
        &'a self,
        hostname: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send + 'a>>
    {
        Box::pin(async move {
            let ws_url = tokio::time::timeout(CAPTURE_TIMEOUT, self.web_socket_url())
                .await
                .context("thumbnail version request timed out")??;
            capture_with_cdp(&ws_url, hostname).await
        })
    }
}

#[derive(Deserialize)]
struct HeadlessVersion {
    #[serde(rename = "webSocketDebuggerUrl")]
    web_socket_debugger_url: String,
}

async fn capture_with_cdp(ws_url: &str, hostname: &str) -> anyhow::Result<Vec<u8>> {
    let (socket, _) =
        tokio::time::timeout(CAPTURE_TIMEOUT, tokio_tungstenite::connect_async(ws_url))
            .await
            .context("thumbnail cdp connect timed out")?
            .context("connect cdp websocket")?;
    let mut cdp = CdpConnection::new(socket);

    let context_id = cdp
        .send_command(None, "Browser.createBrowserContext", json!({}))
        .await?
        .get("browserContextId")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .context("Browser.createBrowserContext missing browserContextId")?;
    let mut cleanup = CdpCleanup::new(context_id.clone());

    let target_id_result = cdp
        .send_command(
            None,
            "Target.createTarget",
            json!({"url":"about:blank","browserContextId":context_id}),
        )
        .await
        .and_then(|value| {
            value
                .get("targetId")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .context("Target.createTarget missing targetId")
        });
    let target_id = match target_id_result {
        Ok(target_id) => target_id,
        Err(err) => {
            cleanup.run(&mut cdp).await;
            return Err(err);
        }
    };
    cleanup.target_id = Some(target_id.clone());

    let result = capture_target(&mut cdp, &target_id, hostname).await;
    cleanup.run(&mut cdp).await;

    result
}

struct CdpCleanup {
    context_id: String,
    target_id: Option<String>,
}

impl CdpCleanup {
    fn new(context_id: String) -> Self {
        Self {
            context_id,
            target_id: None,
        }
    }

    async fn run(&mut self, cdp: &mut CdpConnection) {
        if let Some(target_id) = self.target_id.take() {
            let _ = tokio::time::timeout(
                CLEANUP_TIMEOUT,
                cdp.send_command(None, "Target.closeTarget", json!({"targetId":target_id})),
            )
            .await;
        }
        let _ = tokio::time::timeout(
            CLEANUP_TIMEOUT,
            cdp.send_command(
                None,
                "Browser.disposeBrowserContext",
                json!({"browserContextId":self.context_id}),
            ),
        )
        .await;
    }
}

async fn capture_target(
    cdp: &mut CdpConnection,
    target_id: &str,
    hostname: &str,
) -> anyhow::Result<Vec<u8>> {
    let session_id = cdp
        .send_command(
            None,
            "Target.attachToTarget",
            json!({"targetId":target_id,"flatten":true}),
        )
        .await?
        .get("sessionId")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .context("Target.attachToTarget missing sessionId")?;

    let session = Some(session_id.as_str());
    let _ = cdp
        .send_command(session, "Security.enable", json!({}))
        .await;
    let _ = cdp
        .send_command(
            session,
            "Security.setIgnoreCertificateErrors",
            json!({"ignore":true}),
        )
        .await;
    cdp.send_command(
        session,
        "Emulation.setDeviceMetricsOverride",
        json!({"width":VIEWPORT_WIDTH,"height":VIEWPORT_HEIGHT,"deviceScaleFactor":1,"mobile":false}),
    )
    .await?;
    cdp.send_command(session, "Page.enable", json!({})).await?;
    cdp.send_command(
        session,
        "Page.navigate",
        json!({"url":format!("https://{hostname}")}),
    )
    .await?;
    cdp.wait_for_event(&session_id, "Page.loadEventFired")
        .await?;
    tokio::time::sleep(NAVIGATION_SETTLE).await;
    let result = cdp
        .send_command(
            session,
            "Page.captureScreenshot",
            json!({"format":"jpeg","quality":JPEG_QUALITY}),
        )
        .await?;
    let data = result
        .get("data")
        .and_then(Value::as_str)
        .context("Page.captureScreenshot missing data")?;
    let jpeg = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, data)
        .context("decode screenshot jpeg")?;
    if jpeg.len() > MAX_THUMBNAIL_BYTES {
        bail!("thumbnail exceeds 256KB");
    }
    Ok(jpeg)
}

type CdpSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

struct CdpConnection {
    id: u64,
    sink: SplitSink<CdpSocket, Message>,
    stream: SplitStream<CdpSocket>,
    buffered: VecDeque<Value>,
}

impl CdpConnection {
    fn new(socket: CdpSocket) -> Self {
        let (sink, stream) = socket.split();
        Self {
            id: 0,
            sink,
            stream,
            buffered: VecDeque::new(),
        }
    }

    async fn send_command(
        &mut self,
        session_id: Option<&str>,
        method: &str,
        params: Value,
    ) -> anyhow::Result<Value> {
        self.id += 1;
        let current_id = self.id;
        let mut payload = json!({"id":current_id,"method":method,"params":params});
        if let Some(session_id) = session_id {
            payload["sessionId"] = Value::String(session_id.to_string());
        }
        self.sink
            .send(Message::Text(payload.to_string().into()))
            .await
            .with_context(|| format!("send cdp command {method}"))?;

        if let Some(value) = self.take_buffered_response(current_id) {
            if let Some(error) = value.get("error") {
                bail!("cdp command {method} failed: {error}");
            }
            return Ok(value.get("result").cloned().unwrap_or(Value::Null));
        }
        while let Some(value) = self.read_message().await? {
            if value.get("id").and_then(Value::as_u64) != Some(current_id) {
                self.buffered.push_back(value);
                continue;
            }
            if let Some(error) = value.get("error") {
                bail!("cdp command {method} failed: {error}");
            }
            return Ok(value.get("result").cloned().unwrap_or(Value::Null));
        }
        Err(anyhow!("cdp websocket closed while waiting for {method}"))
    }

    async fn wait_for_event(&mut self, session_id: &str, method: &str) -> anyhow::Result<()> {
        if self.take_buffered_event(session_id, method) {
            return Ok(());
        }
        while let Some(value) = self.read_message().await? {
            if event_matches(&value, session_id, method) {
                return Ok(());
            }
            debug!(event = ?value.get("method"), "ignored cdp event");
            self.buffered.push_back(value);
        }
        Err(anyhow!("cdp websocket closed while waiting for {method}"))
    }

    async fn read_message(&mut self) -> anyhow::Result<Option<Value>> {
        while let Some(message) = self.stream.next().await {
            let message = message.context("read cdp message")?;
            let Message::Text(raw) = message else {
                continue;
            };
            let value = serde_json::from_str(&raw).context("decode cdp message")?;
            return Ok(Some(value));
        }
        Ok(None)
    }

    fn take_buffered_response(&mut self, id: u64) -> Option<Value> {
        let index = self
            .buffered
            .iter()
            .position(|value| value.get("id").and_then(Value::as_u64) == Some(id))?;
        self.buffered.remove(index)
    }

    fn take_buffered_event(&mut self, session_id: &str, method: &str) -> bool {
        let Some(index) = self
            .buffered
            .iter()
            .position(|value| event_matches(value, session_id, method))
        else {
            return false;
        };
        self.buffered.remove(index);
        true
    }
}

fn event_matches(value: &Value, session_id: &str, method: &str) -> bool {
    value.get("method").and_then(Value::as_str) == Some(method)
        && value.get("sessionId").and_then(Value::as_str) == Some(session_id)
}

fn jpeg_reply(body: Vec<u8>) -> ApiReply {
    ApiReply {
        status: StatusCode::OK,
        headers: vec![
            ("Content-Type".to_string(), JPEG_CONTENT_TYPE.to_string()),
            ("Cache-Control".to_string(), CACHE_CONTROL.to_string()),
        ],
        body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockBackend {
        captures: AtomicUsize,
        body: Vec<u8>,
    }

    impl ThumbnailBackend for MockBackend {
        fn capture<'a>(
            &'a self,
            _hostname: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send + 'a>>
        {
            Box::pin(async move {
                self.captures.fetch_add(1, Ordering::SeqCst);
                Ok(self.body.clone())
            })
        }
    }

    #[test]
    fn thumbnail_hostname_strips_prefix_and_lowercases() {
        assert_eq!(
            thumbnail_hostname("/thumbnail/ Demo.Example ").as_deref(),
            Some("demo.example")
        );
        assert_eq!(thumbnail_hostname("/app"), None);
    }

    #[tokio::test]
    async fn cached_thumbnail_returns_jpeg_reply() {
        let service = Arc::new(ThumbnailService::with_backend(Arc::new(MockBackend {
            captures: AtomicUsize::new(0),
            body: b"jpeg".to_vec(),
        })));
        service
            .inner
            .lock()
            .await
            .insert_cache("demo.example".to_string(), b"jpeg".to_vec());

        let reply = super::jpeg_reply(service.cached("demo.example").await.unwrap());

        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.body, b"jpeg");
        assert_eq!(
            reply
                .headers
                .iter()
                .find(|(name, _)| name == "Content-Type")
                .map(|(_, value)| value.as_str()),
            Some("image/jpeg")
        );
    }

    #[tokio::test]
    async fn skipped_prefetches_do_not_reserve_queue_permits_while_waiting_for_state() {
        let service = Arc::new(ThumbnailService::with_backend(Arc::new(MockBackend {
            captures: AtomicUsize::new(0),
            body: b"jpeg".to_vec(),
        })));
        let mut inner = service.inner.lock().await;
        let now = Instant::now();
        for index in 0..QUEUE_SIZE {
            inner
                .last_attempt
                .insert(format!("cached-{index}.example"), now);
        }

        let mut tasks = Vec::with_capacity(QUEUE_SIZE);
        for index in 0..QUEUE_SIZE {
            let service = Arc::clone(&service);
            tasks.push(tokio::spawn(async move {
                service
                    .mark_pending(&format!("cached-{index}.example"))
                    .await
            }));
        }

        tokio::task::yield_now().await;

        assert_eq!(service.queue.available_permits(), QUEUE_SIZE);

        drop(inner);
        for task in tasks {
            assert!(matches!(task.await.unwrap(), PrefetchDecision::Skip));
        }
    }

    #[tokio::test]
    async fn cache_eviction_bounds_unique_hostnames() {
        let service = ThumbnailService::with_backend(Arc::new(MockBackend {
            captures: AtomicUsize::new(0),
            body: b"jpeg".to_vec(),
        }));
        let mut inner = service.inner.lock().await;
        for index in 0..(CACHE_CAPACITY + 8) {
            inner.insert_cache(format!("cached-{index}.example"), vec![index as u8]);
        }

        assert_eq!(inner.cache.len(), CACHE_CAPACITY);
        assert!(!inner.cache.contains_key("cached-0.example"));
        assert!(inner
            .cache
            .contains_key(&format!("cached-{}.example", CACHE_CAPACITY + 7)));
    }

    #[tokio::test]
    async fn last_attempt_eviction_bounds_unique_hostnames() {
        let service = ThumbnailService::with_backend(Arc::new(MockBackend {
            captures: AtomicUsize::new(0),
            body: b"jpeg".to_vec(),
        }));
        let mut inner = service.inner.lock().await;
        let now = Instant::now();
        for index in 0..(LAST_ATTEMPT_CAPACITY + 8) {
            inner.insert_last_attempt(format!("attempt-{index}.example"), now);
        }

        assert_eq!(inner.last_attempt.len(), LAST_ATTEMPT_CAPACITY);
        assert!(!inner.last_attempt.contains_key("attempt-0.example"));
        assert!(inner
            .last_attempt
            .contains_key(&format!("attempt-{}.example", LAST_ATTEMPT_CAPACITY + 7)));
    }
}
