//! U13 hot-reload primitive tests. Pin the swap-atomicity, trust-
//! boundary-key rejection, and audit-trail emission contracts named
//! in `docs/plans/2026-05-04-005-feat-portal-relay-plan.md` U13's
//! Test scenarios.

#![expect(
    clippy::expect_used,
    clippy::redundant_clone,
    reason = "integration test: expect on known-good fixtures; \
              redundant clones keep the bootstrap fixture intact for \
              repeated assertions across the rejection-path tests"
)]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use compact_str::CompactString;
use portal_relay::{RelayServerConfig, ReloadError, ReloadHandle, RuntimeConfig};
use tracing::subscriber::with_default;
use tracing_subscriber::fmt::MakeWriter;

/// Build a deterministic bootstrap config for the tests.
fn baseline_bootstrap() -> RelayServerConfig {
    RelayServerConfig::new(
        CompactString::const_new("test-relay"),
        PathBuf::from("/var/lib/portal/relay"),
        PathBuf::from("/etc/portal/api.key"),
        PathBuf::from("/etc/portal/keyless.key"),
        PathBuf::from("/etc/portal/quic.key"),
    )
}

/// Extract `changed_paths` from a [`ReloadError`].
///
/// `ReloadError` is `#[non_exhaustive]` so cross-crate matches need a
/// wildcard arm; this helper centralizes the panic message and keeps
/// the test bodies focused on the assertion.
fn expect_trust_boundary_changed_paths(err: ReloadError) -> Vec<&'static str> {
    match err {
        ReloadError::TrustBoundaryKeyRequiresRestart { changed_paths } => changed_paths,
        #[allow(
            unreachable_patterns,
            reason = "future ReloadError variants surface as test failure"
        )]
        other => panic!("expected TrustBoundaryKeyRequiresRestart; got {other:?}"),
    }
}

/// 1. Happy-path swap reflects the mutated `bps_per_identity`.
#[test]
fn reload_swaps_runtime_subset_atomically() {
    let bootstrap = baseline_bootstrap();
    let handle = ReloadHandle::new(bootstrap.clone(), RuntimeConfig::default());

    assert_eq!(handle.current().bps_per_identity, 0);

    let mut next = RuntimeConfig::default();
    next.bps_per_identity = 1024;
    handle
        .reload(&bootstrap, next)
        .expect("same bootstrap + new runtime should swap successfully");

    assert_eq!(handle.current().bps_per_identity, 1024);
}

/// 2. State-dir mutation is rejected as a trust-boundary change.
#[test]
fn reload_rejects_state_dir_mutation_as_trust_boundary() {
    let bootstrap = baseline_bootstrap();
    let handle = ReloadHandle::new(bootstrap.clone(), RuntimeConfig::default());

    let mut mutated = bootstrap.clone();
    mutated.state_dir = PathBuf::from("/var/lib/portal/relay-rotated");

    let err = handle
        .reload(&mutated, RuntimeConfig::default())
        .expect_err("state_dir mutation must be rejected");
    let changed_paths = expect_trust_boundary_changed_paths(err);
    assert_eq!(changed_paths, vec!["state_dir"]);

    // The runtime config did NOT swap — current() still reports the
    // initial defaults.
    let current = handle.current();
    assert_eq!(current.bps_per_identity, 0);
    assert!(current.ip_ban_list.is_empty());
}

/// 3. `api_https_key_path` mutation is rejected analogously.
#[test]
fn reload_rejects_api_https_key_path_mutation() {
    let bootstrap = baseline_bootstrap();
    let handle = ReloadHandle::new(bootstrap.clone(), RuntimeConfig::default());

    let mut mutated = bootstrap.clone();
    mutated.api_https_key_path = PathBuf::from("/etc/portal/api.key.rotated");

    let err = handle
        .reload(&mutated, RuntimeConfig::default())
        .expect_err("api_https_key_path mutation must be rejected");
    let changed_paths = expect_trust_boundary_changed_paths(err);
    assert_eq!(changed_paths, vec!["api_https_key_path"]);
}

/// 4. Multi-key mutation lists every changed field in `changed_paths`
///    (order-independent).
#[test]
fn reload_rejects_multiple_trust_boundary_mutations_with_full_list() {
    let bootstrap = baseline_bootstrap();
    let handle = ReloadHandle::new(bootstrap.clone(), RuntimeConfig::default());

    let mut mutated = bootstrap.clone();
    mutated.keyless_signing_key_path = PathBuf::from("/etc/portal/keyless.key.v2");
    mutated.quic_identity_key_path = PathBuf::from("/etc/portal/quic.key.v2");

    let err = handle
        .reload(&mutated, RuntimeConfig::default())
        .expect_err("multi-key mutation must be rejected");
    let changed_paths = expect_trust_boundary_changed_paths(err);
    let observed: HashSet<&'static str> = changed_paths.into_iter().collect();
    let expected: HashSet<&'static str> = ["keyless_signing_key_path", "quic_identity_key_path"]
        .into_iter()
        .collect();
    assert_eq!(observed, expected);
}

/// In-memory `MakeWriter` that captures every formatted log line into
/// a shared `Vec<u8>`; the audit-emission test asserts substrings of
/// the captured output.
#[derive(Clone, Default)]
struct CapturingWriter {
    sink: Arc<Mutex<Vec<u8>>>,
}

impl CapturingWriter {
    fn new() -> Self {
        Self::default()
    }

    fn snapshot(&self) -> String {
        let buf = self.sink.lock().expect("capturing-writer mutex");
        String::from_utf8_lossy(&buf).into_owned()
    }
}

impl<'a> MakeWriter<'a> for CapturingWriter {
    type Writer = CapturingHandle;
    fn make_writer(&'a self) -> Self::Writer {
        CapturingHandle {
            sink: Arc::clone(&self.sink),
        }
    }
}

struct CapturingHandle {
    sink: Arc<Mutex<Vec<u8>>>,
}

impl std::io::Write for CapturingHandle {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        {
            let mut guard = self
                .sink
                .lock()
                .map_err(|_| std::io::Error::other("capturing-writer mutex poisoned"))?;
            guard.extend_from_slice(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 5. Audit-event emission carries `event = "config.reload"` and
///    `swapped_fields = [...]` listing the diff'd runtime field
///    names exactly. Uses the JSON formatter so the assertions
///    parse the structured event rather than substring-matching the
///    text formatter's output (which is brittle to format toggles).
#[test]
fn reload_emits_swapped_fields_in_audit_event() {
    let bootstrap = baseline_bootstrap();
    let handle = ReloadHandle::new(bootstrap.clone(), RuntimeConfig::default());

    let writer = CapturingWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(writer.clone())
        .with_target(false)
        .with_level(false)
        .with_current_span(false)
        .with_span_list(false)
        .without_time()
        .finish();

    let mut next = RuntimeConfig::default();
    next.bps_per_identity = 4096;
    next.ip_ban_list = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];

    with_default(subscriber, || {
        handle
            .reload(&bootstrap, next)
            .expect("happy-path swap with both runtime fields mutated");
    });

    let captured = writer.snapshot();
    let line = captured
        .lines()
        .find(|l| l.contains("\"event\":\"config.reload\""))
        .unwrap_or_else(|| panic!("no config.reload event in captured output: {captured:?}"));

    let parsed: serde_json::Value = serde_json::from_str(line)
        .unwrap_or_else(|e| panic!("failed to parse audit line as JSON ({e}): {line:?}"));
    let fields = parsed
        .get("fields")
        .and_then(serde_json::Value::as_object)
        .unwrap_or_else(|| panic!("audit line missing 'fields' object: {line:?}"));

    assert_eq!(
        fields.get("event").and_then(serde_json::Value::as_str),
        Some("config.reload"),
        "expected fields.event == \"config.reload\"; line = {line:?}",
    );

    let swapped = fields
        .get("swapped_fields")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("audit line missing 'swapped_fields': {line:?}"));
    // `?` formatter on `Vec<&'static str>` produces e.g.
    // `["bps_per_identity", "ip_ban_list"]`. Assert order-stable
    // because the impl appends in the documented diff order.
    assert_eq!(
        swapped, "[\"bps_per_identity\", \"ip_ban_list\"]",
        "swapped_fields shape mismatch; line = {line:?}",
    );
}

/// Per-reader observation outcome. Reported back to the main thread
/// via the join handle so the assertions can distinguish "no torn
/// read" (good) from "race window missed entirely" (test would pass
/// vacuously without this signal — the Codex concern).
#[derive(Debug, Default)]
struct ReaderOutcome {
    saw_old: bool,
    saw_new: bool,
    torn: bool,
}

/// Callbacks registered via [`ReloadHandle::on_reload`] are invoked
/// after a successful reload with the newly-stored [`RuntimeConfig`].
#[test]
fn reload_invokes_registered_callbacks() {
    let bootstrap = baseline_bootstrap();
    let handle = ReloadHandle::new(bootstrap.clone(), RuntimeConfig::default());
    let called = Arc::new(AtomicBool::new(false));
    let called_clone = called.clone();
    handle.on_reload(move |runtime: &RuntimeConfig| {
        assert_eq!(runtime.bps_per_identity, 8192);
        called_clone.store(true, Ordering::SeqCst);
    });
    let new_runtime = RuntimeConfig::default().with_bps_per_identity(8192);
    handle
        .reload(&bootstrap, new_runtime)
        .expect("reload should succeed");
    assert!(
        called.load(Ordering::SeqCst),
        "callback should have been invoked"
    );
}

/// 6. Concurrent readers see the OLD or the NEW `RuntimeConfig`,
///    never a mix.
///
/// Pins the swap-atomicity invariant. The initial state has
/// `(bps_per_identity = 0, ip_ban_list = [])`; the new state has
/// `(bps_per_identity = 1024, ip_ban_list = [127.0.0.1])`. Any
/// reader observing `(0, 1)` or `(1024, 0)` would prove a torn read
/// across the two fields.
///
/// Coordination: a [`Barrier`] gates all readers + the swapper on a
/// shared start point. Before issuing the reload, the main thread
/// waits (bounded) for at least one reader to publish a SAW-OLD
/// observation via the `old_observers` counter — this defeats a
/// scheduler in which every reader starts AFTER the swap and would
/// otherwise vacuously fail the `any_saw_old` assertion. After the
/// reload, an [`AtomicBool`] `swap_done` signals readers to stop
/// spinning. Each reader reports back which states it observed; the
/// main thread asserts AT LEAST ONE reader saw the OLD state and AT
/// LEAST ONE saw the NEW state.
#[test]
fn concurrent_readers_see_old_or_new_never_mixed() {
    const READERS: usize = 100;
    let bootstrap = baseline_bootstrap();
    let handle = ReloadHandle::new(bootstrap.clone(), RuntimeConfig::default());

    let barrier = Arc::new(Barrier::new(READERS + 1));
    let swap_done = Arc::new(AtomicBool::new(false));
    let old_observers = Arc::new(AtomicUsize::new(0));

    let reader_handles: Vec<_> = (0..READERS)
        .map(|_| {
            let h = handle.clone();
            let barrier = Arc::clone(&barrier);
            let swap_done = Arc::clone(&swap_done);
            let old_observers = Arc::clone(&old_observers);
            thread::spawn(move || {
                let mut outcome = ReaderOutcome::default();
                barrier.wait();
                let mut reported_old = false;
                let mut post_swap_samples = 0usize;
                loop {
                    let snap = h.current();
                    let bps = snap.bps_per_identity;
                    let bans = snap.ip_ban_list.len();
                    if bps == 0 && bans == 0 {
                        if !outcome.saw_old {
                            outcome.saw_old = true;
                        }
                        if !reported_old {
                            old_observers.fetch_add(1, Ordering::AcqRel);
                            reported_old = true;
                        }
                    } else if bps == 1024 && bans == 1 {
                        outcome.saw_new = true;
                    } else {
                        outcome.torn = true;
                        break;
                    }
                    if swap_done.load(Ordering::Acquire) {
                        post_swap_samples += 1;
                        if post_swap_samples >= 32 {
                            break;
                        }
                    }
                }
                outcome
            })
        })
        .collect();

    barrier.wait();

    // Bounded handshake: wait for at least one reader to publish a
    // SAW-OLD observation before issuing the reload. Bound at 2s so
    // a hung scheduler surfaces as a timely test failure rather than
    // an infinite loop.
    let handshake_deadline = Instant::now() + Duration::from_secs(2);
    while old_observers.load(Ordering::Acquire) == 0 {
        assert!(
            Instant::now() < handshake_deadline,
            "handshake timeout: no reader observed OLD state within \
             2s — scheduler / runtime is not exercising the pre-swap \
             window",
        );
        thread::yield_now();
    }

    let mut next = RuntimeConfig::default();
    next.bps_per_identity = 1024;
    next.ip_ban_list = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
    handle
        .reload(&bootstrap, next)
        .expect("happy-path swap during concurrent reads");
    swap_done.store(true, Ordering::Release);

    let mut any_saw_old = false;
    let mut any_saw_new = false;
    for (idx, jh) in reader_handles.into_iter().enumerate() {
        let outcome = jh.join().expect("reader thread panicked");
        assert!(!outcome.torn, "reader {idx} observed a torn read");
        any_saw_old |= outcome.saw_old;
        any_saw_new |= outcome.saw_new;
    }

    // Race-window proof: at least one reader observed each side.
    // The handshake above guarantees `any_saw_old`; the post-swap
    // sampling window guarantees `any_saw_new`.
    assert!(
        any_saw_old,
        "no reader saw the OLD state — handshake should have prevented this",
    );
    assert!(
        any_saw_new,
        "no reader saw the NEW state — post-swap sampling window was insufficient",
    );

    // Final state matches the post-swap runtime.
    let after = handle.current();
    assert_eq!(after.bps_per_identity, 1024);
    assert_eq!(after.ip_ban_list.len(), 1);
}
