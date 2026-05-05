//! Filesystem watcher for the runtime-config JSON file.
//!
//! Behind `cfg(feature = "config_file_watch")`. The watcher
//! observes a single JSON file at an operator-supplied path; on
//! change events it deserializes the file content as
//! [`RuntimeConfig`] (per its `default + deny_unknown_fields` serde
//! contract) and calls
//! [`crate::reload::ReloadHandle::reload`] with the held bootstrap
//! config and the new runtime.
//!
//! ## Atomicity caveat
//!
//! Atomic-rename (`write to <path>.tmp`, `rename` onto `<path>`)
//! is the recommended operator write pattern. Because rename
//! replaces the file's inode, watching the leaf path directly
//! would detach the watch from the new inode after the first
//! rename; the watcher therefore observes the **parent
//! directory** non-recursively and filters debounced events down
//! to the operator-supplied path. Without atomic-rename, the
//! watcher may still observe a partially-written file;
//! `notify-debouncer-full` mitigates by batching events within a
//! debounce window before reading. This is best-effort and not a
//! production-grade reliability claim.
//!
//! ## Trust-boundary discipline
//!
//! Only the runtime config is reloaded. Bootstrap config
//! ([`crate::config::RelayServerConfig`]) is immutable per R-S5-4;
//! the watcher does not read or compare against bootstrap fields.
//! If an operator wants to mutate a trust-boundary key path, they
//! must restart the relay binary.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use notify::RecursiveMode;
use notify_debouncer_full::{DebounceEventResult, new_debouncer};
use thiserror::Error;
use tokio::task::JoinHandle;

use crate::config::RuntimeConfig;
use crate::reload::ReloadHandle;

/// Default debounce window — ample for atomic-rename writes,
/// short enough that operator-friendly latency is preserved.
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(250);

/// Errors that can surface from the watcher's setup phase.
///
/// Runtime-loop errors (deserialize failures, reload failures)
/// are logged via `tracing::warn` and do NOT terminate the
/// watcher — the operator's next valid write should recover the
/// loop.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum FileWatchError {
    /// The OS-level notify backend could not initialize (e.g.,
    /// inotify watcher limit exhausted on Linux).
    #[error("notify backend init failed: {0}")]
    NotifyInit(#[from] notify::Error),
    /// The operator-supplied path's parent directory could not
    /// be added to the watch set (parent does not exist,
    /// permissions denied, etc).
    #[error("watch path {path:?} cannot be observed: {source}")]
    WatchPath {
        /// The operator-supplied path that failed to register.
        path: PathBuf,
        /// The underlying notify backend error.
        #[source]
        source: notify::Error,
    },
    /// The operator-supplied path has no parent directory (e.g.,
    /// `path = "/"`). The watcher needs a parent to observe so
    /// that atomic-rename writes do not detach the watch from
    /// the post-rename inode.
    #[error("watch path {path:?} has no parent directory to observe")]
    NoParentDirectory {
        /// The operator-supplied path lacking a parent.
        path: PathBuf,
    },
}

/// Spawn a tokio task that watches `path` for change events and
/// triggers [`ReloadHandle::reload`] on each batch.
///
/// Returns a tokio [`JoinHandle`]. Because tokio `JoinHandle`
/// drop merely **detaches** the task (it does not cancel it),
/// callers that need to stop the watcher MUST call
/// [`JoinHandle::abort`] explicitly; aborting drops the internal
/// [`notify_debouncer_full::Debouncer`] which signals the
/// OS-level watcher to stop. The watcher does NOT eagerly read
/// the file at startup — the caller is responsible for the
/// initial load (or the file may not yet exist when the watcher
/// starts).
///
/// # Errors
///
/// - [`FileWatchError::NotifyInit`] if the OS-level notify
///   backend cannot initialize (e.g., inotify watcher limit
///   exhausted on Linux).
/// - [`FileWatchError::WatchPath`] if the operator-supplied
///   `path`'s parent directory cannot be added to the watch set
///   (parent does not exist, permissions denied, etc).
/// - [`FileWatchError::NoParentDirectory`] if `path` has no
///   parent directory (e.g., a filesystem root). The watcher
///   needs a parent to observe so that atomic-rename writes do
///   not detach the watch from the post-rename inode.
///
/// # Resilience invariant
///
/// Per-event errors (file disappearing mid-read, JSON
/// deserialize failure,
/// [`crate::reload::ReloadError::TrustBoundaryKeyRequiresRestart`]
/// from a mistakenly-mutated bootstrap path) are logged via
/// `tracing::warn` and do NOT terminate the watcher. The
/// operator's next valid write recovers the loop.
pub fn watch_runtime_config(
    handle: Arc<ReloadHandle>,
    path: PathBuf,
) -> Result<JoinHandle<()>, FileWatchError> {
    // Watch the parent directory (non-recursively) so atomic-
    // rename writes — which replace the inode — keep firing
    // events under our watch. Filter the debounced batch to
    // events touching the operator-supplied leaf path.
    //
    // Relative paths like `runtime.json` have `Path::parent()
    // == Some("")`; treat that as `.` so operator-friendly
    // relative paths Just Work. `NoParentDirectory` is reserved
    // for true filesystem roots (`/` or `C:\`) where there is no
    // observable parent.
    let parent = match path.parent() {
        None => return Err(FileWatchError::NoParentDirectory { path: path.clone() }),
        Some(p) if p.as_os_str().is_empty() => PathBuf::from("."),
        Some(p) => p.to_path_buf(),
    };

    // Filtering anchor: the leaf file name is invariant across
    // platform path-prefix canonicalization (e.g., macOS
    // FSEvents may surface paths under `/private/var/...` for a
    // watch registered under `/var/...`). Capture it once and
    // compare leaf-to-leaf inside the loop.
    let target_leaf = path
        .file_name()
        .ok_or_else(|| FileWatchError::NoParentDirectory { path: path.clone() })?
        .to_os_string();

    // The debouncer's event handler runs on the debouncer's
    // internal flush thread; bridge that into the async world via
    // a tokio unbounded channel. `UnboundedSender::send` is sync
    // and non-blocking, so the closure satisfies
    // `FnMut(DebounceEventResult) + Send + 'static`.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<DebounceEventResult>();
    let mut debouncer = new_debouncer(DEFAULT_DEBOUNCE, None, move |result| {
        let _ = tx.send(result);
    })?;

    debouncer
        .watch(&parent, RecursiveMode::NonRecursive)
        .map_err(|source| FileWatchError::WatchPath {
            path: path.clone(),
            source,
        })?;

    let bootstrap = handle.bootstrap();
    let target = path;
    // R9 OR-clause: this `tokio::spawn` returns its `JoinHandle`
    // to the caller, who is responsible for the task's lifecycle
    // via `JoinHandle::abort` (documented in the function-level
    // rustdoc above). Aborting drops `_debouncer` inside the
    // task, which signals the OS-level watcher to stop. No
    // detached-drain / fire-and-forget shape lives here.
    #[expect(
        clippy::disallowed_methods,
        reason = "R9: JoinHandle is returned to the caller and abort() is the documented stop mechanism"
    )]
    let join = tokio::spawn(async move {
        // Move the debouncer into the task so its lifetime is
        // tied to the JoinHandle: aborting the handle drops the
        // debouncer, which stops the OS-level watcher.
        let _debouncer = debouncer;
        while let Some(result) = rx.recv().await {
            match result {
                Ok(events) => {
                    // Non-recursive watch on a single parent
                    // directory means every observed path lives
                    // in that directory; leaf-name equality is
                    // therefore sufficient AND robust to any
                    // platform prefix canonicalization
                    // (e.g., macOS `/private` front-mount).
                    if events.iter().any(|ev| {
                        ev.event
                            .paths
                            .iter()
                            .any(|p| p.file_name() == Some(target_leaf.as_os_str()))
                    }) {
                        apply_runtime_config(&handle, &bootstrap, &target).await;
                    }
                }
                Err(errors) => {
                    for err in errors {
                        tracing::warn!(
                            event = "config.reload.notify_error",
                            path = %target.display(),
                            error = %err,
                            "notify backend reported an error; continuing",
                        );
                    }
                }
            }
        }
    });

    Ok(join)
}

/// Read the JSON file at `path`, deserialize as
/// [`RuntimeConfig`], and call [`ReloadHandle::reload`].
///
/// All failure modes are logged via `tracing::warn` and silently
/// dropped — the watcher's resilience invariant requires that no
/// per-event error terminates the run loop.
async fn apply_runtime_config(
    handle: &ReloadHandle,
    bootstrap: &crate::config::RelayServerConfig,
    path: &Path,
) {
    let bytes = match tokio::fs::read(path).await {
        Ok(b) => b,
        Err(err) => {
            tracing::warn!(
                event = "config.reload.read_failed",
                path = %path.display(),
                error = %err,
                "failed to read runtime-config file; skipping this batch",
            );
            return;
        }
    };

    let runtime = match serde_json::from_slice::<RuntimeConfig>(&bytes) {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(
                event = "config.reload.deserialize_failed",
                path = %path.display(),
                error = %err,
                "runtime-config JSON deserialize failed; skipping this batch",
            );
            return;
        }
    };

    if let Err(err) = handle.reload(bootstrap, runtime) {
        tracing::warn!(
            event = "config.reload.rejected",
            path = %path.display(),
            error = %err,
            "ReloadHandle::reload rejected the swap; skipping this batch",
        );
    }
}
