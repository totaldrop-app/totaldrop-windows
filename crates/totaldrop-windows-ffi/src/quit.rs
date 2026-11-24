// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Graceful shutdown draining for active Windows transfer tasks and router
//! port mappings, matching TotalDrop Linux's `quit.rs` (`#433`, ADR 0016).
//!
//! Because the FFI Tokio runtime lives in a `LazyLock` static, closing the
//! WinUI 3 window must stop active transfers, wait up to [`STOPPING`] for them
//! to notify peers and close sockets, abort stragglers with an [`ABORTED`]
//! unwind window so their dropped mappings queue UPnP/NAT-PMP releases, and
//! finally await `totaldrop_core::portmap::released()`.

use std::future::Future;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::AbortHandle;

/// Default grace period for stopped transfers to notify peers and exit
/// cleanly before being aborted (`1500 ms`, matching Linux `quit.rs`).
pub(crate) const STOPPING: Duration = Duration::from_millis(1500);

/// Unwind window after aborting straggler tasks so dropped resources (port
/// mappings, partial files) complete their release hooks (`200 ms`).
const ABORTED: Duration = Duration::from_millis(200);

/// Global registry of active transfer and decline tasks that may hold a router
/// port mapping or partial file on disk.
pub(crate) static TRANSFERS: Tasks = Tasks::new();

/// Counted task tracker allowing deterministic bounded shutdown draining.
#[derive(Debug)]
pub(crate) struct Tasks {
    running: AtomicUsize,
    idle: Notify,
    handles: Mutex<Vec<AbortHandle>>,
}

impl Default for Tasks {
    fn default() -> Self {
        Self::new()
    }
}

impl Tasks {
    /// Creates an empty task registry; `const` so it can live in a `static`.
    pub(crate) const fn new() -> Self {
        Self {
            running: AtomicUsize::new(0),
            idle: Notify::const_new(),
            handles: Mutex::new(Vec::new()),
        }
    }

    /// Spawns `work` on `runtime`, counting it from invocation until it
    /// finishes, is aborted, or panics.
    pub(crate) fn spawn(
        &'static self,
        runtime: &tokio::runtime::Runtime,
        work: impl Future<Output = ()> + Send + 'static,
    ) {
        let running = Running::new(self);
        let task = runtime.spawn(async move {
            let _running = running;
            work.await;
        });
        if let Ok(mut handles) = self.handles.lock() {
            handles.retain(|h| !h.is_finished());
            handles.push(task.abort_handle());
        }
    }

    /// Resolves once no counted task is running (immediately if already idle).
    pub(crate) async fn idle(&self) {
        loop {
            let ended = self.idle.notified();
            if self.running.load(Ordering::Acquire) == 0 {
                return;
            }
            ended.await;
        }
    }

    /// Aborts every still-running tracked task.
    fn abort_all(&self) {
        if let Ok(mut handles) = self.handles.lock() {
            for handle in handles.iter() {
                handle.abort();
            }
            handles.retain(|h| !h.is_finished());
        }
    }
}

/// RAII guard decrementing [`Tasks::running`] even on abort or panic.
struct Running(&'static Tasks);

impl Running {
    fn new(tasks: &'static Tasks) -> Self {
        tasks.running.fetch_add(1, Ordering::AcqRel);
        Self(tasks)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.0.running.fetch_sub(1, Ordering::AcqRel);
        self.0.idle.notify_waiters();
    }
}

/// Waits at most `stopping` for all tracked `tasks` to exit, aborts remaining
/// stragglers with a `200 ms` unwind window, and then awaits `release`
/// (`totaldrop_core::portmap::released`, self-bounded to `1.6 s`).
///
/// Returns `true` if every task finished voluntarily before `stopping` elapsed.
pub(crate) async fn finish(
    tasks: &Tasks,
    release: impl Future<Output = ()>,
    stopping: Duration,
) -> bool {
    let ended = tokio::time::timeout(stopping, tasks.idle()).await.is_ok();
    if !ended {
        tasks.abort_all();
        let _ = tokio::time::timeout(ABORTED, tasks.idle()).await;
    }
    release.await;
    ended
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use super::{Tasks, finish};

    fn test_runtime() -> Result<tokio::runtime::Runtime, std::io::Error> {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
    }

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn finish_waits_for_voluntary_stop_before_release() -> Result<(), std::io::Error> {
        static TASKS: Tasks = Tasks::new();
        let rt = test_runtime()?;
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropFlag(Arc::clone(&dropped));
        TASKS.spawn(&rt, async move {
            let _guard = guard;
            tokio::time::sleep(Duration::from_millis(25)).await;
        });

        let seen_dropped = Arc::new(AtomicBool::new(false));
        let d = Arc::clone(&dropped);
        let s = Arc::clone(&seen_dropped);
        let ended = rt.block_on(finish(
            &TASKS,
            async move {
                s.store(d.load(Ordering::SeqCst), Ordering::SeqCst);
            },
            Duration::from_secs(1),
        ));
        assert!(ended);
        assert!(seen_dropped.load(Ordering::SeqCst));
        Ok(())
    }

    #[test]
    fn finish_aborts_stalled_task_within_bound_before_release() -> Result<(), std::io::Error> {
        static TASKS: Tasks = Tasks::new();
        let rt = test_runtime()?;
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropFlag(Arc::clone(&dropped));
        TASKS.spawn(&rt, async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });

        let started = Instant::now();
        let seen_dropped = Arc::new(AtomicBool::new(false));
        let d = Arc::clone(&dropped);
        let s = Arc::clone(&seen_dropped);
        let ended = rt.block_on(finish(
            &TASKS,
            async move {
                s.store(d.load(Ordering::SeqCst), Ordering::SeqCst);
            },
            Duration::from_millis(50),
        ));
        assert!(!ended);
        assert!(seen_dropped.load(Ordering::SeqCst));
        assert!(started.elapsed() < Duration::from_secs(1));
        Ok(())
    }
}
