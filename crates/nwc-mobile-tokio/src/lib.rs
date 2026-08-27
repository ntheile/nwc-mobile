//! Tokio deadline and cancellation enforcement for `nwc-mobile` hosts.
//!
//! The core engine remains runtime-independent. Tokio-based wallet and relay
//! adapters can use this crate to enforce every [`OperationContext`] with the
//! same fail-closed behavior.

#![forbid(unsafe_code)]

mod mobile;
mod node;

pub use mobile::{
    LightningNodeProvider, LightningNodeRequest, NwcMobile, NwcMobileCompletionContext,
    NwcMobileCompletionHandler, NwcMobileConfig, NwcMobileSettlementStatus, NwcMobileWakeKind,
    NwcMobileWakeResult, OpenedLightningNode, DEFAULT_NWC_MOBILE_COMPLETION_RESERVE,
};
pub use node::{NwcNode, NwcNodeConfig, DEFAULT_INVOICE_SETTLEMENT_POLL_INTERVAL};

use std::future::Future;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use nwc_mobile::{
    CancellationSignal, HostError, HostErrorKind, OperationBudget, OperationContext, QueueReason,
    WakeDisposition,
};

const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_RESOLVED_SOCKET_ADDRESSES: usize = 16;
const NATIVE_RUNTIME_THREAD_NAME: &str = "nwc-mobile-native";

static NATIVE_RUNTIME_HANDLE: OnceLock<Option<tokio::runtime::Handle>> = OnceLock::new();

/// Tokio task handle that aborts the task when its owner is dropped.
pub struct AbortTaskOnDrop<T> {
    handle: Option<tokio::task::JoinHandle<T>>,
}

impl<T> Drop for AbortTaskOnDrop<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// Spawns an independently scheduled Tokio task with scoped abort-on-drop ownership.
///
/// Returns an internal host error when called outside a Tokio runtime instead
/// of allowing `tokio::spawn` to panic.
pub fn spawn_abort_on_drop<F, T>(operation: F) -> Result<AbortTaskOnDrop<T>, HostError>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let runtime =
        tokio::runtime::Handle::try_current().map_err(|_| host_error(HostErrorKind::Internal))?;
    Ok(AbortTaskOnDrop {
        handle: Some(runtime.spawn(operation)),
    })
}

/// Executes a Tokio-backed future for a native host that has no Tokio runtime.
///
/// Rust async entry points called by Swift or Kotlin can await the returned
/// future directly. The operation itself runs on one process-wide runtime
/// thread, so native entry points do not need to create a runtime or rely on the
/// caller's executor. Dropping this future aborts the spawned operation. Runtime
/// startup and task failures are returned as non-sensitive host errors.
pub async fn run_on_native_runtime<F, T>(operation: F) -> Result<T, HostError>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let handle = native_runtime_handle().ok_or_else(|| host_error(HostErrorKind::Internal))?;
    let mut task = AbortTaskOnDrop {
        handle: Some(handle.spawn(operation)),
    };
    let result = task
        .handle
        .as_mut()
        .ok_or_else(|| host_error(HostErrorKind::Internal))?
        .await
        .map_err(|_| host_error(HostErrorKind::Internal));
    task.handle.take();
    result
}

fn native_runtime_handle() -> Option<&'static tokio::runtime::Handle> {
    NATIVE_RUNTIME_HANDLE
        .get_or_init(|| {
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            std::thread::Builder::new()
                .name(NATIVE_RUNTIME_THREAD_NAME.to_owned())
                .spawn(move || {
                    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    else {
                        let _ = sender.send(None);
                        return;
                    };
                    let handle = runtime.handle().clone();
                    if sender.send(Some(handle)).is_ok() {
                        runtime.block_on(std::future::pending::<()>());
                    }
                })
                .ok()?;
            receiver.recv().ok().flatten()
        })
        .as_ref()
}

/// Resolves a bounded set of socket addresses without blocking the async runtime.
pub async fn resolve_socket_addresses(
    host: String,
    port: u16,
) -> Result<Vec<SocketAddr>, HostError> {
    tokio::task::spawn_blocking(move || {
        let addresses = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|_| host_error(HostErrorKind::Unavailable))?
            .take(MAX_RESOLVED_SOCKET_ADDRESSES)
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            Err(host_error(HostErrorKind::Unavailable))
        } else {
            Ok(addresses)
        }
    })
    .await
    .map_err(|_| host_error(HostErrorKind::Internal))?
}

/// Retries a fallible asynchronous operation with bounded exponential backoff.
///
/// A zero attempt count is normalized to one attempt. The operation's final
/// typed error is returned without logging or stringifying remote diagnostics.
pub async fn retry_with_exponential_backoff<F, Fut, T, E>(
    maximum_attempts: u8,
    base_delay: Duration,
    mut operation: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let maximum_attempts = maximum_attempts.max(1);
    for attempt in 0..maximum_attempts {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(error) if attempt + 1 == maximum_attempts => return Err(error),
            Err(_) => {
                let multiplier = 1_u32.checked_shl(u32::from(attempt)).unwrap_or(u32::MAX);
                tokio::time::sleep(base_delay.saturating_mul(multiplier)).await;
            }
        }
    }
    unreachable!("at least one retry attempt is always executed")
}

/// Suspends the current Tokio task for a monotonic duration.
///
/// Runtime-backed adapters use this instead of depending on Tokio directly for
/// bounded polling intervals.
pub async fn sleep(duration: Duration) {
    tokio::time::sleep(duration).await;
}

/// Monotonic execution window shared by wallet preparation and the wake engine.
#[derive(Clone, Copy, Debug)]
pub struct BackgroundWakeWindow {
    started_at: Instant,
    total: Duration,
}

impl BackgroundWakeWindow {
    /// Returns the time remaining in the complete background execution window.
    #[must_use]
    pub fn remaining(self) -> Duration {
        self.total.saturating_sub(self.started_at.elapsed())
    }

    /// Creates a non-zero engine budget from the remaining background time.
    pub fn operation_budget(self) -> Option<OperationBudget> {
        OperationBudget::new(self.remaining()).ok()
    }
}

/// Runs native wake preparation and execution inside one hard background bound.
///
/// Cancellation or budget exhaustion returns a durable application handoff.
/// The operation receives the original monotonic window so wallet setup time is
/// deducted before it creates the engine's [`OperationBudget`].
pub async fn run_bounded_background_wake<F, Fut>(
    total: Duration,
    cancellation: &dyn CancellationSignal,
    operation: F,
) -> WakeDisposition
where
    F: FnOnce(BackgroundWakeWindow) -> Fut,
    Fut: Future<Output = WakeDisposition>,
{
    if total.is_zero() {
        return WakeDisposition::queued(QueueReason::Deadline);
    }
    if cancellation.is_cancelled() {
        return WakeDisposition::queued(QueueReason::Deadline);
    }
    let window = BackgroundWakeWindow {
        started_at: Instant::now(),
        total,
    };
    match tokio::time::timeout(total, operation(window)).await {
        Ok(disposition) if !cancellation.is_cancelled() => disposition,
        Ok(_) | Err(_) => WakeDisposition::queued(QueueReason::Deadline),
    }
}

/// Runs a host future until it completes, exceeds its budget, or is cancelled.
///
/// Cancellation is biased ahead of the operation when both become ready in the
/// same scheduler turn. A signal that is already cancelled prevents the future
/// from being polled at all.
pub async fn run_with_context<T, F>(
    context: OperationContext<'_>,
    operation: F,
) -> Result<T, HostError>
where
    F: Future<Output = Result<T, HostError>> + Send,
{
    if context.cancellation().is_cancelled() {
        return Err(host_error(HostErrorKind::Cancelled));
    }
    tokio::select! {
        biased;
        () = wait_for_cancellation(context.cancellation()) => {
            Err(host_error(HostErrorKind::Cancelled))
        }
        result = tokio::time::timeout(context.budget().timeout(), operation) => {
            if context.cancellation().is_cancelled() {
                Err(host_error(HostErrorKind::Cancelled))
            } else {
                result.unwrap_or_else(|_| Err(host_error(HostErrorKind::TimedOut)))
            }
        }
    }
}

async fn wait_for_cancellation(cancellation: &dyn CancellationSignal) {
    while !cancellation.is_cancelled() {
        tokio::time::sleep(CANCELLATION_POLL_INTERVAL).await;
    }
}

const fn host_error(kind: HostErrorKind) -> HostError {
    HostError::new(kind)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    use nwc_mobile::{NeverCancelled, OperationBudget};

    use super::*;

    struct ThreadWaker(std::thread::Thread);

    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }

    fn block_on_without_runtime<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::park(),
            }
        }
    }

    #[test]
    fn native_runtime_runs_bounded_wake_for_non_tokio_caller() {
        assert!(tokio::runtime::Handle::try_current().is_err());
        let disposition = block_on_without_runtime(run_on_native_runtime(async {
            run_bounded_background_wake(Duration::from_secs(1), &NeverCancelled, |_| async {
                tokio::time::sleep(Duration::from_millis(1)).await;
                WakeDisposition::Completed {
                    notification: nwc_mobile::NotificationHint::Completed,
                }
            })
            .await
        }))
        .expect("native runtime");

        assert!(matches!(disposition, WakeDisposition::Completed { .. }));
    }

    struct DropSignal(mpsc::SyncSender<()>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[test]
    fn dropping_native_runtime_future_aborts_spawned_operation() {
        let (started_sender, started_receiver) = mpsc::sync_channel(1);
        let (dropped_sender, dropped_receiver) = mpsc::sync_channel(1);
        let mut future = Box::pin(run_on_native_runtime(async move {
            let _drop_signal = DropSignal(dropped_sender);
            let _ = started_sender.send(());
            std::future::pending::<()>().await;
        }));
        let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
        let mut context = Context::from_waker(&waker);

        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        started_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("spawned operation started");
        drop(future);
        dropped_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("spawned operation aborted");
    }

    #[tokio::test]
    async fn dropping_scoped_task_aborts_operation() {
        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = dropped.clone();
        let task = spawn_abort_on_drop(async move {
            let _drop_flag = DropFlag(task_dropped);
            std::future::pending::<()>().await;
        })
        .expect("runtime task");
        tokio::task::yield_now().await;

        drop(task);
        tokio::task::yield_now().await;
        assert!(dropped.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn exponential_retry_returns_success_without_extra_attempts() {
        let attempts = AtomicBool::new(false);
        let result = retry_with_exponential_backoff(3, Duration::ZERO, || async {
            if attempts.swap(true, Ordering::AcqRel) {
                Ok(42)
            } else {
                Err("retry")
            }
        })
        .await;
        assert_eq!(result, Ok(42));
    }

    struct Cancellation(AtomicBool);

    impl Cancellation {
        const fn new(cancelled: bool) -> Self {
            Self(AtomicBool::new(cancelled))
        }

        fn cancel(&self) {
            self.0.store(true, Ordering::Release);
        }
    }

    impl CancellationSignal for Cancellation {
        fn is_cancelled(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
    }

    fn context(cancellation: &dyn CancellationSignal, timeout: Duration) -> OperationContext<'_> {
        OperationContext::new(
            OperationBudget::new(timeout).expect("non-zero budget"),
            cancellation,
        )
    }

    #[tokio::test]
    async fn cancelled_operation_is_never_polled() {
        let cancellation = Cancellation::new(true);
        let polled = AtomicBool::new(false);
        let result = run_with_context(
            context(&cancellation, Duration::from_secs(1)),
            std::future::poll_fn(|_| {
                polled.store(true, Ordering::Release);
                std::task::Poll::Ready(Ok(()))
            }),
        )
        .await;

        assert_eq!(
            result.expect_err("cancelled").kind(),
            HostErrorKind::Cancelled
        );
        assert!(!polled.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn operation_budget_is_enforced() {
        let result = run_with_context(context(&NeverCancelled, Duration::from_millis(1)), async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        })
        .await;

        assert_eq!(result.expect_err("timeout").kind(), HostErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn in_flight_operation_observes_cancellation() {
        let cancellation = Cancellation::new(false);
        let cancel = async {
            tokio::time::sleep(Duration::from_millis(1)).await;
            cancellation.cancel();
        };
        let operation = run_with_context(
            context(&cancellation, Duration::from_secs(1)),
            std::future::pending::<Result<(), HostError>>(),
        );
        let (_, result) = tokio::join!(cancel, operation);

        assert_eq!(
            result.expect_err("cancelled").kind(),
            HostErrorKind::Cancelled
        );
    }

    #[tokio::test]
    async fn operation_completion_rechecks_cancellation() {
        let cancellation = Cancellation::new(false);
        let result = run_with_context(
            context(&cancellation, Duration::from_secs(1)),
            std::future::poll_fn(|_| {
                cancellation.cancel();
                std::task::Poll::Ready(Ok(()))
            }),
        )
        .await;

        assert_eq!(
            result.expect_err("cancelled").kind(),
            HostErrorKind::Cancelled
        );
    }

    #[tokio::test]
    async fn completed_operation_returns_its_result() {
        let result = run_with_context(context(&NeverCancelled, Duration::from_secs(1)), async {
            Ok(42)
        })
        .await;

        assert_eq!(result, Ok(42));
    }

    #[tokio::test]
    async fn bounded_background_wake_accounts_for_preparation_and_timeout() {
        let disposition = run_bounded_background_wake(
            Duration::from_secs(1),
            &NeverCancelled,
            |window| async move {
                assert!(window.operation_budget().is_some());
                WakeDisposition::Completed {
                    notification: nwc_mobile::NotificationHint::Completed,
                }
            },
        )
        .await;
        assert!(matches!(disposition, WakeDisposition::Completed { .. }));

        let disposition =
            run_bounded_background_wake(Duration::from_millis(1), &NeverCancelled, |_| async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                WakeDisposition::Completed {
                    notification: nwc_mobile::NotificationHint::Completed,
                }
            })
            .await;
        assert_eq!(disposition, WakeDisposition::queued(QueueReason::Deadline));
    }

    #[tokio::test]
    async fn bounded_background_wake_does_not_poll_after_cancellation() {
        let cancellation = Cancellation::new(true);
        let polled = AtomicBool::new(false);
        let disposition =
            run_bounded_background_wake(Duration::from_secs(1), &cancellation, |_| async {
                polled.store(true, Ordering::Release);
                WakeDisposition::Completed {
                    notification: nwc_mobile::NotificationHint::Completed,
                }
            })
            .await;

        assert_eq!(disposition, WakeDisposition::queued(QueueReason::Deadline));
        assert!(!polled.load(Ordering::Acquire));
    }
}
