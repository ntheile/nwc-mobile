//! Tokio deadline and cancellation enforcement for `nwc-mobile` hosts.
//!
//! The core engine remains runtime-independent. Tokio-based wallet and relay
//! adapters can use this crate to enforce every [`OperationContext`] with the
//! same fail-closed behavior.

#![forbid(unsafe_code)]

use std::future::Future;
use std::time::{Duration, Instant};

use nwc_mobile::{
    CancellationSignal, HostError, HostErrorKind, OperationBudget, OperationContext, QueueReason,
    WakeDisposition,
};

const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(25);

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

    use nwc_mobile::{NeverCancelled, OperationBudget};

    use super::*;

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
