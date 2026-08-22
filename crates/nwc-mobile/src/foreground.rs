use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::time::Duration;

use crate::{QueueReason, RejectionCode, RetryReason, WakeDisposition};

/// Default number of foreground retries after the first execution attempt.
pub const DEFAULT_FOREGROUND_WAKE_RETRY_ATTEMPTS: u8 = 5;

/// Default delay used for the first application-owned queued retry.
pub const DEFAULT_FOREGROUND_WAKE_RETRY_BASE_DELAY: Duration = Duration::from_secs(2);

/// Bounded retry policy for application-owned wake execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForegroundWakePolicy {
    maximum_retry_attempts: u8,
    queued_retry_base_delay: Duration,
}

impl ForegroundWakePolicy {
    /// Creates a policy when both the retry count and base delay are positive.
    #[must_use]
    pub const fn new(
        maximum_retry_attempts: u8,
        queued_retry_base_delay: Duration,
    ) -> Option<Self> {
        if maximum_retry_attempts == 0 || queued_retry_base_delay.is_zero() {
            return None;
        }
        Some(Self {
            maximum_retry_attempts,
            queued_retry_base_delay,
        })
    }

    /// Returns the number of retries allowed after the first attempt.
    #[must_use]
    pub const fn maximum_retry_attempts(self) -> u8 {
        self.maximum_retry_attempts
    }

    /// Returns the delay used for the first application-owned queued retry.
    #[must_use]
    pub const fn queued_retry_base_delay(self) -> Duration {
        self.queued_retry_base_delay
    }
}

impl Default for ForegroundWakePolicy {
    fn default() -> Self {
        Self {
            maximum_retry_attempts: DEFAULT_FOREGROUND_WAKE_RETRY_ATTEMPTS,
            queued_retry_base_delay: DEFAULT_FOREGROUND_WAKE_RETRY_BASE_DELAY,
        }
    }
}

/// Stable terminal classification for an application-owned wake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ForegroundWakeOutcome {
    /// The request completed and its response reached a durable terminal state.
    Completed,
    /// Another process already owned or completed the request.
    AlreadyProcessed,
    /// The request failed a non-retriable security or authorization check.
    Rejected(RejectionCode),
    /// The bounded foreground retry allowance was exhausted.
    RetryExhausted,
}

/// Stable classification for a scheduled foreground retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ForegroundWakeRetryCause {
    /// The engine selected a retry delay for a transient failure.
    Engine(RetryReason),
    /// The engine handed durable work to the containing application.
    QueuedForApplication(QueueReason),
}

/// The application action selected after one engine execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ForegroundWakeDecision {
    /// Remove the request from the application queue and retain terminal history.
    Finished(ForegroundWakeOutcome),
    /// Keep the request owned until the selected retry delay has elapsed.
    Retry {
        /// Delay before the request becomes eligible to execute again.
        delay: Duration,
        /// Non-sensitive reason for the retry.
        cause: ForegroundWakeRetryCause,
    },
}

/// Tracks process-local ownership and bounded retries for foreground wake work.
///
/// Durable idempotency remains the responsibility of [`crate::WakeLedger`].
/// This coordinator only prevents duplicate application tasks and consistently
/// maps engine dispositions to the next application action. Identifiers are
/// treated as opaque keys and are never formatted or logged.
pub struct ForegroundWakeCoordinator<K> {
    in_flight: HashSet<K>,
    retry_attempts: HashMap<K, u8>,
    policy: ForegroundWakePolicy,
}

impl<K> Default for ForegroundWakeCoordinator<K> {
    fn default() -> Self {
        Self {
            in_flight: HashSet::new(),
            retry_attempts: HashMap::new(),
            policy: ForegroundWakePolicy::default(),
        }
    }
}

impl<K> ForegroundWakeCoordinator<K>
where
    K: Clone + Eq + Hash,
{
    /// Creates an empty coordinator with an explicit retry policy.
    #[must_use]
    pub fn new(policy: ForegroundWakePolicy) -> Self {
        Self {
            policy,
            ..Self::default()
        }
    }

    /// Claims process-local ownership. Returns `false` for a duplicate task.
    pub fn begin(&mut self, identifier: K) -> bool {
        self.in_flight.insert(identifier)
    }

    /// Returns whether the application currently owns a task for this wake.
    #[must_use]
    pub fn is_in_flight(&self, identifier: &K) -> bool {
        self.in_flight.contains(identifier)
    }

    /// Returns the retries already scheduled for this wake.
    #[must_use]
    pub fn retry_attempts(&self, identifier: &K) -> u8 {
        self.retry_attempts.get(identifier).copied().unwrap_or(0)
    }

    /// Releases process-local ownership when a scheduled retry becomes due.
    ///
    /// The attempt counter remains intact so repeated transient failures cannot
    /// reset the retry allowance.
    pub fn retry_due(&mut self, identifier: &K) -> bool {
        self.in_flight.remove(identifier)
    }

    /// Forgets all process-local state after terminal completion or host failure.
    pub fn forget(&mut self, identifier: &K) {
        self.in_flight.remove(identifier);
        self.retry_attempts.remove(identifier);
    }

    /// Clears process-local state when the wallet session changes.
    pub fn reset(&mut self) {
        self.in_flight.clear();
        self.retry_attempts.clear();
    }

    /// Maps an engine disposition to one bounded application action.
    pub fn handle_disposition(
        &mut self,
        identifier: &K,
        disposition: WakeDisposition,
    ) -> ForegroundWakeDecision {
        match disposition {
            WakeDisposition::Completed { .. } => {
                self.finish(identifier, ForegroundWakeOutcome::Completed)
            }
            WakeDisposition::AlreadyProcessed { .. } => {
                self.finish(identifier, ForegroundWakeOutcome::AlreadyProcessed)
            }
            WakeDisposition::Rejected { code, .. } => {
                self.finish(identifier, ForegroundWakeOutcome::Rejected(code))
            }
            WakeDisposition::RetryAfter { delay, reason, .. } => {
                self.retry(identifier, delay, ForegroundWakeRetryCause::Engine(reason))
            }
            WakeDisposition::QueuedForApplication { reason, .. } => {
                let attempt = self.next_attempt(identifier);
                match attempt {
                    Some(attempt) => ForegroundWakeDecision::Retry {
                        delay: queued_retry_delay(self.policy, attempt),
                        cause: ForegroundWakeRetryCause::QueuedForApplication(reason),
                    },
                    None => self.finish(identifier, ForegroundWakeOutcome::RetryExhausted),
                }
            }
        }
    }

    fn retry(
        &mut self,
        identifier: &K,
        delay: Duration,
        cause: ForegroundWakeRetryCause,
    ) -> ForegroundWakeDecision {
        match self.next_attempt(identifier) {
            Some(_) => ForegroundWakeDecision::Retry { delay, cause },
            None => self.finish(identifier, ForegroundWakeOutcome::RetryExhausted),
        }
    }

    fn next_attempt(&mut self, identifier: &K) -> Option<u8> {
        let attempt = self.retry_attempts.entry(identifier.clone()).or_default();
        if *attempt >= self.policy.maximum_retry_attempts {
            None
        } else {
            *attempt += 1;
            Some(*attempt)
        }
    }

    fn finish(&mut self, identifier: &K, outcome: ForegroundWakeOutcome) -> ForegroundWakeDecision {
        self.forget(identifier);
        ForegroundWakeDecision::Finished(outcome)
    }
}

fn queued_retry_delay(policy: ForegroundWakePolicy, attempt: u8) -> Duration {
    let exponent = u32::from(attempt.saturating_sub(1));
    let multiplier = 2_u32.saturating_pow(exponent);
    policy.queued_retry_base_delay.saturating_mul(multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NotificationHint;

    #[test]
    fn duplicate_claims_are_suppressed_until_retry_is_due() {
        let mut coordinator = ForegroundWakeCoordinator::default();
        let event = "event".to_string();

        assert!(coordinator.begin(event.clone()));
        assert!(!coordinator.begin(event.clone()));
        assert!(coordinator.retry_due(&event));
        assert!(coordinator.begin(event));
    }

    #[test]
    fn queued_retries_back_off_and_exhaust_without_resetting_ownership() {
        let policy = ForegroundWakePolicy::new(3, Duration::from_secs(2)).expect("policy");
        let mut coordinator = ForegroundWakeCoordinator::new(policy);
        let event = "event".to_string();
        coordinator.begin(event.clone());

        for expected_delay in [2, 4, 8] {
            let decision = coordinator.handle_disposition(
                &event,
                WakeDisposition::QueuedForApplication {
                    reason: QueueReason::WalletUnavailable,
                    notification: NotificationHint::OpenApplication,
                },
            );
            assert_eq!(
                decision,
                ForegroundWakeDecision::Retry {
                    delay: Duration::from_secs(expected_delay),
                    cause: ForegroundWakeRetryCause::QueuedForApplication(
                        QueueReason::WalletUnavailable
                    ),
                }
            );
            assert!(coordinator.is_in_flight(&event));
        }

        assert_eq!(
            coordinator.handle_disposition(
                &event,
                WakeDisposition::QueuedForApplication {
                    reason: QueueReason::WalletUnavailable,
                    notification: NotificationHint::OpenApplication,
                },
            ),
            ForegroundWakeDecision::Finished(ForegroundWakeOutcome::RetryExhausted)
        );
        assert!(!coordinator.is_in_flight(&event));
        assert_eq!(coordinator.retry_attempts(&event), 0);
    }

    #[test]
    fn engine_retry_delay_is_preserved_and_bounded() {
        let policy = ForegroundWakePolicy::new(1, Duration::from_secs(1)).expect("policy");
        let mut coordinator = ForegroundWakeCoordinator::new(policy);
        let event = "event";
        coordinator.begin(event);
        let retry = WakeDisposition::RetryAfter {
            delay: Duration::from_secs(17),
            reason: RetryReason::RelayUnavailable,
            notification: NotificationHint::Processing,
        };

        assert_eq!(
            coordinator.handle_disposition(&event, retry),
            ForegroundWakeDecision::Retry {
                delay: Duration::from_secs(17),
                cause: ForegroundWakeRetryCause::Engine(RetryReason::RelayUnavailable),
            }
        );
        assert_eq!(
            coordinator.handle_disposition(&event, retry),
            ForegroundWakeDecision::Finished(ForegroundWakeOutcome::RetryExhausted)
        );
    }

    #[test]
    fn terminal_dispositions_clear_all_process_local_state() {
        let cases = [
            (
                WakeDisposition::Completed {
                    notification: NotificationHint::Completed,
                },
                ForegroundWakeOutcome::Completed,
            ),
            (
                WakeDisposition::AlreadyProcessed {
                    notification: NotificationHint::Completed,
                },
                ForegroundWakeOutcome::AlreadyProcessed,
            ),
            (
                WakeDisposition::Rejected {
                    code: RejectionCode::InvalidEvent,
                    notification: NotificationHint::OpenApplication,
                },
                ForegroundWakeOutcome::Rejected(RejectionCode::InvalidEvent),
            ),
        ];

        for (disposition, expected) in cases {
            let mut coordinator = ForegroundWakeCoordinator::default();
            let event = "event";
            coordinator.begin(event);
            assert_eq!(
                coordinator.handle_disposition(&event, disposition),
                ForegroundWakeDecision::Finished(expected)
            );
            assert!(!coordinator.is_in_flight(&event));
            assert_eq!(coordinator.retry_attempts(&event), 0);
        }
    }

    #[test]
    fn reset_and_forget_clear_attempt_state() {
        let mut coordinator = ForegroundWakeCoordinator::default();
        coordinator.begin("first");
        coordinator.handle_disposition(
            &"first",
            WakeDisposition::RetryAfter {
                delay: Duration::from_secs(1),
                reason: RetryReason::WalletUnavailable,
                notification: NotificationHint::Processing,
            },
        );
        coordinator.forget(&"first");
        assert_eq!(coordinator.retry_attempts(&"first"), 0);

        coordinator.begin("second");
        coordinator.reset();
        assert!(!coordinator.is_in_flight(&"second"));
    }

    #[test]
    fn policy_rejects_unbounded_spin_configuration() {
        assert!(ForegroundWakePolicy::new(0, Duration::from_secs(1)).is_none());
        assert!(ForegroundWakePolicy::new(1, Duration::ZERO).is_none());
    }
}
