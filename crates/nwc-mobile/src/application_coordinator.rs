use std::fmt;

/// Native action selected when an approved NWA request has an optional callback.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NwaCallbackBegin {
    /// The authorization flow is complete without opening another application.
    Complete,
    /// Ask the platform to open this already-validated public callback URL.
    OpenUrl(String),
}

/// Native state transition after a callback-open attempt finishes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NwaCallbackCompletion {
    /// No callback attempt was pending.
    Ignored,
    /// The callback opened and the application may clear its review state.
    Complete,
    /// The callback failed to open and remains available for an explicit retry.
    RetryAvailable,
}

/// Owns the non-sensitive callback lifecycle after an NWA approval.
///
/// Callers must only supply callback URLs returned by the validated NWA approval
/// workflow. The coordinator deliberately does not parse arbitrary native URLs.
#[derive(Default)]
pub struct NwaCallbackCoordinator {
    pending_url: Option<String>,
}

impl NwaCallbackCoordinator {
    /// Starts the callback lifecycle for one approved request.
    pub fn begin(&mut self, callback_url: Option<String>) -> NwaCallbackBegin {
        self.pending_url = callback_url;
        match self.pending_url.clone() {
            Some(url) => NwaCallbackBegin::OpenUrl(url),
            None => NwaCallbackBegin::Complete,
        }
    }

    /// Returns the validated callback URL while a retry remains available.
    #[must_use]
    pub fn retry_url(&self) -> Option<String> {
        self.pending_url.clone()
    }

    /// Applies the result of the platform URL-open capability.
    pub fn complete_open(&mut self, opened: bool) -> NwaCallbackCompletion {
        if self.pending_url.is_none() {
            return NwaCallbackCompletion::Ignored;
        }
        if opened {
            self.pending_url = None;
            NwaCallbackCompletion::Complete
        } else {
            NwaCallbackCompletion::RetryAvailable
        }
    }

    /// Cancels or clears all process-local callback state.
    pub fn clear(&mut self) {
        self.pending_url = None;
    }

    /// Returns whether a callback is awaiting its first open or a retry.
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        self.pending_url.is_some()
    }
}

impl fmt::Debug for NwaCallbackCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NwaCallbackCoordinator")
            .field("is_pending", &self.is_pending())
            .finish()
    }
}

/// Preparation required before starting one application registration pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ApplicationRegistrationBegin {
    /// Another pass already owns process-local execution.
    Busy,
    /// The host must durably refresh desired registration state, then call `begin` again.
    RefreshRequired,
    /// The host may start one worker pass.
    Ready,
}

/// Non-sensitive result supplied after one application registration worker pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ApplicationRegistrationPass {
    applied: usize,
    deferred: usize,
    next_attempt_at: Option<u64>,
    failed: bool,
}

impl ApplicationRegistrationPass {
    /// Creates a successful worker result.
    #[must_use]
    pub const fn completed(applied: usize, deferred: usize, next_attempt_at: Option<u64>) -> Self {
        Self {
            applied,
            deferred,
            next_attempt_at,
            failed: false,
        }
    }

    /// Creates a failed worker result whose details remain private to the host logs.
    #[must_use]
    pub const fn failed() -> Self {
        Self {
            applied: 0,
            deferred: 0,
            next_attempt_at: None,
            failed: true,
        }
    }
}

/// Application action selected after a registration pass completes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ApplicationRegistrationCompletion {
    /// No pass was active, so the stale completion was ignored.
    Ignored,
    /// Configuration changed during the pass; immediately reconcile again.
    RunAgain,
    /// The pass failed before returning a durable worker report.
    Failed {
        /// Host timestamp for the bounded fallback retry.
        retry_at: u64,
    },
    /// Provider work was durably deferred.
    Deferred {
        /// Durable worker retry timestamp, when one is available.
        retry_at: Option<u64>,
    },
    /// At least one desired registration was applied.
    Applied {
        /// Number of desired registration changes durably acknowledged.
        applied: usize,
        /// Next durable worker retry timestamp, when more work may remain.
        retry_at: Option<u64>,
    },
    /// No visible status changed; an optional future pass may still be due.
    Idle {
        /// Next durable worker retry timestamp, when more work may remain.
        retry_at: Option<u64>,
    },
}

/// Owns process-local registration refresh, pass, and retry coordination.
///
/// Durable desired state and retry timestamps remain in the shared ledger. This
/// coordinator only prevents overlapping application tasks and rejects stale
/// timer callbacks.
#[derive(Debug, Default)]
pub struct ApplicationRegistrationCoordinator {
    in_flight: bool,
    refresh_pending: bool,
    retry_token: u64,
}

impl ApplicationRegistrationCoordinator {
    /// Marks durable desired registration state for refresh before another pass.
    pub fn mark_refresh_pending(&mut self) {
        self.refresh_pending = true;
    }

    /// Returns whether persistence should retain a pending refresh marker.
    #[must_use]
    pub const fn is_refresh_pending(&self) -> bool {
        self.refresh_pending
    }

    /// Clears the refresh marker only after the durable refresh succeeds.
    pub fn complete_refresh(&mut self) {
        self.refresh_pending = false;
    }

    /// Attempts to claim one process-local worker pass.
    pub fn begin(&mut self) -> ApplicationRegistrationBegin {
        if self.in_flight {
            return ApplicationRegistrationBegin::Busy;
        }
        if self.refresh_pending {
            return ApplicationRegistrationBegin::RefreshRequired;
        }
        self.retry_token = self.retry_token.wrapping_add(1);
        self.in_flight = true;
        ApplicationRegistrationBegin::Ready
    }

    /// Maps one worker result to the next application action.
    pub fn finish(
        &mut self,
        pass: ApplicationRegistrationPass,
        now: u64,
    ) -> ApplicationRegistrationCompletion {
        if !self.in_flight {
            return ApplicationRegistrationCompletion::Ignored;
        }
        self.in_flight = false;
        if self.refresh_pending {
            return ApplicationRegistrationCompletion::RunAgain;
        }
        if pass.failed {
            return ApplicationRegistrationCompletion::Failed {
                retry_at: now.saturating_add(30),
            };
        }
        if pass.deferred > 0 {
            return ApplicationRegistrationCompletion::Deferred {
                retry_at: pass.next_attempt_at,
            };
        }
        if pass.applied > 0 {
            return ApplicationRegistrationCompletion::Applied {
                applied: pass.applied,
                retry_at: pass.next_attempt_at,
            };
        }
        ApplicationRegistrationCompletion::Idle {
            retry_at: pass.next_attempt_at,
        }
    }

    /// Invalidates older timers and returns the token for a newly scheduled retry.
    pub fn schedule_retry(&mut self) -> u64 {
        self.retry_token = self.retry_token.wrapping_add(1);
        self.retry_token
    }

    /// Returns whether a timer still represents the latest requested retry.
    #[must_use]
    pub const fn retry_is_current(&self, token: u64) -> bool {
        token == self.retry_token
    }

    /// Clears all process-local coordination when the containing session resets.
    pub fn reset(&mut self) {
        self.in_flight = false;
        self.refresh_pending = false;
        self.retry_token = self.retry_token.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_failure_remains_retryable_until_success_or_clear() {
        let mut coordinator = NwaCallbackCoordinator::default();
        assert_eq!(
            coordinator.begin(Some("https://app.example/callback".to_owned())),
            NwaCallbackBegin::OpenUrl("https://app.example/callback".to_owned())
        );
        assert_eq!(
            coordinator.complete_open(false),
            NwaCallbackCompletion::RetryAvailable
        );
        assert_eq!(
            coordinator.retry_url().as_deref(),
            Some("https://app.example/callback")
        );
        assert_eq!(
            coordinator.complete_open(true),
            NwaCallbackCompletion::Complete
        );
        assert!(!coordinator.is_pending());
    }

    #[test]
    fn callback_without_url_completes_without_platform_work() {
        let mut coordinator = NwaCallbackCoordinator::default();
        assert_eq!(coordinator.begin(None), NwaCallbackBegin::Complete);
        assert_eq!(
            coordinator.complete_open(true),
            NwaCallbackCompletion::Ignored
        );
    }

    #[test]
    fn registration_refresh_and_in_flight_passes_are_serialized() {
        let mut coordinator = ApplicationRegistrationCoordinator::default();
        coordinator.mark_refresh_pending();
        assert_eq!(
            coordinator.begin(),
            ApplicationRegistrationBegin::RefreshRequired
        );
        coordinator.complete_refresh();
        assert_eq!(coordinator.begin(), ApplicationRegistrationBegin::Ready);
        assert_eq!(coordinator.begin(), ApplicationRegistrationBegin::Busy);
        assert_eq!(
            coordinator.finish(ApplicationRegistrationPass::completed(2, 0, Some(500)), 100,),
            ApplicationRegistrationCompletion::Applied {
                applied: 2,
                retry_at: Some(500),
            }
        );
    }

    #[test]
    fn configuration_change_during_pass_runs_again_before_reporting_results() {
        let mut coordinator = ApplicationRegistrationCoordinator::default();
        assert_eq!(coordinator.begin(), ApplicationRegistrationBegin::Ready);
        coordinator.mark_refresh_pending();
        assert_eq!(
            coordinator.finish(ApplicationRegistrationPass::completed(1, 0, None), 100),
            ApplicationRegistrationCompletion::RunAgain
        );
    }

    #[test]
    fn failed_and_deferred_passes_preserve_bounded_retry_times() {
        let mut coordinator = ApplicationRegistrationCoordinator::default();
        assert_eq!(coordinator.begin(), ApplicationRegistrationBegin::Ready);
        assert_eq!(
            coordinator.finish(ApplicationRegistrationPass::failed(), u64::MAX - 10),
            ApplicationRegistrationCompletion::Failed { retry_at: u64::MAX }
        );
        assert_eq!(coordinator.begin(), ApplicationRegistrationBegin::Ready);
        assert_eq!(
            coordinator.finish(ApplicationRegistrationPass::completed(0, 1, Some(250)), 100,),
            ApplicationRegistrationCompletion::Deferred {
                retry_at: Some(250),
            }
        );
    }

    #[test]
    fn newer_retry_tokens_reject_stale_timers() {
        let mut coordinator = ApplicationRegistrationCoordinator::default();
        let first = coordinator.schedule_retry();
        let second = coordinator.schedule_retry();
        assert!(!coordinator.retry_is_current(first));
        assert!(coordinator.retry_is_current(second));
    }
}
