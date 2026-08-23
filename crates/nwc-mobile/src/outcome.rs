use std::time::Duration;

use crate::NwcMethod;

/// A native notification presentation category.
///
/// Hosts map this value to localized, generic text. It never contains remote
/// server or payment content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NotificationHint {
    /// Work is queued or still in progress.
    Processing,
    /// The request completed without requiring user attention.
    Completed,
    /// A validated NIP-47 request completed without requiring user attention.
    ///
    /// Native hosts use only the typed method to select static, localized copy.
    /// No request parameters or wallet response values cross this boundary.
    Request {
        /// The completed NIP-47 method.
        method: NwcMethod,
    },
    /// The containing application should be opened to continue safely.
    OpenApplication,
}

/// Why work was durably handed to the containing application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QueueReason {
    /// The platform background deadline is too close.
    Deadline,
    /// Secure storage is unavailable in the current execution context.
    SecureStorageUnavailable,
    /// The wallet backend cannot be opened safely in this context.
    WalletUnavailable,
    /// The request method is not supported by the background adapter.
    UnsupportedInBackground,
    /// The durable ledger cannot be acquired within the background budget.
    LedgerBusy,
}

/// Why an operation may be retried without changing authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RetryReason {
    /// A relay could not be reached within the current attempt budget.
    RelayUnavailable,
    /// A wallet capability or ambiguous payment state was temporarily unavailable.
    WalletUnavailable,
    /// Publishing a response failed after the result was persisted.
    ResponsePublishFailed,
    /// A response could not be committed before its claim was lost.
    ResponsePersistenceFailed,
    /// A wake-provider registration operation failed transiently.
    RegistrationUnavailable,
}

/// A stable, non-sensitive reason for rejecting a wake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RejectionCode {
    /// The platform payload is malformed or exceeds policy bounds.
    InvalidWakePayload,
    /// The referenced connection does not exist or has been revoked.
    ConnectionUnavailable,
    /// The relay is not an approved destination for the connection.
    RelayNotAllowed,
    /// The fetched or embedded event does not match the wake envelope.
    EventMismatch,
    /// The event signature or recipient is invalid.
    InvalidEvent,
    /// The decrypted NIP-47 request is malformed or unsupported.
    InvalidRequest,
    /// The event is too old or too far in the future.
    EventOutsideFreshnessWindow,
    /// The client is not authorized to call the requested method.
    MethodNotAllowed,
    /// The request would exceed the connection budget.
    BudgetExceeded,
}

/// The platform-neutral result of ingesting or executing a wake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WakeDisposition {
    /// The request reached a durable terminal state.
    Completed {
        /// Generic notification presentation guidance.
        notification: NotificationHint,
    },
    /// Another execution context already owns or completed this event.
    AlreadyProcessed {
        /// Generic notification presentation guidance.
        notification: NotificationHint,
    },
    /// The request was persisted for the containing application.
    QueuedForApplication {
        /// Why execution was handed off.
        reason: QueueReason,
        /// Generic notification presentation guidance.
        notification: NotificationHint,
    },
    /// The durable operation may be attempted again later.
    RetryAfter {
        /// Minimum retry delay selected by policy.
        delay: Duration,
        /// Stable retry classification.
        reason: RetryReason,
        /// Generic notification presentation guidance.
        notification: NotificationHint,
    },
    /// The request failed a non-retriable security or policy check.
    Rejected {
        /// Stable rejection classification.
        code: RejectionCode,
        /// Generic notification presentation guidance.
        notification: NotificationHint,
    },
}

/// Stable high-level classification of an engine disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WakeDispositionKind {
    /// The request reached a durable terminal state.
    Completed,
    /// Another execution context already owns or completed the request.
    AlreadyProcessed,
    /// The containing application must resume the durable request.
    QueuedForApplication,
    /// Native or foreground code may retry after a delay.
    RetryAfter,
    /// The request failed a non-retriable check.
    Rejected,
}

impl WakeDisposition {
    /// Creates a conservative containing-application handoff.
    #[must_use]
    pub const fn queued(reason: QueueReason) -> Self {
        Self::QueuedForApplication {
            reason,
            notification: NotificationHint::OpenApplication,
        }
    }

    /// Creates a conservative invalid-payload rejection.
    #[must_use]
    pub const fn rejected(code: RejectionCode) -> Self {
        Self::Rejected {
            code,
            notification: NotificationHint::OpenApplication,
        }
    }

    /// Returns the stable high-level classification.
    #[must_use]
    pub const fn kind(self) -> WakeDispositionKind {
        match self {
            Self::Completed { .. } => WakeDispositionKind::Completed,
            Self::AlreadyProcessed { .. } => WakeDispositionKind::AlreadyProcessed,
            Self::QueuedForApplication { .. } => WakeDispositionKind::QueuedForApplication,
            Self::RetryAfter { .. } => WakeDispositionKind::RetryAfter,
            Self::Rejected { .. } => WakeDispositionKind::Rejected,
        }
    }

    /// Returns generic presentation guidance without exposing result details.
    #[must_use]
    pub const fn notification(self) -> NotificationHint {
        match self {
            Self::Completed { notification }
            | Self::AlreadyProcessed { notification }
            | Self::QueuedForApplication { notification, .. }
            | Self::RetryAfter { notification, .. }
            | Self::Rejected { notification, .. } => notification,
        }
    }
}
