//! Stable, non-sensitive UniFFI lifecycle types for native mobile adapters.
//!
//! This crate validates the untrusted push envelope before it reaches the core
//! engine and translates engine outcomes into a closed Swift/Kotlin contract.
//! Wallet secrets, decrypted requests, invoices, and remote error text are
//! deliberately absent from this interface.

#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use nwc_mobile::{
    BackgroundBudget, NotificationHint, QueueReason, RejectionCode, RetryReason, WakeDisposition,
    WakeEnvelope, WakeEnvelopeError, WakeInput,
};

mod host_bridge;
mod mobile_engine;

pub use host_bridge::{
    MobileCancellation, MobileCreatedInvoice, MobileHostError, MobileInvoiceLookup,
    MobileListTransactionsRequest, MobileMakeInvoiceRequest, MobileNwcMethod,
    MobilePayInvoiceRequest, MobilePaymentFailure, MobilePaymentQuote, MobilePaymentStatus,
    MobileRelayTransport, MobileSecretProvider, MobileTransactionDirection,
    MobileWakeRegistrationChange, MobileWakeRegistrationTransport, MobileWalletBackend,
    MobileWalletInfo, MobileWalletTransaction,
};
pub use mobile_engine::{
    MobileBudgetInterval, MobileConnectionRequest, MobileConnectionState, MobileEngineError,
    MobileFeePolicy, MobileNwcEncryption, MobileNwcEngine, MobilePaymentReconciliationReport,
    MobileWakeRegistrationReport,
};

uniffi::setup_scaffolding!();

/// Untrusted platform fields decoded from an APNs or FCM notification.
///
/// Native adapters should pass strings through without logging them. Validation
/// and canonicalization happen in [`validate_wake_envelope`].
#[derive(Clone, Eq, PartialEq, uniffi::Record)]
pub struct MobileWakeEnvelope {
    /// Secure relay URL selected by the wake provider.
    pub relay_url: String,
    /// Lower- or uppercase hexadecimal Nostr event identifier.
    pub event_id_hex: String,
    /// Hexadecimal public key for the expected wallet service.
    pub wallet_service_public_key_hex: String,
    /// Optional serialized Nostr request event included by the provider.
    pub embedded_event_json: Option<String>,
    /// Whole seconds since the Unix epoch when the native adapter received it.
    pub received_at_seconds: u64,
}

impl fmt::Debug for MobileWakeEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MobileWakeEnvelope")
            .field("relay_url", &"[redacted]")
            .field("event_id_hex", &"[redacted]")
            .field("wallet_service_public_key_hex", &"[redacted]")
            .field("has_embedded_event", &self.embedded_event_json.is_some())
            .field("received_at_seconds", &self.received_at_seconds)
            .finish()
    }
}

/// A stable failure classification safe to surface to native lifecycle code.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Error)]
pub enum MobileWakeContractError {
    /// The relay was malformed, oversized, or did not use secure WebSockets.
    InvalidRelay,
    /// The event identifier did not encode exactly 32 bytes of hexadecimal.
    InvalidEventId,
    /// The wallet-service key did not encode exactly 32 bytes of hexadecimal.
    InvalidWalletServicePublicKey,
    /// The optional serialized event exceeded the FFI payload bound.
    EmbeddedEventTooLarge,
    /// The platform window did not leave a positive cleanup reserve.
    InvalidBackgroundWindow,
}

impl fmt::Display for MobileWakeContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRelay => "wake relay is invalid or insecure",
            Self::InvalidEventId => "wake event id is invalid",
            Self::InvalidWalletServicePublicKey => "wallet service public key is invalid",
            Self::EmbeddedEventTooLarge => "embedded wake event exceeds the payload limit",
            Self::InvalidBackgroundWindow => "background window does not leave cleanup time",
        })
    }
}

impl std::error::Error for MobileWakeContractError {}

/// A push envelope whose basic sizes and domain encodings have been checked.
///
/// This is an opaque object so native code cannot mutate validated values before
/// a later engine call. Full connection, signature, recipient, and freshness
/// validation still occurs in `nwc-mobile` before decryption or side effects.
#[derive(Debug, uniffi::Object)]
pub struct ValidatedMobileWake {
    input: WakeInput,
}

#[uniffi::export]
impl ValidatedMobileWake {
    /// Returns the canonical lowercase request event id for native dedup metrics.
    pub fn event_id_hex(&self) -> String {
        self.input.event_id().to_hex()
    }

    /// Returns whether the provider embedded a serialized request event.
    pub fn has_embedded_event(&self) -> bool {
        self.input.embedded_event_json().is_some()
    }

    /// Returns when native code received the wake.
    pub fn received_at_seconds(&self) -> u64 {
        self.input.received_at().as_secs()
    }
}

impl ValidatedMobileWake {
    /// Returns the core wake input for the engine bridge.
    #[must_use]
    pub fn core_input(&self) -> WakeInput {
        self.input.clone()
    }
}

/// Validates and seals an untrusted native wake envelope.
#[uniffi::export]
pub fn validate_wake_envelope(
    envelope: MobileWakeEnvelope,
) -> Result<Arc<ValidatedMobileWake>, MobileWakeContractError> {
    Ok(Arc::new(ValidatedMobileWake {
        input: WakeEnvelope::new(
            envelope.relay_url,
            envelope.event_id_hex,
            envelope.wallet_service_public_key_hex,
            envelope.embedded_event_json,
            envelope.received_at_seconds,
        )
        .validate()
        .map_err(MobileWakeContractError::from)?,
    }))
}

impl From<WakeEnvelopeError> for MobileWakeContractError {
    fn from(error: WakeEnvelopeError) -> Self {
        match error {
            WakeEnvelopeError::InvalidRelay => Self::InvalidRelay,
            WakeEnvelopeError::InvalidEventId => Self::InvalidEventId,
            WakeEnvelopeError::InvalidWalletServicePublicKey => Self::InvalidWalletServicePublicKey,
            WakeEnvelopeError::EmbeddedEventTooLarge => Self::EmbeddedEventTooLarge,
            _ => Self::EmbeddedEventTooLarge,
        }
    }
}

/// Native time allocation derived from a complete OS background window.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileExecutionWindow {
    /// Maximum duration available for Rust and host capability execution.
    pub execution_milliseconds: u64,
    /// Duration reserved for checkpointing and invoking the OS completion path.
    pub cleanup_milliseconds: u64,
}

/// Validates a native background window and reserves cleanup time.
#[uniffi::export]
pub fn mobile_execution_window(
    total_milliseconds: u64,
    cleanup_milliseconds: u64,
) -> Result<MobileExecutionWindow, MobileWakeContractError> {
    let budget = BackgroundBudget::new(
        Duration::from_millis(total_milliseconds),
        Duration::from_millis(cleanup_milliseconds),
    )
    .map_err(|_| MobileWakeContractError::InvalidBackgroundWindow)?;
    let execution_milliseconds = u64::try_from(budget.execution_budget().as_millis())
        .map_err(|_| MobileWakeContractError::InvalidBackgroundWindow)?;

    Ok(MobileExecutionWindow {
        execution_milliseconds,
        cleanup_milliseconds,
    })
}

/// Generic native notification presentation guidance.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum MobileNotificationHint {
    /// Work is queued or still in progress.
    Processing,
    /// The request completed without requiring user attention.
    Completed,
    /// The containing application should be opened to continue safely.
    OpenApplication,
}

/// Why work was handed to the containing application.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum MobileQueueReason {
    /// The background deadline is too close.
    Deadline,
    /// Protected storage is unavailable in this execution context.
    SecureStorageUnavailable,
    /// The wallet backend cannot be opened safely in this context.
    WalletUnavailable,
    /// The request is not supported by the background adapter.
    UnsupportedInBackground,
    /// The durable ledger could not be acquired in time.
    LedgerBusy,
}

/// Why native code may schedule a retry without new authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum MobileRetryReason {
    /// An approved relay was temporarily unavailable.
    RelayUnavailable,
    /// A wallet capability or ambiguous payment state was temporarily unavailable.
    WalletUnavailable,
    /// The response could not be published after its result was persisted.
    ResponsePublishFailed,
    /// The response could not be committed before its claim was lost.
    ResponsePersistenceFailed,
    /// A wake-provider registration call failed transiently.
    RegistrationUnavailable,
}

/// Stable security or policy rejection classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum MobileRejectionCode {
    /// The platform payload was malformed or oversized.
    InvalidWakePayload,
    /// The connection does not exist or was revoked.
    ConnectionUnavailable,
    /// The relay is not approved for the connection.
    RelayNotAllowed,
    /// The fetched or embedded event did not match the wake.
    EventMismatch,
    /// The event signature or recipient was invalid.
    InvalidEvent,
    /// The decrypted request was malformed or unsupported.
    InvalidRequest,
    /// The event timestamp was outside policy.
    EventOutsideFreshnessWindow,
    /// The connection did not authorize the method.
    MethodNotAllowed,
    /// The request would exceed the connection budget.
    BudgetExceeded,
}

/// Platform-neutral lifecycle result returned to Swift or Kotlin.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum MobileWakeDisposition {
    /// The request reached a durable terminal state.
    Completed {
        /// Generic notification guidance.
        notification: MobileNotificationHint,
    },
    /// Another process already owns or completed the event.
    AlreadyProcessed {
        /// Generic notification guidance.
        notification: MobileNotificationHint,
    },
    /// The containing application must resume the durable work.
    QueuedForApplication {
        /// Stable queue classification.
        reason: MobileQueueReason,
        /// Generic notification guidance.
        notification: MobileNotificationHint,
    },
    /// Native code may schedule the durable operation again.
    RetryAfter {
        /// Minimum retry delay chosen by Rust policy.
        delay_milliseconds: u64,
        /// Stable retry classification.
        reason: MobileRetryReason,
        /// Generic notification guidance.
        notification: MobileNotificationHint,
    },
    /// A non-retriable security or policy check failed.
    Rejected {
        /// Stable rejection classification.
        code: MobileRejectionCode,
        /// Generic notification guidance.
        notification: MobileNotificationHint,
    },
}

impl From<WakeDisposition> for MobileWakeDisposition {
    fn from(disposition: WakeDisposition) -> Self {
        match disposition {
            WakeDisposition::Completed { notification } => Self::Completed {
                notification: notification.into(),
            },
            WakeDisposition::AlreadyProcessed { notification } => Self::AlreadyProcessed {
                notification: notification.into(),
            },
            WakeDisposition::QueuedForApplication {
                reason,
                notification,
            } => Self::QueuedForApplication {
                reason: reason.into(),
                notification: notification.into(),
            },
            WakeDisposition::RetryAfter {
                delay,
                reason,
                notification,
            } => Self::RetryAfter {
                delay_milliseconds: duration_milliseconds(delay),
                reason: reason.into(),
                notification: notification.into(),
            },
            WakeDisposition::Rejected { code, notification } => Self::Rejected {
                code: code.into(),
                notification: notification.into(),
            },
            _ => Self::QueuedForApplication {
                reason: MobileQueueReason::UnsupportedInBackground,
                notification: MobileNotificationHint::OpenApplication,
            },
        }
    }
}

fn duration_milliseconds(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

impl From<NotificationHint> for MobileNotificationHint {
    fn from(hint: NotificationHint) -> Self {
        match hint {
            NotificationHint::Processing => Self::Processing,
            NotificationHint::Completed => Self::Completed,
            NotificationHint::OpenApplication => Self::OpenApplication,
            _ => Self::OpenApplication,
        }
    }
}

impl From<QueueReason> for MobileQueueReason {
    fn from(reason: QueueReason) -> Self {
        match reason {
            QueueReason::Deadline => Self::Deadline,
            QueueReason::SecureStorageUnavailable => Self::SecureStorageUnavailable,
            QueueReason::WalletUnavailable => Self::WalletUnavailable,
            QueueReason::UnsupportedInBackground => Self::UnsupportedInBackground,
            QueueReason::LedgerBusy => Self::LedgerBusy,
            _ => Self::UnsupportedInBackground,
        }
    }
}

impl From<RetryReason> for MobileRetryReason {
    fn from(reason: RetryReason) -> Self {
        match reason {
            RetryReason::RelayUnavailable => Self::RelayUnavailable,
            RetryReason::WalletUnavailable => Self::WalletUnavailable,
            RetryReason::ResponsePublishFailed => Self::ResponsePublishFailed,
            RetryReason::ResponsePersistenceFailed => Self::ResponsePersistenceFailed,
            RetryReason::RegistrationUnavailable => Self::RegistrationUnavailable,
            _ => Self::WalletUnavailable,
        }
    }
}

impl From<RejectionCode> for MobileRejectionCode {
    fn from(code: RejectionCode) -> Self {
        match code {
            RejectionCode::InvalidWakePayload => Self::InvalidWakePayload,
            RejectionCode::ConnectionUnavailable => Self::ConnectionUnavailable,
            RejectionCode::RelayNotAllowed => Self::RelayNotAllowed,
            RejectionCode::EventMismatch => Self::EventMismatch,
            RejectionCode::InvalidEvent => Self::InvalidEvent,
            RejectionCode::InvalidRequest => Self::InvalidRequest,
            RejectionCode::EventOutsideFreshnessWindow => Self::EventOutsideFreshnessWindow,
            RejectionCode::MethodNotAllowed => Self::MethodNotAllowed,
            RejectionCode::BudgetExceeded => Self::BudgetExceeded,
            _ => Self::InvalidWakePayload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn envelope() -> MobileWakeEnvelope {
        MobileWakeEnvelope {
            relay_url: "wss://relay.example/path".to_owned(),
            event_id_hex: HEX.to_ascii_uppercase(),
            wallet_service_public_key_hex: HEX.to_owned(),
            embedded_event_json: Some("{}".to_owned()),
            received_at_seconds: 1_750_000_000,
        }
    }

    #[test]
    fn validates_and_seals_native_wake_input() {
        let wake = validate_wake_envelope(envelope()).expect("valid wake");

        assert_eq!(wake.event_id_hex(), HEX);
        assert!(wake.has_embedded_event());
        assert_eq!(wake.received_at_seconds(), 1_750_000_000);
        assert_eq!(wake.core_input().relay(), "wss://relay.example/path");
    }

    #[test]
    fn rejects_insecure_or_oversized_untrusted_fields() {
        let mut insecure = envelope();
        insecure.relay_url = "ws://relay.example".to_owned();
        assert_eq!(
            validate_wake_envelope(insecure).unwrap_err(),
            MobileWakeContractError::InvalidRelay
        );

        let mut oversized = envelope();
        oversized.embedded_event_json =
            Some("x".repeat(nwc_mobile::MAX_EMBEDDED_WAKE_EVENT_BYTES + 1));
        assert_eq!(
            validate_wake_envelope(oversized).unwrap_err(),
            MobileWakeContractError::EmbeddedEventTooLarge
        );
    }

    #[test]
    fn native_wake_debug_output_redacts_transport_content() {
        let wake = envelope();
        let debug = format!("{wake:?}");

        assert!(!debug.contains("relay.example"));
        assert!(!debug.contains(HEX));
        assert!(!debug.contains("{}"));
        assert!(debug.contains("has_embedded_event: true"));
    }

    #[test]
    fn background_window_reserves_native_cleanup_time() {
        assert_eq!(
            mobile_execution_window(30_000, 5_000),
            Ok(MobileExecutionWindow {
                execution_milliseconds: 25_000,
                cleanup_milliseconds: 5_000,
            })
        );
        assert_eq!(
            mobile_execution_window(30_000, 30_000),
            Err(MobileWakeContractError::InvalidBackgroundWindow)
        );
    }

    #[test]
    fn maps_core_lifecycle_outcomes_without_remote_text() {
        let retry = WakeDisposition::RetryAfter {
            delay: Duration::from_millis(1_250),
            reason: RetryReason::RelayUnavailable,
            notification: NotificationHint::Processing,
        };
        assert_eq!(
            MobileWakeDisposition::from(retry),
            MobileWakeDisposition::RetryAfter {
                delay_milliseconds: 1_250,
                reason: MobileRetryReason::RelayUnavailable,
                notification: MobileNotificationHint::Processing,
            }
        );

        let rejected = WakeDisposition::Rejected {
            code: RejectionCode::BudgetExceeded,
            notification: NotificationHint::OpenApplication,
        };
        assert_eq!(
            MobileWakeDisposition::from(rejected),
            MobileWakeDisposition::Rejected {
                code: MobileRejectionCode::BudgetExceeded,
                notification: MobileNotificationHint::OpenApplication,
            }
        );
    }
}
