//! Secure Nostr Wallet Connect infrastructure for mobile wallets.
//!
//! This crate will own platform-independent wake validation, durable execution
//! state, payment accounting, and Nostr Wallet Auth policy. It deliberately does
//! not depend on a particular Lightning wallet or mobile operating system.

#![forbid(unsafe_code)]

mod application;
mod application_coordinator;
mod application_icon_cache;
mod application_manager;
mod application_metadata;
mod connection_registry;
mod connection_service;
mod diagnostics;
mod engine;
mod error;
mod foreground;
mod host;
mod ledger;
mod mobile_service;
mod nip98;
mod nostr_validation;
mod nwa;
mod nwc_info;
mod outcome;
mod payment_accounting;
mod payment_reconciliation;
mod policy;
mod time;
mod types;
mod wake_envelope;
mod wake_registration;
mod wake_registration_worker;

pub use application::{
    build_connection_uri, client_secret_storage_key, encode_connection_relays,
    maximum_mobile_fee_sat, parse_connection_relays, ApplicationError, ApplicationRevocation,
    ApplicationWorkflowError, ApprovedApplicationConnection, ClientSecretStore,
    ClientSecretStoreError, ConnectionDraft, ConnectionPresentation, ConnectionSelection,
    CreatedWalletConnection, NwaApprovalSelection, WalletConnectionRequest,
    DEFAULT_MAXIMUM_CONNECTION_RELAYS,
};
pub use application_coordinator::{
    ApplicationRegistrationBegin, ApplicationRegistrationCompletion,
    ApplicationRegistrationCoordinator, ApplicationRegistrationPass, NwaCallbackBegin,
    NwaCallbackCompletion, NwaCallbackCoordinator,
};
pub use application_icon_cache::{
    ApplicationIconCache, ApplicationIconCacheError, ApplicationIconUrl, MAX_APPLICATION_ICON_BYTES,
};
pub use application_manager::{
    registration_retry_delay, ApprovedNwaApplication, NwcApplicationManager, RegistrationStart,
    MINIMUM_REGISTRATION_RETRY_DELAY, NWC_MOBILE_DATABASE_FILE,
};
pub use application_metadata::{ApplicationConnectionMetadata, ConnectionBudgetUsage};
pub use connection_registry::{
    ActiveConnection, ConnectionTombstone, NewConnection, RegistryError, StoredConnection,
};
pub use connection_service::{
    ApprovedNwaConnection, ConnectionManager, LegacyConnectionImport, LegacyMigrationResult,
    NwaApproval, NwaApprovalError,
};
pub use diagnostics::{WakeDiagnosticCode, WakeDiagnosticCollector, WakeDiagnosticSink};
pub use engine::{ReadOnlyWakeEngine, WakeEngine};
pub use error::DomainError;
pub use foreground::{
    ForegroundWakeCoordinator, ForegroundWakeDecision, ForegroundWakeOutcome, ForegroundWakePolicy,
    ForegroundWakeRetryCause, DEFAULT_FOREGROUND_WAKE_RETRY_ATTEMPTS,
    DEFAULT_FOREGROUND_WAKE_RETRY_BASE_DELAY,
};
pub use host::{
    AmountMsat, AmountSat, AtomicCancellation, CancellationSignal, CreatedInvoice, HostError,
    HostErrorKind, HostFuture, InvoiceLookup, ListTransactionsRequest, MakeInvoiceRequest,
    NeverCancelled, OperationBudget, OperationContext, PayInvoiceRequest, PaymentFailure,
    PaymentQuote, PaymentStatus, RelayTransport, SecretProvider, SecureRelayUrl,
    SecureWakeServerUrl, TransactionDirection, WalletBackend, WalletInfo, WalletTransaction,
};
pub use ledger::{ClaimOutcome, EventLease, LedgerError, TerminalEvent, TerminalKind, WakeLedger};
pub use mobile_service::{
    HostConnectionAuthorization, HostMigrationReport, LegacyHostConnection, MobileServiceError,
    NwaRequestPresentation, NwcMobileService,
};
pub use nip98::{Nip98Authorization, Nip98AuthorizationError, Nip98SigningKey};
pub use nostr_validation::{
    DecryptedNwcRequest, NostrEventError, NwcEncryption, NwcEventValidator, NwcSecretKey,
    ValidatedNwcEvent,
};
pub use nwa::{NwaCallback, NwaError, NwaParsePolicy, NwaRequest, NwaRequestId};
pub use nwc_info::{build_nwc_info_event, NwcInfoEventError};
pub use outcome::{
    NotificationHint, QueueReason, RejectionCode, RetryReason, WakeDisposition, WakeDispositionKind,
};
pub use payment_accounting::{
    DurablePaymentState, PaymentAccountingError, PaymentAttempt, PaymentReservationOutcome,
};
pub use payment_reconciliation::{
    PaymentReconciler, PaymentReconciliationError, PaymentReconciliationReport,
    MAX_PAYMENT_RECONCILIATION_BATCH,
};
pub use policy::{BudgetInterval, BudgetPolicy, ConnectionPolicy, FeePolicy, WakePolicy};
pub use time::{BackgroundBudget, Clock, SystemClock, UnixTimestamp};
pub use types::{
    ConnectionId, ConnectionRevision, EventId, NwcMethod, PaymentHash, PaymentPreimage, PublicKey,
    WakeInput,
};
pub use wake_envelope::{
    WakeEnvelope, WakeEnvelopeError, MAX_EMBEDDED_WAKE_EVENT_BYTES, MAX_WAKE_PAYLOAD_JSON_BYTES,
};
pub use wake_registration::{
    WakeRegistrationChange, WakeRegistrationError, MAX_WAKE_REGISTRATION_BATCH,
};
pub use wake_registration_worker::{
    WakeRegistrationTransport, WakeRegistrationWorker, WakeRegistrationWorkerError,
    WakeRegistrationWorkerReport,
};
