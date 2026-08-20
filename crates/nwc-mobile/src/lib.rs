//! Secure Nostr Wallet Connect infrastructure for mobile wallets.
//!
//! This crate will own platform-independent wake validation, durable execution
//! state, payment accounting, and Nostr Wallet Auth policy. It deliberately does
//! not depend on a particular Lightning wallet or mobile operating system.

#![forbid(unsafe_code)]

mod error;
mod host;
mod nostr_validation;
mod nwa;
mod outcome;
mod policy;
mod time;
mod types;

pub use error::DomainError;
pub use host::{
    AmountMsat, AmountSat, CancellationSignal, CreatedInvoice, HostError, HostErrorKind,
    HostFuture, InvoiceLookup, ListTransactionsRequest, MakeInvoiceRequest, NeverCancelled,
    OperationBudget, OperationContext, PayInvoiceRequest, PaymentFailure, PaymentStatus,
    RelayTransport, SecretProvider, SecureRelayUrl, TransactionDirection, WalletBackend,
    WalletInfo, WalletTransaction,
};
pub use nostr_validation::{
    DecryptedNwcRequest, NostrEventError, NwcEncryption, NwcEventValidator, NwcSecretKey,
    ValidatedNwcEvent,
};
pub use nwa::{NwaCallback, NwaError, NwaParsePolicy, NwaRequest, NwaRequestId};
pub use outcome::{NotificationHint, QueueReason, RejectionCode, RetryReason, WakeDisposition};
pub use policy::{BudgetInterval, BudgetPolicy, ConnectionPolicy, FeePolicy, WakePolicy};
pub use time::{BackgroundBudget, Clock, SystemClock, UnixTimestamp};
pub use types::{
    ConnectionId, ConnectionRevision, EventId, NwcMethod, PaymentHash, PaymentPreimage, PublicKey,
    WakeInput,
};
