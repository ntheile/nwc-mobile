//! Secure Nostr Wallet Connect infrastructure for mobile wallets.
//!
//! This crate will own platform-independent wake validation, durable execution
//! state, payment accounting, and Nostr Wallet Auth policy. It deliberately does
//! not depend on a particular Lightning wallet or mobile operating system.

#![forbid(unsafe_code)]

mod error;
mod nostr_validation;
mod nwa;
mod outcome;
mod policy;
mod time;
mod types;

pub use error::DomainError;
pub use nostr_validation::{
    DecryptedNwcRequest, NostrEventError, NwcEncryption, NwcEventValidator, NwcSecretKey,
    ValidatedNwcEvent,
};
pub use nwa::{NwaCallback, NwaError, NwaParsePolicy, NwaRequest, NwaRequestId};
pub use outcome::{NotificationHint, QueueReason, RejectionCode, RetryReason, WakeDisposition};
pub use policy::{BudgetInterval, BudgetPolicy, ConnectionPolicy, FeePolicy, WakePolicy};
pub use time::{BackgroundBudget, Clock, SystemClock, UnixTimestamp};
pub use types::{
    ConnectionId, ConnectionRevision, EventId, NwcMethod, PaymentHash, PublicKey, WakeInput,
};
