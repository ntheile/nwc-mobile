//! Secure Nostr Wallet Connect infrastructure for mobile wallets.
//!
//! This crate will own platform-independent wake validation, durable execution
//! state, payment accounting, and Nostr Wallet Auth policy. It deliberately does
//! not depend on a particular Lightning wallet or mobile operating system.

#![forbid(unsafe_code)]

mod error;
mod outcome;
mod policy;
mod time;
mod types;

pub use error::DomainError;
pub use outcome::{NotificationHint, QueueReason, RejectionCode, RetryReason, WakeDisposition};
pub use policy::{BudgetInterval, BudgetPolicy, ConnectionPolicy, FeePolicy, WakePolicy};
pub use time::{BackgroundBudget, Clock, SystemClock, UnixTimestamp};
pub use types::{
    ConnectionId, ConnectionRevision, EventId, NwcMethod, PaymentHash, PublicKey, WakeInput,
};
