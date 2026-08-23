use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use url::Url;
use zeroize::Zeroizing;

use crate::{
    ConnectionId, DomainError, EventId, NwcMethod, NwcSecretKey, PaymentHash, PaymentPreimage,
    PublicKey, UnixTimestamp,
};

const MAX_RELAY_URL_BYTES: usize = 2_048;
const MAX_WAKE_SERVER_URL_BYTES: usize = 2_048;

/// A boxed asynchronous operation returned by a host capability.
///
/// The explicit box keeps capability traits object-safe without a proc-macro
/// dependency. Native adapters normally return `Box::pin(async move { ... })`.
pub type HostFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A millisatoshi amount with an explicit unit.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct AmountMsat(u64);

impl AmountMsat {
    /// Creates an amount from millisatoshis.
    #[must_use]
    pub const fn from_msat(value: u64) -> Self {
        Self(value)
    }

    /// Returns the amount in millisatoshis.
    #[must_use]
    pub const fn as_msat(self) -> u64 {
        self.0
    }
}

/// A satoshi amount with an explicit unit.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct AmountSat(u64);

impl AmountSat {
    /// Creates an amount from satoshis.
    #[must_use]
    pub const fn from_sat(value: u64) -> Self {
        Self(value)
    }

    /// Returns the amount in satoshis.
    #[must_use]
    pub const fn as_sat(self) -> u64 {
        self.0
    }
}

/// The remaining monotonic time available to one host operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationBudget(Duration);

impl OperationBudget {
    /// Creates a non-zero operation budget.
    pub fn new(timeout: Duration) -> Result<Self, DomainError> {
        if timeout.is_zero() {
            return Err(DomainError::InvalidOperationBudget);
        }
        Ok(Self(timeout))
    }

    /// Returns the maximum time the host may spend on the operation.
    #[must_use]
    pub const fn timeout(self) -> Duration {
        self.0
    }
}

/// Allows the engine or operating system to cancel in-flight host work.
pub trait CancellationSignal: Send + Sync {
    /// Returns `true` once work should stop and checkpoint.
    fn is_cancelled(&self) -> bool;
}

/// Thread-safe monotonic cancellation shared by native lifecycle adapters.
#[derive(Debug, Default)]
pub struct AtomicCancellation(AtomicBool);

impl AtomicCancellation {
    /// Creates an active cancellation signal.
    #[must_use]
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// Permanently marks the signal as cancelled.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Returns whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

impl CancellationSignal for AtomicCancellation {
    fn is_cancelled(&self) -> bool {
        self.is_cancelled()
    }
}

/// A cancellation signal for foreground work without external cancellation.
#[derive(Clone, Copy, Debug, Default)]
pub struct NeverCancelled;

impl CancellationSignal for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// Deadline and cancellation state supplied to each host capability call.
#[derive(Clone, Copy)]
pub struct OperationContext<'a> {
    budget: OperationBudget,
    cancellation: &'a dyn CancellationSignal,
}

impl<'a> OperationContext<'a> {
    /// Creates an operation context from the current remaining budget.
    #[must_use]
    pub const fn new(budget: OperationBudget, cancellation: &'a dyn CancellationSignal) -> Self {
        Self {
            budget,
            cancellation,
        }
    }

    /// Returns the remaining execution budget captured for this call.
    #[must_use]
    pub const fn budget(self) -> OperationBudget {
        self.budget
    }

    /// Returns the cancellation signal.
    #[must_use]
    pub const fn cancellation(self) -> &'a dyn CancellationSignal {
        self.cancellation
    }
}

impl fmt::Debug for OperationContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationContext")
            .field("budget", &self.budget)
            .field("cancelled", &self.cancellation.is_cancelled())
            .finish()
    }
}

/// A stable, non-sensitive host failure classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HostErrorKind {
    /// The capability is temporarily unavailable.
    Unavailable,
    /// The operation exceeded its supplied budget.
    TimedOut,
    /// The operation observed cancellation.
    Cancelled,
    /// The typed request was rejected by the wallet implementation.
    Rejected,
    /// The requested wallet object does not exist.
    NotFound,
    /// An operation with the same idempotency key is already in progress.
    AlreadyInProgress,
    /// The host encountered an internal failure.
    Internal,
}

/// A host error safe to persist or expose across FFI.
///
/// Remote response bodies and wallet error strings deliberately do not cross
/// this boundary. Hosts may log private details in their own protected logs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostError {
    kind: HostErrorKind,
}

impl HostError {
    /// Creates a host error from its stable classification.
    #[must_use]
    pub const fn new(kind: HostErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure classification.
    #[must_use]
    pub const fn kind(self) -> HostErrorKind {
        self.kind
    }

    /// Returns whether policy may retry the operation without new consent.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(
            self.kind,
            HostErrorKind::Unavailable | HostErrorKind::TimedOut | HostErrorKind::AlreadyInProgress
        )
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            HostErrorKind::Unavailable => "host capability is unavailable",
            HostErrorKind::TimedOut => "host capability timed out",
            HostErrorKind::Cancelled => "host capability was cancelled",
            HostErrorKind::Rejected => "host capability rejected the request",
            HostErrorKind::NotFound => "host object was not found",
            HostErrorKind::AlreadyInProgress => "host operation is already in progress",
            HostErrorKind::Internal => "host capability failed",
        })
    }
}

impl std::error::Error for HostError {}

/// A syntactically valid secure WebSocket relay URL.
///
/// This type does not prove that a connection approved the relay. The engine
/// must still compare it against the durable connection allowlist.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecureRelayUrl(String);

impl SecureRelayUrl {
    /// Parses and canonicalizes a bounded `wss://` URL.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        if value.is_empty() || value.len() > MAX_RELAY_URL_BYTES {
            return Err(DomainError::InvalidRelayUrl);
        }
        let relay = Url::parse(value).map_err(|_| DomainError::InvalidRelayUrl)?;
        if relay.scheme() != "wss"
            || relay.host_str().is_none()
            || !relay.username().is_empty()
            || relay.password().is_some()
            || relay.fragment().is_some()
        {
            return Err(DomainError::InvalidRelayUrl);
        }
        let relay = relay.to_string();
        if relay.len() > MAX_RELAY_URL_BYTES {
            return Err(DomainError::InvalidRelayUrl);
        }
        Ok(Self(relay))
    }

    /// Returns the canonical secure relay URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecureRelayUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecureRelayUrl([redacted])")
    }
}

/// A syntactically valid HTTPS wake-provider endpoint.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecureWakeServerUrl(String);

impl SecureWakeServerUrl {
    /// Parses and canonicalizes a bounded `https://` URL without credentials.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        if value.is_empty() || value.len() > MAX_WAKE_SERVER_URL_BYTES {
            return Err(DomainError::InvalidWakeServerUrl);
        }
        let endpoint = Url::parse(value).map_err(|_| DomainError::InvalidWakeServerUrl)?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(DomainError::InvalidWakeServerUrl);
        }
        let endpoint = endpoint.to_string();
        if endpoint.len() > MAX_WAKE_SERVER_URL_BYTES {
            return Err(DomainError::InvalidWakeServerUrl);
        }
        Ok(Self(endpoint))
    }

    /// Returns the canonical HTTPS endpoint.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecureWakeServerUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecureWakeServerUrl([redacted])")
    }
}

/// Information returned for the NIP-47 `get_info` method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletInfo {
    public_key: Option<PublicKey>,
    methods: BTreeSet<NwcMethod>,
    notifications: BTreeSet<NwcNotificationType>,
}

/// NIP-47 notification types a wallet backend can durably deliver.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum NwcNotificationType {
    /// A created invoice settled and funds were received.
    PaymentReceived,
    /// An outgoing invoice payment settled successfully.
    PaymentSent,
}

impl NwcNotificationType {
    /// Returns the canonical NIP-47 notification name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PaymentReceived => "payment_received",
            Self::PaymentSent => "payment_sent",
        }
    }
}

impl WalletInfo {
    /// Creates wallet information from optional public identity and methods.
    #[must_use]
    pub fn new(
        public_key: Option<PublicKey>,
        methods: impl IntoIterator<Item = NwcMethod>,
    ) -> Self {
        Self {
            public_key,
            methods: methods.into_iter().collect(),
            notifications: BTreeSet::new(),
        }
    }

    /// Declares notification types the backend can durably deliver.
    #[must_use]
    pub fn with_notifications(
        mut self,
        notifications: impl IntoIterator<Item = NwcNotificationType>,
    ) -> Self {
        self.notifications = notifications.into_iter().collect();
        self
    }

    /// Returns the wallet public key when the backend exposes one.
    #[must_use]
    pub const fn public_key(&self) -> Option<&PublicKey> {
        self.public_key.as_ref()
    }

    /// Iterates over methods implemented by the wallet backend.
    pub fn methods(&self) -> impl ExactSizeIterator<Item = NwcMethod> + '_ {
        self.methods.iter().copied()
    }

    /// Iterates over notification types implemented by the wallet backend.
    pub fn notifications(&self) -> impl ExactSizeIterator<Item = NwcNotificationType> + '_ {
        self.notifications.iter().copied()
    }
}

/// A single-invoice capability that lets a wallet backend signal settlement.
#[derive(Clone, Eq, PartialEq)]
pub struct InvoiceSettlementTrigger {
    request_event_id: EventId,
    token: Zeroizing<[u8; 32]>,
}

impl InvoiceSettlementTrigger {
    pub(crate) fn generate(request_event_id: EventId) -> Result<Self, HostError> {
        let mut token = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut *token).map_err(|_| HostError::new(HostErrorKind::Unavailable))?;
        Ok(Self {
            request_event_id,
            token,
        })
    }

    /// Returns the NWC request event that owns this capability.
    #[must_use]
    pub const fn request_event_id(&self) -> &EventId {
        &self.request_event_id
    }

    /// Returns the random capability bytes for a trusted wallet backend.
    #[must_use]
    pub fn token_bytes(&self) -> &[u8; 32] {
        &self.token
    }
}

impl fmt::Debug for InvoiceSettlementTrigger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvoiceSettlementTrigger")
            .field("request_event_id", &"[redacted]")
            .field("token", &"[redacted]")
            .finish()
    }
}

/// A request to create a Lightning invoice.
#[derive(Clone, Eq, PartialEq)]
pub struct MakeInvoiceRequest {
    amount: AmountMsat,
    description: Option<String>,
    expiry: Duration,
    settlement_trigger: Option<InvoiceSettlementTrigger>,
}

impl MakeInvoiceRequest {
    /// Creates an invoice request after protocol-level validation and bounds.
    #[must_use]
    pub fn new(amount: AmountMsat, description: Option<String>, expiry: Duration) -> Self {
        Self {
            amount,
            description,
            expiry,
            settlement_trigger: None,
        }
    }

    pub(crate) fn with_settlement_trigger(
        mut self,
        settlement_trigger: InvoiceSettlementTrigger,
    ) -> Self {
        self.settlement_trigger = Some(settlement_trigger);
        self
    }

    /// Returns the requested invoice amount.
    #[must_use]
    pub const fn amount(&self) -> AmountMsat {
        self.amount
    }

    /// Returns the sanitized and policy-bounded payer-visible description.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the requested invoice lifetime.
    #[must_use]
    pub const fn expiry(&self) -> Duration {
        self.expiry
    }

    /// Returns the optional server-side settlement capability.
    #[must_use]
    pub const fn settlement_trigger(&self) -> Option<&InvoiceSettlementTrigger> {
        self.settlement_trigger.as_ref()
    }
}

impl fmt::Debug for MakeInvoiceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MakeInvoiceRequest")
            .field("amount", &self.amount)
            .field(
                "description",
                &self.description.as_ref().map(|_| "[redacted]"),
            )
            .field("expiry", &self.expiry)
            .field("has_settlement_trigger", &self.settlement_trigger.is_some())
            .finish()
    }
}

/// A newly created Lightning invoice.
#[derive(Clone, Eq, PartialEq)]
pub struct CreatedInvoice {
    invoice: String,
    payment_hash: PaymentHash,
    amount: AmountMsat,
    expires_at: UnixTimestamp,
}

impl CreatedInvoice {
    /// Creates an invoice result returned by a wallet backend.
    #[must_use]
    pub fn new(
        invoice: String,
        payment_hash: PaymentHash,
        amount: AmountMsat,
        expires_at: UnixTimestamp,
    ) -> Self {
        Self {
            invoice,
            payment_hash,
            amount,
            expires_at,
        }
    }

    /// Returns the encoded Lightning invoice.
    #[must_use]
    pub fn invoice(&self) -> &str {
        &self.invoice
    }

    /// Returns the invoice payment hash.
    #[must_use]
    pub const fn payment_hash(&self) -> &PaymentHash {
        &self.payment_hash
    }

    /// Returns the invoice amount.
    #[must_use]
    pub const fn amount(&self) -> AmountMsat {
        self.amount
    }

    /// Returns the invoice expiration time.
    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }
}

impl fmt::Debug for CreatedInvoice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedInvoice")
            .field("invoice", &"[redacted]")
            .field("payment_hash", &self.payment_hash)
            .field("amount", &self.amount)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// A request to initiate a Lightning payment after durable budget reservation.
#[derive(Clone, Eq, PartialEq)]
pub struct PayInvoiceRequest {
    invoice: String,
    amount: Option<AmountMsat>,
    maximum_fee: AmountSat,
    idempotency_key: EventId,
}

impl PayInvoiceRequest {
    /// Creates a payment request bound to the Nostr event id.
    #[must_use]
    pub fn new(
        invoice: String,
        amount: Option<AmountMsat>,
        maximum_fee: AmountSat,
        idempotency_key: EventId,
    ) -> Self {
        Self {
            invoice,
            amount,
            maximum_fee,
            idempotency_key,
        }
    }

    /// Returns the encoded Lightning invoice.
    #[must_use]
    pub fn invoice(&self) -> &str {
        &self.invoice
    }

    /// Returns an explicit amount for amountless invoices.
    #[must_use]
    pub const fn amount(&self) -> Option<AmountMsat> {
        self.amount
    }

    /// Returns the maximum fee authorized by engine policy.
    #[must_use]
    pub const fn maximum_fee(&self) -> AmountSat {
        self.maximum_fee
    }

    /// Returns the stable request idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> &EventId {
        &self.idempotency_key
    }
}

impl fmt::Debug for PayInvoiceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PayInvoiceRequest")
            .field("invoice", &"[redacted]")
            .field("amount", &self.amount)
            .field("maximum_fee", &self.maximum_fee)
            .field("idempotency_key", &self.idempotency_key)
            .finish()
    }
}

/// A side-effect-free decode of the payment the wallet would initiate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentQuote {
    payment_hash: PaymentHash,
    principal: AmountMsat,
}

impl PaymentQuote {
    /// Creates a quote from wallet-validated invoice metadata.
    #[must_use]
    pub const fn new(payment_hash: PaymentHash, principal: AmountMsat) -> Self {
        Self {
            payment_hash,
            principal,
        }
    }

    /// Returns the invoice payment hash used for global deduplication.
    #[must_use]
    pub const fn payment_hash(&self) -> &PaymentHash {
        &self.payment_hash
    }

    /// Returns the exact millisatoshi principal the wallet would pay.
    #[must_use]
    pub const fn principal(&self) -> AmountMsat {
        self.principal
    }
}

/// A stable reason a Lightning payment definitively failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PaymentFailure {
    /// The invoice was invalid or expired.
    InvalidInvoice,
    /// The wallet lacked sufficient funds.
    InsufficientFunds,
    /// No route completed within the wallet's constraints.
    NoRoute,
    /// The recipient rejected or permanently failed the payment.
    RecipientRejected,
    /// The wallet reported another permanent failure.
    Other,
}

/// The wallet's durable view of a payment hash.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PaymentStatus {
    /// The wallet has no record of this payment hash.
    Unknown,
    /// A payment is in flight or its outcome remains ambiguous.
    Pending,
    /// The payment settled.
    Succeeded {
        /// Payment preimage returned to the NWC client.
        preimage: PaymentPreimage,
        /// Principal amount paid.
        amount: AmountMsat,
        /// Actual routing fee paid.
        fee: AmountMsat,
    },
    /// The payment failed definitively and cannot later settle.
    Failed {
        /// Stable failure classification.
        reason: PaymentFailure,
    },
}

/// A typed lookup selector for an invoice or payment.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum InvoiceLookup {
    /// Look up by payment hash.
    PaymentHash(PaymentHash),
    /// Look up by encoded Lightning invoice.
    Invoice(String),
}

impl fmt::Debug for InvoiceLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PaymentHash(hash) => formatter.debug_tuple("PaymentHash").field(hash).finish(),
            Self::Invoice(_) => formatter.write_str("Invoice([redacted])"),
        }
    }
}

/// Direction of a wallet transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TransactionDirection {
    /// Funds received by the wallet.
    Incoming,
    /// Funds sent by the wallet.
    Outgoing,
}

/// A wallet transaction safe for the engine to encode as an NWC response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletTransaction {
    /// Payment hash when one is known.
    pub payment_hash: Option<PaymentHash>,
    /// Transaction direction.
    pub direction: TransactionDirection,
    /// Principal amount.
    pub amount: AmountMsat,
    /// Routing fee for outgoing payments.
    pub fee: AmountMsat,
    /// Creation time.
    pub created_at: UnixTimestamp,
    /// Settlement time when settled.
    pub settled_at: Option<UnixTimestamp>,
    /// Current durable payment state.
    pub status: PaymentStatus,
}

/// A bounded transaction-list query produced by the protocol parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListTransactionsRequest {
    /// Inclusive lower creation-time bound.
    pub from: Option<UnixTimestamp>,
    /// Inclusive upper creation-time bound.
    pub until: Option<UnixTimestamp>,
    /// Maximum records to return after policy capping.
    pub limit: u16,
    /// Records to skip after policy capping.
    pub offset: u32,
    /// Optional direction filter.
    pub direction: Option<TransactionDirection>,
    /// Whether unpaid invoices may be returned.
    pub include_unpaid: bool,
}

/// Wallet operations supplied by the containing application.
///
/// The engine calls these methods only after event authentication, connection
/// authorization, and method-policy checks. `start_payment` is called only
/// after a durable budget reservation is committed.
pub trait WalletBackend: Send + Sync {
    /// Returns wallet identity and supported methods.
    fn get_info<'a>(
        &'a self,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<WalletInfo, HostError>>;

    /// Returns the spendable wallet balance.
    fn get_balance<'a>(
        &'a self,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<AmountMsat, HostError>>;

    /// Creates a Lightning invoice.
    fn make_invoice<'a>(
        &'a self,
        request: MakeInvoiceRequest,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<CreatedInvoice, HostError>>;

    /// Parses and validates an invoice without initiating or persisting a payment.
    fn quote_payment<'a>(
        &'a self,
        invoice: &'a str,
        amount: Option<AmountMsat>,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<PaymentQuote, HostError>>;

    /// Reads durable payment state without initiating a payment.
    fn payment_status<'a>(
        &'a self,
        payment_hash: &'a PaymentHash,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<PaymentStatus, HostError>>;

    /// Starts an idempotent payment after engine-side reservation.
    ///
    /// Any returned error is treated as an ambiguous initiation: the engine
    /// retains the debit and queries `payment_status` on retry. Definitive
    /// failures must be returned as `PaymentStatus::Failed`.
    fn start_payment<'a>(
        &'a self,
        request: PayInvoiceRequest,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<PaymentStatus, HostError>>;

    /// Looks up one invoice or payment.
    fn lookup_invoice<'a>(
        &'a self,
        request: InvoiceLookup,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<Option<WalletTransaction>, HostError>>;

    /// Lists wallet transactions using engine-capped bounds.
    fn list_transactions<'a>(
        &'a self,
        request: ListTransactionsRequest,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<Vec<WalletTransaction>, HostError>>;
}

/// Relay I/O supplied by the containing application.
///
/// Implementations must enforce the supplied budget and cancellation signal.
/// They must not follow redirects or silently substitute a different relay.
pub trait RelayTransport: Send + Sync {
    /// Fetches the exact event id from one already-approved secure relay.
    ///
    /// Implementations must configure their WebSocket receive limit to
    /// `maximum_event_bytes` before buffering a message. An over-limit message
    /// must fail with [`HostErrorKind::Rejected`] instead of being allocated as
    /// a `String`.
    fn fetch_event<'a>(
        &'a self,
        relay: &'a SecureRelayUrl,
        event_id: &'a EventId,
        maximum_event_bytes: usize,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<Option<String>, HostError>>;

    /// Publishes an engine-built response event to one approved secure relay.
    fn publish_event<'a>(
        &'a self,
        relay: &'a SecureRelayUrl,
        event_json: &'a str,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<(), HostError>>;
}

/// Narrow access to platform-protected NWC secret material.
pub trait SecretProvider: Send + Sync {
    /// Loads the wallet-service secret for one active connection.
    ///
    /// The returned value is zeroized on drop and must not be cached by the
    /// engine beyond the cryptographic operation that requested it.
    fn load_nwc_secret(&self, connection_id: &ConnectionId) -> Result<NwcSecretKey, HostError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn operation_budget_fails_closed_at_zero() {
        assert_eq!(
            OperationBudget::new(Duration::ZERO),
            Err(DomainError::InvalidOperationBudget)
        );
    }

    #[test]
    fn relay_requires_secure_bounded_url_without_credentials() {
        assert!(SecureRelayUrl::parse("wss://relay.example.com/nwc/").is_ok());
        assert_eq!(
            SecureRelayUrl::parse("ws://relay.example.com"),
            Err(DomainError::InvalidRelayUrl)
        );
        assert_eq!(
            SecureRelayUrl::parse("wss://secret@relay.example.com"),
            Err(DomainError::InvalidRelayUrl)
        );
        assert_eq!(
            SecureRelayUrl::parse("wss://relay.example.com/#fragment"),
            Err(DomainError::InvalidRelayUrl)
        );
        let expanded_path = format!("wss://relay.example.com/{}", "é".repeat(500));
        assert!(expanded_path.len() <= MAX_RELAY_URL_BYTES);
        assert_eq!(
            SecureRelayUrl::parse(&expanded_path),
            Err(DomainError::InvalidRelayUrl)
        );
    }

    #[test]
    fn sensitive_host_values_are_redacted_from_debug() {
        let request = PayInvoiceRequest::new(
            "lnbc-secret-invoice".to_string(),
            Some(AmountMsat::from_msat(1_000)),
            AmountSat::from_sat(10),
            EventId::from_hex(HEX).expect("event id"),
        );
        let make_invoice = MakeInvoiceRequest::new(
            AmountMsat::from_msat(1_000),
            Some("attacker-controlled-description".to_string()),
            Duration::from_secs(60),
        )
        .with_settlement_trigger(
            InvoiceSettlementTrigger::generate(EventId::from_hex(HEX).expect("event id"))
                .expect("settlement trigger"),
        );
        let relay = SecureRelayUrl::parse("wss://private.example.com").expect("relay");
        let wake_server = SecureWakeServerUrl::parse("https://wake.private.example.com/register")
            .expect("wake server");

        let request_debug = format!("{request:?}");
        let make_invoice_debug = format!("{make_invoice:?}");
        let relay_debug = format!("{relay:?}");
        let wake_server_debug = format!("{wake_server:?}");
        assert!(!request_debug.contains("secret-invoice"));
        assert!(!request_debug.contains(HEX));
        assert!(!make_invoice_debug.contains("attacker-controlled"));
        assert!(!make_invoice_debug.contains(HEX));
        assert!(!relay_debug.contains("private.example.com"));
        assert!(!wake_server_debug.contains("private.example.com"));
    }

    #[test]
    fn wake_server_requires_bounded_https_without_credentials_or_fragment() {
        assert!(SecureWakeServerUrl::parse("https://wake.example.com/v1/register").is_ok());
        for invalid in [
            "http://wake.example.com/v1/register",
            "https://secret@wake.example.com/v1/register",
            "https://wake.example.com/v1/register#fragment",
        ] {
            assert_eq!(
                SecureWakeServerUrl::parse(invalid),
                Err(DomainError::InvalidWakeServerUrl)
            );
        }
        let expanded_path = format!("https://wake.example.com/{}", "é".repeat(500));
        assert!(expanded_path.len() <= MAX_WAKE_SERVER_URL_BYTES);
        assert_eq!(
            SecureWakeServerUrl::parse(&expanded_path),
            Err(DomainError::InvalidWakeServerUrl)
        );
    }

    #[test]
    fn host_errors_expose_only_stable_classification() {
        let unavailable = HostError::new(HostErrorKind::Unavailable);
        let rejected = HostError::new(HostErrorKind::Rejected);

        assert!(unavailable.is_retryable());
        assert!(!rejected.is_retryable());
        assert_eq!(unavailable.to_string(), "host capability is unavailable");
    }

    #[test]
    fn capability_traits_are_object_safe() {
        fn accepts_capability<T: ?Sized>() {}

        accepts_capability::<dyn WalletBackend>();
        accepts_capability::<dyn RelayTransport>();
        accepts_capability::<dyn SecretProvider>();
    }
}
