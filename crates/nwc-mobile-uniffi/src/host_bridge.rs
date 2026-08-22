//! FFI-safe host capabilities used by the native engine facade.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use nwc_mobile::{
    AmountMsat, CancellationSignal, CreatedInvoice, EventId, HostError, HostErrorKind, HostFuture,
    InvoiceLookup, ListTransactionsRequest, MakeInvoiceRequest, NwcMethod, NwcSecretKey,
    OperationContext, PayInvoiceRequest, PaymentFailure, PaymentHash, PaymentPreimage,
    PaymentQuote, PaymentStatus, PublicKey, RelayTransport, SecretProvider, SecureRelayUrl,
    SecureWakeServerUrl, TransactionDirection, UnixTimestamp, WakeRegistrationChange,
    WakeRegistrationTransport, WalletBackend, WalletInfo, WalletTransaction,
};
use zeroize::Zeroize;

const MAX_INVOICE_BYTES: usize = 16 * 1024;
const MAX_TRANSACTION_RESULTS: usize = 100;

/// Cooperative cancellation shared by Rust, Swift, and Kotlin background work.
#[derive(Debug, uniffi::Object)]
pub struct MobileCancellation {
    cancelled: AtomicBool,
}

#[uniffi::export]
impl MobileCancellation {
    /// Creates an active cancellation signal.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            cancelled: AtomicBool::new(false),
        })
    }

    /// Requests cooperative cancellation. Calling this repeatedly is safe.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Returns whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl CancellationSignal for MobileCancellation {
    fn is_cancelled(&self) -> bool {
        self.is_cancelled()
    }
}

/// Stable native host failure classification.
///
/// Error strings, remote response bodies, and wallet diagnostics stay in the
/// host's protected logs and never cross into Rust durable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Error)]
pub enum MobileHostError {
    /// The capability is temporarily unavailable.
    Unavailable,
    /// The operation exceeded its supplied timeout.
    TimedOut,
    /// The operation observed cancellation.
    Cancelled,
    /// The host rejected a malformed or unsupported typed value.
    Rejected,
    /// The requested wallet object does not exist.
    NotFound,
    /// An idempotent operation with the same key is already running.
    AlreadyInProgress,
    /// The host encountered an internal failure.
    Internal,
}

impl fmt::Display for MobileHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "native capability is unavailable",
            Self::TimedOut => "native capability timed out",
            Self::Cancelled => "native capability was cancelled",
            Self::Rejected => "native capability rejected the request",
            Self::NotFound => "native wallet object was not found",
            Self::AlreadyInProgress => "native operation is already in progress",
            Self::Internal => "native capability failed",
        })
    }
}

impl std::error::Error for MobileHostError {}

impl From<MobileHostError> for HostError {
    fn from(error: MobileHostError) -> Self {
        let kind = match error {
            MobileHostError::Unavailable => HostErrorKind::Unavailable,
            MobileHostError::TimedOut => HostErrorKind::TimedOut,
            MobileHostError::Cancelled => HostErrorKind::Cancelled,
            MobileHostError::Rejected => HostErrorKind::Rejected,
            MobileHostError::NotFound => HostErrorKind::NotFound,
            MobileHostError::AlreadyInProgress => HostErrorKind::AlreadyInProgress,
            MobileHostError::Internal => HostErrorKind::Internal,
        };
        Self::new(kind)
    }
}

/// NIP-47 method advertised by a native wallet backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum MobileNwcMethod {
    /// Return wallet information.
    GetInfo,
    /// Return spendable balance.
    GetBalance,
    /// Create an invoice.
    MakeInvoice,
    /// Pay an invoice.
    PayInvoice,
    /// Look up one invoice or payment.
    LookupInvoice,
    /// List wallet transactions.
    ListTransactions,
}

impl From<MobileNwcMethod> for NwcMethod {
    fn from(method: MobileNwcMethod) -> Self {
        match method {
            MobileNwcMethod::GetInfo => Self::GetInfo,
            MobileNwcMethod::GetBalance => Self::GetBalance,
            MobileNwcMethod::MakeInvoice => Self::MakeInvoice,
            MobileNwcMethod::PayInvoice => Self::PayInvoice,
            MobileNwcMethod::LookupInvoice => Self::LookupInvoice,
            MobileNwcMethod::ListTransactions => Self::ListTransactions,
        }
    }
}

impl TryFrom<NwcMethod> for MobileNwcMethod {
    type Error = MobileHostError;

    fn try_from(method: NwcMethod) -> Result<Self, Self::Error> {
        Ok(match method {
            NwcMethod::GetInfo => Self::GetInfo,
            NwcMethod::GetBalance => Self::GetBalance,
            NwcMethod::MakeInvoice => Self::MakeInvoice,
            NwcMethod::PayInvoice => Self::PayInvoice,
            NwcMethod::LookupInvoice => Self::LookupInvoice,
            NwcMethod::ListTransactions => Self::ListTransactions,
            _ => return Err(MobileHostError::Rejected),
        })
    }
}

/// Wallet identity and supported methods returned by native code.
#[derive(Clone, Eq, PartialEq, uniffi::Record)]
pub struct MobileWalletInfo {
    /// Optional 32-byte hexadecimal wallet public key.
    pub public_key_hex: Option<String>,
    /// Methods the backend actually implements.
    pub methods: Vec<MobileNwcMethod>,
}

impl fmt::Debug for MobileWalletInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MobileWalletInfo")
            .field("has_public_key", &self.public_key_hex.is_some())
            .field("methods", &self.methods)
            .finish()
    }
}

/// Typed invoice-creation request passed to native code.
#[derive(Clone, Eq, PartialEq, uniffi::Record)]
pub struct MobileMakeInvoiceRequest {
    /// Requested amount in millisatoshis.
    pub amount_msat: u64,
    /// Sanitized, bounded description.
    pub description: Option<String>,
    /// Requested invoice lifetime.
    pub expiry_seconds: u64,
}

impl fmt::Debug for MobileMakeInvoiceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MobileMakeInvoiceRequest")
            .field("amount_msat", &self.amount_msat)
            .field("has_description", &self.description.is_some())
            .field("expiry_seconds", &self.expiry_seconds)
            .finish()
    }
}

/// Invoice result returned by native code.
#[derive(Clone, Eq, PartialEq, uniffi::Record)]
pub struct MobileCreatedInvoice {
    /// Encoded Lightning invoice.
    pub invoice: String,
    /// 32-byte hexadecimal payment hash.
    pub payment_hash_hex: String,
    /// Invoice amount in millisatoshis.
    pub amount_msat: u64,
    /// Whole-second Unix expiration time.
    pub expires_at_seconds: u64,
}

impl fmt::Debug for MobileCreatedInvoice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MobileCreatedInvoice")
            .field("invoice", &"[redacted]")
            .field("payment_hash_hex", &"[redacted]")
            .field("amount_msat", &self.amount_msat)
            .field("expires_at_seconds", &self.expires_at_seconds)
            .finish()
    }
}

/// Side-effect-free payment metadata returned before budget reservation.
#[derive(Clone, Eq, PartialEq, uniffi::Record)]
pub struct MobilePaymentQuote {
    /// 32-byte hexadecimal payment hash.
    pub payment_hash_hex: String,
    /// Exact principal in millisatoshis.
    pub principal_msat: u64,
}

impl fmt::Debug for MobilePaymentQuote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MobilePaymentQuote")
            .field("payment_hash_hex", &"[redacted]")
            .field("principal_msat", &self.principal_msat)
            .finish()
    }
}

/// Payment initiation request passed only after Rust commits a reservation.
#[derive(Clone, Eq, PartialEq, uniffi::Record)]
pub struct MobilePayInvoiceRequest {
    /// Encoded Lightning invoice.
    pub invoice: String,
    /// Explicit millisatoshi amount for an amountless invoice.
    pub amount_msat: Option<u64>,
    /// Maximum routing fee authorized by Rust policy.
    pub maximum_fee_sat: u64,
    /// Nostr event id used as the wallet idempotency key.
    pub idempotency_key_hex: String,
}

impl fmt::Debug for MobilePayInvoiceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MobilePayInvoiceRequest")
            .field("invoice", &"[redacted]")
            .field("amount_msat", &self.amount_msat)
            .field("maximum_fee_sat", &self.maximum_fee_sat)
            .field("idempotency_key_hex", &"[redacted]")
            .finish()
    }
}

/// Stable definitive payment-failure classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum MobilePaymentFailure {
    /// The invoice was invalid or expired.
    InvalidInvoice,
    /// The wallet lacked funds.
    InsufficientFunds,
    /// No route completed within constraints.
    NoRoute,
    /// The recipient rejected the payment.
    RecipientRejected,
    /// Another permanent failure occurred.
    Other,
}

/// Native wallet view of a payment hash.
#[derive(Clone, Eq, PartialEq, uniffi::Enum)]
pub enum MobilePaymentStatus {
    /// The wallet has no payment record.
    Unknown,
    /// The payment is pending or ambiguous.
    Pending,
    /// The payment settled.
    Succeeded {
        /// 32-byte hexadecimal payment preimage.
        preimage_hex: String,
        /// Principal paid in millisatoshis.
        amount_msat: u64,
        /// Routing fee paid in millisatoshis.
        fee_msat: u64,
    },
    /// The payment failed definitively.
    Failed {
        /// Stable permanent failure classification.
        reason: MobilePaymentFailure,
    },
}

impl fmt::Debug for MobilePaymentStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => formatter.write_str("Unknown"),
            Self::Pending => formatter.write_str("Pending"),
            Self::Succeeded {
                amount_msat,
                fee_msat,
                ..
            } => formatter
                .debug_struct("Succeeded")
                .field("preimage_hex", &"[redacted]")
                .field("amount_msat", amount_msat)
                .field("fee_msat", fee_msat)
                .finish(),
            Self::Failed { reason } => formatter
                .debug_struct("Failed")
                .field("reason", reason)
                .finish(),
        }
    }
}

/// Typed lookup selector passed to native code.
#[derive(Clone, Eq, PartialEq, uniffi::Enum)]
pub enum MobileInvoiceLookup {
    /// Look up a 32-byte hexadecimal payment hash.
    PaymentHash { payment_hash_hex: String },
    /// Look up an encoded Lightning invoice.
    Invoice { invoice: String },
}

impl fmt::Debug for MobileInvoiceLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PaymentHash { .. } => formatter.write_str("PaymentHash([redacted])"),
            Self::Invoice { .. } => formatter.write_str("Invoice([redacted])"),
        }
    }
}

/// Wallet transaction direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum MobileTransactionDirection {
    /// Funds received.
    Incoming,
    /// Funds sent.
    Outgoing,
}

/// Bounded transaction list request passed to native code.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileListTransactionsRequest {
    /// Inclusive lower creation-time bound.
    pub from_seconds: Option<u64>,
    /// Inclusive upper creation-time bound.
    pub until_seconds: Option<u64>,
    /// Engine-capped maximum number of records.
    pub limit: u16,
    /// Number of records to skip.
    pub offset: u32,
    /// Optional direction filter.
    pub direction: Option<MobileTransactionDirection>,
    /// Whether unpaid invoices may be returned.
    pub include_unpaid: bool,
}

/// Wallet transaction returned by native code.
#[derive(Clone, Eq, PartialEq, uniffi::Record)]
pub struct MobileWalletTransaction {
    /// Optional 32-byte hexadecimal payment hash.
    pub payment_hash_hex: Option<String>,
    /// Transaction direction.
    pub direction: MobileTransactionDirection,
    /// Principal amount in millisatoshis.
    pub amount_msat: u64,
    /// Routing fee in millisatoshis.
    pub fee_msat: u64,
    /// Whole-second Unix creation time.
    pub created_at_seconds: u64,
    /// Whole-second Unix settlement time.
    pub settled_at_seconds: Option<u64>,
    /// Durable payment status.
    pub status: MobilePaymentStatus,
}

impl fmt::Debug for MobileWalletTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MobileWalletTransaction")
            .field("has_payment_hash", &self.payment_hash_hex.is_some())
            .field("direction", &self.direction)
            .field("amount_msat", &self.amount_msat)
            .field("fee_msat", &self.fee_msat)
            .field("created_at_seconds", &self.created_at_seconds)
            .field("settled_at_seconds", &self.settled_at_seconds)
            .field("status", &self.status)
            .finish()
    }
}

/// Wallet operations implemented by the containing Swift or Kotlin app.
#[allow(async_fn_in_trait)]
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait MobileWalletBackend: Send + Sync {
    /// Returns wallet identity and implemented methods.
    async fn get_info(
        &self,
        timeout_milliseconds: u64,
        cancellation: Arc<MobileCancellation>,
    ) -> Result<MobileWalletInfo, MobileHostError>;

    /// Returns spendable balance in millisatoshis.
    async fn get_balance(
        &self,
        timeout_milliseconds: u64,
        cancellation: Arc<MobileCancellation>,
    ) -> Result<u64, MobileHostError>;

    /// Creates an invoice.
    async fn make_invoice(
        &self,
        request: MobileMakeInvoiceRequest,
        timeout_milliseconds: u64,
        cancellation: Arc<MobileCancellation>,
    ) -> Result<MobileCreatedInvoice, MobileHostError>;

    /// Parses an invoice without initiating payment.
    async fn quote_payment(
        &self,
        invoice: String,
        amount_msat: Option<u64>,
        timeout_milliseconds: u64,
        cancellation: Arc<MobileCancellation>,
    ) -> Result<MobilePaymentQuote, MobileHostError>;

    /// Reads durable payment status.
    async fn payment_status(
        &self,
        payment_hash_hex: String,
        timeout_milliseconds: u64,
        cancellation: Arc<MobileCancellation>,
    ) -> Result<MobilePaymentStatus, MobileHostError>;

    /// Starts an idempotent payment after Rust-side reservation.
    async fn start_payment(
        &self,
        request: MobilePayInvoiceRequest,
        timeout_milliseconds: u64,
        cancellation: Arc<MobileCancellation>,
    ) -> Result<MobilePaymentStatus, MobileHostError>;

    /// Looks up one invoice or payment.
    async fn lookup_invoice(
        &self,
        request: MobileInvoiceLookup,
        timeout_milliseconds: u64,
        cancellation: Arc<MobileCancellation>,
    ) -> Result<Option<MobileWalletTransaction>, MobileHostError>;

    /// Lists wallet transactions using engine-capped bounds.
    async fn list_transactions(
        &self,
        request: MobileListTransactionsRequest,
        timeout_milliseconds: u64,
        cancellation: Arc<MobileCancellation>,
    ) -> Result<Vec<MobileWalletTransaction>, MobileHostError>;
}

/// Relay operations implemented by the containing Swift or Kotlin app.
#[allow(async_fn_in_trait)]
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait MobileRelayTransport: Send + Sync {
    /// Fetches one exact event from an approved secure relay.
    async fn fetch_event(
        &self,
        relay_url: String,
        event_id_hex: String,
        maximum_event_bytes: u64,
        timeout_milliseconds: u64,
        cancellation: Arc<MobileCancellation>,
    ) -> Result<Option<String>, MobileHostError>;

    /// Publishes an engine-built response to an approved secure relay.
    async fn publish_event(
        &self,
        relay_url: String,
        event_json: String,
        timeout_milliseconds: u64,
        cancellation: Arc<MobileCancellation>,
    ) -> Result<(), MobileHostError>;
}

/// Narrow, on-demand access to platform-protected NWC secrets.
#[uniffi::export(with_foreign)]
pub trait MobileSecretProvider: Send + Sync {
    /// Returns exactly 32 secret bytes for one connection.
    ///
    /// Native code must create a fresh buffer for this call and must not log or
    /// cache it. Rust zeroizes its received copy immediately after validation.
    fn load_nwc_secret(&self, connection_id: String) -> Result<Vec<u8>, MobileHostError>;
}

/// Public, revision-bound wake-provider change passed to native networking.
#[derive(Clone, Eq, PartialEq, uniffi::Record)]
pub struct MobileWakeRegistrationChange {
    /// Stable wallet-local connection identifier used for idempotency.
    pub connection_id: String,
    /// Monotonic connection revision; providers must reject older revisions.
    pub connection_revision: u64,
    /// Whether the provider should enable or disable delivery.
    pub enabled: bool,
    /// Approved NWC client's 32-byte hexadecimal public key.
    pub client_public_key_hex: String,
    /// Wallet service's 32-byte hexadecimal public key.
    pub wallet_service_public_key_hex: String,
    /// Exact secure relay set associated with this revision.
    pub relay_urls: Vec<String>,
}

impl fmt::Debug for MobileWakeRegistrationChange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MobileWakeRegistrationChange")
            .field("connection_id", &"[redacted]")
            .field("connection_revision", &self.connection_revision)
            .field("enabled", &self.enabled)
            .field("client_public_key_hex", &"[redacted]")
            .field("wallet_service_public_key_hex", &"[redacted]")
            .field("relay_count", &self.relay_urls.len())
            .finish()
    }
}

/// HTTPS wake-provider operation implemented by the containing mobile app.
///
/// Implementations must disable redirects and return only a stable error class;
/// response bodies and transport diagnostics stay in protected native logs.
#[allow(async_fn_in_trait)]
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait MobileWakeRegistrationTransport: Send + Sync {
    /// Applies one exact desired provider state within the supplied deadline.
    async fn apply_wake_registration(
        &self,
        server_url: String,
        change: MobileWakeRegistrationChange,
        timeout_milliseconds: u64,
        cancellation: Arc<MobileCancellation>,
    ) -> Result<(), MobileHostError>;
}

/// Adapts the native wake-provider transport to the durable core worker.
pub(crate) struct MobileWakeRegistrationBridge {
    transport: Arc<dyn MobileWakeRegistrationTransport>,
    cancellation: Arc<MobileCancellation>,
}

impl MobileWakeRegistrationBridge {
    #[must_use]
    pub(crate) fn new(
        transport: Arc<dyn MobileWakeRegistrationTransport>,
        cancellation: Arc<MobileCancellation>,
    ) -> Self {
        Self {
            transport,
            cancellation,
        }
    }
}

impl WakeRegistrationTransport for MobileWakeRegistrationBridge {
    fn apply<'a>(
        &'a self,
        server_url: &'a SecureWakeServerUrl,
        change: &'a WakeRegistrationChange,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async move {
            self.transport
                .apply_wake_registration(
                    server_url.as_str().to_owned(),
                    MobileWakeRegistrationChange {
                        connection_id: change.connection_id().as_str().to_owned(),
                        connection_revision: change.connection_revision().value(),
                        enabled: change.enabled(),
                        client_public_key_hex: change.client_pubkey().to_hex(),
                        wallet_service_public_key_hex: change.wallet_service_pubkey().to_hex(),
                        relay_urls: change
                            .relays()
                            .iter()
                            .map(|relay| relay.as_str().to_owned())
                            .collect(),
                    },
                    timeout_milliseconds(context),
                    self.cancellation.clone(),
                )
                .await
                .map_err(HostError::from)
        })
    }
}

/// Adapts FFI-safe native capabilities to the core engine traits.
///
/// This adapter is crate-private so callers cannot pair it with an engine
/// context backed by a different cancellation object. [`crate::MobileNwcEngine`]
/// constructs a fresh bridge for each execution and supplies the same
/// [`MobileCancellation`] to both sides of the boundary.
pub(crate) struct MobileHostBridge {
    wallet: Arc<dyn MobileWalletBackend>,
    relays: Arc<dyn MobileRelayTransport>,
    secrets: Arc<dyn MobileSecretProvider>,
    cancellation: Arc<MobileCancellation>,
}

impl MobileHostBridge {
    /// Creates an adapter for one engine execution and cancellation scope.
    #[must_use]
    pub(crate) fn new(
        wallet: Arc<dyn MobileWalletBackend>,
        relays: Arc<dyn MobileRelayTransport>,
        secrets: Arc<dyn MobileSecretProvider>,
        cancellation: Arc<MobileCancellation>,
    ) -> Self {
        Self {
            wallet,
            relays,
            secrets,
            cancellation,
        }
    }
}

impl WalletBackend for MobileHostBridge {
    fn get_info<'a>(
        &'a self,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<WalletInfo, HostError>> {
        Box::pin(async move {
            let info = self
                .wallet
                .get_info(timeout_milliseconds(context), self.cancellation.clone())
                .await
                .map_err(HostError::from)?;
            let public_key = info
                .public_key_hex
                .map(|key| PublicKey::from_hex(&key))
                .transpose()
                .map_err(|_| rejected())?;
            Ok(WalletInfo::new(
                public_key,
                info.methods.into_iter().map(NwcMethod::from),
            ))
        })
    }

    fn get_balance<'a>(
        &'a self,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<AmountMsat, HostError>> {
        Box::pin(async move {
            self.wallet
                .get_balance(timeout_milliseconds(context), self.cancellation.clone())
                .await
                .map(AmountMsat::from_msat)
                .map_err(HostError::from)
        })
    }

    fn make_invoice<'a>(
        &'a self,
        request: MakeInvoiceRequest,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<CreatedInvoice, HostError>> {
        Box::pin(async move {
            let created = self
                .wallet
                .make_invoice(
                    MobileMakeInvoiceRequest {
                        amount_msat: request.amount().as_msat(),
                        description: request.description().map(str::to_owned),
                        expiry_seconds: request.expiry().as_secs(),
                    },
                    timeout_milliseconds(context),
                    self.cancellation.clone(),
                )
                .await
                .map_err(HostError::from)?;
            if created.invoice.is_empty() || created.invoice.len() > MAX_INVOICE_BYTES {
                return Err(rejected());
            }
            let payment_hash =
                PaymentHash::from_hex(&created.payment_hash_hex).map_err(|_| rejected())?;
            Ok(CreatedInvoice::new(
                created.invoice,
                payment_hash,
                AmountMsat::from_msat(created.amount_msat),
                UnixTimestamp::from_secs(created.expires_at_seconds),
            ))
        })
    }

    fn quote_payment<'a>(
        &'a self,
        invoice: &'a str,
        amount: Option<AmountMsat>,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<PaymentQuote, HostError>> {
        Box::pin(async move {
            if invoice.is_empty() || invoice.len() > MAX_INVOICE_BYTES {
                return Err(rejected());
            }
            let quote = self
                .wallet
                .quote_payment(
                    invoice.to_owned(),
                    amount.map(AmountMsat::as_msat),
                    timeout_milliseconds(context),
                    self.cancellation.clone(),
                )
                .await
                .map_err(HostError::from)?;
            let payment_hash =
                PaymentHash::from_hex(&quote.payment_hash_hex).map_err(|_| rejected())?;
            Ok(PaymentQuote::new(
                payment_hash,
                AmountMsat::from_msat(quote.principal_msat),
            ))
        })
    }

    fn payment_status<'a>(
        &'a self,
        payment_hash: &'a PaymentHash,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<PaymentStatus, HostError>> {
        Box::pin(async move {
            let status = self
                .wallet
                .payment_status(
                    payment_hash.to_hex(),
                    timeout_milliseconds(context),
                    self.cancellation.clone(),
                )
                .await
                .map_err(HostError::from)?;
            core_payment_status(status)
        })
    }

    fn start_payment<'a>(
        &'a self,
        request: PayInvoiceRequest,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<PaymentStatus, HostError>> {
        Box::pin(async move {
            let status = self
                .wallet
                .start_payment(
                    MobilePayInvoiceRequest {
                        invoice: request.invoice().to_owned(),
                        amount_msat: request.amount().map(AmountMsat::as_msat),
                        maximum_fee_sat: request.maximum_fee().as_sat(),
                        idempotency_key_hex: request.idempotency_key().to_hex(),
                    },
                    timeout_milliseconds(context),
                    self.cancellation.clone(),
                )
                .await
                .map_err(HostError::from)?;
            core_payment_status(status)
        })
    }

    fn lookup_invoice<'a>(
        &'a self,
        request: InvoiceLookup,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<Option<WalletTransaction>, HostError>> {
        Box::pin(async move {
            let request = match request {
                InvoiceLookup::PaymentHash(hash) => MobileInvoiceLookup::PaymentHash {
                    payment_hash_hex: hash.to_hex(),
                },
                InvoiceLookup::Invoice(invoice) => {
                    if invoice.is_empty() || invoice.len() > MAX_INVOICE_BYTES {
                        return Err(rejected());
                    }
                    MobileInvoiceLookup::Invoice { invoice }
                }
                _ => return Err(rejected()),
            };
            self.wallet
                .lookup_invoice(
                    request,
                    timeout_milliseconds(context),
                    self.cancellation.clone(),
                )
                .await
                .map_err(HostError::from)?
                .map(core_transaction)
                .transpose()
        })
    }

    fn list_transactions<'a>(
        &'a self,
        request: ListTransactionsRequest,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<Vec<WalletTransaction>, HostError>> {
        Box::pin(async move {
            let transactions = self
                .wallet
                .list_transactions(
                    MobileListTransactionsRequest {
                        from_seconds: request.from.map(UnixTimestamp::as_secs),
                        until_seconds: request.until.map(UnixTimestamp::as_secs),
                        limit: request.limit,
                        offset: request.offset,
                        direction: request.direction.map(mobile_direction).transpose()?,
                        include_unpaid: request.include_unpaid,
                    },
                    timeout_milliseconds(context),
                    self.cancellation.clone(),
                )
                .await
                .map_err(HostError::from)?;
            if transactions.len() > usize::from(request.limit)
                || transactions.len() > MAX_TRANSACTION_RESULTS
            {
                return Err(rejected());
            }
            transactions.into_iter().map(core_transaction).collect()
        })
    }
}

impl RelayTransport for MobileHostBridge {
    fn fetch_event<'a>(
        &'a self,
        relay: &'a SecureRelayUrl,
        event_id: &'a EventId,
        maximum_event_bytes: usize,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<Option<String>, HostError>> {
        Box::pin(async move {
            let maximum_event_bytes = u64::try_from(maximum_event_bytes).map_err(|_| rejected())?;
            let event = self
                .relays
                .fetch_event(
                    relay.as_str().to_owned(),
                    event_id.to_hex(),
                    maximum_event_bytes,
                    timeout_milliseconds(context),
                    self.cancellation.clone(),
                )
                .await
                .map_err(HostError::from)?;
            if event.as_ref().is_some_and(|value| {
                u64::try_from(value.len()).map_or(true, |length| length > maximum_event_bytes)
            }) {
                return Err(rejected());
            }
            Ok(event)
        })
    }

    fn publish_event<'a>(
        &'a self,
        relay: &'a SecureRelayUrl,
        event_json: &'a str,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(async move {
            self.relays
                .publish_event(
                    relay.as_str().to_owned(),
                    event_json.to_owned(),
                    timeout_milliseconds(context),
                    self.cancellation.clone(),
                )
                .await
                .map_err(HostError::from)
        })
    }
}

impl SecretProvider for MobileHostBridge {
    fn load_nwc_secret(
        &self,
        connection_id: &nwc_mobile::ConnectionId,
    ) -> Result<NwcSecretKey, HostError> {
        let mut bytes = self
            .secrets
            .load_nwc_secret(connection_id.as_str().to_owned())
            .map_err(HostError::from)?;
        if bytes.len() != 32 {
            bytes.zeroize();
            return Err(rejected());
        }
        let mut secret = [0_u8; 32];
        secret.copy_from_slice(&bytes);
        bytes.zeroize();
        let result = NwcSecretKey::from_bytes(secret).map_err(|_| rejected());
        secret.zeroize();
        result
    }
}

fn timeout_milliseconds(context: OperationContext<'_>) -> u64 {
    u64::try_from(context.budget().timeout().as_millis()).unwrap_or(u64::MAX)
}

fn rejected() -> HostError {
    HostError::new(HostErrorKind::Rejected)
}

fn core_payment_status(status: MobilePaymentStatus) -> Result<PaymentStatus, HostError> {
    match status {
        MobilePaymentStatus::Unknown => Ok(PaymentStatus::Unknown),
        MobilePaymentStatus::Pending => Ok(PaymentStatus::Pending),
        MobilePaymentStatus::Succeeded {
            preimage_hex,
            amount_msat,
            fee_msat,
        } => Ok(PaymentStatus::Succeeded {
            preimage: PaymentPreimage::from_hex(&preimage_hex).map_err(|_| rejected())?,
            amount: AmountMsat::from_msat(amount_msat),
            fee: AmountMsat::from_msat(fee_msat),
        }),
        MobilePaymentStatus::Failed { reason } => Ok(PaymentStatus::Failed {
            reason: match reason {
                MobilePaymentFailure::InvalidInvoice => PaymentFailure::InvalidInvoice,
                MobilePaymentFailure::InsufficientFunds => PaymentFailure::InsufficientFunds,
                MobilePaymentFailure::NoRoute => PaymentFailure::NoRoute,
                MobilePaymentFailure::RecipientRejected => PaymentFailure::RecipientRejected,
                MobilePaymentFailure::Other => PaymentFailure::Other,
            },
        }),
    }
}

fn core_transaction(transaction: MobileWalletTransaction) -> Result<WalletTransaction, HostError> {
    Ok(WalletTransaction {
        payment_hash: transaction
            .payment_hash_hex
            .map(|hash| PaymentHash::from_hex(&hash))
            .transpose()
            .map_err(|_| rejected())?,
        direction: match transaction.direction {
            MobileTransactionDirection::Incoming => TransactionDirection::Incoming,
            MobileTransactionDirection::Outgoing => TransactionDirection::Outgoing,
        },
        amount: AmountMsat::from_msat(transaction.amount_msat),
        fee: AmountMsat::from_msat(transaction.fee_msat),
        created_at: UnixTimestamp::from_secs(transaction.created_at_seconds),
        settled_at: transaction.settled_at_seconds.map(UnixTimestamp::from_secs),
        status: core_payment_status(transaction.status)?,
    })
}

fn mobile_direction(
    direction: TransactionDirection,
) -> Result<MobileTransactionDirection, HostError> {
    match direction {
        TransactionDirection::Incoming => Ok(MobileTransactionDirection::Incoming),
        TransactionDirection::Outgoing => Ok(MobileTransactionDirection::Outgoing),
        _ => Err(rejected()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nwc_mobile::{OperationBudget, PaymentStatus};
    use std::sync::Mutex;
    use std::time::Duration;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn registration_change_debug_redacts_provider_metadata() {
        let change = MobileWakeRegistrationChange {
            connection_id: "private-connection".to_owned(),
            connection_revision: 7,
            enabled: true,
            client_public_key_hex: HEX.to_owned(),
            wallet_service_public_key_hex: HEX.to_owned(),
            relay_urls: vec!["wss://relay.example".to_owned()],
        };
        let debug = format!("{change:?}");

        assert!(!debug.contains("private-connection"));
        assert!(!debug.contains(HEX));
        assert!(!debug.contains("relay.example"));
        assert!(debug.contains("connection_revision: 7"));
        assert!(debug.contains("relay_count: 1"));
    }

    #[derive(Debug, Default)]
    struct TestWallet {
        last_payment: Mutex<Option<MobilePayInvoiceRequest>>,
    }

    #[async_trait::async_trait]
    impl MobileWalletBackend for TestWallet {
        async fn get_info(
            &self,
            _timeout_milliseconds: u64,
            _cancellation: Arc<MobileCancellation>,
        ) -> Result<MobileWalletInfo, MobileHostError> {
            Ok(MobileWalletInfo {
                public_key_hex: Some(HEX.to_owned()),
                methods: vec![MobileNwcMethod::GetInfo, MobileNwcMethod::PayInvoice],
            })
        }

        async fn get_balance(
            &self,
            _timeout_milliseconds: u64,
            _cancellation: Arc<MobileCancellation>,
        ) -> Result<u64, MobileHostError> {
            Ok(42_000)
        }

        async fn make_invoice(
            &self,
            request: MobileMakeInvoiceRequest,
            _timeout_milliseconds: u64,
            _cancellation: Arc<MobileCancellation>,
        ) -> Result<MobileCreatedInvoice, MobileHostError> {
            Ok(MobileCreatedInvoice {
                invoice: "lnbc-test".to_owned(),
                payment_hash_hex: HEX.to_owned(),
                amount_msat: request.amount_msat,
                expires_at_seconds: 2_000,
            })
        }

        async fn quote_payment(
            &self,
            _invoice: String,
            amount_msat: Option<u64>,
            _timeout_milliseconds: u64,
            _cancellation: Arc<MobileCancellation>,
        ) -> Result<MobilePaymentQuote, MobileHostError> {
            Ok(MobilePaymentQuote {
                payment_hash_hex: HEX.to_owned(),
                principal_msat: amount_msat.unwrap_or(1_000),
            })
        }

        async fn payment_status(
            &self,
            _payment_hash_hex: String,
            _timeout_milliseconds: u64,
            _cancellation: Arc<MobileCancellation>,
        ) -> Result<MobilePaymentStatus, MobileHostError> {
            Ok(MobilePaymentStatus::Pending)
        }

        async fn start_payment(
            &self,
            request: MobilePayInvoiceRequest,
            _timeout_milliseconds: u64,
            _cancellation: Arc<MobileCancellation>,
        ) -> Result<MobilePaymentStatus, MobileHostError> {
            *self.last_payment.lock().expect("payment mutex") = Some(request);
            Ok(MobilePaymentStatus::Pending)
        }

        async fn lookup_invoice(
            &self,
            _request: MobileInvoiceLookup,
            _timeout_milliseconds: u64,
            _cancellation: Arc<MobileCancellation>,
        ) -> Result<Option<MobileWalletTransaction>, MobileHostError> {
            Ok(None)
        }

        async fn list_transactions(
            &self,
            _request: MobileListTransactionsRequest,
            _timeout_milliseconds: u64,
            _cancellation: Arc<MobileCancellation>,
        ) -> Result<Vec<MobileWalletTransaction>, MobileHostError> {
            Ok(Vec::new())
        }
    }

    #[derive(Debug, Default)]
    struct TestRelay;

    #[async_trait::async_trait]
    impl MobileRelayTransport for TestRelay {
        async fn fetch_event(
            &self,
            _relay_url: String,
            _event_id_hex: String,
            _maximum_event_bytes: u64,
            _timeout_milliseconds: u64,
            _cancellation: Arc<MobileCancellation>,
        ) -> Result<Option<String>, MobileHostError> {
            Ok(Some("{}".to_owned()))
        }

        async fn publish_event(
            &self,
            _relay_url: String,
            _event_json: String,
            _timeout_milliseconds: u64,
            _cancellation: Arc<MobileCancellation>,
        ) -> Result<(), MobileHostError> {
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct TestSecrets;

    impl MobileSecretProvider for TestSecrets {
        fn load_nwc_secret(&self, _connection_id: String) -> Result<Vec<u8>, MobileHostError> {
            Ok(vec![1_u8; 32])
        }
    }

    #[derive(Debug, Default)]
    struct ShortSecret;

    impl MobileSecretProvider for ShortSecret {
        fn load_nwc_secret(&self, _connection_id: String) -> Result<Vec<u8>, MobileHostError> {
            Ok(vec![1_u8; 31])
        }
    }

    fn bridge(cancellation: Arc<MobileCancellation>) -> MobileHostBridge {
        MobileHostBridge::new(
            Arc::new(TestWallet::default()),
            Arc::new(TestRelay),
            Arc::new(TestSecrets),
            cancellation,
        )
    }

    fn context<'a>(cancellation: &'a MobileCancellation) -> OperationContext<'a> {
        OperationContext::new(
            OperationBudget::new(Duration::from_millis(1_250)).expect("budget"),
            cancellation,
        )
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let mut task_context = std::task::Context::from_waker(std::task::Waker::noop());
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut task_context) {
                std::task::Poll::Ready(output) => return output,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn wallet_bridge_converts_typed_values_and_budget() {
        let cancellation = MobileCancellation::new();
        let bridge = bridge(cancellation.clone());
        let info = block_on(bridge.get_info(context(&cancellation))).expect("wallet info");

        assert_eq!(info.public_key().expect("public key").to_hex(), HEX);
        assert!(info.methods().any(|method| method == NwcMethod::PayInvoice));
        assert_eq!(
            block_on(bridge.get_balance(context(&cancellation))),
            Ok(AmountMsat::from_msat(42_000))
        );
    }

    #[test]
    fn malformed_native_values_fail_closed() {
        assert_eq!(
            core_payment_status(MobilePaymentStatus::Succeeded {
                preimage_hex: "not-a-preimage".to_owned(),
                amount_msat: 1_000,
                fee_msat: 1,
            })
            .expect_err("invalid preimage")
            .kind(),
            HostErrorKind::Rejected
        );
    }

    #[test]
    fn secret_bridge_rejects_wrong_length_key_material() {
        let bridge = MobileHostBridge::new(
            Arc::new(TestWallet::default()),
            Arc::new(TestRelay),
            Arc::new(ShortSecret),
            MobileCancellation::new(),
        );
        let connection = nwc_mobile::ConnectionId::parse("connection:test").expect("connection");

        assert_eq!(
            SecretProvider::load_nwc_secret(&bridge, &connection)
                .expect_err("short secret")
                .kind(),
            HostErrorKind::Rejected
        );
    }

    #[test]
    fn cancellation_is_monotonic_and_shared() {
        let cancellation = MobileCancellation::new();
        let clone = cancellation.clone();
        assert!(!clone.is_cancelled());
        cancellation.cancel();
        assert!(clone.is_cancelled());
    }

    #[test]
    fn sensitive_ffi_values_redact_debug_output() {
        let payment = MobilePayInvoiceRequest {
            invoice: "lnbc-secret".to_owned(),
            amount_msat: Some(1_000),
            maximum_fee_sat: 10,
            idempotency_key_hex: HEX.to_owned(),
        };
        let status = MobilePaymentStatus::Succeeded {
            preimage_hex: HEX.to_owned(),
            amount_msat: 1_000,
            fee_msat: 2,
        };

        assert!(!format!("{payment:?}").contains("lnbc-secret"));
        assert!(!format!("{payment:?}").contains(HEX));
        assert!(!format!("{status:?}").contains(HEX));
    }

    #[test]
    fn payment_status_conversion_preserves_pending_state() {
        assert_eq!(
            core_payment_status(MobilePaymentStatus::Pending),
            Ok(PaymentStatus::Pending)
        );
    }
}
