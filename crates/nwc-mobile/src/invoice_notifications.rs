use std::fmt;

use nostr::hashes::{sha256, Hash};
use nostr::nips::nip47::{
    Notification, NotificationResult, NotificationType, PaymentNotification, TransactionState,
    TransactionType,
};
use nostr::{EventBuilder, JsonUtil, Keys, Kind, PublicKey as NostrPublicKey, Tag, Timestamp};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    ActiveConnection, AmountMsat, CancellationSignal, Clock, ConnectionId, ConnectionRevision,
    EventId, HostError, InvoiceLookup, LedgerError, NwcEncryption, NwcSecretKey, OperationBudget,
    PaymentHash, PaymentStatus, RelayTransport, SecretProvider, UnixTimestamp, WakeLedger,
    WalletBackend, WalletTransaction,
};

const MAX_INVOICE_BYTES: usize = 16_384;
const MAX_DESCRIPTION_BYTES: usize = 4_096;
const MAX_NOTIFICATION_EVENT_BYTES: usize = 128 * 1_024;
const DEFAULT_BATCH_SIZE: usize = 20;
const SETTLEMENT_RECONCILIATION_GRACE_SECONDS: u64 = 24 * 60 * 60;
const SETTLEMENT_TRIGGER_TOKEN_BYTES: usize = 32;

pub(crate) const ADD_INVOICE_SETTLEMENT_TRIGGER: &str = r#"
ALTER TABLE nwc_created_invoices ADD COLUMN settlement_trigger_token BLOB
    CHECK(settlement_trigger_token IS NULL OR
          (typeof(settlement_trigger_token) = 'blob' AND length(settlement_trigger_token) = 32));
UPDATE nwc_created_invoices
SET settlement_trigger_token = randomblob(32)
WHERE settlement_trigger_token IS NULL;
"#;

pub(crate) const CREATE_INVOICE_NOTIFICATION_SCHEMA: &str = r#"
CREATE TABLE nwc_created_invoices (
    request_event_id    BLOB PRIMARY KEY NOT NULL
                        CHECK(typeof(request_event_id) = 'blob' AND length(request_event_id) = 32),
    payment_hash        BLOB NOT NULL UNIQUE
                        CHECK(typeof(payment_hash) = 'blob' AND length(payment_hash) = 32),
    connection_id       TEXT NOT NULL REFERENCES connections(connection_id) ON DELETE RESTRICT,
    connection_revision INTEGER NOT NULL CHECK(connection_revision >= 0),
    invoice             TEXT NOT NULL
                        CHECK(length(CAST(invoice AS BLOB)) BETWEEN 1 AND 16384),
    description         TEXT
                        CHECK(description IS NULL OR length(CAST(description AS BLOB)) <= 4096),
    amount_msat         INTEGER NOT NULL CHECK(amount_msat > 0),
    created_at          INTEGER NOT NULL CHECK(created_at >= 0),
    expires_at          INTEGER NOT NULL CHECK(expires_at > created_at),
    last_checked_at     INTEGER NOT NULL CHECK(last_checked_at >= created_at),
    notification_event_json TEXT,
    notification_created_at INTEGER,
    completed_at        INTEGER,
    CHECK(notification_event_json IS NULL OR
          (typeof(notification_event_json) = 'text' AND
           length(CAST(notification_event_json AS BLOB)) <= 131072)),
    CHECK((notification_event_json IS NULL AND notification_created_at IS NULL) OR
          (notification_event_json IS NOT NULL AND notification_created_at IS NOT NULL)),
    CHECK(completed_at IS NULL OR notification_event_json IS NOT NULL)
) STRICT;

CREATE INDEX nwc_created_invoices_pending
    ON nwc_created_invoices(last_checked_at, created_at)
    WHERE completed_at IS NULL;

CREATE TABLE nwc_invoice_notification_relays (
    request_event_id BLOB NOT NULL
                     REFERENCES nwc_created_invoices(request_event_id) ON DELETE CASCADE,
    position         INTEGER NOT NULL CHECK(position >= 0),
    relay_url        TEXT NOT NULL
                     CHECK(length(CAST(relay_url AS BLOB)) BETWEEN 1 AND 2048),
    delivered_at     INTEGER,
    PRIMARY KEY(request_event_id, position),
    UNIQUE(request_event_id, relay_url)
) STRICT;

CREATE TABLE nwc_sent_payments (
    request_event_id    BLOB PRIMARY KEY NOT NULL
                        CHECK(typeof(request_event_id) = 'blob' AND length(request_event_id) = 32),
    payment_hash        BLOB NOT NULL UNIQUE
                        CHECK(typeof(payment_hash) = 'blob' AND length(payment_hash) = 32),
    connection_id       TEXT NOT NULL REFERENCES connections(connection_id) ON DELETE RESTRICT,
    connection_revision INTEGER NOT NULL CHECK(connection_revision >= 0),
    invoice             TEXT NOT NULL
                        CHECK(length(CAST(invoice AS BLOB)) BETWEEN 1 AND 16384),
    amount_msat         INTEGER NOT NULL CHECK(amount_msat > 0),
    fee_msat            INTEGER NOT NULL CHECK(fee_msat >= 0),
    preimage            BLOB NOT NULL
                        CHECK(typeof(preimage) = 'blob' AND length(preimage) = 32),
    created_at          INTEGER NOT NULL CHECK(created_at >= 0),
    settled_at          INTEGER NOT NULL CHECK(settled_at >= created_at),
    notification_event_json TEXT,
    completed_at        INTEGER,
    CHECK(notification_event_json IS NULL OR
          (typeof(notification_event_json) = 'text' AND
           length(CAST(notification_event_json AS BLOB)) <= 131072)),
    CHECK(completed_at IS NULL OR notification_event_json IS NOT NULL)
) STRICT;

CREATE INDEX nwc_sent_payments_pending
    ON nwc_sent_payments(created_at)
    WHERE completed_at IS NULL;

CREATE TABLE nwc_sent_payment_relays (
    request_event_id BLOB NOT NULL
                     REFERENCES nwc_sent_payments(request_event_id) ON DELETE CASCADE,
    position         INTEGER NOT NULL CHECK(position >= 0),
    relay_url        TEXT NOT NULL
                     CHECK(length(CAST(relay_url AS BLOB)) BETWEEN 1 AND 2048),
    delivered_at     INTEGER,
    PRIMARY KEY(request_event_id, position),
    UNIQUE(request_event_id, relay_url)
) STRICT;
"#;

/// A durable invoice created for one authenticated NWC request.
#[derive(Clone, Eq, PartialEq)]
pub struct TrackedNwcInvoice {
    request_event_id: EventId,
    payment_hash: PaymentHash,
    connection_id: ConnectionId,
    connection_revision: ConnectionRevision,
    invoice: String,
    description: Option<String>,
    amount: AmountMsat,
    created_at: UnixTimestamp,
    expires_at: UnixTimestamp,
    notification_event_json: Option<String>,
}

impl TrackedNwcInvoice {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        request_event_id: EventId,
        payment_hash: PaymentHash,
        connection_id: ConnectionId,
        connection_revision: ConnectionRevision,
        invoice: String,
        description: Option<String>,
        amount: AmountMsat,
        created_at: UnixTimestamp,
        expires_at: UnixTimestamp,
    ) -> Self {
        Self {
            request_event_id,
            payment_hash,
            connection_id,
            connection_revision,
            invoice,
            description,
            amount,
            created_at,
            expires_at,
            notification_event_json: None,
        }
    }

    /// Returns the NWC request event that created the invoice.
    #[must_use]
    pub const fn request_event_id(&self) -> &EventId {
        &self.request_event_id
    }

    /// Returns the wallet payment hash.
    #[must_use]
    pub const fn payment_hash(&self) -> &PaymentHash {
        &self.payment_hash
    }

    /// Returns the owning connection identifier.
    #[must_use]
    pub const fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    /// Returns the owning connection revision.
    #[must_use]
    pub const fn connection_revision(&self) -> ConnectionRevision {
        self.connection_revision
    }

    /// Returns the encoded Lightning invoice.
    #[must_use]
    pub fn invoice(&self) -> &str {
        &self.invoice
    }

    /// Returns the optional payer-visible description.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the invoice amount.
    #[must_use]
    pub const fn amount(&self) -> AmountMsat {
        self.amount
    }

    /// Returns when the invoice was created.
    #[must_use]
    pub const fn created_at(&self) -> UnixTimestamp {
        self.created_at
    }

    /// Returns when the invoice expires.
    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }

    /// Returns the canonical encrypted notification event once constructed.
    #[must_use]
    pub fn notification_event_json(&self) -> Option<&str> {
        self.notification_event_json.as_deref()
    }
}

impl fmt::Debug for TrackedNwcInvoice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrackedNwcInvoice")
            .field("request_event_id", &self.request_event_id)
            .field("payment_hash", &self.payment_hash)
            .field("connection_id", &"[redacted]")
            .field("connection_revision", &self.connection_revision)
            .field("invoice", &"[redacted]")
            .field(
                "description",
                &self.description.as_ref().map(|_| "[redacted]"),
            )
            .field("amount", &self.amount)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field(
                "has_notification_event",
                &self.notification_event_json.is_some(),
            )
            .finish()
    }
}

/// A successful outgoing NWC payment awaiting `payment_sent` delivery.
#[derive(Clone, Eq, PartialEq)]
pub struct TrackedNwcPayment {
    request_event_id: EventId,
    payment_hash: PaymentHash,
    connection_id: ConnectionId,
    connection_revision: ConnectionRevision,
    invoice: String,
    amount: AmountMsat,
    fee: AmountMsat,
    preimage: crate::PaymentPreimage,
    created_at: UnixTimestamp,
    settled_at: UnixTimestamp,
    notification_event_json: Option<String>,
}

/// Public routing metadata for a server-scheduled invoice settlement check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvoiceSettlementMonitor {
    request_event_id: EventId,
    client_pubkey: crate::PublicKey,
    wallet_service_pubkey: crate::PublicKey,
    relays: Vec<crate::SecureRelayUrl>,
    expires_at: UnixTimestamp,
    completed: bool,
    trigger_token_hash: String,
}

impl InvoiceSettlementMonitor {
    /// Returns the original `make_invoice` request event identifier.
    #[must_use]
    pub const fn request_event_id(&self) -> &EventId {
        &self.request_event_id
    }

    /// Returns the authorized NWC client public key.
    #[must_use]
    pub const fn client_pubkey(&self) -> &crate::PublicKey {
        &self.client_pubkey
    }

    /// Returns the wallet-service public key used to authenticate scheduling.
    #[must_use]
    pub const fn wallet_service_pubkey(&self) -> &crate::PublicKey {
        &self.wallet_service_pubkey
    }

    /// Returns the approved relays where the original request can be fetched.
    #[must_use]
    pub fn relays(&self) -> &[crate::SecureRelayUrl] {
        &self.relays
    }

    /// Returns the maximum time the server may schedule checks.
    #[must_use]
    pub const fn expires_at(&self) -> UnixTimestamp {
        self.expires_at
    }

    /// Returns whether the NIP-47 notification has reached every relay.
    #[must_use]
    pub const fn completed(&self) -> bool {
        self.completed
    }

    /// Returns the SHA-256 commitment to the single-invoice wake capability.
    #[must_use]
    pub fn trigger_token_hash(&self) -> &str {
        &self.trigger_token_hash
    }
}

impl TrackedNwcPayment {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        request_event_id: EventId,
        payment_hash: PaymentHash,
        connection: &ActiveConnection,
        invoice: String,
        amount: AmountMsat,
        fee: AmountMsat,
        preimage: crate::PaymentPreimage,
        created_at: UnixTimestamp,
        settled_at: UnixTimestamp,
    ) -> Self {
        Self {
            request_event_id,
            payment_hash,
            connection_id: connection.id().clone(),
            connection_revision: connection.revision(),
            invoice,
            amount,
            fee,
            preimage,
            created_at,
            settled_at,
            notification_event_json: None,
        }
    }
}

impl fmt::Debug for TrackedNwcPayment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrackedNwcPayment")
            .field("request_event_id", &self.request_event_id)
            .field("payment_hash", &self.payment_hash)
            .field("connection_id", &"[redacted]")
            .field("connection_revision", &self.connection_revision)
            .field("invoice", &"[redacted]")
            .field("amount", &self.amount)
            .field("fee", &self.fee)
            .field("created_at", &self.created_at)
            .field("settled_at", &self.settled_at)
            .field(
                "has_notification_event",
                &self.notification_event_json.is_some(),
            )
            .finish()
    }
}

/// A stable failure while constructing or delivering an invoice notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum InvoiceNotificationError {
    /// Durable notification state could not be read or updated.
    Ledger,
    /// Wallet settlement state could not be read.
    Wallet,
    /// The wallet-service signing key was unavailable or mismatched.
    Secret,
    /// The NIP-47 event could not be constructed.
    Build,
}

impl fmt::Display for InvoiceNotificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ledger => "invoice notification storage is unavailable",
            Self::Wallet => "invoice settlement state is unavailable",
            Self::Secret => "invoice notification signing key is unavailable",
            Self::Build => "invoice notification event could not be built",
        })
    }
}

impl std::error::Error for InvoiceNotificationError {}

/// Non-sensitive counts from one bounded settlement-notification pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InvoiceNotificationWorkerReport {
    /// Number of durable payment records inspected.
    pub inspected: usize,
    /// Number of invoices that have not settled yet.
    pub pending: usize,
    /// Number of records discarded after expiration or revocation.
    pub expired: usize,
    /// Number of notifications delivered to every configured relay.
    pub delivered: usize,
    /// Number of notifications retaining retryable relay work.
    pub retryable: usize,
}

impl InvoiceNotificationWorkerReport {
    /// Returns whether another worker pass is required.
    #[must_use]
    pub const fn has_pending_work(self) -> bool {
        self.pending > 0 || self.retryable > 0
    }
}

/// Bounded, retry-safe worker for NIP-47 `payment_received` notifications.
pub struct InvoiceNotificationWorker<'a> {
    ledger: &'a WakeLedger,
    wallet: &'a dyn WalletBackend,
    relays: &'a dyn RelayTransport,
    secrets: &'a dyn SecretProvider,
    clock: &'a dyn Clock,
}

impl<'a> InvoiceNotificationWorker<'a> {
    /// Creates a worker from host wallet, relay, key, clock, and ledger capabilities.
    #[must_use]
    pub const fn new(
        ledger: &'a WakeLedger,
        wallet: &'a dyn WalletBackend,
        relays: &'a dyn RelayTransport,
        secrets: &'a dyn SecretProvider,
        clock: &'a dyn Clock,
    ) -> Self {
        Self {
            ledger,
            wallet,
            relays,
            secrets,
            clock,
        }
    }

    /// Runs one bounded, cancellation-aware notification pass.
    pub async fn run(
        &self,
        budget: OperationBudget,
        cancellation: &dyn CancellationSignal,
    ) -> Result<InvoiceNotificationWorkerReport, InvoiceNotificationError> {
        let deadline = crate::time::OperationDeadline::new(budget);
        let mut report = InvoiceNotificationWorkerReport::default();
        let payments = self
            .ledger
            .pending_nwc_sent_payments(DEFAULT_BATCH_SIZE)
            .map_err(|_| InvoiceNotificationError::Ledger)?;
        for payment in payments {
            if cancellation.is_cancelled() {
                break;
            }
            report.inspected += 1;
            let connection = self
                .ledger
                .load_active_connection(&payment.connection_id)
                .map_err(|_| InvoiceNotificationError::Ledger)?
                .filter(|connection| connection.revision() == payment.connection_revision);
            let Some(connection) = connection else {
                self.ledger
                    .discard_nwc_sent_payment(&payment.request_event_id)
                    .map_err(|_| InvoiceNotificationError::Ledger)?;
                report.expired += 1;
                continue;
            };
            let event_json = match &payment.notification_event_json {
                Some(event) => event.clone(),
                None => {
                    let secret = self
                        .secrets
                        .load_nwc_secret(connection.id())
                        .map_err(|_| InvoiceNotificationError::Secret)?;
                    let proposed =
                        build_payment_sent_notification_event(&connection, &secret, &payment)?;
                    self.ledger
                        .store_nwc_sent_notification_event(&payment.request_event_id, &proposed)
                        .map_err(|_| InvoiceNotificationError::Ledger)?
                }
            };
            let relays = self
                .ledger
                .undelivered_nwc_sent_relays(&payment.request_event_id)
                .map_err(|_| InvoiceNotificationError::Ledger)?;
            let mut failed = false;
            for relay in relays {
                let Some(context) = deadline.context(cancellation) else {
                    failed = true;
                    break;
                };
                match self
                    .relays
                    .publish_event(&relay, &event_json, context)
                    .await
                {
                    Ok(()) => self
                        .ledger
                        .acknowledge_nwc_sent_relay(
                            &payment.request_event_id,
                            &relay,
                            self.clock.now(),
                        )
                        .map_err(|_| InvoiceNotificationError::Ledger)?,
                    Err(_) => failed = true,
                }
            }
            if failed {
                report.retryable += 1;
            } else {
                self.ledger
                    .complete_nwc_sent_notification(&payment.request_event_id, self.clock.now())
                    .map_err(|_| InvoiceNotificationError::Ledger)?;
                report.delivered += 1;
            }
        }
        let invoices = self
            .ledger
            .pending_nwc_invoices(DEFAULT_BATCH_SIZE)
            .map_err(|_| InvoiceNotificationError::Ledger)?;
        for invoice in invoices {
            if cancellation.is_cancelled() {
                break;
            }
            self.process_invoice(&invoice, &deadline, cancellation, &mut report)
                .await?;
        }
        Ok(report)
    }

    /// Reconciles and publishes one exact NWC-created invoice.
    ///
    /// Server-scheduled mobile wakes use this path so an older pending invoice
    /// cannot consume the platform background window ahead of the invoice that
    /// caused the wake.
    pub async fn run_invoice(
        &self,
        request_event_id: &EventId,
        budget: OperationBudget,
        cancellation: &dyn CancellationSignal,
    ) -> Result<InvoiceNotificationWorkerReport, InvoiceNotificationError> {
        let deadline = crate::time::OperationDeadline::new(budget);
        let mut report = InvoiceNotificationWorkerReport::default();
        let invoice = self
            .ledger
            .pending_nwc_invoice(request_event_id)
            .map_err(|_| InvoiceNotificationError::Ledger)?;
        if let Some(invoice) = invoice {
            self.process_invoice(&invoice, &deadline, cancellation, &mut report)
                .await?;
        }
        Ok(report)
    }

    async fn process_invoice(
        &self,
        invoice: &TrackedNwcInvoice,
        deadline: &crate::time::OperationDeadline,
        cancellation: &dyn CancellationSignal,
        report: &mut InvoiceNotificationWorkerReport,
    ) -> Result<(), InvoiceNotificationError> {
        report.inspected += 1;
        self.ledger
            .touch_nwc_invoice(invoice.request_event_id(), self.clock.now())
            .map_err(|_| InvoiceNotificationError::Ledger)?;
        let event_json = match invoice.notification_event_json() {
            Some(event) => event.to_owned(),
            None => {
                let Some(context) = deadline.context(cancellation) else {
                    report.retryable += 1;
                    return Ok(());
                };
                let transaction = match self
                    .wallet
                    .lookup_invoice(
                        InvoiceLookup::PaymentHash(invoice.payment_hash().clone()),
                        context,
                    )
                    .await
                {
                    Ok(transaction) => transaction,
                    Err(_) => {
                        report.retryable += 1;
                        return Ok(());
                    }
                };
                let Some(transaction) = transaction else {
                    self.defer_or_expire_invoice(invoice, report)?;
                    return Ok(());
                };
                if !matches!(transaction.status, PaymentStatus::Succeeded { .. }) {
                    self.defer_or_expire_invoice(invoice, report)?;
                    return Ok(());
                }
                let connection = self
                    .ledger
                    .load_active_connection(invoice.connection_id())
                    .map_err(|_| InvoiceNotificationError::Ledger)?
                    .filter(|connection| connection.revision() == invoice.connection_revision());
                let Some(connection) = connection else {
                    self.ledger
                        .expire_nwc_invoice(invoice.request_event_id(), self.clock.now())
                        .map_err(|_| InvoiceNotificationError::Ledger)?;
                    report.expired += 1;
                    return Ok(());
                };
                let secret = self
                    .secrets
                    .load_nwc_secret(connection.id())
                    .map_err(|_| InvoiceNotificationError::Secret)?;
                let proposed = build_payment_received_notification_event(
                    &connection,
                    &secret,
                    invoice,
                    &transaction,
                )?;
                self.ledger
                    .store_nwc_invoice_notification_event(
                        invoice.request_event_id(),
                        &proposed,
                        transaction.settled_at.unwrap_or_else(|| self.clock.now()),
                    )
                    .map_err(|_| InvoiceNotificationError::Ledger)?
            }
        };
        let relays = self
            .ledger
            .undelivered_nwc_invoice_relays(invoice.request_event_id())
            .map_err(|_| InvoiceNotificationError::Ledger)?;
        if relays.is_empty() {
            self.ledger
                .complete_nwc_invoice_notification(invoice.request_event_id(), self.clock.now())
                .map_err(|_| InvoiceNotificationError::Ledger)?;
            report.delivered += 1;
            return Ok(());
        }
        let mut failed = false;
        for relay in relays {
            if cancellation.is_cancelled() {
                failed = true;
                break;
            }
            match self
                .relays
                .publish_event(
                    &relay,
                    &event_json,
                    match deadline.context(cancellation) {
                        Some(context) => context,
                        None => {
                            failed = true;
                            break;
                        }
                    },
                )
                .await
            {
                Ok(()) => self
                    .ledger
                    .acknowledge_nwc_invoice_relay(
                        invoice.request_event_id(),
                        &relay,
                        self.clock.now(),
                    )
                    .map_err(|_| InvoiceNotificationError::Ledger)?,
                Err(_) => failed = true,
            }
        }
        if failed {
            report.retryable += 1;
        } else {
            self.ledger
                .complete_nwc_invoice_notification(invoice.request_event_id(), self.clock.now())
                .map_err(|_| InvoiceNotificationError::Ledger)?;
            report.delivered += 1;
        }
        Ok(())
    }

    fn defer_or_expire_invoice(
        &self,
        invoice: &TrackedNwcInvoice,
        report: &mut InvoiceNotificationWorkerReport,
    ) -> Result<(), InvoiceNotificationError> {
        let stale_at = invoice
            .expires_at()
            .as_secs()
            .saturating_add(SETTLEMENT_RECONCILIATION_GRACE_SECONDS);
        if self.clock.now().as_secs() >= stale_at {
            self.ledger
                .expire_nwc_invoice(invoice.request_event_id(), self.clock.now())
                .map_err(|_| InvoiceNotificationError::Ledger)?;
            report.expired += 1;
        } else {
            report.pending += 1;
        }
        Ok(())
    }
}

/// Builds and signs a NIP-47 `payment_received` event for one authorized client.
pub fn build_payment_received_notification_event(
    connection: &ActiveConnection,
    wallet_secret: &NwcSecretKey,
    invoice: &TrackedNwcInvoice,
    transaction: &WalletTransaction,
) -> Result<String, InvoiceNotificationError> {
    let (preimage, amount, fee) = match &transaction.status {
        PaymentStatus::Succeeded {
            preimage,
            amount,
            fee,
        } => (preimage.to_hex(), *amount, *fee),
        _ => return Err(InvoiceNotificationError::Build),
    };
    if transaction.direction != crate::TransactionDirection::Incoming
        || transaction.payment_hash.as_ref() != Some(invoice.payment_hash())
    {
        return Err(InvoiceNotificationError::Build);
    }
    let settled_at = transaction
        .settled_at
        .ok_or(InvoiceNotificationError::Build)?;
    let notification = Notification {
        notification_type: NotificationType::PaymentReceived,
        notification: NotificationResult::PaymentReceived(PaymentNotification {
            transaction_type: Some(TransactionType::Incoming),
            state: Some(TransactionState::Settled),
            invoice: invoice.invoice().to_owned(),
            description: invoice.description().map(str::to_owned),
            description_hash: None,
            preimage,
            payment_hash: invoice.payment_hash().to_hex(),
            amount: amount.as_msat(),
            fees_paid: fee.as_msat(),
            created_at: Timestamp::from(invoice.created_at().as_secs()),
            expires_at: Some(Timestamp::from(invoice.expires_at().as_secs())),
            settled_at: Timestamp::from(settled_at.as_secs()),
            metadata: None,
        }),
    };
    let plaintext = notification.as_json();
    let secret = wallet_secret
        .nostr_secret()
        .map_err(|_| InvoiceNotificationError::Secret)?;
    let keys = Keys::new(secret.clone());
    if keys.public_key().as_bytes() != connection.wallet_service_pubkey().as_bytes() {
        return Err(InvoiceNotificationError::Secret);
    }
    let client = NostrPublicKey::from_byte_array(*connection.client_pubkey().as_bytes());
    let (kind, content, tags) = match connection.encryption() {
        NwcEncryption::Nip44V2 => (
            Kind::Custom(23_197),
            nostr::nips::nip44::encrypt(
                &secret,
                &client,
                plaintext,
                nostr::nips::nip44::Version::V2,
            )
            .map_err(|_| InvoiceNotificationError::Build)?,
            vec![
                Tag::public_key(client),
                Tag::custom(nostr::TagKind::custom("encryption"), ["nip44_v2"]),
            ],
        ),
        NwcEncryption::LegacyNip04 => (
            Kind::WalletConnectNotification,
            nostr::nips::nip04::encrypt(&secret, &client, plaintext)
                .map_err(|_| InvoiceNotificationError::Build)?,
            vec![Tag::public_key(client)],
        ),
    };
    EventBuilder::new(kind, content)
        .tags(tags)
        .custom_created_at(Timestamp::from(settled_at.as_secs()))
        .sign_with_keys(&keys)
        .map(|event| event.as_json())
        .map_err(|_| InvoiceNotificationError::Build)
}

/// Builds and signs a NIP-47 `payment_sent` event for one authorized client.
pub fn build_payment_sent_notification_event(
    connection: &ActiveConnection,
    wallet_secret: &NwcSecretKey,
    payment: &TrackedNwcPayment,
) -> Result<String, InvoiceNotificationError> {
    let notification = Notification {
        notification_type: NotificationType::PaymentSent,
        notification: NotificationResult::PaymentSent(PaymentNotification {
            transaction_type: Some(TransactionType::Outgoing),
            state: Some(TransactionState::Settled),
            invoice: payment.invoice.clone(),
            description: None,
            description_hash: None,
            preimage: payment.preimage.to_hex(),
            payment_hash: payment.payment_hash.to_hex(),
            amount: payment.amount.as_msat(),
            fees_paid: payment.fee.as_msat(),
            created_at: Timestamp::from(payment.created_at.as_secs()),
            expires_at: None,
            settled_at: Timestamp::from(payment.settled_at.as_secs()),
            metadata: None,
        }),
    };
    build_notification_event(
        connection,
        wallet_secret,
        notification.as_json(),
        payment.settled_at,
    )
}

fn build_notification_event(
    connection: &ActiveConnection,
    wallet_secret: &NwcSecretKey,
    plaintext: String,
    created_at: UnixTimestamp,
) -> Result<String, InvoiceNotificationError> {
    let secret = wallet_secret
        .nostr_secret()
        .map_err(|_| InvoiceNotificationError::Secret)?;
    let keys = Keys::new(secret.clone());
    if keys.public_key().as_bytes() != connection.wallet_service_pubkey().as_bytes() {
        return Err(InvoiceNotificationError::Secret);
    }
    let client = NostrPublicKey::from_byte_array(*connection.client_pubkey().as_bytes());
    let (kind, content, tags) = match connection.encryption() {
        NwcEncryption::Nip44V2 => (
            Kind::Custom(23_197),
            nostr::nips::nip44::encrypt(
                &secret,
                &client,
                plaintext,
                nostr::nips::nip44::Version::V2,
            )
            .map_err(|_| InvoiceNotificationError::Build)?,
            vec![
                Tag::public_key(client),
                Tag::custom(nostr::TagKind::custom("encryption"), ["nip44_v2"]),
            ],
        ),
        NwcEncryption::LegacyNip04 => (
            Kind::WalletConnectNotification,
            nostr::nips::nip04::encrypt(&secret, &client, plaintext)
                .map_err(|_| InvoiceNotificationError::Build)?,
            vec![Tag::public_key(client)],
        ),
    };
    EventBuilder::new(kind, content)
        .tags(tags)
        .custom_created_at(Timestamp::from(created_at.as_secs()))
        .sign_with_keys(&keys)
        .map(|event| event.as_json())
        .map_err(|_| InvoiceNotificationError::Build)
}

impl WakeLedger {
    /// Loads non-sensitive scheduling metadata for one NWC-created invoice.
    pub fn nwc_invoice_monitor(
        &self,
        event_id: &EventId,
    ) -> Result<Option<InvoiceSettlementMonitor>, LedgerError> {
        let connection = self.lock_connection()?;
        let row = connection
            .query_row(
                "SELECT i.request_event_id, c.client_pubkey, c.wallet_service_pubkey,
                        i.expires_at, i.completed_at IS NOT NULL,
                        i.settlement_trigger_token
                 FROM nwc_created_invoices i
                 JOIN connections c ON c.connection_id = i.connection_id
                    AND c.revision = i.connection_revision
                 WHERE i.request_event_id = ?1",
                params![event_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, bool>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((request, client, wallet, expires_at, completed, trigger_token)) = row else {
            return Ok(None);
        };
        let fixed = |value: Vec<u8>| value.try_into().map_err(|_| LedgerError::CorruptData);
        let mut statement = connection.prepare(
            "SELECT relay_url FROM nwc_invoice_notification_relays
             WHERE request_event_id = ?1 ORDER BY position",
        )?;
        let relays = statement
            .query_map(params![event_id.as_bytes().as_slice()], |row| {
                row.get::<_, String>(0)
            })?
            .map(|relay| {
                crate::SecureRelayUrl::parse(&relay.map_err(LedgerError::from)?)
                    .map_err(|_| LedgerError::CorruptData)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(InvoiceSettlementMonitor {
            request_event_id: EventId::from_bytes(fixed(request)?),
            client_pubkey: crate::PublicKey::from_bytes(fixed(client)?),
            wallet_service_pubkey: crate::PublicKey::from_bytes(fixed(wallet)?),
            relays,
            expires_at: UnixTimestamp::from_secs(
                u64::try_from(expires_at).map_err(|_| LedgerError::CorruptData)?,
            ),
            completed,
            trigger_token_hash: sha256::Hash::hash(&trigger_token).to_string(),
        }))
    }

    pub(crate) fn record_nwc_sent_payment(
        &self,
        payment: &TrackedNwcPayment,
        relays: &[crate::SecureRelayUrl],
    ) -> Result<(), LedgerError> {
        if payment.invoice.is_empty() || payment.invoice.len() > MAX_INVOICE_BYTES {
            return Err(LedgerError::CorruptData);
        }
        let revision = i64::try_from(payment.connection_revision.value())
            .map_err(|_| LedgerError::ValueOutOfRange)?;
        let amount =
            i64::try_from(payment.amount.as_msat()).map_err(|_| LedgerError::ValueOutOfRange)?;
        let fee = i64::try_from(payment.fee.as_msat()).map_err(|_| LedgerError::ValueOutOfRange)?;
        let created_at = i64::try_from(payment.created_at.as_secs())
            .map_err(|_| LedgerError::ValueOutOfRange)?;
        let settled_at = i64::try_from(payment.settled_at.as_secs())
            .map_err(|_| LedgerError::ValueOutOfRange)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO nwc_sent_payments (
                request_event_id, payment_hash, connection_id, connection_revision,
                invoice, amount_msat, fee_msat, preimage, created_at, settled_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(request_event_id) DO NOTHING",
            params![
                payment.request_event_id.as_bytes().as_slice(),
                payment.payment_hash.as_bytes().as_slice(),
                payment.connection_id.as_str(),
                revision,
                payment.invoice,
                amount,
                fee,
                payment.preimage.as_bytes().as_slice(),
                created_at,
                settled_at,
            ],
        )?;
        for (position, relay) in relays.iter().enumerate() {
            transaction.execute(
                "INSERT INTO nwc_sent_payment_relays (
                    request_event_id, position, relay_url
                 ) VALUES (?1, ?2, ?3)
                 ON CONFLICT(request_event_id, position) DO NOTHING",
                params![
                    payment.request_event_id.as_bytes().as_slice(),
                    i64::try_from(position).map_err(|_| LedgerError::ValueOutOfRange)?,
                    relay.as_str(),
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn pending_nwc_sent_payments(
        &self,
        maximum: usize,
    ) -> Result<Vec<TrackedNwcPayment>, LedgerError> {
        if maximum == 0 || maximum > 100 {
            return Err(LedgerError::InvalidPruneBatch);
        }
        let connection = self.lock_connection()?;
        let mut statement = connection.prepare(
            "SELECT request_event_id, payment_hash, connection_id, connection_revision,
                    invoice, amount_msat, fee_msat, preimage, created_at, settled_at,
                    notification_event_json
             FROM nwc_sent_payments WHERE completed_at IS NULL
             ORDER BY created_at, request_event_id LIMIT ?1",
        )?;
        let payments = statement
            .query_map(
                params![i64::try_from(maximum).map_err(|_| LedgerError::ValueOutOfRange)?],
                decode_sent_payment,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into);
        payments
    }

    pub(crate) fn store_nwc_sent_notification_event(
        &self,
        event_id: &EventId,
        proposed_event_json: &str,
    ) -> Result<String, LedgerError> {
        if proposed_event_json.is_empty()
            || proposed_event_json.len() > MAX_NOTIFICATION_EVENT_BYTES
        {
            return Err(LedgerError::ResponseTooLarge);
        }
        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "UPDATE nwc_sent_payments SET notification_event_json = ?2
             WHERE request_event_id = ?1 AND completed_at IS NULL
               AND notification_event_json IS NULL",
            params![event_id.as_bytes().as_slice(), proposed_event_json],
        )?;
        let canonical = transaction
            .query_row(
                "SELECT notification_event_json FROM nwc_sent_payments
                 WHERE request_event_id = ?1 AND completed_at IS NULL",
                params![event_id.as_bytes().as_slice()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(LedgerError::ConnectionUnavailable)?;
        transaction.commit()?;
        Ok(canonical)
    }

    pub(crate) fn undelivered_nwc_sent_relays(
        &self,
        event_id: &EventId,
    ) -> Result<Vec<crate::SecureRelayUrl>, LedgerError> {
        let connection = self.lock_connection()?;
        let mut statement = connection.prepare(
            "SELECT relay_url FROM nwc_sent_payment_relays
             WHERE request_event_id = ?1 AND delivered_at IS NULL ORDER BY position",
        )?;
        let relays = statement
            .query_map(params![event_id.as_bytes().as_slice()], |row| {
                row.get::<_, String>(0)
            })?
            .map(|row| {
                row.map_err(LedgerError::from).and_then(|relay| {
                    crate::SecureRelayUrl::parse(&relay).map_err(|_| LedgerError::CorruptData)
                })
            })
            .collect();
        relays
    }

    pub(crate) fn acknowledge_nwc_sent_relay(
        &self,
        event_id: &EventId,
        relay: &crate::SecureRelayUrl,
        delivered_at: UnixTimestamp,
    ) -> Result<(), LedgerError> {
        let delivered_at =
            i64::try_from(delivered_at.as_secs()).map_err(|_| LedgerError::ValueOutOfRange)?;
        self.lock_connection()?.execute(
            "UPDATE nwc_sent_payment_relays SET delivered_at = ?3
             WHERE request_event_id = ?1 AND relay_url = ?2 AND delivered_at IS NULL",
            params![event_id.as_bytes().as_slice(), relay.as_str(), delivered_at],
        )?;
        Ok(())
    }

    pub(crate) fn complete_nwc_sent_notification(
        &self,
        event_id: &EventId,
        completed_at: UnixTimestamp,
    ) -> Result<(), LedgerError> {
        let completed_at =
            i64::try_from(completed_at.as_secs()).map_err(|_| LedgerError::ValueOutOfRange)?;
        self.lock_connection()?.execute(
            "UPDATE nwc_sent_payments SET completed_at = ?2
             WHERE request_event_id = ?1 AND notification_event_json IS NOT NULL
               AND completed_at IS NULL AND NOT EXISTS (
                   SELECT 1 FROM nwc_sent_payment_relays
                   WHERE request_event_id = ?1 AND delivered_at IS NULL
               )",
            params![event_id.as_bytes().as_slice(), completed_at],
        )?;
        Ok(())
    }

    pub(crate) fn discard_nwc_sent_payment(&self, event_id: &EventId) -> Result<(), LedgerError> {
        self.lock_connection()?.execute(
            "DELETE FROM nwc_sent_payments WHERE request_event_id = ?1",
            params![event_id.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    pub(crate) fn record_nwc_invoice(
        &self,
        invoice: &TrackedNwcInvoice,
        relays: &[crate::SecureRelayUrl],
    ) -> Result<TrackedNwcInvoice, LedgerError> {
        if invoice.invoice.is_empty()
            || invoice.invoice.len() > MAX_INVOICE_BYTES
            || invoice
                .description
                .as_ref()
                .is_some_and(|value| value.len() > MAX_DESCRIPTION_BYTES)
            || invoice.amount.as_msat() == 0
            || invoice.expires_at <= invoice.created_at
        {
            return Err(LedgerError::CorruptData);
        }
        let revision = i64::try_from(invoice.connection_revision.value())
            .map_err(|_| LedgerError::ValueOutOfRange)?;
        let amount =
            i64::try_from(invoice.amount.as_msat()).map_err(|_| LedgerError::ValueOutOfRange)?;
        let created_at = i64::try_from(invoice.created_at.as_secs())
            .map_err(|_| LedgerError::ValueOutOfRange)?;
        let expires_at = i64::try_from(invoice.expires_at.as_secs())
            .map_err(|_| LedgerError::ValueOutOfRange)?;
        let mut settlement_trigger_token = [0_u8; SETTLEMENT_TRIGGER_TOKEN_BYTES];
        getrandom::fill(&mut settlement_trigger_token)
            .map_err(|_| LedgerError::RandomnessUnavailable)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO nwc_created_invoices (
                request_event_id, payment_hash, connection_id, connection_revision,
                invoice, description, amount_msat, created_at, expires_at, last_checked_at,
                settlement_trigger_token
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?8, ?10)
             ON CONFLICT(request_event_id) DO NOTHING",
            params![
                invoice.request_event_id.as_bytes().as_slice(),
                invoice.payment_hash.as_bytes().as_slice(),
                invoice.connection_id.as_str(),
                revision,
                invoice.invoice,
                invoice.description,
                amount,
                created_at,
                expires_at,
                settlement_trigger_token.as_slice(),
            ],
        )?;
        let existing = load_invoice(&transaction, &invoice.request_event_id)?
            .ok_or(LedgerError::CorruptData)?;
        if existing.payment_hash != invoice.payment_hash
            || existing.connection_id != invoice.connection_id
            || existing.connection_revision != invoice.connection_revision
            || existing.invoice != invoice.invoice
        {
            return Err(LedgerError::ClaimMetadataMismatch);
        }
        for (position, relay) in relays.iter().enumerate() {
            let position = i64::try_from(position).map_err(|_| LedgerError::ValueOutOfRange)?;
            transaction.execute(
                "INSERT INTO nwc_invoice_notification_relays (
                    request_event_id, position, relay_url
                 ) VALUES (?1, ?2, ?3)
                 ON CONFLICT(request_event_id, position) DO NOTHING",
                params![
                    invoice.request_event_id.as_bytes().as_slice(),
                    position,
                    relay.as_str(),
                ],
            )?;
        }
        transaction.commit()?;
        Ok(existing)
    }

    pub(crate) fn load_nwc_invoice(
        &self,
        event_id: &EventId,
    ) -> Result<Option<TrackedNwcInvoice>, LedgerError> {
        let connection = self.lock_connection()?;
        load_invoice(&connection, event_id)
    }

    pub(crate) fn load_nwc_invoice_by_encoded_invoice(
        &self,
        invoice: &str,
    ) -> Result<Option<TrackedNwcInvoice>, LedgerError> {
        if invoice.is_empty() || invoice.len() > MAX_INVOICE_BYTES {
            return Ok(None);
        }
        let connection = self.lock_connection()?;
        connection
            .query_row(
                "SELECT request_event_id, payment_hash, connection_id, connection_revision,
                        invoice, description, amount_msat, created_at, expires_at,
                        notification_event_json
                 FROM nwc_created_invoices
                 WHERE invoice = ?1
                 ORDER BY created_at DESC, request_event_id
                 LIMIT 1",
                params![invoice],
                decode_invoice,
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn load_nwc_invoice_by_payment_hash(
        &self,
        payment_hash: &PaymentHash,
    ) -> Result<Option<TrackedNwcInvoice>, LedgerError> {
        let connection = self.lock_connection()?;
        connection
            .query_row(
                "SELECT request_event_id, payment_hash, connection_id, connection_revision,
                        invoice, description, amount_msat, created_at, expires_at,
                        notification_event_json
                 FROM nwc_created_invoices
                 WHERE payment_hash = ?1
                 LIMIT 1",
                params![payment_hash.as_bytes().as_slice()],
                decode_invoice,
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn pending_nwc_invoices(
        &self,
        maximum: usize,
    ) -> Result<Vec<TrackedNwcInvoice>, LedgerError> {
        if maximum == 0 || maximum > 100 {
            return Err(LedgerError::InvalidPruneBatch);
        }
        let limit = i64::try_from(maximum).map_err(|_| LedgerError::ValueOutOfRange)?;
        let connection = self.lock_connection()?;
        let mut statement = connection.prepare(
            "SELECT request_event_id, payment_hash, connection_id, connection_revision,
                    invoice, description, amount_msat, created_at, expires_at,
                    notification_event_json
             FROM nwc_created_invoices
             WHERE completed_at IS NULL
             ORDER BY last_checked_at, created_at, request_event_id
             LIMIT ?1",
        )?;
        let invoices = statement
            .query_map(params![limit], decode_invoice)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into);
        invoices
    }

    pub(crate) fn pending_nwc_invoice(
        &self,
        event_id: &EventId,
    ) -> Result<Option<TrackedNwcInvoice>, LedgerError> {
        let connection = self.lock_connection()?;
        connection
            .query_row(
                "SELECT request_event_id, payment_hash, connection_id, connection_revision,
                        invoice, description, amount_msat, created_at, expires_at,
                        notification_event_json
                 FROM nwc_created_invoices
                 WHERE request_event_id = ?1 AND completed_at IS NULL
                 LIMIT 1",
                params![event_id.as_bytes().as_slice()],
                decode_invoice,
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn touch_nwc_invoice(
        &self,
        event_id: &EventId,
        checked_at: UnixTimestamp,
    ) -> Result<(), LedgerError> {
        let checked_at =
            i64::try_from(checked_at.as_secs()).map_err(|_| LedgerError::ValueOutOfRange)?;
        self.lock_connection()?.execute(
            "UPDATE nwc_created_invoices
             SET last_checked_at = MAX(?2, last_checked_at + 1)
             WHERE request_event_id = ?1 AND completed_at IS NULL",
            params![event_id.as_bytes().as_slice(), checked_at],
        )?;
        Ok(())
    }

    pub(crate) fn store_nwc_invoice_notification_event(
        &self,
        event_id: &EventId,
        proposed_event_json: &str,
        created_at: UnixTimestamp,
    ) -> Result<String, LedgerError> {
        if proposed_event_json.is_empty()
            || proposed_event_json.len() > MAX_NOTIFICATION_EVENT_BYTES
        {
            return Err(LedgerError::ResponseTooLarge);
        }
        let created_at =
            i64::try_from(created_at.as_secs()).map_err(|_| LedgerError::ValueOutOfRange)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "UPDATE nwc_created_invoices
             SET notification_event_json = ?2, notification_created_at = ?3
             WHERE request_event_id = ?1 AND completed_at IS NULL
               AND notification_event_json IS NULL",
            params![
                event_id.as_bytes().as_slice(),
                proposed_event_json,
                created_at
            ],
        )?;
        let canonical = transaction
            .query_row(
                "SELECT notification_event_json FROM nwc_created_invoices
                 WHERE request_event_id = ?1 AND completed_at IS NULL",
                params![event_id.as_bytes().as_slice()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(LedgerError::ConnectionUnavailable)?;
        transaction.commit()?;
        Ok(canonical)
    }

    pub(crate) fn undelivered_nwc_invoice_relays(
        &self,
        event_id: &EventId,
    ) -> Result<Vec<crate::SecureRelayUrl>, LedgerError> {
        let connection = self.lock_connection()?;
        let mut statement = connection.prepare(
            "SELECT relay_url FROM nwc_invoice_notification_relays
             WHERE request_event_id = ?1 AND delivered_at IS NULL
             ORDER BY position",
        )?;
        let relays = statement
            .query_map(params![event_id.as_bytes().as_slice()], |row| {
                row.get::<_, String>(0)
            })?
            .map(|row| {
                row.map_err(LedgerError::from).and_then(|relay| {
                    crate::SecureRelayUrl::parse(&relay).map_err(|_| LedgerError::CorruptData)
                })
            })
            .collect();
        relays
    }

    pub(crate) fn acknowledge_nwc_invoice_relay(
        &self,
        event_id: &EventId,
        relay: &crate::SecureRelayUrl,
        delivered_at: UnixTimestamp,
    ) -> Result<(), LedgerError> {
        let delivered_at =
            i64::try_from(delivered_at.as_secs()).map_err(|_| LedgerError::ValueOutOfRange)?;
        let connection = self.lock_connection()?;
        connection.execute(
            "UPDATE nwc_invoice_notification_relays SET delivered_at = ?3
             WHERE request_event_id = ?1 AND relay_url = ?2 AND delivered_at IS NULL",
            params![event_id.as_bytes().as_slice(), relay.as_str(), delivered_at],
        )?;
        Ok(())
    }

    pub(crate) fn complete_nwc_invoice_notification(
        &self,
        event_id: &EventId,
        completed_at: UnixTimestamp,
    ) -> Result<(), LedgerError> {
        let completed_at =
            i64::try_from(completed_at.as_secs()).map_err(|_| LedgerError::ValueOutOfRange)?;
        let connection = self.lock_connection()?;
        connection.execute(
            "UPDATE nwc_created_invoices SET completed_at = ?2
             WHERE request_event_id = ?1 AND notification_event_json IS NOT NULL
               AND completed_at IS NULL
               AND NOT EXISTS (
                   SELECT 1 FROM nwc_invoice_notification_relays
                   WHERE request_event_id = ?1 AND delivered_at IS NULL
               )",
            params![event_id.as_bytes().as_slice(), completed_at],
        )?;
        Ok(())
    }

    pub(crate) fn expire_nwc_invoice(
        &self,
        event_id: &EventId,
        _completed_at: UnixTimestamp,
    ) -> Result<(), LedgerError> {
        let connection = self.lock_connection()?;
        connection.execute(
            "DELETE FROM nwc_created_invoices
             WHERE request_event_id = ?1 AND notification_event_json IS NULL",
            params![event_id.as_bytes().as_slice()],
        )?;
        Ok(())
    }
}

fn load_invoice(
    connection: &rusqlite::Connection,
    event_id: &EventId,
) -> Result<Option<TrackedNwcInvoice>, LedgerError> {
    connection
        .query_row(
            "SELECT request_event_id, payment_hash, connection_id, connection_revision,
                    invoice, description, amount_msat, created_at, expires_at,
                    notification_event_json
             FROM nwc_created_invoices WHERE request_event_id = ?1",
            params![event_id.as_bytes().as_slice()],
            decode_invoice,
        )
        .optional()
        .map_err(Into::into)
}

fn decode_invoice(row: &rusqlite::Row<'_>) -> rusqlite::Result<TrackedNwcInvoice> {
    let event: Vec<u8> = row.get(0)?;
    let hash: Vec<u8> = row.get(1)?;
    let event: [u8; 32] = event
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let hash: [u8; 32] = hash.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;
    let revision: i64 = row.get(3)?;
    let amount: i64 = row.get(6)?;
    let created_at: i64 = row.get(7)?;
    let expires_at: i64 = row.get(8)?;
    Ok(TrackedNwcInvoice {
        request_event_id: EventId::from_bytes(event),
        payment_hash: PaymentHash::from_bytes(hash),
        connection_id: ConnectionId::parse(row.get::<_, String>(2)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        connection_revision: ConnectionRevision::from_value(
            u64::try_from(revision).map_err(|_| rusqlite::Error::InvalidQuery)?,
        ),
        invoice: row.get(4)?,
        description: row.get(5)?,
        amount: AmountMsat::from_msat(
            u64::try_from(amount).map_err(|_| rusqlite::Error::InvalidQuery)?,
        ),
        created_at: UnixTimestamp::from_secs(
            u64::try_from(created_at).map_err(|_| rusqlite::Error::InvalidQuery)?,
        ),
        expires_at: UnixTimestamp::from_secs(
            u64::try_from(expires_at).map_err(|_| rusqlite::Error::InvalidQuery)?,
        ),
        notification_event_json: row.get(9)?,
    })
}

fn decode_sent_payment(row: &rusqlite::Row<'_>) -> rusqlite::Result<TrackedNwcPayment> {
    let event: Vec<u8> = row.get(0)?;
    let hash: Vec<u8> = row.get(1)?;
    let preimage: Vec<u8> = row.get(7)?;
    let event: [u8; 32] = event
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let hash: [u8; 32] = hash.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;
    let preimage: [u8; 32] = preimage
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let unsigned = |value: i64| u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery);
    Ok(TrackedNwcPayment {
        request_event_id: EventId::from_bytes(event),
        payment_hash: PaymentHash::from_bytes(hash),
        connection_id: ConnectionId::parse(row.get::<_, String>(2)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        connection_revision: ConnectionRevision::from_value(unsigned(row.get(3)?)?),
        invoice: row.get(4)?,
        amount: AmountMsat::from_msat(unsigned(row.get(5)?)?),
        fee: AmountMsat::from_msat(unsigned(row.get(6)?)?),
        preimage: crate::PaymentPreimage::from_bytes(preimage),
        created_at: UnixTimestamp::from_secs(unsigned(row.get(8)?)?),
        settled_at: UnixTimestamp::from_secs(unsigned(row.get(9)?)?),
        notification_event_json: row.get(10)?,
    })
}

impl From<HostError> for InvoiceNotificationError {
    fn from(_: HostError) -> Self {
        Self::Wallet
    }
}
