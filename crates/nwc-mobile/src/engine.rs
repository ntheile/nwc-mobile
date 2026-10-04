use std::time::Duration;

use nostr::nips::nip47::{
    self, ErrorCode, GetBalanceResponse, GetInfoResponse, LookupInvoiceResponse,
    MakeInvoiceResponse, Method, NIP47Error, PayInvoiceResponse, Request, RequestParams, Response,
    ResponseResult, TransactionState, TransactionType,
};
use nostr::{JsonUtil, Timestamp};

use crate::time::OperationDeadline;
use crate::{
    ActiveConnection, AmountMsat, AmountSat, CancellationSignal, ClaimOutcome, Clock, EventLease,
    HostError, HostErrorKind, InvoiceLookup, LedgerError, ListTransactionsRequest,
    MakeInvoiceRequest, NotificationHint, NwcEventValidator, NwcMethod, NwcWalletBackend,
    OperationBudget, OperationContext, PayInvoiceRequest, PaymentAccountingError, PaymentFailure,
    PaymentHash, PaymentReservationOutcome, PaymentStatus, QueueReason, RejectionCode,
    RelayTransport, RetryReason, SecretProvider, SecureRelayUrl, TerminalKind, UnixTimestamp,
    WakeDiagnosticCode, WakeDiagnosticSink, WakeDisposition, WakeInput, WakeLedger, WakePolicy,
    WalletTransaction,
};

const ENGINE_RETRY_DELAY: Duration = Duration::from_secs(5);
const DEFAULT_LIST_LIMIT: u16 = 20;
const MAX_LIST_LIMIT: u16 = 100;
const DEFAULT_INVOICE_EXPIRY: Duration = Duration::from_secs(60 * 60);
const MAX_INVOICE_EXPIRY: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MAX_INVOICE_DESCRIPTION_BYTES: usize = 1_024;

/// Executes authenticated, durable NIP-47 reads, invoice creation, and invoice payments.
///
/// The containing application owns relay, secret-storage, wallet, clock, and
/// cancellation capabilities. This engine owns validation order, replay state,
/// authorization checks, response construction, and commit-before-publish.
pub struct WakeEngine<'a> {
    ledger: &'a WakeLedger,
    wallet: &'a dyn NwcWalletBackend,
    relays: &'a dyn RelayTransport,
    secrets: &'a dyn SecretProvider,
    clock: &'a dyn Clock,
    validator: NwcEventValidator,
    maximum_event_bytes: usize,
    diagnostics: Option<&'a dyn WakeDiagnosticSink>,
}

impl<'a> WakeEngine<'a> {
    /// Creates an engine over host capabilities and one durable ledger.
    #[must_use]
    pub const fn new(
        ledger: &'a WakeLedger,
        wallet: &'a dyn NwcWalletBackend,
        relays: &'a dyn RelayTransport,
        secrets: &'a dyn SecretProvider,
        clock: &'a dyn Clock,
        policy: WakePolicy,
    ) -> Self {
        Self {
            ledger,
            wallet,
            relays,
            secrets,
            clock,
            validator: NwcEventValidator::new(policy),
            maximum_event_bytes: policy.maximum_payload_bytes(),
            diagnostics: None,
        }
    }

    /// Attaches a host-owned sink for bounded, non-secret execution codes.
    #[must_use]
    pub fn with_diagnostics(mut self, diagnostics: &'a dyn WakeDiagnosticSink) -> Self {
        self.diagnostics = Some(diagnostics);
        self
    }

    /// Validates, claims, executes, commits, and publishes one wake request.
    pub async fn execute(
        &self,
        wake: WakeInput,
        budget: OperationBudget,
        cancellation: &dyn CancellationSignal,
    ) -> WakeDisposition {
        let deadline = OperationDeadline::new(budget);
        if cancellation.is_cancelled() {
            return queued(QueueReason::Deadline);
        }
        let authorization_time = self.clock.now();
        // Only byte-for-byte retained, already initiated foreground work can recover
        // after expiry. This never grants new payment or direct-method authority.
        let recovery = match self.ledger.is_foreground_recovery_wake(&wake) {
            Ok(value) => value,
            Err(_) => return queued(QueueReason::LedgerBusy),
        };
        let relay = match SecureRelayUrl::parse(wake.relay()) {
            Ok(relay) => relay,
            Err(_) => return rejected(RejectionCode::InvalidWakePayload),
        };
        match self.ledger.is_relay_approved_for_wallet(
            wake.wallet_service_pubkey(),
            &relay,
            authorization_time,
        ) {
            Ok(true) => {}
            Ok(false) if !recovery => return rejected(RejectionCode::RelayNotAllowed),
            Ok(false) => {}
            Err(_) => return queued(QueueReason::LedgerBusy),
        }

        let event_json = if let Some(event) = wake.embedded_event_json() {
            event.to_owned()
        } else {
            let Some(context) = deadline.context(cancellation) else {
                return queued(QueueReason::Deadline);
            };
            match self
                .relays
                .fetch_event(&relay, wake.event_id(), self.maximum_event_bytes, context)
                .await
            {
                Ok(Some(event)) => event,
                Err(error) if error.kind() == HostErrorKind::Rejected => {
                    return rejected(RejectionCode::InvalidEvent)
                }
                Ok(None) | Err(_) => {
                    return retry(ENGINE_RETRY_DELAY, RetryReason::RelayUnavailable)
                }
            }
        };

        let candidate_author = match self.validator.candidate_author(&event_json) {
            Ok(author) => author,
            Err(_) => return rejected(RejectionCode::InvalidEvent),
        };
        let connection = match self
            .ledger
            .load_active_connection_by_keys(&candidate_author, wake.wallet_service_pubkey())
        {
            Ok(Some(connection)) => connection,
            Ok(None) => return rejected(RejectionCode::ConnectionUnavailable),
            Err(_) => return queued(QueueReason::LedgerBusy),
        };
        if connection.is_expired_at(authorization_time) && !recovery {
            return rejected(RejectionCode::ConnectionUnavailable);
        }
        if !connection.allows_relay(&relay) {
            return rejected(RejectionCode::RelayNotAllowed);
        }
        let validated = match self.validator.validate_request_for_replay(
            &event_json,
            wake.event_id(),
            connection.client_pubkey(),
            connection.wallet_service_pubkey(),
            connection.encryption(),
        ) {
            Ok(event) => event,
            Err(error) => return rejected(event_rejection(error)),
        };

        let Some(lease_duration) = lease_duration_for_budget(deadline.remaining()) else {
            return queued(QueueReason::Deadline);
        };
        let lease = match self.ledger.claim_event(
            validated.id(),
            connection.id(),
            connection.revision(),
            self.clock.now(),
            lease_duration,
        ) {
            Ok(ClaimOutcome::Acquired(lease)) => lease,
            Ok(ClaimOutcome::InProgress { .. }) => return already_processed(),
            Ok(ClaimOutcome::Terminal(terminal)) => {
                diagnostic_stage("terminal_response_replayed");
                return self
                    .republish_terminal(
                        validated.id(),
                        &connection,
                        &relay,
                        terminal.response_event_json(),
                        terminal
                            .request_method()
                            .map_or(NotificationHint::Completed, |method| {
                                NotificationHint::Request { method }
                            }),
                        &deadline,
                        cancellation,
                    )
                    .await;
            }
            Err(_) => return queued(QueueReason::LedgerBusy),
        };
        if !lease.freshness_was_accepted() {
            if !self
                .validator
                .accepts_event_time(validated.created_at(), self.clock.now())
            {
                return self.reject_claim(&lease, RejectionCode::EventOutsideFreshnessWindow);
            }
            if self
                .ledger
                .accept_event_freshness(&lease, self.clock.now())
                .is_err()
            {
                return self.release_to_application(&lease, QueueReason::LedgerBusy);
            }
        }

        let (request, purchase_json) = {
            let Some(context) = deadline.context(cancellation) else {
                return self.release_to_application(&lease, QueueReason::Deadline);
            };
            let secret = match self.secrets.load_nwc_secret(connection.id(), context).await {
                Ok(secret) => secret,
                Err(_) => {
                    return self
                        .release_to_application(&lease, QueueReason::SecureStorageUnavailable)
                }
            };
            match validated.decrypt(&secret).and_then(|plaintext| {
                let value: nostr::serde_json::Value =
                    nostr::serde_json::from_str(plaintext.as_json())
                        .map_err(|_| crate::NostrEventError::MalformedEvent)?;
                if value["method"] == "authorize_browser"
                    && self
                        .ledger
                        .is_reusable_foreground(connection.id().as_str())
                        .unwrap_or(false)
                {
                    self.ledger
                        .parse_browser_pairing_challenge(
                            &connection,
                            &event_json,
                            &secret,
                            self.clock.now(),
                        )
                        .map_err(|_| crate::NostrEventError::MalformedEvent)?;
                    return Ok((None, None));
                }
                Request::from_json(plaintext.as_json())
                    .map(|request| {
                        (
                            Some(request),
                            value
                                .get("params")
                                .and_then(|p| p.get("purchase"))
                                .map(|p| p.to_string()),
                        )
                    })
                    .map_err(|_| crate::NostrEventError::MalformedEvent)
            }) {
                Ok(request) => request,
                Err(_) => {
                    return self.reject_claim(&lease, RejectionCode::InvalidRequest);
                }
            }
        };

        let Some(request) = request else {
            // Browser repair is never acknowledged automatically. The explicit
            // foreground challenge API separately verifies and approves it.
            return self.release_to_application(&lease, QueueReason::UnsupportedInBackground);
        };
        diagnostic_request(
            "request_parsed",
            request.method,
            connection.policy().methods(),
        );

        let Some(method) = domain_method(request.method) else {
            diagnostic_request(
                "request_not_implemented",
                request.method,
                connection.policy().methods(),
            );
            return self
                .respond_with_error(
                    &lease,
                    &connection,
                    &validated,
                    &relay,
                    request.method,
                    ErrorCode::NotImplemented,
                    RejectionCode::InvalidRequest,
                    &deadline,
                    cancellation,
                )
                .await;
        };
        if !connection.policy().allows(method) {
            diagnostic_request(
                "request_not_authorized",
                request.method,
                connection.policy().methods(),
            );
            return self
                .respond_with_error(
                    &lease,
                    &connection,
                    &validated,
                    &relay,
                    request.method,
                    ErrorCode::Restricted,
                    RejectionCode::MethodNotAllowed,
                    &deadline,
                    cancellation,
                )
                .await;
        }
        if method == NwcMethod::PayInvoice {
            self.record_diagnostic(WakeDiagnosticCode::PaymentRequestAccepted);
            let RequestParams::PayInvoice(payment) = request.params else {
                return self.reject_claim(&lease, RejectionCode::InvalidRequest);
            };
            match self.ledger.foreground_payments_enabled() {
                Ok(true) => {
                    if self
                        .ledger
                        .retain_foreground_wake(&wake, &event_json)
                        .is_err()
                    {
                        return self.release_to_application(&lease, QueueReason::LedgerBusy);
                    }
                }
                Ok(false) => {}
                Err(_) => return self.release_to_application(&lease, QueueReason::LedgerBusy),
            }
            return self
                .execute_payment(
                    &lease,
                    &connection,
                    &validated,
                    &relay,
                    payment,
                    purchase_json.as_deref(),
                    &deadline,
                    cancellation,
                )
                .await;
        }
        if !is_direct_request(method) {
            diagnostic_request(
                "request_not_directly_supported",
                request.method,
                connection.policy().methods(),
            );
            return self
                .respond_with_error(
                    &lease,
                    &connection,
                    &validated,
                    &relay,
                    request.method,
                    ErrorCode::NotImplemented,
                    RejectionCode::InvalidRequest,
                    &deadline,
                    cancellation,
                )
                .await;
        }
        if let Err(disposition) = self.ensure_claim_connection_active(&connection, &lease) {
            return disposition;
        }
        let Some(context) = deadline.context(cancellation) else {
            return self.release_to_application(&lease, QueueReason::Deadline);
        };
        let result = match self
            .execute_request(request, &connection, &validated, context)
            .await
        {
            Ok(result) => result,
            Err(error) if error.is_retryable() => {
                return self.retry_claim(&lease, RetryReason::WalletUnavailable)
            }
            Err(error) if error.kind() == HostErrorKind::Cancelled => {
                return self.release_to_application(&lease, QueueReason::Deadline)
            }
            Err(error) => {
                let code = host_error_code(error);
                return self
                    .respond_with_error(
                        &lease,
                        &connection,
                        &validated,
                        &relay,
                        protocol_method(method),
                        code,
                        RejectionCode::InvalidRequest,
                        &deadline,
                        cancellation,
                    )
                    .await;
            }
        };
        if let Err(disposition) = self.ensure_claim_connection_active(&connection, &lease) {
            return disposition;
        }
        let response = Response {
            result_type: result.method,
            error: None,
            result: Some(result.result),
        };
        self.commit_and_publish(
            &lease,
            &connection,
            &validated,
            &relay,
            response,
            &deadline,
            cancellation,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_payment(
        &self,
        lease: &EventLease,
        connection: &ActiveConnection,
        validated: &crate::ValidatedNwcEvent,
        relay: &SecureRelayUrl,
        payment: nip47::PayInvoiceRequest,
        purchase_json: Option<&str>,
        deadline: &OperationDeadline,
        cancellation: &dyn CancellationSignal,
    ) -> WakeDisposition {
        let explicit_amount = payment.amount.map(AmountMsat::from_msat);
        match self.ledger.load_payment_attempt_by_event(validated.id()) {
            Ok(Some(attempt)) => {
                if attempt.connection_id() != connection.id()
                    || attempt.connection_revision() != connection.revision()
                {
                    return self
                        .payment_error(
                            lease,
                            connection,
                            validated,
                            relay,
                            ErrorCode::Other,
                            RejectionCode::InvalidRequest,
                            deadline,
                            cancellation,
                        )
                        .await;
                }
                return self
                    .continue_payment(
                        lease,
                        connection,
                        validated,
                        relay,
                        &payment.invoice,
                        explicit_amount,
                        attempt,
                        deadline,
                        cancellation,
                    )
                    .await;
            }
            Ok(None) => {}
            Err(_) => return self.release_to_application(lease, QueueReason::LedgerBusy),
        }
        if payment.invoice.is_empty() || payment.invoice.len() > 16_384 {
            return self
                .payment_error(
                    lease,
                    connection,
                    validated,
                    relay,
                    ErrorCode::Other,
                    RejectionCode::InvalidRequest,
                    deadline,
                    cancellation,
                )
                .await;
        }
        let Some(context) = deadline.context(cancellation) else {
            return self.release_to_application(lease, QueueReason::Deadline);
        };
        let quote = match self
            .wallet
            .quote_payment(&payment.invoice, explicit_amount, context)
            .await
        {
            Ok(quote) => quote,
            Err(error) if error.is_retryable() => {
                self.record_diagnostic(WakeDiagnosticCode::PaymentQuoteFailed);
                return self.retry_claim(lease, RetryReason::WalletUnavailable);
            }
            Err(error) if error.kind() == HostErrorKind::Cancelled => {
                self.record_diagnostic(WakeDiagnosticCode::PaymentQuoteFailed);
                return self.release_to_application(lease, QueueReason::Deadline);
            }
            Err(_) => {
                self.record_diagnostic(WakeDiagnosticCode::PaymentQuoteFailed);
                return self
                    .payment_error(
                        lease,
                        connection,
                        validated,
                        relay,
                        ErrorCode::Other,
                        RejectionCode::InvalidRequest,
                        deadline,
                        cancellation,
                    )
                    .await;
            }
        };
        if self.ledger.foreground_payments_enabled().unwrap_or(true)
            && !self
                .ledger
                .has_foreground_binding(connection.id().as_str())
                .unwrap_or(false)
        {
            return self.release_to_application(lease, QueueReason::UnsupportedInBackground);
        }
        let reusable = self
            .ledger
            .is_reusable_foreground(connection.id().as_str())
            .unwrap_or(false);
        if reusable
            && purchase_json.is_none_or(|json| {
                self.ledger
                    .retain_purchase(
                        validated.id(),
                        json,
                        quote.payment_hash(),
                        quote.principal(),
                    )
                    .is_err()
            })
        {
            return self
                .payment_error(
                    lease,
                    connection,
                    validated,
                    relay,
                    ErrorCode::Restricted,
                    RejectionCode::InvalidRequest,
                    deadline,
                    cancellation,
                )
                .await;
        }
        if !reusable
            && self.ledger.foreground_payments_enabled().unwrap_or(true)
            && !self
                .ledger
                .matches_foreground_binding(
                    connection.id().as_str(),
                    quote.payment_hash(),
                    quote.principal(),
                    &payment.invoice,
                )
                .unwrap_or(false)
        {
            return self
                .payment_error(
                    lease,
                    connection,
                    validated,
                    relay,
                    ErrorCode::Restricted,
                    RejectionCode::InvalidRequest,
                    deadline,
                    cancellation,
                )
                .await;
        }
        let Some(principal_sat) = msat_to_sat_ceil(quote.principal().as_msat()) else {
            return self
                .payment_error(
                    lease,
                    connection,
                    validated,
                    relay,
                    ErrorCode::Other,
                    RejectionCode::InvalidRequest,
                    deadline,
                    cancellation,
                )
                .await;
        };
        if principal_sat == 0 {
            return self
                .payment_error(
                    lease,
                    connection,
                    validated,
                    relay,
                    ErrorCode::Other,
                    RejectionCode::InvalidRequest,
                    deadline,
                    cancellation,
                )
                .await;
        }
        if self
            .ledger
            .quote_foreground_payment(validated.id(), &payment.invoice, quote.principal())
            .is_err()
        {
            return self.release_to_application(lease, QueueReason::LedgerBusy);
        }
        let reservation = match self.ledger.reserve_payment(
            validated.id(),
            quote.payment_hash(),
            connection,
            principal_sat,
            self.clock.now(),
        ) {
            Ok(reservation) => reservation,
            Err(PaymentAccountingError::BudgetExceeded) => {
                self.record_diagnostic(WakeDiagnosticCode::PaymentBudgetExceeded);
                return self
                    .payment_error(
                        lease,
                        connection,
                        validated,
                        relay,
                        ErrorCode::QuotaExceeded,
                        RejectionCode::BudgetExceeded,
                        deadline,
                        cancellation,
                    )
                    .await;
            }
            Err(PaymentAccountingError::ConnectionUnavailable) => {
                return self.reject_claim(lease, RejectionCode::ConnectionUnavailable)
            }
            Err(
                PaymentAccountingError::InvalidAmount
                | PaymentAccountingError::ValueOutOfRange
                | PaymentAccountingError::ReservationConflict,
            ) => {
                return self
                    .payment_error(
                        lease,
                        connection,
                        validated,
                        relay,
                        ErrorCode::Other,
                        RejectionCode::InvalidRequest,
                        deadline,
                        cancellation,
                    )
                    .await
            }
            Err(_) => return self.release_to_application(lease, QueueReason::LedgerBusy),
        };
        let (attempt, already_tracked) = match reservation {
            PaymentReservationOutcome::Reserved(attempt)
            | PaymentReservationOutcome::Existing(attempt) => (attempt, false),
            PaymentReservationOutcome::AlreadyTracked(attempt) => (attempt, true),
        };
        if already_tracked {
            return self
                .payment_error(
                    lease,
                    connection,
                    validated,
                    relay,
                    ErrorCode::RateLimited,
                    RejectionCode::InvalidRequest,
                    deadline,
                    cancellation,
                )
                .await;
        }
        self.continue_payment(
            lease,
            connection,
            validated,
            relay,
            &payment.invoice,
            explicit_amount,
            attempt,
            deadline,
            cancellation,
        )
        .await
    }

    /// Continues an authenticated durable payment attempt without re-quoting it.
    #[allow(clippy::too_many_arguments)]
    async fn continue_payment(
        &self,
        lease: &EventLease,
        connection: &ActiveConnection,
        validated: &crate::ValidatedNwcEvent,
        relay: &SecureRelayUrl,
        invoice: &str,
        explicit_amount: Option<AmountMsat>,
        attempt: crate::PaymentAttempt,
        deadline: &OperationDeadline,
        cancellation: &dyn CancellationSignal,
    ) -> WakeDisposition {
        match self.ledger.foreground_payment_status(validated.id()) {
            Ok(Some(PaymentStatus::Pending)) => {
                return self.release_to_application(lease, QueueReason::UnsupportedInBackground);
            }
            Ok(Some(status)) => {
                // Rejection before submission still needs a terminal accounting marker.
                if !attempt.was_initiated()
                    && self
                        .ledger
                        .mark_payment_initiated(attempt.payment_hash(), self.clock.now())
                        .is_err()
                {
                    return self.release_to_application(lease, QueueReason::LedgerBusy);
                }
                return self
                    .finish_payment_status(
                        lease,
                        connection,
                        validated,
                        relay,
                        invoice,
                        attempt.payment_hash(),
                        status,
                        deadline,
                        cancellation,
                    )
                    .await;
            }
            Ok(None) => {}
            Err(_) => return self.release_to_application(lease, QueueReason::LedgerBusy),
        }
        if attempt.has_ambiguous_legacy_initiation() {
            return self
                .payment_error(
                    lease,
                    connection,
                    validated,
                    relay,
                    ErrorCode::Other,
                    RejectionCode::InvalidRequest,
                    deadline,
                    cancellation,
                )
                .await;
        }
        // A definitive durable failure must replay even while the wallet is
        // unavailable. Recheck authorization before constructing its response.
        if attempt.state() == crate::DurablePaymentState::Failed {
            if let Err(disposition) = self.ensure_claim_connection_active(connection, lease) {
                return disposition;
            }
            return self
                .payment_error(
                    lease,
                    connection,
                    validated,
                    relay,
                    ErrorCode::PaymentFailed,
                    RejectionCode::InvalidRequest,
                    deadline,
                    cancellation,
                )
                .await;
        }
        // The durable marker is written before crossing the host boundary. If
        // that boundary was never crossed, a hash-only success may belong to
        // an external payer. Resume by the event-id key first so the adapter
        // can identify this exact logical payment without disclosing another
        // payer's preimage.
        let must_resume_before_status =
            attempt.state() == crate::DurablePaymentState::Reserved && attempt.was_initiated();
        if !must_resume_before_status {
            let Some(context) = deadline.context(cancellation) else {
                return self.retry_claim(lease, RetryReason::WalletUnavailable);
            };
            let status = match self
                .wallet
                .payment_status(attempt.payment_hash(), context)
                .await
            {
                Ok(status) => status,
                Err(_) => {
                    self.record_diagnostic(WakeDiagnosticCode::PaymentStatusLookupFailed);
                    return self.retry_claim(lease, RetryReason::WalletUnavailable);
                }
            };
            if !matches!(status, PaymentStatus::Unknown) {
                if !attempt.may_disclose_settlement() {
                    if self
                        .ledger
                        .release_uninitiated_payment(attempt.payment_hash(), self.clock.now())
                        .is_err()
                    {
                        return self.release_to_application(lease, QueueReason::LedgerBusy);
                    }
                    return self
                        .payment_error(
                            lease,
                            connection,
                            validated,
                            relay,
                            ErrorCode::Other,
                            RejectionCode::InvalidRequest,
                            deadline,
                            cancellation,
                        )
                        .await;
                }
                return self
                    .finish_payment_status(
                        lease,
                        connection,
                        validated,
                        relay,
                        invoice,
                        attempt.payment_hash(),
                        status,
                        deadline,
                        cancellation,
                    )
                    .await;
            }
        }
        if let Err(disposition) = self.ensure_claim_connection_active(connection, lease) {
            return disposition;
        }
        if attempt.state() == crate::DurablePaymentState::Succeeded {
            return self.retry_claim(lease, RetryReason::WalletUnavailable);
        }
        let request = PayInvoiceRequest::new(
            invoice.to_owned(),
            explicit_amount,
            AmountSat::from_sat(attempt.fee_reserve_sat()),
            validated.id().clone(),
        );
        if !attempt.was_initiated() {
            if deadline.context(cancellation).is_none() {
                return self.retry_claim(lease, RetryReason::WalletUnavailable);
            }
            if self
                .ledger
                .mark_payment_initiated(attempt.payment_hash(), self.clock.now())
                .is_err()
            {
                return self.release_to_application(lease, QueueReason::LedgerBusy);
            }
        }
        let Some(context) = deadline.context(cancellation) else {
            return self.retry_claim(lease, RetryReason::WalletUnavailable);
        };
        match self.wallet.start_payment(request, context).await {
            Ok(status) => {
                self.finish_payment_status(
                    lease,
                    connection,
                    validated,
                    relay,
                    invoice,
                    attempt.payment_hash(),
                    status,
                    deadline,
                    cancellation,
                )
                .await
            }
            Err(error) if !error.confirms_payment_was_not_submitted() => {
                self.record_diagnostic(WakeDiagnosticCode::PaymentBackendFailed);
                if self
                    .ledger
                    .mark_payment_pending(attempt.payment_hash(), self.clock.now())
                    .is_err()
                {
                    return self.release_to_application(lease, QueueReason::LedgerBusy);
                }
                self.retry_claim(lease, RetryReason::WalletUnavailable)
            }
            Err(_) => {
                self.finish_payment_status(
                    lease,
                    connection,
                    validated,
                    relay,
                    invoice,
                    attempt.payment_hash(),
                    PaymentStatus::Failed {
                        reason: PaymentFailure::Other,
                    },
                    deadline,
                    cancellation,
                )
                .await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish_payment_status(
        &self,
        lease: &EventLease,
        connection: &ActiveConnection,
        validated: &crate::ValidatedNwcEvent,
        relay: &SecureRelayUrl,
        invoice: &str,
        payment_hash: &PaymentHash,
        status: PaymentStatus,
        deadline: &OperationDeadline,
        cancellation: &dyn CancellationSignal,
    ) -> WakeDisposition {
        match status {
            PaymentStatus::Unknown | PaymentStatus::Pending => {
                self.record_diagnostic(WakeDiagnosticCode::PaymentPending);
                if self
                    .ledger
                    .mark_payment_pending(payment_hash, self.clock.now())
                    .is_err()
                {
                    return self.release_to_application(lease, QueueReason::LedgerBusy);
                }
                self.retry_claim(lease, RetryReason::WalletUnavailable)
            }
            PaymentStatus::Succeeded {
                preimage,
                amount,
                fee,
            } => {
                self.record_diagnostic(WakeDiagnosticCode::PaymentSucceeded);
                let settled_at = self.clock.now();
                if self
                    .ledger
                    .mark_payment_succeeded(payment_hash, amount, fee, settled_at)
                    .is_err()
                {
                    return self.release_to_application(lease, QueueReason::LedgerBusy);
                }
                let notification = crate::TrackedNwcPayment::new(
                    validated.id().clone(),
                    payment_hash.clone(),
                    connection,
                    invoice.to_owned(),
                    amount,
                    fee,
                    preimage.clone(),
                    settled_at,
                    settled_at,
                );
                if self
                    .ledger
                    .record_nwc_sent_payment(&notification, connection.relays())
                    .is_err()
                {
                    return self.release_to_application(lease, QueueReason::LedgerBusy);
                }
                if let Err(disposition) = self.ensure_claim_connection_active(connection, lease) {
                    return disposition;
                }
                self.commit_and_publish(
                    lease,
                    connection,
                    validated,
                    relay,
                    Response {
                        result_type: Method::PayInvoice,
                        error: None,
                        result: Some(ResponseResult::PayInvoice(PayInvoiceResponse {
                            preimage: preimage.to_hex(),
                            fees_paid: Some(fee.as_msat()),
                        })),
                    },
                    deadline,
                    cancellation,
                )
                .await
            }
            PaymentStatus::Failed { reason } => {
                self.record_diagnostic(match reason {
                    PaymentFailure::InsufficientFunds => {
                        WakeDiagnosticCode::PaymentInsufficientFunds
                    }
                    _ => WakeDiagnosticCode::PaymentBackendFailed,
                });
                if self
                    .ledger
                    .mark_payment_failed(payment_hash, self.clock.now())
                    .is_err()
                {
                    return self.release_to_application(lease, QueueReason::LedgerBusy);
                }
                self.payment_error(
                    lease,
                    connection,
                    validated,
                    relay,
                    payment_failure_code(reason),
                    RejectionCode::InvalidRequest,
                    deadline,
                    cancellation,
                )
                .await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn payment_error(
        &self,
        lease: &EventLease,
        connection: &ActiveConnection,
        validated: &crate::ValidatedNwcEvent,
        relay: &SecureRelayUrl,
        error_code: ErrorCode,
        rejection: RejectionCode,
        deadline: &OperationDeadline,
        cancellation: &dyn CancellationSignal,
    ) -> WakeDisposition {
        self.respond_with_error(
            lease,
            connection,
            validated,
            relay,
            Method::PayInvoice,
            error_code,
            rejection,
            deadline,
            cancellation,
        )
        .await
    }

    async fn execute_request(
        &self,
        request: Request,
        connection: &ActiveConnection,
        validated: &crate::ValidatedNwcEvent,
        context: OperationContext<'_>,
    ) -> Result<DirectRequestResult, HostError> {
        match request.params {
            RequestParams::GetInfo => {
                let info = self.wallet.get_info(context).await?;
                let backend_methods = info.methods().collect::<Vec<_>>();
                let methods = backend_methods
                    .iter()
                    .copied()
                    .filter(|method| {
                        connection.policy().allows(*method) && is_engine_supported(*method)
                    })
                    .map(protocol_method)
                    .collect::<Vec<_>>();
                diagnostic_get_info(
                    connection.policy().methods(),
                    backend_methods.iter().copied(),
                    methods.iter().copied(),
                );
                Ok(DirectRequestResult {
                    method: Method::GetInfo,
                    result: ResponseResult::GetInfo(GetInfoResponse {
                        alias: None,
                        color: None,
                        pubkey: info.public_key().map(|key| key.to_hex()),
                        network: None,
                        block_height: None,
                        block_hash: None,
                        methods,
                        notifications: info
                            .notifications()
                            .map(|notification| notification.as_str().to_owned())
                            .collect(),
                    }),
                })
            }
            RequestParams::GetBalance => {
                let balance = self.wallet.get_balance(context).await?;
                Ok(DirectRequestResult {
                    method: Method::GetBalance,
                    result: ResponseResult::GetBalance(GetBalanceResponse {
                        balance: balance.as_msat(),
                    }),
                })
            }
            RequestParams::MakeInvoice(request) => {
                diagnostic_stage("make_invoice_dispatch_started");
                let (request, description) =
                    parse_make_invoice_request(request).map_err(HostError::new)?;
                let created_at = self.clock.now();
                let tracked = if let Some(existing) =
                    self.ledger
                        .load_nwc_invoice(validated.id())
                        .map_err(|_| HostError::new(HostErrorKind::Unavailable))?
                {
                    existing
                } else {
                    let created = self.wallet.make_invoice(request, context).await?;
                    let tracked = crate::TrackedNwcInvoice::new(
                        validated.id().clone(),
                        created.payment_hash().clone(),
                        connection.id().clone(),
                        connection.revision(),
                        created.invoice().to_owned(),
                        description.clone(),
                        created.amount(),
                        created_at,
                        created.expires_at(),
                    );
                    self.ledger
                        .record_nwc_invoice(&tracked, connection.relays())
                        .map_err(|_| HostError::new(HostErrorKind::Unavailable))?
                };
                diagnostic_stage("make_invoice_dispatch_completed");
                Ok(DirectRequestResult {
                    method: Method::MakeInvoice,
                    result: ResponseResult::MakeInvoice(MakeInvoiceResponse {
                        invoice: tracked.invoice().to_owned(),
                        payment_hash: Some(tracked.payment_hash().to_hex()),
                        description: tracked.description().map(str::to_owned),
                        description_hash: None,
                        preimage: None,
                        amount: Some(tracked.amount().as_msat()),
                        created_at: Some(Timestamp::from(tracked.created_at().as_secs())),
                        expires_at: Some(Timestamp::from(tracked.expires_at().as_secs())),
                    }),
                })
            }
            RequestParams::LookupInvoice(request) => {
                // A freshly created invoice can be durably visible in the
                // nwc-mobile ledger before another short-lived host process
                // observes its wallet checkpoint. Resolve exact wallet-created
                // selectors through the ledger first so this transient view
                // cannot turn the client's first lookup into a terminal
                // NotFound response that stops settlement polling.
                let tracked = if let Some(invoice) = request.invoice.as_deref() {
                    self.ledger
                        .load_nwc_invoice_by_encoded_invoice(invoice)
                        .map_err(|_| HostError::new(HostErrorKind::Unavailable))?
                } else if let Some(payment_hash) = request.payment_hash.as_deref() {
                    let payment_hash = PaymentHash::from_hex(payment_hash)
                        .map_err(|_| HostError::new(HostErrorKind::Rejected))?;
                    self.ledger
                        .load_nwc_invoice_by_payment_hash(&payment_hash)
                        .map_err(|_| HostError::new(HostErrorKind::Unavailable))?
                } else {
                    None
                };
                let lookup = tracked.as_ref().map_or_else(
                    || parse_lookup_request(request).map_err(HostError::new),
                    |invoice| Ok(InvoiceLookup::PaymentHash(invoice.payment_hash().clone())),
                )?;
                let transaction = if self
                    .ledger
                    .foreground_payments_enabled()
                    .map_err(|_| HostError::new(HostErrorKind::Unavailable))?
                {
                    self.ledger
                        .lookup_foreground_payment(connection.id().as_str(), &lookup)
                        .map_err(|_| HostError::new(HostErrorKind::Unavailable))?
                } else {
                    self.wallet.lookup_invoice(lookup, context).await?
                };
                let response = transaction
                    .or_else(|| {
                        tracked
                            .as_ref()
                            .filter(|invoice| invoice.expires_at() > self.clock.now())
                            .map(pending_tracked_invoice_transaction)
                    })
                    .map(transaction_response)
                    .transpose()
                    .map_err(HostError::new)?
                    .ok_or_else(|| HostError::new(HostErrorKind::NotFound))?;
                Ok(DirectRequestResult {
                    method: Method::LookupInvoice,
                    result: ResponseResult::LookupInvoice(response),
                })
            }
            RequestParams::ListTransactions(request) => {
                let request = parse_list_request(request).map_err(HostError::new)?;
                let transactions = self.wallet.list_transactions(request, context).await?;
                let responses = transactions
                    .into_iter()
                    .map(transaction_response)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(HostError::new)?;
                Ok(DirectRequestResult {
                    method: Method::ListTransactions,
                    result: ResponseResult::ListTransactions(responses),
                })
            }
            _ => Err(HostError::new(HostErrorKind::Rejected)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn respond_with_error(
        &self,
        lease: &EventLease,
        connection: &ActiveConnection,
        validated: &crate::ValidatedNwcEvent,
        relay: &SecureRelayUrl,
        method: Method,
        error_code: ErrorCode,
        rejection: RejectionCode,
        deadline: &OperationDeadline,
        cancellation: &dyn CancellationSignal,
    ) -> WakeDisposition {
        if let Err(disposition) = self.ensure_claim_connection_active(connection, lease) {
            return disposition;
        }
        let response = Response {
            result_type: method,
            error: Some(NIP47Error {
                code: error_code,
                message: protocol_error_message(error_code).to_owned(),
            }),
            result: None,
        };
        let disposition = self
            .commit_and_publish(
                lease,
                connection,
                validated,
                relay,
                response,
                deadline,
                cancellation,
            )
            .await;
        match disposition {
            WakeDisposition::Completed { notification } => WakeDisposition::Rejected {
                code: rejection,
                notification,
            },
            other => other,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn commit_and_publish(
        &self,
        lease: &EventLease,
        connection: &ActiveConnection,
        validated: &crate::ValidatedNwcEvent,
        relay: &SecureRelayUrl,
        response: Response,
        deadline: &OperationDeadline,
        cancellation: &dyn CancellationSignal,
    ) -> WakeDisposition {
        let request_method = domain_method(response.result_type);
        let notification = request_method.map_or(NotificationHint::Completed, |method| {
            NotificationHint::Request { method }
        });
        let mut response_json = response.as_json();
        let Some(context) = deadline.context(cancellation) else {
            return self.release_to_application(lease, QueueReason::Deadline);
        };
        let secret = match self.secrets.load_nwc_secret(connection.id(), context).await {
            Ok(secret) => secret,
            Err(_) => {
                return self.release_to_application(lease, QueueReason::SecureStorageUnavailable)
            }
        };
        if response.error.is_none() && response.result_type == Method::GetInfo {
            match self
                .ledger
                .connection_payer_metadata(connection.id().as_str())
            {
                Ok(Some(metadata)) => {
                    let Ok(mut value) =
                        nostr::serde_json::from_str::<nostr::serde_json::Value>(&response_json)
                    else {
                        return self.release_to_application(lease, QueueReason::LedgerBusy);
                    };
                    if let Some(username) = metadata.payer_username() {
                        value["result"]["payer_username"] = username.into();
                    }
                    if let Some(name) = metadata.wallet_name() {
                        value["result"]["alias"] = name.into();
                    }
                    match self
                        .ledger
                        .connection_address(connection.id().as_str(), &secret)
                    {
                        Ok(Some(address)) => value["result"]["payer_address"] = address,
                        Ok(None) => {}
                        Err(_) => {
                            return self.release_to_application(lease, QueueReason::LedgerBusy)
                        }
                    }
                    response_json = value.to_string();
                }
                Ok(None) => {}
                Err(_) => return self.release_to_application(lease, QueueReason::LedgerBusy),
            }
        }
        if response.error.is_none()
            && self
                .ledger
                .is_reusable_foreground(connection.id().as_str())
                .unwrap_or(false)
        {
            let mut value: nostr::serde_json::Value =
                match nostr::serde_json::from_str(&response_json) {
                    Ok(value) => value,
                    Err(_) => return self.reject_claim(lease, RejectionCode::InvalidRequest),
                };
            if response.result_type == Method::GetInfo {
                let result = &mut value["result"];
                result["payment_mode"] = "confirm_each".into();
                result["budget_basis"] = "invoice_principal".into();
                result["fee_policy"] = "wallet_managed".into();
                result["purchase_versions"] = nostr::serde_json::json!([1]);
                result["browser_pairing_versions"] = nostr::serde_json::json!([1]);
                result["budget_limit_msats"] = (connection.policy().budget().limit_sat() * 1000)
                    .to_string()
                    .into();
                result["budget_renewal"] = "monthly".into();
                result["expires_at"] = connection.expires_at().map(|t| t.as_secs()).into();
            } else if response.result_type == Method::PayInvoice {
                match self.ledger.purchase_response(validated.id(), &secret) {
                    Ok(Some(purchase)) => value["result"]["purchase"] = purchase,
                    _ => return self.release_to_application(lease, QueueReason::LedgerBusy),
                }
            }
            response_json = value.to_string();
        }
        let event_json =
            match validated.build_response_event(&secret, &response_json, self.clock.now()) {
                Ok(event) => event,
                Err(_) => return self.reject_claim(lease, RejectionCode::InvalidRequest),
            };
        drop(secret);
        let completion = match request_method {
            Some(method) => self.ledger.complete_nwc_event_for_active_connection(
                lease,
                connection.id(),
                connection.revision(),
                &event_json,
                method,
                self.clock.now(),
            ),
            None => self.ledger.complete_event_for_active_connection(
                lease,
                connection.id(),
                connection.revision(),
                &event_json,
                self.clock.now(),
            ),
        };
        match completion {
            Ok(()) => {}
            Err(error) => return self.completion_failed(lease, error),
        }
        self.republish_terminal(
            validated.id(),
            connection,
            relay,
            Some(&event_json),
            notification,
            deadline,
            cancellation,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn republish_terminal(
        &self,
        event_id: &crate::EventId,
        connection: &ActiveConnection,
        relay: &SecureRelayUrl,
        event_json: Option<&str>,
        notification: NotificationHint,
        deadline: &OperationDeadline,
        cancellation: &dyn CancellationSignal,
    ) -> WakeDisposition {
        let Some(event_json) = event_json else {
            return already_processed();
        };
        match self.revision_is_active(connection) {
            Ok(true) => {}
            Ok(false) => return rejected(RejectionCode::ConnectionUnavailable),
            Err(_) => return queued(QueueReason::LedgerBusy),
        }
        let Some(context) = deadline.context(cancellation) else {
            self.record_diagnostic(WakeDiagnosticCode::ResponsePublishFailed);
            return retry(ENGINE_RETRY_DELAY, RetryReason::ResponsePublishFailed);
        };
        match self.relays.publish_event(relay, event_json, context).await {
            Ok(()) => {
                if self
                    .ledger
                    .acknowledge_foreground_response(event_id)
                    .is_err()
                {
                    return queued(QueueReason::LedgerBusy);
                }
                completed(notification)
            }
            Err(_) => {
                self.record_diagnostic(WakeDiagnosticCode::ResponsePublishFailed);
                retry(ENGINE_RETRY_DELAY, RetryReason::ResponsePublishFailed)
            }
        }
    }

    fn revision_is_active(
        &self,
        connection: &ActiveConnection,
    ) -> Result<bool, crate::RegistryError> {
        self.ledger
            .is_connection_revision_active(connection.id(), connection.revision())
    }

    fn ensure_claim_connection_active(
        &self,
        connection: &ActiveConnection,
        lease: &EventLease,
    ) -> Result<(), WakeDisposition> {
        match self.revision_is_active(connection) {
            Ok(true) => Ok(()),
            Ok(false) => Err(self.reject_claim(lease, RejectionCode::ConnectionUnavailable)),
            Err(_) => Err(self.release_to_application(lease, QueueReason::LedgerBusy)),
        }
    }

    fn reject_claim(&self, lease: &EventLease, code: RejectionCode) -> WakeDisposition {
        match self
            .ledger
            .complete_event(lease, TerminalKind::Rejected, None, self.clock.now())
        {
            Ok(()) => rejected(code),
            Err(_) => queued(QueueReason::LedgerBusy),
        }
    }

    fn retry_claim(&self, lease: &EventLease, reason: RetryReason) -> WakeDisposition {
        match self
            .ledger
            .retry_later(lease, self.clock.now(), ENGINE_RETRY_DELAY)
        {
            Ok(()) => retry(ENGINE_RETRY_DELAY, reason),
            Err(_) => queued(QueueReason::LedgerBusy),
        }
    }

    fn completion_failed(&self, lease: &EventLease, error: LedgerError) -> WakeDisposition {
        match error {
            LedgerError::ConnectionUnavailable => rejected(RejectionCode::ConnectionUnavailable),
            LedgerError::LostLease => {
                retry(ENGINE_RETRY_DELAY, RetryReason::ResponsePersistenceFailed)
            }
            LedgerError::ResponseTooLarge => queued(QueueReason::UnsupportedInBackground),
            _ => self.retry_claim(lease, RetryReason::ResponsePersistenceFailed),
        }
    }

    fn release_to_application(&self, lease: &EventLease, reason: QueueReason) -> WakeDisposition {
        match self
            .ledger
            .retry_later(lease, self.clock.now(), ENGINE_RETRY_DELAY)
        {
            Ok(()) => queued(reason),
            Err(_) => queued(QueueReason::LedgerBusy),
        }
    }

    fn record_diagnostic(&self, code: WakeDiagnosticCode) {
        if let Some(diagnostics) = self.diagnostics {
            diagnostics.record(code);
        }
    }
}

/// Compatibility name for the engine introduced with read-only execution.
pub type ReadOnlyWakeEngine<'a> = WakeEngine<'a>;

struct DirectRequestResult {
    method: Method,
    result: ResponseResult,
}

fn parse_make_invoice_request(
    request: nip47::MakeInvoiceRequest,
) -> Result<(MakeInvoiceRequest, Option<String>), HostErrorKind> {
    if request.amount == 0 || request.description_hash.is_some() {
        return Err(HostErrorKind::Rejected);
    }
    let description = request.description;
    if description
        .as_ref()
        .is_some_and(|description| description.len() > MAX_INVOICE_DESCRIPTION_BYTES)
    {
        return Err(HostErrorKind::Rejected);
    }
    let expiry = Duration::from_secs(request.expiry.unwrap_or(DEFAULT_INVOICE_EXPIRY.as_secs()));
    if expiry.is_zero() || expiry > MAX_INVOICE_EXPIRY {
        return Err(HostErrorKind::Rejected);
    }
    Ok((
        MakeInvoiceRequest::new(
            AmountMsat::from_msat(request.amount),
            description.clone(),
            expiry,
        ),
        description,
    ))
}

fn parse_lookup_request(
    request: nip47::LookupInvoiceRequest,
) -> Result<InvoiceLookup, HostErrorKind> {
    match (request.payment_hash, request.invoice) {
        (Some(hash), None) => PaymentHash::from_hex(&hash)
            .map(InvoiceLookup::PaymentHash)
            .map_err(|_| HostErrorKind::Rejected),
        (_, Some(invoice)) if !invoice.is_empty() && invoice.len() <= 16_384 => {
            // NIP-47 clients may include both selectors. Keep the behavior of
            // Rebel's original NWC implementation and treat the encoded invoice
            // as authoritative; the wallet backend derives its payment hash from
            // the invoice instead of trusting the redundant request field.
            Ok(InvoiceLookup::Invoice(invoice))
        }
        _ => Err(HostErrorKind::Rejected),
    }
}

fn parse_list_request(
    request: nip47::ListTransactionsRequest,
) -> Result<ListTransactionsRequest, HostErrorKind> {
    let from = request
        .from
        .map(|value| UnixTimestamp::from_secs(value.as_secs()));
    let until = request
        .until
        .map(|value| UnixTimestamp::from_secs(value.as_secs()));
    if matches!((from, until), (Some(from), Some(until)) if from > until) {
        return Err(HostErrorKind::Rejected);
    }
    let requested_limit = request.limit.unwrap_or(u64::from(DEFAULT_LIST_LIMIT));
    let limit = u16::try_from(requested_limit.min(u64::from(MAX_LIST_LIMIT)))
        .map_err(|_| HostErrorKind::Rejected)?;
    let offset = u32::try_from(request.offset.unwrap_or(0)).map_err(|_| HostErrorKind::Rejected)?;
    let direction = request.transaction_type.map(|direction| match direction {
        TransactionType::Incoming => crate::TransactionDirection::Incoming,
        TransactionType::Outgoing => crate::TransactionDirection::Outgoing,
    });
    Ok(ListTransactionsRequest {
        from,
        until,
        limit,
        offset,
        direction,
        include_unpaid: request.unpaid.unwrap_or(false),
    })
}

fn transaction_response(
    transaction: WalletTransaction,
) -> Result<LookupInvoiceResponse, HostErrorKind> {
    let payment_hash = transaction
        .payment_hash
        .ok_or(HostErrorKind::Internal)?
        .to_hex();
    let (state, preimage) = match transaction.status {
        PaymentStatus::Unknown | PaymentStatus::Pending => (TransactionState::Pending, None),
        PaymentStatus::Succeeded { preimage, .. } => {
            (TransactionState::Settled, Some(preimage.to_hex()))
        }
        PaymentStatus::Failed { .. } => (TransactionState::Failed, None),
    };
    Ok(LookupInvoiceResponse {
        transaction_type: Some(match transaction.direction {
            crate::TransactionDirection::Incoming => TransactionType::Incoming,
            crate::TransactionDirection::Outgoing => TransactionType::Outgoing,
        }),
        state: Some(state),
        invoice: None,
        description: None,
        description_hash: None,
        preimage,
        payment_hash,
        amount: transaction.amount.as_msat(),
        fees_paid: transaction.fee.as_msat(),
        created_at: Timestamp::from(transaction.created_at.as_secs()),
        expires_at: None,
        settled_at: transaction
            .settled_at
            .map(|time| Timestamp::from(time.as_secs())),
        metadata: None,
    })
}

fn pending_tracked_invoice_transaction(invoice: &crate::TrackedNwcInvoice) -> WalletTransaction {
    WalletTransaction {
        payment_hash: Some(invoice.payment_hash().clone()),
        direction: crate::TransactionDirection::Incoming,
        amount: invoice.amount(),
        fee: AmountMsat::default(),
        created_at: invoice.created_at(),
        settled_at: None,
        status: PaymentStatus::Pending,
    }
}

fn domain_method(method: Method) -> Option<NwcMethod> {
    match method {
        Method::GetInfo => Some(NwcMethod::GetInfo),
        Method::GetBalance => Some(NwcMethod::GetBalance),
        Method::MakeInvoice => Some(NwcMethod::MakeInvoice),
        Method::PayInvoice => Some(NwcMethod::PayInvoice),
        Method::LookupInvoice => Some(NwcMethod::LookupInvoice),
        Method::ListTransactions => Some(NwcMethod::ListTransactions),
        _ => None,
    }
}

fn protocol_method(method: NwcMethod) -> Method {
    match method {
        NwcMethod::GetInfo => Method::GetInfo,
        NwcMethod::GetBalance => Method::GetBalance,
        NwcMethod::MakeInvoice => Method::MakeInvoice,
        NwcMethod::PayInvoice => Method::PayInvoice,
        NwcMethod::LookupInvoice => Method::LookupInvoice,
        NwcMethod::ListTransactions => Method::ListTransactions,
    }
}

fn is_direct_request(method: NwcMethod) -> bool {
    matches!(
        method,
        NwcMethod::GetInfo
            | NwcMethod::GetBalance
            | NwcMethod::MakeInvoice
            | NwcMethod::LookupInvoice
            | NwcMethod::ListTransactions
    )
}

fn is_engine_supported(method: NwcMethod) -> bool {
    method == NwcMethod::PayInvoice || is_direct_request(method)
}

#[cfg(feature = "diagnostics")]
fn diagnostic_stage(stage: &str) {
    eprintln!("nwc-mobile diagnostic stage={stage}");
}

#[cfg(not(feature = "diagnostics"))]
fn diagnostic_stage(_stage: &str) {}

#[cfg(feature = "diagnostics")]
fn diagnostic_request(
    stage: &str,
    method: Method,
    policy_methods: impl IntoIterator<Item = NwcMethod>,
) {
    let policy_methods = diagnostic_method_names(policy_methods);
    eprintln!(
        "nwc-mobile diagnostic stage={stage} method={method} policy_methods=[{policy_methods}]"
    );
}

#[cfg(not(feature = "diagnostics"))]
fn diagnostic_request(
    _stage: &str,
    _method: Method,
    _policy_methods: impl IntoIterator<Item = NwcMethod>,
) {
}

#[cfg(feature = "diagnostics")]
fn diagnostic_get_info(
    policy_methods: impl IntoIterator<Item = NwcMethod>,
    backend_methods: impl IntoIterator<Item = NwcMethod>,
    advertised_methods: impl IntoIterator<Item = Method>,
) {
    let policy_methods = diagnostic_method_names(policy_methods);
    let backend_methods = diagnostic_method_names(backend_methods);
    let advertised_methods = advertised_methods
        .into_iter()
        .map(|method| method.to_string())
        .collect::<Vec<_>>()
        .join(",");
    eprintln!(
        "nwc-mobile diagnostic stage=get_info_response policy_methods=[{policy_methods}] backend_methods=[{backend_methods}] advertised_methods=[{advertised_methods}]"
    );
}

#[cfg(not(feature = "diagnostics"))]
fn diagnostic_get_info(
    _policy_methods: impl IntoIterator<Item = NwcMethod>,
    _backend_methods: impl IntoIterator<Item = NwcMethod>,
    _advertised_methods: impl IntoIterator<Item = Method>,
) {
}

#[cfg(feature = "diagnostics")]
fn diagnostic_method_names(methods: impl IntoIterator<Item = NwcMethod>) -> String {
    methods
        .into_iter()
        .map(NwcMethod::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

fn event_rejection(error: crate::NostrEventError) -> RejectionCode {
    match error {
        crate::NostrEventError::InvalidCreatedAt => RejectionCode::EventOutsideFreshnessWindow,
        crate::NostrEventError::EventIdMismatch => RejectionCode::EventMismatch,
        _ => RejectionCode::InvalidEvent,
    }
}

fn host_error_code(error: HostError) -> ErrorCode {
    match error.kind() {
        HostErrorKind::NotFound => ErrorCode::NotFound,
        HostErrorKind::Rejected => ErrorCode::Other,
        _ => ErrorCode::Internal,
    }
}

const fn payment_failure_code(reason: PaymentFailure) -> ErrorCode {
    match reason {
        PaymentFailure::InsufficientFunds => ErrorCode::InsufficientBalance,
        PaymentFailure::InvalidInvoice
        | PaymentFailure::NoRoute
        | PaymentFailure::RecipientRejected
        | PaymentFailure::Other => ErrorCode::PaymentFailed,
    }
}

const fn msat_to_sat_ceil(amount_msat: u64) -> Option<u64> {
    match amount_msat.checked_add(999) {
        Some(rounded) => Some(rounded / 1_000),
        None => None,
    }
}

fn lease_duration_for_budget(remaining: Duration) -> Option<Duration> {
    if remaining.is_zero() {
        return None;
    }
    let rounded_seconds = remaining
        .as_secs()
        .checked_add(u64::from(remaining.subsec_nanos() != 0))?;
    rounded_seconds.checked_add(1).map(Duration::from_secs)
}

const fn protocol_error_message(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::NotImplemented => "method is not implemented",
        ErrorCode::Restricted => "method is not authorized",
        ErrorCode::NotFound => "wallet object was not found",
        ErrorCode::Other => "request was rejected",
        _ => "wallet operation failed",
    }
}

const fn completed(notification: NotificationHint) -> WakeDisposition {
    WakeDisposition::Completed { notification }
}

const fn already_processed() -> WakeDisposition {
    WakeDisposition::AlreadyProcessed {
        notification: NotificationHint::Completed,
    }
}

const fn queued(reason: QueueReason) -> WakeDisposition {
    WakeDisposition::QueuedForApplication {
        reason,
        notification: NotificationHint::OpenApplication,
    }
}

const fn retry(delay: Duration, reason: RetryReason) -> WakeDisposition {
    WakeDisposition::RetryAfter {
        delay,
        reason,
        notification: NotificationHint::Processing,
    }
}

const fn rejected(code: RejectionCode) -> WakeDisposition {
    WakeDisposition::Rejected {
        code,
        notification: NotificationHint::Completed,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::future::Future;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::task::{Context, Poll, Waker};

    use nostr::{Event, EventBuilder, Keys, SecretKey, Tag};

    use super::*;
    use crate::{
        AmountMsat, BudgetInterval, BudgetPolicy, ConnectionId, ConnectionPolicy, CreatedInvoice,
        FeePolicy, HostFuture, NewConnection, PayInvoiceRequest, PaymentQuote, PublicKey,
        WalletInfo,
    };

    const CLIENT_SECRET: [u8; 32] = [1_u8; 32];
    const WALLET_SECRET: [u8; 32] = [2_u8; 32];
    const RELAY: &str = "wss://relay.example.com/nwc";

    struct TestDatabase {
        directory: PathBuf,
        path: PathBuf,
    }

    impl TestDatabase {
        fn new() -> Self {
            let mut random = [0_u8; 8];
            getrandom::fill(&mut random).expect("test randomness");
            use std::fmt::Write as _;
            let suffix = random.iter().fold(String::new(), |mut suffix, byte| {
                write!(&mut suffix, "{byte:02x}").expect("write suffix");
                suffix
            });
            let directory = std::env::temp_dir()
                .join(format!("nwc-mobile-engine-{}-{suffix}", std::process::id()));
            fs::create_dir(&directory).expect("create test directory");
            let path = directory.join("engine.sqlite3");
            Self { directory, path }
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    struct FixedClock(AtomicUsize);

    impl FixedClock {
        fn new(seconds: u64) -> Self {
            Self(AtomicUsize::new(
                usize::try_from(seconds).expect("test timestamp"),
            ))
        }

        fn set(&self, seconds: u64) {
            self.0.store(
                usize::try_from(seconds).expect("test timestamp"),
                Ordering::SeqCst,
            );
        }
    }

    impl Clock for FixedClock {
        fn now(&self) -> UnixTimestamp {
            UnixTimestamp::from_secs(
                u64::try_from(self.0.load(Ordering::SeqCst)).expect("test timestamp"),
            )
        }
    }

    struct TestSecrets {
        bytes: [u8; 32],
        loads: AtomicUsize,
    }

    impl TestSecrets {
        fn wallet() -> Self {
            Self {
                bytes: WALLET_SECRET,
                loads: AtomicUsize::new(0),
            }
        }
    }

    impl SecretProvider for TestSecrets {
        fn load_nwc_secret<'b>(
            &'b self,
            _connection_id: &'b ConnectionId,
            _context: OperationContext<'b>,
        ) -> HostFuture<'b, Result<crate::NwcSecretKey, HostError>> {
            Box::pin(async move {
                self.loads.fetch_add(1, Ordering::SeqCst);
                crate::NwcSecretKey::from_bytes(self.bytes)
                    .map_err(|_| HostError::new(HostErrorKind::Internal))
            })
        }
    }

    struct ExpiringResponseSecrets<'a> {
        clock: &'a FixedClock,
        loads: AtomicUsize,
    }

    impl SecretProvider for ExpiringResponseSecrets<'_> {
        fn load_nwc_secret<'b>(
            &'b self,
            _connection_id: &'b ConnectionId,
            _context: OperationContext<'b>,
        ) -> HostFuture<'b, Result<crate::NwcSecretKey, HostError>> {
            Box::pin(async move {
                if self.loads.fetch_add(1, Ordering::SeqCst) == 1 {
                    self.clock.set(1_000);
                }
                crate::NwcSecretKey::from_bytes(WALLET_SECRET)
                    .map_err(|_| HostError::new(HostErrorKind::Internal))
            })
        }
    }

    #[derive(Default)]
    struct TestRelay {
        fetched_event: Mutex<Option<String>>,
        published: Mutex<Vec<String>>,
        fetch_calls: AtomicUsize,
        maximum_fetch_bytes: AtomicUsize,
        fail_next_publish: AtomicBool,
    }

    impl RelayTransport for TestRelay {
        fn fetch_event<'a>(
            &'a self,
            _relay: &'a SecureRelayUrl,
            _event_id: &'a crate::EventId,
            maximum_event_bytes: usize,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<Option<String>, HostError>> {
            self.fetch_calls.fetch_add(1, Ordering::SeqCst);
            self.maximum_fetch_bytes
                .store(maximum_event_bytes, Ordering::SeqCst);
            let event = self.fetched_event.lock().expect("fetch lock");
            if event
                .as_ref()
                .is_some_and(|event| event.len() > maximum_event_bytes)
            {
                return Box::pin(async { Err(HostError::new(HostErrorKind::Rejected)) });
            }
            let event = event.clone();
            Box::pin(async move { Ok(event) })
        }

        fn publish_event<'a>(
            &'a self,
            _relay: &'a SecureRelayUrl,
            event_json: &'a str,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<(), HostError>> {
            if self.fail_next_publish.swap(false, Ordering::SeqCst) {
                return Box::pin(async { Err(HostError::new(HostErrorKind::Unavailable)) });
            }
            self.published
                .lock()
                .expect("publish lock")
                .push(event_json.to_owned());
            Box::pin(async { Ok(()) })
        }
    }

    #[derive(Default)]
    struct TestWallet<'a> {
        balance_calls: AtomicUsize,
        invoice_requests: Mutex<Vec<MakeInvoiceRequest>>,
        lookup_requests: Mutex<Vec<InvoiceLookup>>,
        lookup_returns_none: AtomicBool,
        revoke_on_balance: Mutex<Option<(&'a WakeLedger, ConnectionId, crate::ConnectionRevision)>>,
        quote: Mutex<Option<PaymentQuote>>,
        payment_statuses: Mutex<VecDeque<Result<PaymentStatus, HostError>>>,
        start_results: Mutex<VecDeque<Result<PaymentStatus, HostError>>>,
        start_requests: Mutex<Vec<PayInvoiceRequest>>,
        quote_calls: AtomicUsize,
        status_calls: AtomicUsize,
        start_calls: AtomicUsize,
    }

    impl NwcWalletBackend for TestWallet<'_> {
        fn get_info<'a>(
            &'a self,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<WalletInfo, HostError>> {
            Box::pin(async {
                Ok(WalletInfo::new(
                    None,
                    [
                        NwcMethod::GetInfo,
                        NwcMethod::GetBalance,
                        NwcMethod::MakeInvoice,
                        NwcMethod::PayInvoice,
                    ],
                )
                .with_notifications([
                    crate::NwcNotificationType::PaymentReceived,
                    crate::NwcNotificationType::PaymentSent,
                ]))
            })
        }

        fn get_balance<'a>(
            &'a self,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<AmountMsat, HostError>> {
            self.balance_calls.fetch_add(1, Ordering::SeqCst);
            if let Some((ledger, id, revision)) =
                self.revoke_on_balance.lock().expect("revoke lock").take()
            {
                ledger
                    .tombstone_connection(&id, revision, UnixTimestamp::from_secs(100))
                    .expect("revoke connection during host call");
            }
            Box::pin(async { Ok(AmountMsat::from_msat(42_000)) })
        }

        fn make_invoice<'a>(
            &'a self,
            request: MakeInvoiceRequest,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<CreatedInvoice, HostError>> {
            self.invoice_requests
                .lock()
                .expect("invoice requests lock")
                .push(request);
            Box::pin(async {
                Ok(CreatedInvoice::new(
                    "lnbc420n1test".to_string(),
                    PaymentHash::from_bytes([8_u8; 32]),
                    AmountMsat::from_msat(42_000),
                    UnixTimestamp::from_secs(700),
                ))
            })
        }

        fn quote_payment<'a>(
            &'a self,
            _invoice: &'a str,
            _amount: Option<AmountMsat>,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<crate::PaymentQuote, HostError>> {
            self.quote_calls.fetch_add(1, Ordering::SeqCst);
            let result = self
                .quote
                .lock()
                .expect("quote lock")
                .clone()
                .ok_or_else(|| HostError::new(HostErrorKind::Rejected));
            Box::pin(async move { result })
        }

        fn payment_status<'a>(
            &'a self,
            _payment_hash: &'a PaymentHash,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<PaymentStatus, HostError>> {
            self.status_calls.fetch_add(1, Ordering::SeqCst);
            let result = self
                .payment_statuses
                .lock()
                .expect("status lock")
                .pop_front()
                .unwrap_or_else(|| Err(HostError::new(HostErrorKind::Internal)));
            Box::pin(async move { result })
        }

        fn start_payment<'a>(
            &'a self,
            request: PayInvoiceRequest,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<PaymentStatus, HostError>> {
            self.start_calls.fetch_add(1, Ordering::SeqCst);
            self.start_requests
                .lock()
                .expect("start requests lock")
                .push(request);
            let result = self
                .start_results
                .lock()
                .expect("start lock")
                .pop_front()
                .unwrap_or_else(|| Err(HostError::new(HostErrorKind::Internal)));
            Box::pin(async move { result })
        }

        fn lookup_invoice<'a>(
            &'a self,
            request: InvoiceLookup,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<Option<WalletTransaction>, HostError>> {
            self.lookup_requests
                .lock()
                .expect("lookup requests lock")
                .push(request);
            if self.lookup_returns_none.load(Ordering::SeqCst) {
                return Box::pin(async { Ok(None) });
            }
            Box::pin(async {
                Ok(Some(WalletTransaction {
                    payment_hash: Some(PaymentHash::from_bytes([8_u8; 32])),
                    direction: crate::TransactionDirection::Incoming,
                    amount: AmountMsat::from_msat(42_000),
                    fee: AmountMsat::from_msat(0),
                    created_at: UnixTimestamp::from_secs(100),
                    settled_at: None,
                    status: PaymentStatus::Pending,
                }))
            })
        }

        fn list_transactions<'a>(
            &'a self,
            _request: ListTransactionsRequest,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<Vec<WalletTransaction>, HostError>> {
            unavailable()
        }
    }

    fn unavailable<'a, T: Send + 'a>() -> HostFuture<'a, Result<T, HostError>> {
        Box::pin(async { Err(HostError::new(HostErrorKind::Internal)) })
    }

    fn client_keys() -> Keys {
        Keys::new(SecretKey::from_slice(&CLIENT_SECRET).expect("client secret"))
    }

    fn wallet_keys() -> Keys {
        Keys::new(SecretKey::from_slice(&WALLET_SECRET).expect("wallet secret"))
    }

    fn domain_key(key: nostr::PublicKey) -> PublicKey {
        PublicKey::from_bytes(*key.as_bytes())
    }

    fn connection_id() -> ConnectionId {
        ConnectionId::parse("connection:engine-test").expect("connection id")
    }

    fn insert_connection(ledger: &WakeLedger) -> ActiveConnection {
        ledger
            .insert_connection(
                NewConnection::new(
                    connection_id(),
                    domain_key(client_keys().public_key()),
                    domain_key(wallet_keys().public_key()),
                    vec![SecureRelayUrl::parse(RELAY).expect("relay")],
                    ConnectionPolicy::new(
                        [
                            NwcMethod::GetInfo,
                            NwcMethod::GetBalance,
                            NwcMethod::MakeInvoice,
                            NwcMethod::LookupInvoice,
                            NwcMethod::ListTransactions,
                            NwcMethod::PayInvoice,
                        ],
                        BudgetPolicy::new(
                            1_000,
                            BudgetInterval::Never,
                            FeePolicy::CountTowardBudget {
                                maximum_fee_sat: 25,
                            },
                        ),
                    ),
                    crate::NwcEncryption::Nip44V2,
                    WakePolicy::default(),
                )
                .expect("new connection"),
                UnixTimestamp::from_secs(90),
            )
            .expect("insert connection")
    }

    fn request_event(request: Request, created_at: u64) -> Event {
        request_json_event(&request.as_json(), created_at)
    }
    fn request_json_event(request: &str, created_at: u64) -> Event {
        let client = client_keys();
        let wallet = wallet_keys();
        let encrypted = nostr::nips::nip44::encrypt(
            client.secret_key(),
            &wallet.public_key(),
            request,
            nostr::nips::nip44::Version::V2,
        )
        .expect("encrypt request");
        EventBuilder::new(nostr::Kind::WalletConnectRequest, encrypted)
            .tag(Tag::public_key(wallet.public_key()))
            .custom_created_at(Timestamp::from(created_at))
            .sign_with_keys(&client)
            .expect("request event")
    }

    fn wake(event: &Event, relay: &str, embedded: bool) -> WakeInput {
        WakeInput::new(
            relay.to_owned(),
            crate::EventId::from_bytes(*event.id.as_bytes()),
            domain_key(wallet_keys().public_key()),
            embedded.then(|| event.as_json()),
            UnixTimestamp::from_secs(100),
        )
    }

    fn engine<'a>(
        ledger: &'a WakeLedger,
        wallet: &'a TestWallet<'a>,
        relay: &'a TestRelay,
        secrets: &'a dyn SecretProvider,
        clock: &'a FixedClock,
    ) -> WakeEngine<'a> {
        WakeEngine::new(ledger, wallet, relay, secrets, clock, WakePolicy::default())
    }

    fn execute(engine: &WakeEngine<'_>, wake: WakeInput) -> WakeDisposition {
        block_on(engine.execute(
            wake,
            OperationBudget::new(Duration::from_secs(10)).expect("budget"),
            &crate::NeverCancelled,
        ))
    }

    #[test]
    fn encrypted_balance_round_trip_is_committed_before_replay() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let wallet = TestWallet::default();
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let engine = engine(&ledger, &wallet, &relay, &secrets, &clock);
        let event = request_event(Request::get_balance(), 100);

        assert_eq!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::Completed {
                notification: NotificationHint::Request {
                    method: NwcMethod::GetBalance,
                },
            }
        );
        assert_eq!(wallet.balance_calls.load(Ordering::SeqCst), 1);
        let published = relay.published.lock().expect("published lock");
        assert_eq!(published.len(), 1);
        let response_event = Event::from_json(&published[0]).expect("response event");
        response_event.verify().expect("valid response signature");
        assert_eq!(response_event.kind, nostr::Kind::WalletConnectResponse);
        let plaintext = nostr::nips::nip44::decrypt(
            client_keys().secret_key(),
            &response_event.pubkey,
            &response_event.content,
        )
        .expect("decrypt response");
        let response = Response::from_json(plaintext).expect("NIP-47 response");
        assert_eq!(
            response.result,
            Some(ResponseResult::GetBalance(GetBalanceResponse {
                balance: 42_000
            }))
        );
        drop(published);

        assert_eq!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::Completed {
                notification: NotificationHint::Request {
                    method: NwcMethod::GetBalance,
                },
            }
        );
        assert_eq!(wallet.balance_calls.load(Ordering::SeqCst), 1);
        assert_eq!(relay.published.lock().expect("published lock").len(), 2);
    }

    #[test]
    fn get_info_advertises_authorized_invoice_support() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let wallet = TestWallet::default();
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let engine = engine(&ledger, &wallet, &relay, &secrets, &clock);
        let event = request_event(Request::get_info(), 100);

        assert!(matches!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::Completed { .. }
        ));
        let published = relay.published.lock().expect("published lock");
        let response_event = Event::from_json(&published[0]).expect("response event");
        let plaintext = nostr::nips::nip44::decrypt(
            client_keys().secret_key(),
            &response_event.pubkey,
            &response_event.content,
        )
        .expect("decrypt response");
        let response = Response::from_json(plaintext).expect("NIP-47 response");

        assert!(matches!(
            response.result,
            Some(ResponseResult::GetInfo(info))
                if info.methods.contains(&Method::PayInvoice)
                    && info.methods.contains(&Method::MakeInvoice)
                    && info.notifications == vec!["payment_received", "payment_sent"]
        ));
    }

    #[test]
    fn make_invoice_round_trip_calls_host_and_returns_created_invoice() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let wallet = TestWallet::default();
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let engine = engine(&ledger, &wallet, &relay, &secrets, &clock);
        let event = request_event(
            Request::make_invoice(nip47::MakeInvoiceRequest {
                amount: 42_000,
                description: Some("coffee".to_string()),
                description_hash: None,
                expiry: Some(600),
            }),
            100,
        );

        assert!(matches!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::Completed { .. }
        ));
        let requests = wallet
            .invoice_requests
            .lock()
            .expect("invoice requests lock");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].amount(), AmountMsat::from_msat(42_000));
        assert_eq!(requests[0].description(), Some("coffee"));
        assert_eq!(requests[0].expiry(), Duration::from_secs(600));
        drop(requests);

        let published = relay.published.lock().expect("published lock");
        let response_event = Event::from_json(&published[0]).expect("response event");
        let plaintext = nostr::nips::nip44::decrypt(
            client_keys().secret_key(),
            &response_event.pubkey,
            &response_event.content,
        )
        .expect("decrypt response");
        let response = Response::from_json(plaintext).expect("NIP-47 response");
        assert!(matches!(
            response.result,
            Some(ResponseResult::MakeInvoice(result))
                if result.invoice == "lnbc420n1test"
                    && result.payment_hash == Some(PaymentHash::from_bytes([8_u8; 32]).to_hex())
                    && result.amount == Some(42_000)
                    && result.expires_at == Some(Timestamp::from(700))
        ));
        let tracked = ledger.pending_nwc_invoices(10).expect("tracked invoices");
        assert_eq!(tracked.len(), 1);
        assert_eq!(
            tracked[0].request_event_id(),
            &crate::EventId::from_bytes(*event.id.as_bytes())
        );
    }

    #[test]
    fn targeted_invoice_worker_reconciles_the_requested_invoice() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let wallet = TestWallet::default();
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let engine = engine(&ledger, &wallet, &relay, &secrets, &clock);
        let event = request_event(
            Request::make_invoice(nip47::MakeInvoiceRequest {
                amount: 42_000,
                description: None,
                description_hash: None,
                expiry: Some(600),
            }),
            100,
        );
        assert!(matches!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::Completed { .. }
        ));

        let event_id = crate::EventId::from_bytes(*event.id.as_bytes());
        let report = block_on(
            crate::InvoiceNotificationWorker::new(&ledger, &wallet, &relay, &secrets, &clock)
                .run_invoice(
                    &event_id,
                    OperationBudget::new(Duration::from_secs(10)).expect("budget"),
                    &crate::NeverCancelled,
                ),
        )
        .expect("targeted invoice pass");

        assert_eq!(report.inspected, 1);
        assert_eq!(report.pending, 1);
        assert_eq!(wallet.lookup_requests.lock().expect("lookup lock").len(), 1);
    }

    #[test]
    fn lookup_invoice_accepts_alby_dual_selector_request() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let wallet = TestWallet::default();
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let engine = engine(&ledger, &wallet, &relay, &secrets, &clock);
        let event = request_event(
            Request::lookup_invoice(nip47::LookupInvoiceRequest {
                payment_hash: Some(PaymentHash::from_bytes([8_u8; 32]).to_hex()),
                invoice: Some("lnbc-alby-dual-selector".to_owned()),
            }),
            100,
        );

        assert_eq!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::Completed {
                notification: NotificationHint::Request {
                    method: NwcMethod::LookupInvoice,
                },
            }
        );
        assert!(matches!(
            wallet
                .lookup_requests
                .lock()
                .expect("lookup requests lock")
                .as_slice(),
            [InvoiceLookup::Invoice(invoice)] if invoice == "lnbc-alby-dual-selector"
        ));
    }

    #[test]
    fn freshly_created_invoice_stays_pending_during_transient_wallet_miss() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let wallet = TestWallet::default();
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let engine = engine(&ledger, &wallet, &relay, &secrets, &clock);
        let create = request_event(
            Request::make_invoice(nip47::MakeInvoiceRequest {
                amount: 42_000,
                description: Some("coffee".to_string()),
                description_hash: None,
                expiry: Some(600),
            }),
            100,
        );
        assert!(matches!(
            execute(&engine, wake(&create, RELAY, true)),
            WakeDisposition::Completed { .. }
        ));

        wallet
            .lookup_requests
            .lock()
            .expect("lookup requests lock")
            .clear();
        wallet.lookup_returns_none.store(true, Ordering::SeqCst);
        let lookup = request_event(
            Request::lookup_invoice(nip47::LookupInvoiceRequest {
                // The encoded invoice remains authoritative when a client
                // redundantly supplies a mismatched hash.
                payment_hash: Some(PaymentHash::from_bytes([9_u8; 32]).to_hex()),
                invoice: Some("lnbc420n1test".to_owned()),
            }),
            100,
        );

        assert_eq!(
            execute(&engine, wake(&lookup, RELAY, true)),
            WakeDisposition::Completed {
                notification: NotificationHint::Request {
                    method: NwcMethod::LookupInvoice,
                },
            }
        );
        let requests = wallet.lookup_requests.lock().expect("lookup requests lock");
        assert!(!requests.is_empty());
        assert!(requests.iter().all(|request| matches!(
            request,
            InvoiceLookup::PaymentHash(hash)
                if hash == &PaymentHash::from_bytes([8_u8; 32])
        )));
    }

    #[test]
    fn pending_invoice_batch_rotates_after_each_check() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger);
        let relay = SecureRelayUrl::parse(RELAY).expect("relay");

        for byte in 1_u8..=21 {
            let invoice = crate::TrackedNwcInvoice::new(
                crate::EventId::from_bytes([byte; 32]),
                PaymentHash::from_bytes([byte; 32]),
                connection.id().clone(),
                connection.revision(),
                format!("lnbc-{byte}"),
                None,
                AmountMsat::from_msat(1_000),
                UnixTimestamp::from_secs(100),
                UnixTimestamp::from_secs(700),
            );
            ledger
                .record_nwc_invoice(&invoice, std::slice::from_ref(&relay))
                .expect("record invoice");
        }

        let first_batch = ledger.pending_nwc_invoices(20).expect("first batch");
        assert_eq!(first_batch.len(), 20);
        for invoice in &first_batch {
            ledger
                .touch_nwc_invoice(invoice.request_event_id(), UnixTimestamp::from_secs(100))
                .expect("touch invoice");
        }

        let next_batch = ledger.pending_nwc_invoices(20).expect("next batch");
        assert_eq!(
            next_batch[0].request_event_id(),
            &crate::EventId::from_bytes([21_u8; 32])
        );
    }

    #[test]
    fn make_invoice_request_bounds_fail_closed() {
        assert!(parse_make_invoice_request(nip47::MakeInvoiceRequest {
            amount: 0,
            description: None,
            description_hash: None,
            expiry: None,
        })
        .is_err());
        assert!(parse_make_invoice_request(nip47::MakeInvoiceRequest {
            amount: 1_000,
            description: Some("x".repeat(MAX_INVOICE_DESCRIPTION_BYTES + 1)),
            description_hash: None,
            expiry: None,
        })
        .is_err());
        assert!(parse_make_invoice_request(nip47::MakeInvoiceRequest {
            amount: 1_000,
            description: None,
            description_hash: Some("unsupported".to_string()),
            expiry: None,
        })
        .is_err());
        assert!(parse_make_invoice_request(nip47::MakeInvoiceRequest {
            amount: 1_000,
            description: None,
            description_hash: None,
            expiry: Some(MAX_INVOICE_EXPIRY.as_secs() + 1),
        })
        .is_err());
    }

    #[test]
    fn publish_failure_reuses_terminal_response_after_freshness_expiry() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let wallet = TestWallet::default();
        let relay = TestRelay::default();
        relay.fail_next_publish.store(true, Ordering::SeqCst);
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let diagnostics = crate::WakeDiagnosticCollector::default();
        let engine =
            engine(&ledger, &wallet, &relay, &secrets, &clock).with_diagnostics(&diagnostics);
        let event = request_event(Request::get_balance(), 100);

        assert!(matches!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::RetryAfter {
                reason: RetryReason::ResponsePublishFailed,
                ..
            }
        ));
        assert!(diagnostics
            .codes()
            .contains(&WakeDiagnosticCode::ResponsePublishFailed));
        assert_eq!(wallet.balance_calls.load(Ordering::SeqCst), 1);
        clock.set(1_000);
        assert_eq!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::Completed {
                notification: NotificationHint::Request {
                    method: NwcMethod::GetBalance,
                },
            }
        );
        assert_eq!(wallet.balance_calls.load(Ordering::SeqCst), 1);
        assert_eq!(relay.published.lock().expect("published lock").len(), 1);
    }

    #[test]
    fn terminal_commit_failure_remains_retryable() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger);
        let wallet = TestWallet::default();
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let engine = engine(&ledger, &wallet, &relay, &secrets, &clock);
        let event_id = crate::EventId::from_bytes([11_u8; 32]);
        let ClaimOutcome::Acquired(lease) = ledger
            .claim_event(
                &event_id,
                connection.id(),
                connection.revision(),
                clock.now(),
                Duration::from_secs(10),
            )
            .expect("claim event")
        else {
            panic!("event was not acquired");
        };

        assert!(matches!(
            engine.completion_failed(&lease, LedgerError::LostLease),
            WakeDisposition::RetryAfter {
                reason: RetryReason::ResponsePersistenceFailed,
                ..
            }
        ));
        assert!(matches!(
            engine.completion_failed(&lease, LedgerError::DatabaseUnavailable),
            WakeDisposition::RetryAfter {
                reason: RetryReason::ResponsePersistenceFailed,
                ..
            }
        ));
    }

    #[test]
    fn lease_expiry_during_response_commit_requests_retry() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let wallet = TestWallet::default();
        let relay = TestRelay::default();
        let clock = FixedClock::new(100);
        let secrets = ExpiringResponseSecrets {
            clock: &clock,
            loads: AtomicUsize::new(0),
        };
        let engine = engine(&ledger, &wallet, &relay, &secrets, &clock);
        let event = request_event(Request::get_balance(), 100);

        assert!(matches!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::RetryAfter {
                reason: RetryReason::ResponsePersistenceFailed,
                ..
            }
        ));
        assert_eq!(wallet.balance_calls.load(Ordering::SeqCst), 1);
        assert!(relay.published.lock().expect("published lock").is_empty());
    }

    #[test]
    fn fetched_event_substitution_is_rejected_before_wallet_access() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let wallet = TestWallet::default();
        let relay = TestRelay::default();
        let expected = request_event(Request::get_balance(), 100);
        let substituted = request_event(Request::get_balance(), 99);
        *relay.fetched_event.lock().expect("fetch lock") = Some(substituted.as_json());
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let engine = engine(&ledger, &wallet, &relay, &secrets, &clock);

        assert!(matches!(
            execute(&engine, wake(&expected, RELAY, false)),
            WakeDisposition::Rejected {
                code: RejectionCode::EventMismatch,
                ..
            }
        ));
        assert_eq!(relay.fetch_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            relay.maximum_fetch_bytes.load(Ordering::SeqCst),
            WakePolicy::default().maximum_payload_bytes()
        );
        assert_eq!(wallet.balance_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn oversized_relay_event_is_rejected_at_transport_receive_bound() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let wallet = TestWallet::default();
        let relay = TestRelay::default();
        const TEST_EVENT_LIMIT: usize = 1_024;
        *relay.fetched_event.lock().expect("fetch lock") = Some("x".repeat(TEST_EVENT_LIMIT + 1));
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let policy = WakePolicy::new(
            Duration::from_secs(10 * 60),
            Duration::from_secs(30),
            Duration::from_secs(24 * 60 * 60),
            TEST_EVENT_LIMIT,
            2,
        )
        .expect("test wake policy");
        let engine = WakeEngine::new(&ledger, &wallet, &relay, &secrets, &clock, policy);
        let event = request_event(Request::get_balance(), 100);

        assert!(matches!(
            execute(&engine, wake(&event, RELAY, false)),
            WakeDisposition::Rejected {
                code: RejectionCode::InvalidEvent,
                ..
            }
        ));
        assert_eq!(relay.fetch_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            relay.maximum_fetch_bytes.load(Ordering::SeqCst),
            TEST_EVENT_LIMIT
        );
        assert_eq!(wallet.balance_calls.load(Ordering::SeqCst), 0);
        assert_eq!(secrets.loads.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn unapproved_relay_is_rejected_before_fetch_or_embedded_event_parsing() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let wallet = TestWallet::default();
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let engine = engine(&ledger, &wallet, &relay, &secrets, &clock);
        let event = request_event(Request::get_balance(), 100);

        assert!(matches!(
            execute(&engine, wake(&event, "wss://attacker.example.com", true)),
            WakeDisposition::Rejected {
                code: RejectionCode::RelayNotAllowed,
                ..
            }
        ));
        assert_eq!(relay.fetch_calls.load(Ordering::SeqCst), 0);
        assert_eq!(wallet.balance_calls.load(Ordering::SeqCst), 0);
        assert!(relay.published.lock().expect("published lock").is_empty());
    }

    #[test]
    fn mismatched_platform_secret_is_terminal_without_wallet_access() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let wallet = TestWallet::default();
        let relay = TestRelay::default();
        let secrets = TestSecrets {
            bytes: [3_u8; 32],
            loads: AtomicUsize::new(0),
        };
        let clock = FixedClock::new(100);
        let engine = engine(&ledger, &wallet, &relay, &secrets, &clock);
        let event = request_event(Request::get_balance(), 100);

        assert!(matches!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::Rejected {
                code: RejectionCode::InvalidRequest,
                ..
            }
        ));
        assert_eq!(wallet.balance_calls.load(Ordering::SeqCst), 0);
        assert!(relay.published.lock().expect("published lock").is_empty());
    }

    #[test]
    fn revocation_during_host_read_prevents_response_publication() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let active = insert_connection(&ledger);
        let wallet = TestWallet::default();
        *wallet.revoke_on_balance.lock().expect("revoke lock") =
            Some((&ledger, active.id().clone(), active.revision()));
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let engine = engine(&ledger, &wallet, &relay, &secrets, &clock);
        let event = request_event(Request::get_balance(), 100);

        assert!(matches!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::Rejected {
                code: RejectionCode::ConnectionUnavailable,
                ..
            }
        ));
        assert_eq!(wallet.balance_calls.load(Ordering::SeqCst), 1);
        assert!(relay.published.lock().expect("published lock").is_empty());
        assert!(matches!(
            ledger.load_connection(active.id()).expect("connection"),
            Some(crate::StoredConnection::Tombstoned(_))
        ));
    }

    #[test]
    fn rejected_payment_response_recovers_after_expiry_without_spending() {
        use nostr::hashes::{sha256, Hash};
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).unwrap();
        let connection = insert_connection(&ledger);
        ledger.enable_foreground_payments().unwrap();
        let preimage = crate::PaymentPreimage::from_bytes([7; 32]);
        let hash = PaymentHash::from_bytes(sha256::Hash::hash(preimage.as_bytes()).to_byte_array());
        ledger
            .bind_foreground_payment(connection.id().as_str(), "wallet-a", &hash, 600_000, 10)
            .unwrap();
        let wallet = TestWallet::default();
        *wallet.quote.lock().unwrap() = Some(PaymentQuote::new(
            hash.clone(),
            AmountMsat::from_msat(600_000),
        ));
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let before = FixedClock::new(100);
        let request = request_event(
            Request::pay_invoice(nip47::PayInvoiceRequest::new("lnbc-expiring")),
            100,
        );
        let input = wake(&request, RELAY, true);
        let event = input.event_id().clone();
        assert!(matches!(
            execute(&engine(&ledger, &wallet, &relay, &secrets, &before), input),
            WakeDisposition::QueuedForApplication { .. }
        ));
        ledger
            .reject_foreground_payment(&event, false, UnixTimestamp::from_secs(100))
            .unwrap();
        ledger
            .lock_connection()
            .unwrap()
            .execute(
                "UPDATE connections SET expires_at=101 WHERE connection_id=?1",
                [connection.id().as_str()],
            )
            .unwrap();
        let after = FixedClock::new(102);
        relay.fail_next_publish.store(true, Ordering::SeqCst);
        let retained = ledger
            .foreground_payment_wake(&event, UnixTimestamp::from_secs(102))
            .unwrap();
        assert!(matches!(
            execute(
                &engine(&ledger, &wallet, &relay, &secrets, &after),
                retained
            ),
            WakeDisposition::RetryAfter { .. }
        ));
        assert_eq!(
            ledger
                .foreground_recovery_events(connection.id().as_str())
                .unwrap(),
            vec![event.clone()]
        );
        let retained = ledger
            .foreground_payment_wake(&event, UnixTimestamp::from_secs(102))
            .unwrap();
        assert!(matches!(
            execute(
                &engine(&ledger, &wallet, &relay, &secrets, &after),
                retained
            ),
            WakeDisposition::Completed { .. }
        ));
        assert!(ledger
            .foreground_recovery_events(connection.id().as_str())
            .unwrap()
            .is_empty());
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn address_only_consent_is_encrypted_and_immutable() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).unwrap();
        let connection = insert_connection(&ledger);
        ledger
            .set_connection_payer_metadata(
                connection.id().as_str(),
                &crate::ConnectionPayerMetadata::new(None, None).unwrap(),
            )
            .unwrap();
        assert!(ledger
            .connection_payer_metadata(connection.id().as_str())
            .unwrap()
            .is_none());
        let secret = crate::NwcSecretKey::from_bytes(
            wallet_keys()
                .secret_key()
                .as_secret_bytes()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let address = nostr::serde_json::json!({"line1":"123 Example Street","city":"Austin","zipCode":"78701","countryCode":"US"});
        ledger
            .set_connection_address(connection.id().as_str(), &address.to_string(), &secret)
            .unwrap();
        let reopened = WakeLedger::open(&database.path).unwrap();
        assert_eq!(
            reopened
                .connection_address(connection.id().as_str(), &secret)
                .unwrap(),
            Some(address.clone())
        );
        assert!(reopened
            .connection_payer_metadata(connection.id().as_str())
            .unwrap()
            .unwrap()
            .payer_username()
            .is_none());
        assert!(reopened
            .set_connection_address(connection.id().as_str(), &address.to_string(), &secret)
            .is_err());
    }

    #[test]
    fn expired_authority_only_recovers_exact_previously_initiated_foreground_payment() {
        use nostr::hashes::{sha256, Hash};
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).unwrap();
        let connection = insert_connection(&ledger);
        ledger.enable_foreground_payments().unwrap();
        let preimage = crate::PaymentPreimage::from_bytes([7; 32]);
        let hash = PaymentHash::from_bytes(sha256::Hash::hash(preimage.as_bytes()).to_byte_array());
        ledger
            .bind_foreground_payment(connection.id().as_str(), "wallet-a", &hash, 600_000, 10)
            .unwrap();
        let wallet = TestWallet::default();
        *wallet.quote.lock().unwrap() = Some(PaymentQuote::new(
            hash.clone(),
            AmountMsat::from_msat(600_000),
        ));
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let before = FixedClock::new(100);
        let request = request_event(
            Request::pay_invoice(nip47::PayInvoiceRequest::new("lnbc-expiring")),
            100,
        );
        let input = wake(&request, RELAY, true);
        let event = input.event_id().clone();
        assert!(matches!(
            execute(&engine(&ledger, &wallet, &relay, &secrets, &before), input),
            WakeDisposition::QueuedForApplication { .. }
        ));
        ledger
            .lock_connection()
            .unwrap()
            .execute(
                "UPDATE connections SET expires_at=101 WHERE connection_id=?1",
                [connection.id().as_str()],
            )
            .unwrap();
        let after = FixedClock::new(102);
        // Retention alone does not authorize work after expiry.
        assert!(matches!(
            execute(
                &engine(&ledger, &wallet, &relay, &secrets, &after),
                wake(&request, RELAY, true)
            ),
            WakeDisposition::Rejected { .. }
        ));
        ledger
            .begin_foreground_payment(&event, "wallet-a", UnixTimestamp::from_secs(100))
            .unwrap();
        assert_eq!(
            ledger
                .foreground_recovery_events(connection.id().as_str())
                .unwrap(),
            vec![event.clone()]
        );
        let fresh = request_event(
            Request::pay_invoice(nip47::PayInvoiceRequest::new("lnbc-expiring")),
            102,
        );
        assert!(matches!(
            execute(
                &engine(&ledger, &wallet, &relay, &secrets, &after),
                wake(&fresh, RELAY, true)
            ),
            WakeDisposition::Rejected { .. }
        ));
        assert!(matches!(
            execute(
                &engine(&ledger, &wallet, &relay, &secrets, &after),
                ledger
                    .foreground_payment_wake(&event, UnixTimestamp::from_secs(102))
                    .unwrap()
            ),
            WakeDisposition::QueuedForApplication { .. }
        ));
        let fresh_info = request_event(Request::get_info(), 102);
        assert!(matches!(
            execute(
                &engine(&ledger, &wallet, &relay, &secrets, &after),
                wake(&fresh_info, RELAY, true)
            ),
            WakeDisposition::Rejected { .. }
        ));
        assert!(ledger
            .begin_foreground_payment(&event, "wallet-a", UnixTimestamp::from_secs(102))
            .is_err());
        ledger
            .complete_foreground_payment(
                &event,
                &preimage,
                AmountMsat::from_msat(600_000),
                AmountMsat::from_msat(1000),
                UnixTimestamp::from_secs(102),
            )
            .unwrap();
        relay.fail_next_publish.store(true, Ordering::SeqCst);
        let retained = ledger
            .foreground_payment_wake(&event, UnixTimestamp::from_secs(102))
            .unwrap();
        assert!(matches!(
            execute(
                &engine(&ledger, &wallet, &relay, &secrets, &after),
                retained
            ),
            WakeDisposition::RetryAfter { .. }
        ));
        assert_eq!(
            ledger
                .foreground_recovery_events(connection.id().as_str())
                .unwrap(),
            vec![event.clone()]
        );
        let retained = ledger
            .foreground_payment_wake(&event, UnixTimestamp::from_secs(102))
            .unwrap();
        assert!(matches!(
            execute(
                &engine(&ledger, &wallet, &relay, &secrets, &after),
                retained
            ),
            WakeDisposition::Completed { .. }
        ));
        assert!(ledger
            .foreground_recovery_events(connection.id().as_str())
            .unwrap()
            .is_empty());
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 0);
        let retained = ledger
            .foreground_payment_wake(&event, UnixTimestamp::from_secs(102))
            .unwrap();
        assert!(matches!(
            execute(
                &engine(&ledger, &wallet, &relay, &secrets, &after),
                retained
            ),
            WakeDisposition::Completed { .. }
        ));
    }

    #[test]
    fn reusable_budget_reservations_are_atomic_across_concurrent_requests() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).unwrap();
        let initial = insert_connection(&ledger);
        ledger.enable_foreground_payments().unwrap();
        ledger.lock_connection().unwrap().execute("UPDATE connections SET foreground_fee_policy='wallet_managed',budget_interval='monthly',expires_at=1000 WHERE connection_id=?1",[initial.id().as_str()]).unwrap();
        ledger
            .bind_reusable_foreground_wallet(initial.id().as_str(), "wallet-a")
            .unwrap();
        let connection = ledger
            .load_active_connection(initial.id())
            .unwrap()
            .unwrap();
        let barrier = std::sync::Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let threads = [1_u8, 2].map(|id| {
                let path = &database.path;
                let connection = &connection;
                let barrier = &barrier;
                scope.spawn(move || {
                    let local = WakeLedger::open(path).unwrap();
                    barrier.wait();
                    local.reserve_payment(
                        &crate::EventId::from_bytes([id; 32]),
                        &PaymentHash::from_bytes([id; 32]),
                        connection,
                        600,
                        UnixTimestamp::from_secs(100),
                    )
                })
            });
            threads.map(|thread| thread.join().unwrap())
        });
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(PaymentAccountingError::BudgetExceeded)))
                .count(),
            1
        );
        assert_eq!(
            ledger
                .lock_connection()
                .unwrap()
                .query_row("SELECT SUM(used_sat) FROM budget_periods", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            600
        );
    }

    #[test]
    fn browser_pairing_requires_explicit_approval_and_never_changes_authority() {
        use nostr::serde_json::json;
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).unwrap();
        let initial = insert_connection(&ledger);
        ledger.enable_foreground_payments().unwrap();
        ledger.lock_connection().unwrap().execute("UPDATE connections SET foreground_fee_policy='wallet_managed',budget_interval='monthly',expires_at=1000 WHERE connection_id=?1",[initial.id().as_str()]).unwrap();
        ledger
            .bind_reusable_foreground_wallet(initial.id().as_str(), "wallet-a")
            .unwrap();
        let connection = ledger
            .load_active_connection(initial.id())
            .unwrap()
            .unwrap();
        ledger
            .reserve_payment(
                &crate::EventId::from_bytes([77; 32]),
                &PaymentHash::from_bytes([77; 32]),
                &connection,
                300,
                UnixTimestamp::from_secs(100),
            )
            .unwrap();
        let secret = crate::NwcSecretKey::from_bytes(
            wallet_keys()
                .secret_key()
                .as_secret_bytes()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let params = json!({"version":1,"challenge_id":"challenge-one","nonce":"ab".repeat(32),"audience":"https://pay.example","expires_at":200,"client_pubkey":client_keys().public_key().to_hex(),"wallet_pubkey":wallet_keys().public_key().to_hex()});
        let event = request_json_event(
            &json!({"method":"authorize_browser","params":params}).to_string(),
            100,
        );
        let wallet = TestWallet::default();
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        assert!(matches!(
            execute(
                &engine(&ledger, &wallet, &relay, &secrets, &clock),
                wake(&event, RELAY, true)
            ),
            WakeDisposition::QueuedForApplication { .. }
        ));
        assert!(relay.published.lock().unwrap().is_empty());
        assert_eq!(
            ledger.browser_pairing_connection("challenge-one").unwrap(),
            connection.id().as_str()
        );
        let details = ledger
            .parse_browser_pairing_challenge(
                &connection,
                &event.as_json(),
                &secret,
                UnixTimestamp::from_secs(100),
            )
            .unwrap();
        assert_eq!(details.nonce, "ab".repeat(32));
        let proof = ledger
            .approve_browser_pairing(
                &connection,
                "challenge-one",
                &secret,
                UnixTimestamp::from_secs(100),
            )
            .unwrap();
        assert_eq!(
            proof,
            ledger
                .approve_browser_pairing(
                    &connection,
                    "challenge-one",
                    &secret,
                    UnixTimestamp::from_secs(101)
                )
                .unwrap()
        );
        let response = Event::from_json(&proof).unwrap();
        response.verify().unwrap();
        let plain = nostr::nips::nip44::decrypt(
            client_keys().secret_key(),
            &wallet_keys().public_key(),
            &response.content,
        )
        .unwrap();
        let value: nostr::serde_json::Value = nostr::serde_json::from_str(&plain).unwrap();
        assert_eq!(value["result"]["approved"], true);
        assert_eq!(value["result"]["nonce"], params["nonce"]);
        assert_eq!(value["result"]["audience"], params["audience"]);
        assert!(ledger
            .approve_browser_pairing(
                &connection,
                "challenge-one",
                &secret,
                UnixTimestamp::from_secs(200)
            )
            .is_err());
        let mut swapped = params.clone();
        swapped["audience"] = "https://attacker.example".into();
        let other = request_json_event(
            &json!({"method":"authorize_browser","params":swapped}).to_string(),
            100,
        );
        assert!(ledger
            .parse_browser_pairing_challenge(
                &connection,
                &other.as_json(),
                &secret,
                UnixTimestamp::from_secs(100)
            )
            .is_err());
        assert_eq!(
            ledger
                .lock_connection()
                .unwrap()
                .query_row("SELECT SUM(used_sat) FROM budget_periods", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            300
        );
        let unchanged = ledger
            .load_active_connection(connection.id())
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.revision(), connection.revision());
        assert_eq!(unchanged.policy(), connection.policy());
        assert_eq!(unchanged.expires_at(), connection.expires_at());
        ledger
            .tombstone_connection(
                connection.id(),
                connection.revision(),
                UnixTimestamp::from_secs(110),
            )
            .unwrap();
        assert!(ledger
            .approve_browser_pairing(
                &connection,
                "challenge-one",
                &secret,
                UnixTimestamp::from_secs(111)
            )
            .is_err());
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn payer_metadata_upgrade_keeps_existing_authority_without_inventing_disclosure() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).unwrap();
        let connection = insert_connection(&ledger);
        ledger
            .lock_connection()
            .unwrap()
            .execute_batch("DROP TABLE connection_payer_metadata; PRAGMA user_version=17;")
            .unwrap();
        drop(ledger);
        let upgraded = WakeLedger::open(&database.path).unwrap();
        assert!(upgraded
            .connection_payer_metadata(connection.id().as_str())
            .unwrap()
            .is_none());
        let rows: i64 = upgraded
            .lock_connection()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM connections WHERE connection_id=?1 AND status='active'",
                [connection.id().as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 1);
        upgraded
            .set_connection_payer_metadata(
                connection.id().as_str(),
                &crate::ConnectionPayerMetadata::new(Some("alice".into()), Some("Lexe".into()))
                    .unwrap(),
            )
            .unwrap();
        drop(upgraded);
        let reopened = WakeLedger::open(&database.path).unwrap();
        assert_eq!(
            reopened
                .connection_payer_metadata(connection.id().as_str())
                .unwrap()
                .unwrap()
                .payer_username(),
            Some("alice")
        );
    }

    #[test]
    fn reusable_purchases_keep_consent_and_charge_only_requested_principal() {
        use crate::PaymentPreimage;
        use nostr::hashes::{sha256, Hash};
        use nostr::serde_json::json;
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).unwrap();
        let connection = insert_connection(&ledger);
        ledger.enable_foreground_payments().unwrap();
        ledger.lock_connection().unwrap().execute("UPDATE connections SET foreground_fee_policy='wallet_managed',budget_interval='monthly',budget_limit_sat=1200,expires_at=1000 WHERE connection_id=?1",[connection.id().as_str()]).unwrap();
        ledger
            .bind_reusable_foreground_wallet(connection.id().as_str(), "wallet-a")
            .unwrap();
        let wallet = TestWallet::default();
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let secret = crate::NwcSecretKey::from_bytes(
            wallet_keys()
                .secret_key()
                .as_secret_bytes()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let clock = FixedClock::new(100);
        let reopened = WakeLedger::open(&database.path).unwrap();
        for sequence in 0..2_u8 {
            let now = 100;
            let preimage = PaymentPreimage::from_bytes([sequence + 7; 32]);
            let hash =
                PaymentHash::from_bytes(sha256::Hash::hash(preimage.as_bytes()).to_byte_array());
            *wallet.quote.lock().unwrap() = Some(PaymentQuote::new(
                hash.clone(),
                AmountMsat::from_msat(600_000),
            ));
            let purchase = json!({"version":1,"id":format!("purchase-{sequence}"),"merchant":{"id":"merchant","name":"Merchant","origin":"https://merchant.example"},"invoice_binding":{"payment_hash":hash.to_hex(),"principal_msats":"600000"},"requested_customer_fields":[{"field":"email","required":true}]});
            let request=request_json_event(&json!({"method":"pay_invoice","params":{"invoice":format!("lnbc-reusable-{sequence}"),"purchase":purchase}}).to_string(),now);
            let input = wake(&request, RELAY, true);
            let event = input.event_id().clone();
            assert!(matches!(
                execute(&engine(&ledger, &wallet, &relay, &secrets, &clock), input),
                WakeDisposition::QueuedForApplication { .. }
            ));
            assert!(ledger
                .begin_foreground_payment(&event, "wallet-a", UnixTimestamp::from_secs(now))
                .is_err());
            assert!(ledger
                .begin_foreground_payment_with_consent(
                    &event,
                    "wallet-a",
                    "{}",
                    &secret,
                    UnixTimestamp::from_secs(now)
                )
                .is_err());
            assert!(ledger
                .begin_foreground_payment_with_consent(
                    &event,
                    "wallet-b",
                    r#"{"email":"payer@example.com"}"#,
                    &secret,
                    UnixTimestamp::from_secs(now)
                )
                .is_err());
            assert!(ledger
                .begin_foreground_payment_with_consent(
                    &event,
                    "wallet-a",
                    r#"{"email":"payer@example.com","phone":"+15555550123"}"#,
                    &secret,
                    UnixTimestamp::from_secs(now)
                )
                .is_err());
            ledger
                .begin_foreground_payment_with_consent(
                    &event,
                    "wallet-a",
                    r#"{"email":"payer@example.com"}"#,
                    &secret,
                    UnixTimestamp::from_secs(now),
                )
                .unwrap();
            let cipher: String = ledger
                .lock_connection()
                .unwrap()
                .query_row(
                    "SELECT consent_ciphertext FROM foreground_payment_requests WHERE event_id=?1",
                    [event.as_bytes().as_slice()],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(!cipher.contains("payer@example.com"));
            assert!(reopened
                .begin_foreground_payment_with_consent(
                    &event,
                    "wallet-a",
                    r#"{"email":"changed@example.com"}"#,
                    &secret,
                    UnixTimestamp::from_secs(now)
                )
                .is_err());
            reopened
                .complete_foreground_payment(
                    &event,
                    &preimage,
                    AmountMsat::from_msat(650_000),
                    AmountMsat::from_msat(20_000),
                    UnixTimestamp::from_secs(now),
                )
                .unwrap();
            assert_eq!(
                reopened
                    .load_payment_attempt(&hash)
                    .unwrap()
                    .unwrap()
                    .charged_sat(),
                Some(600)
            );
            let retained = reopened
                .foreground_payment_wake(&event, UnixTimestamp::from_secs(now))
                .unwrap();
            assert!(matches!(
                execute(
                    &engine(&reopened, &wallet, &relay, &secrets, &clock),
                    retained
                ),
                WakeDisposition::Completed { .. }
            ));
            let published = relay.published.lock().unwrap();
            let response = Event::from_json(published.last().unwrap()).unwrap();
            let plain = nostr::nips::nip44::decrypt(
                client_keys().secret_key(),
                &wallet_keys().public_key(),
                &response.content,
            )
            .unwrap();
            let value: nostr::serde_json::Value = nostr::serde_json::from_str(&plain).unwrap();
            assert_eq!(
                value["result"]["purchase"],
                json!({"id":format!("purchase-{sequence}"),"customer_data":{"email":"payer@example.com"}})
            );
            assert_eq!(value["result"]["fees_paid"], 20_000);
            drop(published);
        }
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 0);
        let used: i64 = ledger
            .lock_connection()
            .unwrap()
            .query_row("SELECT SUM(used_sat) FROM budget_periods", [], |r| r.get(0))
            .unwrap();
        assert_eq!(used, 1200);
        assert!(ledger
            .reserve_payment(
                &crate::EventId::from_bytes([88; 32]),
                &PaymentHash::from_bytes([88; 32]),
                &connection,
                1,
                UnixTimestamp::from_secs(102)
            )
            .is_err());
        assert!(ledger
            .connection_payer_metadata(connection.id().as_str())
            .unwrap()
            .is_none());
        ledger
            .set_connection_payer_metadata(
                connection.id().as_str(),
                &crate::ConnectionPayerMetadata::new(Some("alice".into()), Some("My Lexe".into()))
                    .unwrap(),
            )
            .unwrap();
        let address = nostr::serde_json::json!({"line1":"123 Example Street","city":"Austin","zipCode":"78701","countryCode":"US"});
        assert!(ledger
            .connection_address(connection.id().as_str(), &secret)
            .unwrap()
            .is_none());
        ledger
            .set_connection_address(connection.id().as_str(), &address.to_string(), &secret)
            .unwrap();
        assert!(ledger
            .set_connection_address(connection.id().as_str(), &address.to_string(), &secret)
            .is_err());
        assert!(ledger
            .connection_address("other-client", &secret)
            .unwrap()
            .is_none());
        let cipher: String = ledger
            .lock_connection()
            .unwrap()
            .query_row(
                "SELECT address_ciphertext FROM connection_payer_metadata WHERE connection_id=?1",
                [connection.id().as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!cipher.contains("Example"));
        let reopened_identity = WakeLedger::open(&database.path).unwrap();
        let identity = reopened_identity
            .connection_payer_metadata(connection.id().as_str())
            .unwrap()
            .unwrap();
        assert_eq!(identity.payer_username(), Some("alice"));
        assert!(reopened_identity
            .connection_payer_metadata("other-client")
            .unwrap()
            .is_none());
        assert!(ledger
            .set_connection_payer_metadata(
                connection.id().as_str(),
                &crate::ConnectionPayerMetadata::new(Some("bob".into()), None).unwrap()
            )
            .is_err());
        let info = request_event(Request::get_info(), 100);
        assert!(matches!(
            execute(
                &engine(&ledger, &wallet, &relay, &secrets, &clock),
                wake(&info, RELAY, true)
            ),
            WakeDisposition::Completed { .. }
        ));
        let published = relay.published.lock().unwrap();
        let response = Event::from_json(published.last().unwrap()).unwrap();
        let plain = nostr::nips::nip44::decrypt(
            client_keys().secret_key(),
            &wallet_keys().public_key(),
            &response.content,
        )
        .unwrap();
        let value: nostr::serde_json::Value = nostr::serde_json::from_str(&plain).unwrap();
        assert_eq!(value["result"]["payment_mode"], "confirm_each");
        assert_eq!(value["result"]["budget_limit_msats"], "1200000");
        assert_eq!(value["result"]["payer_username"], "alice");
        assert_eq!(value["result"]["payer_address"], address);
        assert_eq!(value["result"]["alias"], "My Lexe");
        let public_info = crate::build_nwc_info_event(
            &secret,
            Some(connection.client_pubkey()),
            connection.policy().methods(),
            connection.encryption(),
            UnixTimestamp::from_secs(100),
        )
        .unwrap();
        assert!(!public_info.contains("alice"));
        assert!(!public_info.contains("Example"));
        assert!(!public_info.contains("My Lexe"));
        reopened_identity.lock_connection().unwrap().execute("UPDATE connections SET status='tombstoned',tombstoned_at=101,updated_at=101 WHERE connection_id=?1", [connection.id().as_str()]).unwrap();
        assert_eq!(
            reopened_identity
                .connection_payer_metadata(connection.id().as_str())
                .unwrap()
                .unwrap()
                .payer_username(),
            Some("alice")
        );
        assert!(reopened_identity
            .connection_address(connection.id().as_str(), &secret)
            .unwrap()
            .is_none());
    }

    #[test]
    fn foreground_handoff_survives_restart_and_never_calls_native_payment() {
        exercise_foreground_handoff(false, 1000, false);
    }

    #[test]
    fn wallet_managed_handoff_keeps_exact_invoice_and_honest_extra_cost_after_restart() {
        exercise_foreground_handoff(true, 1000, false);
    }

    #[test]
    fn capped_over_fee_success_survives_crash_and_is_accounted_as_violation() {
        exercise_foreground_handoff(false, 11_000, false);
    }

    #[test]
    fn foreground_v14_success_backfills_actual_amount_and_keeps_idempotent_completion() {
        exercise_foreground_handoff(false, 1000, true);
    }

    fn exercise_foreground_handoff(wallet_managed: bool, fee_msat: u64, migrate: bool) {
        use crate::PaymentPreimage;
        use nostr::hashes::{sha256, Hash};
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger);
        let preimage = PaymentPreimage::from_bytes([7; 32]);
        let hash = PaymentHash::from_bytes(sha256::Hash::hash(preimage.as_bytes()).to_byte_array());
        ledger.enable_foreground_payments().expect("gate");
        if wallet_managed {
            ledger.lock_connection().unwrap().execute("UPDATE connections SET foreground_fee_policy='wallet_managed',maximum_fee_sat=0,budget_limit_sat=600 WHERE connection_id=?1",[connection.id().as_str()]).unwrap();
            assert!(ledger
                .bind_foreground_payment(connection.id().as_str(), "wallet-a", &hash, 600_000, 0)
                .is_err());
            ledger
                .bind_wallet_managed_foreground_payment(
                    connection.id().as_str(),
                    "wallet-a",
                    &hash,
                    600_000,
                    "lnbc-foreground",
                )
                .unwrap();
            assert!(!ledger
                .matches_foreground_binding(
                    connection.id().as_str(),
                    &hash,
                    AmountMsat::from_msat(600_000),
                    "lnbc-substituted"
                )
                .unwrap());
            assert!(!ledger
                .matches_foreground_binding(
                    connection.id().as_str(),
                    &hash,
                    AmountMsat::from_msat(600_001),
                    "lnbc-foreground"
                )
                .unwrap());
            assert!(!ledger
                .matches_foreground_binding(
                    connection.id().as_str(),
                    &PaymentHash::from_bytes([9; 32]),
                    AmountMsat::from_msat(600_000),
                    "lnbc-foreground"
                )
                .unwrap());
        } else {
            assert!(ledger
                .bind_wallet_managed_foreground_payment(
                    connection.id().as_str(),
                    "wallet-a",
                    &hash,
                    600_000,
                    "lnbc-foreground"
                )
                .is_err());
            ledger
                .bind_foreground_payment(connection.id().as_str(), "wallet-a", &hash, 600_000, 10)
                .unwrap();
        }
        let wallet = TestWallet::default();
        *wallet.quote.lock().expect("quote") = Some(PaymentQuote::new(
            hash.clone(),
            AmountMsat::from_msat(600_000),
        ));
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let request = request_event(
            Request::pay_invoice(nip47::PayInvoiceRequest::new("lnbc-foreground")),
            100,
        );
        let input = wake(&request, RELAY, true);
        let event = input.event_id().clone();
        assert!(matches!(
            execute(&engine(&ledger, &wallet, &relay, &secrets, &clock), input),
            WakeDisposition::QueuedForApplication { .. }
        ));
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            ledger.foreground_payments().expect("pending")[0].amount_msat,
            600_000
        );
        assert!(ledger
            .begin_foreground_payment(&event, "wallet-b", UnixTimestamp::from_secs(100))
            .is_err());
        ledger
            .begin_foreground_payment(&event, "wallet-a", UnixTimestamp::from_secs(100))
            .expect("begin once");
        let reopened = WakeLedger::open(&database.path).expect("reopen");
        assert!(reopened
            .begin_foreground_payment(&event, "wallet-a", UnixTimestamp::from_secs(100))
            .is_err());
        assert!(reopened
            .reject_foreground_payment(&event, false, UnixTimestamp::from_secs(100))
            .is_err());
        assert!(reopened
            .complete_foreground_payment(
                &event,
                &PaymentPreimage::from_bytes([8; 32]),
                AmountMsat::from_msat(600_000),
                AmountMsat::from_msat(fee_msat),
                UnixTimestamp::from_secs(100)
            )
            .is_err());
        assert!(reopened
            .complete_foreground_payment(
                &event,
                &preimage,
                AmountMsat::from_msat(599_999),
                AmountMsat::from_msat(fee_msat),
                UnixTimestamp::from_secs(100)
            )
            .is_err());
        let actual_amount = if wallet_managed { 650_000 } else { 600_000 };
        if fee_msat > 10_000 {
            // Simulate process death after durable success evidence, before accounting.
            reopened.lock_connection().unwrap().execute("UPDATE foreground_payment_requests SET state='succeeded',preimage=?2,actual_amount_msat=?3,fee_msat=?4 WHERE event_id=?1",rusqlite::params![event.as_bytes().as_slice(),preimage.as_bytes().as_slice(),actual_amount,fee_msat]).unwrap();
            let after_crash = WakeLedger::open(&database.path).unwrap();
            let report = block_on(
                crate::PaymentReconciler::new(&after_crash, &wallet, &clock).reconcile(
                    10,
                    OperationBudget::new(Duration::from_secs(2)).unwrap(),
                    &crate::NeverCancelled,
                ),
            )
            .unwrap();
            assert_eq!(report.succeeded(), 1);
        }
        reopened
            .complete_foreground_payment(
                &event,
                &preimage,
                AmountMsat::from_msat(actual_amount),
                AmountMsat::from_msat(fee_msat),
                UnixTimestamp::from_secs(100),
            )
            .expect("complete");
        reopened
            .complete_foreground_payment(
                &event,
                &preimage,
                AmountMsat::from_msat(actual_amount),
                AmountMsat::from_msat(fee_msat),
                UnixTimestamp::from_secs(100),
            )
            .unwrap();
        assert!(reopened
            .complete_foreground_payment(
                &event,
                &preimage,
                AmountMsat::from_msat(actual_amount + 1),
                AmountMsat::from_msat(fee_msat),
                UnixTimestamp::from_secs(100)
            )
            .is_err());
        let pending = &reopened.foreground_payments().unwrap()[0];
        assert_eq!(pending.amount_msat, 600_000);
        assert_eq!(pending.actual_amount_msat, Some(actual_amount));
        assert_eq!(pending.fee_msat, Some(fee_msat));
        assert_eq!(
            pending.maximum_fee_sat,
            if wallet_managed { None } else { Some(10) }
        );
        assert_eq!(
            reopened
                .load_payment_attempt(&hash)
                .unwrap()
                .unwrap()
                .authorization_exceeded(),
            !wallet_managed && fee_msat > 10_000
        );
        let resumed = reopened
            .foreground_payment_wake(&event, UnixTimestamp::from_secs(100))
            .expect("retained wake");
        let result = execute(
            &engine(&reopened, &wallet, &relay, &secrets, &clock),
            resumed,
        );
        assert!(
            matches!(result, WakeDisposition::Completed { .. }),
            "{result:?}"
        );
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            reopened
                .load_payment_attempt(&hash)
                .expect("attempt")
                .expect("present")
                .state(),
            crate::DurablePaymentState::Succeeded
        );
        assert!(matches!(
            execute(
                &engine(&reopened, &wallet, &relay, &secrets, &clock),
                wake(&request, RELAY, true)
            ),
            WakeDisposition::Completed { .. }
        ));
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 0);
        if migrate {
            reopened.lock_connection().unwrap().execute_batch("DROP TABLE connection_payer_metadata; DROP TABLE browser_pairing_challenges; DROP TABLE foreground_reusable_bindings; ALTER TABLE foreground_payment_requests DROP COLUMN purchase_json; ALTER TABLE foreground_payment_requests DROP COLUMN consent_ciphertext; ALTER TABLE foreground_payment_requests DROP COLUMN response_published; ALTER TABLE foreground_payment_requests DROP COLUMN actual_amount_msat; ALTER TABLE foreground_payment_bindings DROP COLUMN invoice; ALTER TABLE connections DROP COLUMN foreground_fee_policy; PRAGMA user_version=14;").unwrap();
            let upgraded = WakeLedger::open(&database.path).unwrap();
            assert_eq!(
                upgraded.foreground_payments().unwrap()[0].actual_amount_msat,
                Some(600_000)
            );
            upgraded
                .complete_foreground_payment(
                    &event,
                    &preimage,
                    AmountMsat::from_msat(600_000),
                    AmountMsat::from_msat(fee_msat),
                    UnixTimestamp::from_secs(100),
                )
                .unwrap();
            // Later openings do not overwrite already populated actual evidence.
            upgraded.lock_connection().unwrap().execute("UPDATE foreground_payment_requests SET actual_amount_msat=600001 WHERE event_id=?1",rusqlite::params![event.as_bytes().as_slice()]).unwrap();
            let reopened_again = WakeLedger::open(&database.path).unwrap();
            assert_eq!(
                reopened_again.foreground_payments().unwrap()[0].actual_amount_msat,
                Some(600001)
            );
        }
    }

    #[test]
    fn foreground_rejection_refunds_and_unbound_request_can_resume() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger);
        let hash = PaymentHash::from_bytes([5; 32]);
        ledger.enable_foreground_payments().expect("gate");
        let wallet = TestWallet::default();
        *wallet.quote.lock().expect("quote") = Some(PaymentQuote::new(
            hash.clone(),
            AmountMsat::from_msat(600_000),
        ));
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let request = request_event(
            Request::pay_invoice(nip47::PayInvoiceRequest::new("lnbc-decline")),
            100,
        );
        let input = wake(&request, RELAY, true);
        let event = input.event_id().clone();
        assert!(matches!(
            execute(&engine(&ledger, &wallet, &relay, &secrets, &clock), input),
            WakeDisposition::QueuedForApplication { .. }
        ));
        assert!(ledger.load_payment_attempt(&hash).expect("load").is_none());
        ledger
            .bind_foreground_payment(connection.id().as_str(), "wallet-a", &hash, 600_000, 10)
            .expect("binding after request");
        let resumed = ledger
            .foreground_payment_wake(&event, UnixTimestamp::from_secs(100))
            .expect("wake");
        assert!(matches!(
            execute(&engine(&ledger, &wallet, &relay, &secrets, &clock), resumed),
            WakeDisposition::QueuedForApplication { .. }
        ));
        assert_eq!(
            ledger
                .load_payment_attempt(&hash)
                .expect("load")
                .expect("present")
                .reserved_sat(),
            610
        );
        ledger
            .reject_foreground_payment(&event, false, UnixTimestamp::from_secs(100))
            .expect("reject");
        assert!(ledger
            .begin_foreground_payment(&event, "wallet-a", UnixTimestamp::from_secs(100))
            .is_err());
        let used: u64 = ledger
            .lock_connection()
            .expect("db")
            .query_row("SELECT used_sat FROM budget_periods", [], |r| r.get(0))
            .expect("budget");
        assert_eq!(used, 0);
        let resumed = ledger
            .foreground_payment_wake(&event, UnixTimestamp::from_secs(100))
            .expect("wake");
        execute(&engine(&ledger, &wallet, &relay, &secrets, &clock), resumed);
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            ledger
                .load_payment_attempt(&hash)
                .expect("load")
                .expect("present")
                .state(),
            crate::DurablePaymentState::Failed
        );
    }

    #[test]
    fn timed_out_payment_stays_debited_and_late_settlement_reconciles() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let wallet = TestWallet::default();
        let payment_hash = PaymentHash::from_bytes([4_u8; 32]);
        *wallet.quote.lock().expect("quote lock") = Some(PaymentQuote::new(
            payment_hash.clone(),
            AmountMsat::from_msat(600_000),
        ));
        wallet
            .payment_statuses
            .lock()
            .expect("status lock")
            .extend([
                Ok(PaymentStatus::Unknown),
                Ok(PaymentStatus::Succeeded {
                    preimage: crate::PaymentPreimage::from_bytes([5_u8; 32]),
                    amount: AmountMsat::from_msat(600_000),
                    fee: AmountMsat::from_msat(500),
                }),
            ]);
        wallet
            .start_results
            .lock()
            .expect("start lock")
            .push_back(Err(HostError::new(HostErrorKind::TimedOut)));
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let engine = engine(&ledger, &wallet, &relay, &secrets, &clock);
        let event = request_event(
            Request::pay_invoice(nip47::PayInvoiceRequest::new("lnbc-test-invoice")),
            100,
        );

        assert!(matches!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::RetryAfter {
                reason: RetryReason::WalletUnavailable,
                ..
            }
        ));
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            ledger
                .load_payment_attempt(&payment_hash)
                .expect("attempt")
                .expect("pending attempt")
                .state(),
            crate::DurablePaymentState::Pending
        );

        clock.set(106);
        let duplicate = request_event(
            Request::pay_invoice(nip47::PayInvoiceRequest::new("lnbc-test-invoice")),
            101,
        );
        assert!(matches!(
            execute(&engine, wake(&duplicate, RELAY, true)),
            WakeDisposition::Rejected {
                code: RejectionCode::InvalidRequest,
                ..
            }
        ));
        assert_eq!(wallet.status_calls.load(Ordering::SeqCst), 1);
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 1);

        clock.set(1_000);
        assert!(matches!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::Completed { .. }
        ));
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 1);
        let settled = ledger
            .load_payment_attempt(&payment_hash)
            .expect("attempt")
            .expect("settled attempt");
        assert_eq!(settled.state(), crate::DurablePaymentState::Succeeded);
        assert_eq!(settled.charged_sat(), Some(601));
        assert_eq!(
            ledger
                .pending_nwc_sent_payments(10)
                .expect("sent notifications")
                .len(),
            1
        );
        let published = relay.published.lock().expect("published lock");
        assert_eq!(published.len(), 2);
        let response_event =
            Event::from_json(published.last().expect("payment response")).expect("response event");
        let plaintext = nostr::nips::nip44::decrypt(
            client_keys().secret_key(),
            &response_event.pubkey,
            &response_event.content,
        )
        .expect("decrypt response");
        let response = Response::from_json(plaintext).expect("NIP-47 response");
        assert!(matches!(
            response.result,
            Some(ResponseResult::PayInvoice(result)) if result.fees_paid == Some(500)
        ));
    }

    #[test]
    fn external_settlement_is_not_charged_or_disclosed() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let active = insert_connection(&ledger);
        let wallet = TestWallet::default();
        let payment_hash = PaymentHash::from_bytes([0x31_u8; 32]);
        *wallet.quote.lock().expect("quote lock") = Some(PaymentQuote::new(
            payment_hash.clone(),
            AmountMsat::from_msat(600_000),
        ));
        wallet
            .payment_statuses
            .lock()
            .expect("status lock")
            .push_back(Ok(PaymentStatus::Succeeded {
                preimage: crate::PaymentPreimage::from_bytes([0x32_u8; 32]),
                amount: AmountMsat::from_msat(600_000),
                fee: AmountMsat::from_msat(500),
            }));
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let engine = engine(&ledger, &wallet, &relay, &secrets, &clock);
        let event = request_event(
            Request::pay_invoice(nip47::PayInvoiceRequest::new("lnbc-external-settlement")),
            100,
        );

        assert!(matches!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::Rejected {
                code: RejectionCode::InvalidRequest,
                ..
            }
        ));
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 0);
        assert!(ledger
            .load_payment_attempt(&payment_hash)
            .expect("attempt lookup")
            .is_none());

        let published = relay.published.lock().expect("published lock");
        let response_event =
            Event::from_json(published.last().expect("error response")).expect("response event");
        let plaintext = nostr::nips::nip44::decrypt(
            client_keys().secret_key(),
            &response_event.pubkey,
            &response_event.content,
        )
        .expect("decrypt response");
        let response = Response::from_json(plaintext).expect("NIP-47 response");
        assert!(response.error.is_some());
        assert!(response.result.is_none());
        drop(published);

        let next_event = request_event(Request::get_info(), 100);
        assert!(matches!(
            ledger.reserve_payment(
                &crate::EventId::from_bytes(*next_event.id.as_bytes()),
                &PaymentHash::from_bytes([0x33_u8; 32]),
                &active,
                975,
                UnixTimestamp::from_secs(101),
            ),
            Ok(PaymentReservationOutcome::Reserved(_))
        ));
    }

    #[test]
    fn ambiguous_initiated_payment_resumes_with_the_same_idempotency_key() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let wallet = TestWallet::default();
        *wallet.quote.lock().expect("quote lock") = Some(PaymentQuote::new(
            PaymentHash::from_bytes([0x41_u8; 32]),
            AmountMsat::from_msat(100_000),
        ));
        wallet
            .payment_statuses
            .lock()
            .expect("status lock")
            .extend([Ok(PaymentStatus::Unknown), Ok(PaymentStatus::Unknown)]);
        wallet.start_results.lock().expect("start lock").extend([
            Err(HostError::new(HostErrorKind::TimedOut)),
            Err(HostError::new(HostErrorKind::AlreadyInProgress)),
        ]);
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let engine = engine(&ledger, &wallet, &relay, &secrets, &clock);
        let event = request_event(
            Request::pay_invoice(nip47::PayInvoiceRequest::new("lnbc-ambiguous")),
            100,
        );

        assert!(matches!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::RetryAfter { .. }
        ));
        clock.set(106);
        assert!(matches!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::RetryAfter { .. }
        ));
        assert_eq!(wallet.status_calls.load(Ordering::SeqCst), 2);
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 2);
        let requests = wallet.start_requests.lock().expect("start requests lock");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].idempotency_key(), requests[1].idempotency_key());
        assert_eq!(requests[0].invoice(), requests[1].invoice());
        assert_eq!(requests[0].amount(), requests[1].amount());
        assert_eq!(requests[0].maximum_fee(), requests[1].maximum_fee());
    }

    #[test]
    fn durable_failed_payment_replays_terminal_error_when_wallet_status_is_unknown() {
        assert_durable_failed_payment_replay(Ok(PaymentStatus::Unknown));
    }

    #[test]
    fn durable_failed_payment_replays_terminal_error_when_wallet_status_is_unavailable() {
        assert_durable_failed_payment_replay(Err(HostError::new(HostErrorKind::Unavailable)));
    }

    /// Checks that interrupted failure responses replay without another wallet query.
    fn assert_durable_failed_payment_replay(replay_status: Result<PaymentStatus, HostError>) {
        struct CancelAfterFailure<'a> {
            ledger: &'a WakeLedger,
            hash: &'a PaymentHash,
        }

        impl CancellationSignal for CancelAfterFailure<'_> {
            fn is_cancelled(&self) -> bool {
                self.ledger
                    .load_payment_attempt(self.hash)
                    .expect("attempt lookup")
                    .is_some_and(|attempt| attempt.state() == crate::DurablePaymentState::Failed)
            }
        }

        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let wallet = TestWallet::default();
        let hash = PaymentHash::from_bytes([0x49; 32]);
        *wallet.quote.lock().expect("quote lock") = Some(PaymentQuote::new(
            hash.clone(),
            AmountMsat::from_msat(600_000),
        ));
        wallet
            .payment_statuses
            .lock()
            .expect("status lock")
            .extend([Ok(PaymentStatus::Unknown), replay_status]);
        wallet
            .start_results
            .lock()
            .expect("start lock")
            .push_back(Err(HostError::new(HostErrorKind::Rejected)));
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let event = request_event(
            Request::pay_invoice(nip47::PayInvoiceRequest::new("lnbc-failed-response-retry")),
            100,
        );

        let first = block_on(engine(&ledger, &wallet, &relay, &secrets, &clock).execute(
            wake(&event, RELAY, true),
            OperationBudget::new(Duration::from_secs(10)).expect("budget"),
            &CancelAfterFailure {
                ledger: &ledger,
                hash: &hash,
            },
        ));
        assert!(matches!(
            first,
            WakeDisposition::QueuedForApplication {
                reason: QueueReason::Deadline,
                ..
            }
        ));
        assert_eq!(wallet.status_calls.load(Ordering::SeqCst), 1);
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 1);
        assert!(relay.published.lock().expect("published lock").is_empty());
        assert_eq!(
            ledger
                .load_payment_attempt(&hash)
                .expect("attempt lookup")
                .expect("failed attempt")
                .state(),
            crate::DurablePaymentState::Failed
        );

        clock.set(106);
        assert!(matches!(
            execute(
                &engine(&ledger, &wallet, &relay, &secrets, &clock),
                wake(&event, RELAY, true)
            ),
            WakeDisposition::Rejected { .. }
        ));
        assert_eq!(wallet.status_calls.load(Ordering::SeqCst), 1);
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            ledger
                .load_payment_attempt(&hash)
                .expect("attempt lookup")
                .expect("failed attempt")
                .state(),
            crate::DurablePaymentState::Failed
        );

        let published = relay.published.lock().expect("published lock");
        let response_event = Event::from_json(published.last().expect("error response"))
            .expect("valid response event");
        let plaintext = nostr::nips::nip44::decrypt(
            client_keys().secret_key(),
            &response_event.pubkey,
            &response_event.content,
        )
        .expect("decrypt response");
        let response = Response::from_json(plaintext).expect("NIP-47 response");
        assert!(matches!(
            response.error,
            Some(NIP47Error {
                code: ErrorCode::PaymentFailed,
                ..
            })
        ));
        assert!(response.result.is_none());
    }

    #[test]
    fn cancellation_after_initiation_marker_resumes_before_status_and_releases_rejection() {
        struct CancelAfterMarker<'a> {
            ledger: &'a WakeLedger,
            hash: &'a PaymentHash,
        }

        impl CancellationSignal for CancelAfterMarker<'_> {
            fn is_cancelled(&self) -> bool {
                self.ledger
                    .load_payment_attempt(self.hash)
                    .expect("attempt lookup")
                    .is_some_and(|attempt| attempt.was_initiated())
            }
        }

        let database = TestDatabase::new();
        let hash = PaymentHash::from_bytes([0x51; 32]);
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let event = request_event(
            Request::pay_invoice(nip47::PayInvoiceRequest::new("lnbc-cancel-before-start")),
            100,
        );

        {
            let ledger = WakeLedger::open(&database.path).expect("ledger");
            insert_connection(&ledger);
            let wallet = TestWallet::default();
            *wallet.quote.lock().expect("quote lock") = Some(PaymentQuote::new(
                hash.clone(),
                AmountMsat::from_msat(600_000),
            ));
            wallet
                .payment_statuses
                .lock()
                .expect("status lock")
                .push_back(Ok(PaymentStatus::Unknown));
            let first = block_on(engine(&ledger, &wallet, &relay, &secrets, &clock).execute(
                wake(&event, RELAY, true),
                OperationBudget::new(Duration::from_secs(10)).expect("budget"),
                &CancelAfterMarker {
                    ledger: &ledger,
                    hash: &hash,
                },
            ));
            assert!(matches!(first, WakeDisposition::RetryAfter { .. }));
            assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 0);
            assert!(ledger
                .load_payment_attempt(&hash)
                .expect("attempt lookup")
                .expect("attempt")
                .was_initiated());
        }
        let reopened = WakeLedger::open(&database.path).expect("reopen ledger");
        let wallet = TestWallet::default();
        wallet
            .payment_statuses
            .lock()
            .expect("status lock")
            .push_back(Ok(PaymentStatus::Succeeded {
                preimage: crate::PaymentPreimage::from_bytes([0x55; 32]),
                amount: AmountMsat::from_msat(600_000),
                fee: AmountMsat::from_msat(500),
            }));
        wallet
            .start_results
            .lock()
            .expect("start lock")
            .push_back(Err(HostError::new(HostErrorKind::Rejected)));
        clock.set(106);
        assert!(matches!(
            execute(
                &engine(&reopened, &wallet, &relay, &secrets, &clock),
                wake(&event, RELAY, true)
            ),
            WakeDisposition::Rejected { .. }
        ));
        assert_eq!(wallet.status_calls.load(Ordering::SeqCst), 0);
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 1);
        let attempt = reopened
            .load_payment_attempt(&hash)
            .expect("attempt lookup")
            .expect("attempt");
        assert_eq!(attempt.state(), crate::DurablePaymentState::Failed);
        let active = match reopened
            .load_connection(&connection_id())
            .expect("connection lookup")
            .expect("stored connection")
        {
            crate::StoredConnection::Active(active) => active,
            crate::StoredConnection::Tombstoned(_) => panic!("connection unexpectedly revoked"),
        };
        let next_event = request_event(Request::get_info(), 106);
        assert!(matches!(
            reopened.reserve_payment(
                &crate::EventId::from_bytes(*next_event.id.as_bytes()),
                &PaymentHash::from_bytes([0x54; 32]),
                &active,
                975,
                UnixTimestamp::from_secs(106),
            ),
            Ok(PaymentReservationOutcome::Reserved(_))
        ));
    }

    #[test]
    fn retry_recovers_settlement_before_requoting_an_expired_invoice() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let wallet = TestWallet::default();
        let hash = PaymentHash::from_bytes([0x52; 32]);
        *wallet.quote.lock().expect("quote lock") = Some(PaymentQuote::new(
            hash.clone(),
            AmountMsat::from_msat(600_000),
        ));
        wallet
            .payment_statuses
            .lock()
            .expect("status lock")
            .extend([
                Ok(PaymentStatus::Unknown),
                Ok(PaymentStatus::Succeeded {
                    preimage: crate::PaymentPreimage::from_bytes([0x53; 32]),
                    amount: AmountMsat::from_msat(600_000),
                    fee: AmountMsat::from_msat(500),
                }),
            ]);
        wallet
            .start_results
            .lock()
            .expect("start lock")
            .push_back(Err(HostError::new(HostErrorKind::TimedOut)));
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let event = request_event(
            Request::pay_invoice(nip47::PayInvoiceRequest::new("lnbc-expired-on-retry")),
            100,
        );
        let engine = engine(&ledger, &wallet, &relay, &secrets, &clock);
        assert!(matches!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::RetryAfter { .. }
        ));

        *wallet.quote.lock().expect("quote lock") = None;
        clock.set(106);
        assert!(matches!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::Completed { .. }
        ));
        assert_eq!(wallet.quote_calls.load(Ordering::SeqCst), 1);
        assert_eq!(wallet.status_calls.load(Ordering::SeqCst), 2);
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 1);
        let published = relay.published.lock().expect("published lock");
        let response_event = Event::from_json(published.last().expect("response event"))
            .expect("valid response event");
        let plaintext = nostr::nips::nip44::decrypt(
            client_keys().secret_key(),
            &response_event.pubkey,
            &response_event.content,
        )
        .expect("decrypt response");
        let response = Response::from_json(plaintext).expect("NIP-47 response");
        assert!(response.error.is_none());
        assert!(matches!(
            response.result,
            Some(ResponseResult::PayInvoice(_))
        ));
    }

    #[test]
    fn budget_rejection_happens_before_status_or_payment_start() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let wallet = TestWallet::default();
        *wallet.quote.lock().expect("quote lock") = Some(PaymentQuote::new(
            PaymentHash::from_bytes([6_u8; 32]),
            AmountMsat::from_msat(990_000),
        ));
        let relay = TestRelay::default();
        let secrets = TestSecrets::wallet();
        let clock = FixedClock::new(100);
        let diagnostics = crate::WakeDiagnosticCollector::default();
        let engine =
            engine(&ledger, &wallet, &relay, &secrets, &clock).with_diagnostics(&diagnostics);
        let event = request_event(
            Request::pay_invoice(nip47::PayInvoiceRequest::new("lnbc-over-budget")),
            100,
        );

        assert!(matches!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::Rejected {
                code: RejectionCode::BudgetExceeded,
                ..
            }
        ));
        assert_eq!(
            diagnostics.codes(),
            [
                WakeDiagnosticCode::PaymentRequestAccepted,
                WakeDiagnosticCode::PaymentBudgetExceeded,
            ]
        );
        assert_eq!(wallet.status_calls.load(Ordering::SeqCst), 0);
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn read_only_request_selectors_are_compatible_and_bounded() {
        let hash = crate::PaymentHash::from_bytes([9_u8; 32]);
        assert!(matches!(
            parse_lookup_request(nip47::LookupInvoiceRequest {
                payment_hash: Some(hash.to_hex()),
                invoice: None,
            }),
            Ok(InvoiceLookup::PaymentHash(_))
        ));
        assert!(matches!(
            parse_lookup_request(nip47::LookupInvoiceRequest {
                payment_hash: Some(hash.to_hex()),
                invoice: Some("lnbc-alby-dual-selector".to_owned()),
            }),
            Ok(InvoiceLookup::Invoice(invoice)) if invoice == "lnbc-alby-dual-selector"
        ));
        assert!(matches!(
            parse_lookup_request(nip47::LookupInvoiceRequest {
                payment_hash: None,
                invoice: Some("lnbc-alby-invoice-selector".to_owned()),
            }),
            Ok(InvoiceLookup::Invoice(invoice)) if invoice == "lnbc-alby-invoice-selector"
        ));
        assert_eq!(
            parse_lookup_request(nip47::LookupInvoiceRequest {
                payment_hash: None,
                invoice: None,
            }),
            Err(HostErrorKind::Rejected)
        );
        assert_eq!(
            parse_lookup_request(nip47::LookupInvoiceRequest {
                payment_hash: Some(hash.to_hex()),
                invoice: Some("x".repeat(16_385)),
            }),
            Err(HostErrorKind::Rejected)
        );

        let bounded = parse_list_request(nip47::ListTransactionsRequest {
            limit: Some(10_000),
            ..Default::default()
        })
        .expect("bounded list");
        assert_eq!(bounded.limit, MAX_LIST_LIMIT);
        assert_eq!(
            parse_list_request(nip47::ListTransactionsRequest {
                from: Some(Timestamp::from(20_u64)),
                until: Some(Timestamp::from(10_u64)),
                ..Default::default()
            }),
            Err(HostErrorKind::Rejected)
        );
        assert_eq!(
            parse_list_request(nip47::ListTransactionsRequest {
                offset: Some(u64::MAX),
                ..Default::default()
            }),
            Err(HostErrorKind::Rejected)
        );
    }

    #[test]
    fn wallet_transactions_convert_without_private_metadata() {
        let response = transaction_response(WalletTransaction {
            payment_hash: Some(crate::PaymentHash::from_bytes([9_u8; 32])),
            direction: crate::TransactionDirection::Outgoing,
            amount: AmountMsat::from_msat(25_000),
            fee: AmountMsat::from_msat(500),
            created_at: UnixTimestamp::from_secs(90),
            settled_at: Some(UnixTimestamp::from_secs(99)),
            status: PaymentStatus::Succeeded {
                preimage: crate::PaymentPreimage::from_bytes([8_u8; 32]),
                amount: AmountMsat::from_msat(25_000),
                fee: AmountMsat::from_msat(500),
            },
        })
        .expect("transaction response");

        assert_eq!(response.transaction_type, Some(TransactionType::Outgoing));
        assert_eq!(response.state, Some(TransactionState::Settled));
        assert_eq!(response.amount, 25_000);
        assert_eq!(response.fees_paid, 500);
        assert!(response.invoice.is_none());
        assert!(response.description.is_none());
        assert!(response.metadata.is_none());
    }

    #[test]
    fn claim_lease_rounds_up_with_wall_clock_safety() {
        assert_eq!(
            lease_duration_for_budget(Duration::from_secs(10)),
            Some(Duration::from_secs(11))
        );
        assert_eq!(
            lease_duration_for_budget(Duration::from_millis(1_500)),
            Some(Duration::from_secs(3))
        );
        assert_eq!(lease_duration_for_budget(Duration::ZERO), None);
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut context = Context::from_waker(Waker::noop());
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
