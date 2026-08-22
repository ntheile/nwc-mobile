use std::time::Duration;

use nostr::nips::nip47::{
    self, ErrorCode, GetBalanceResponse, GetInfoResponse, LookupInvoiceResponse, Method,
    NIP47Error, PayInvoiceResponse, Request, RequestParams, Response, ResponseResult,
    TransactionState, TransactionType,
};
use nostr::{JsonUtil, Timestamp};

use crate::time::OperationDeadline;
use crate::{
    ActiveConnection, AmountMsat, AmountSat, CancellationSignal, ClaimOutcome, Clock, EventLease,
    HostError, HostErrorKind, InvoiceLookup, LedgerError, ListTransactionsRequest,
    NotificationHint, NwcEventValidator, NwcMethod, OperationBudget, OperationContext,
    PayInvoiceRequest, PaymentAccountingError, PaymentFailure, PaymentHash,
    PaymentReservationOutcome, PaymentStatus, QueueReason, RejectionCode, RelayTransport,
    RetryReason, SecretProvider, SecureRelayUrl, TerminalKind, UnixTimestamp, WakeDisposition,
    WakeInput, WakeLedger, WakePolicy, WalletBackend, WalletTransaction,
};

const ENGINE_RETRY_DELAY: Duration = Duration::from_secs(5);
const DEFAULT_LIST_LIMIT: u16 = 20;
const MAX_LIST_LIMIT: u16 = 100;

/// Executes authenticated, durable NIP-47 reads and invoice payments.
///
/// The containing application owns relay, secret-storage, wallet, clock, and
/// cancellation capabilities. This engine owns validation order, replay state,
/// authorization checks, response construction, and commit-before-publish.
pub struct WakeEngine<'a> {
    ledger: &'a WakeLedger,
    wallet: &'a dyn WalletBackend,
    relays: &'a dyn RelayTransport,
    secrets: &'a dyn SecretProvider,
    clock: &'a dyn Clock,
    validator: NwcEventValidator,
    maximum_event_bytes: usize,
}

impl<'a> WakeEngine<'a> {
    /// Creates an engine over host capabilities and one durable ledger.
    #[must_use]
    pub const fn new(
        ledger: &'a WakeLedger,
        wallet: &'a dyn WalletBackend,
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
        }
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
            Ok(false) => return rejected(RejectionCode::RelayNotAllowed),
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
        if connection.is_expired_at(authorization_time) {
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
                return self
                    .republish_terminal(
                        &connection,
                        &relay,
                        terminal.response_event_json(),
                        &deadline,
                        cancellation,
                    )
                    .await;
            }
            Err(_) => return queued(QueueReason::LedgerBusy),
        };
        if !self
            .validator
            .accepts_event_time(validated.created_at(), self.clock.now())
        {
            return self.reject_claim(&lease, RejectionCode::EventOutsideFreshnessWindow);
        }

        let request = {
            let secret = match self.secrets.load_nwc_secret(connection.id()) {
                Ok(secret) => secret,
                Err(_) => {
                    return self
                        .release_to_application(&lease, QueueReason::SecureStorageUnavailable)
                }
            };
            match validated.decrypt(&secret).and_then(|plaintext| {
                Request::from_json(plaintext.as_json())
                    .map_err(|_| crate::NostrEventError::MalformedEvent)
            }) {
                Ok(request) => request,
                Err(_) => {
                    return self.reject_claim(&lease, RejectionCode::InvalidRequest);
                }
            }
        };

        let Some(method) = domain_method(request.method) else {
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
            let RequestParams::PayInvoice(payment) = request.params else {
                return self.reject_claim(&lease, RejectionCode::InvalidRequest);
            };
            return self
                .execute_payment(
                    &lease,
                    &connection,
                    &validated,
                    &relay,
                    payment,
                    &deadline,
                    cancellation,
                )
                .await;
        }
        if !is_read_only(method) {
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
        let result = match self.execute_request(request, &connection, context).await {
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
        deadline: &OperationDeadline,
        cancellation: &dyn CancellationSignal,
    ) -> WakeDisposition {
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
        let explicit_amount = payment.amount.map(AmountMsat::from_msat);
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
                return self.retry_claim(lease, RetryReason::WalletUnavailable)
            }
            Err(error) if error.kind() == HostErrorKind::Cancelled => {
                return self.release_to_application(lease, QueueReason::Deadline)
            }
            Err(_) => {
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
        };
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
        let reservation = match self.ledger.reserve_payment(
            validated.id(),
            quote.payment_hash(),
            connection,
            principal_sat,
            self.clock.now(),
        ) {
            Ok(reservation) => reservation,
            Err(PaymentAccountingError::BudgetExceeded) => {
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
                    .await
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
        let attempt = match &reservation {
            PaymentReservationOutcome::Reserved(attempt)
            | PaymentReservationOutcome::Existing(attempt)
            | PaymentReservationOutcome::AlreadyTracked(attempt) => attempt,
        };
        if matches!(&reservation, PaymentReservationOutcome::AlreadyTracked(_)) {
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
        let Some(context) = deadline.context(cancellation) else {
            return self.retry_claim(lease, RetryReason::WalletUnavailable);
        };
        let status = match self
            .wallet
            .payment_status(attempt.payment_hash(), context)
            .await
        {
            Ok(status) => status,
            Err(_) => return self.retry_claim(lease, RetryReason::WalletUnavailable),
        };
        if !matches!(status, PaymentStatus::Unknown) {
            return self
                .finish_payment_status(
                    lease,
                    connection,
                    validated,
                    relay,
                    attempt.payment_hash(),
                    status,
                    deadline,
                    cancellation,
                )
                .await;
        }
        if let Err(disposition) = self.ensure_claim_connection_active(connection, lease) {
            return disposition;
        }
        let Some(context) = deadline.context(cancellation) else {
            return self.retry_claim(lease, RetryReason::WalletUnavailable);
        };
        let request = PayInvoiceRequest::new(
            payment.invoice,
            explicit_amount,
            AmountSat::from_sat(attempt.fee_reserve_sat()),
            validated.id().clone(),
        );
        match self.wallet.start_payment(request, context).await {
            Ok(status) => {
                self.finish_payment_status(
                    lease,
                    connection,
                    validated,
                    relay,
                    attempt.payment_hash(),
                    status,
                    deadline,
                    cancellation,
                )
                .await
            }
            Err(_) => {
                if self
                    .ledger
                    .mark_payment_pending(attempt.payment_hash(), self.clock.now())
                    .is_err()
                {
                    return self.release_to_application(lease, QueueReason::LedgerBusy);
                }
                self.retry_claim(lease, RetryReason::WalletUnavailable)
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
        payment_hash: &PaymentHash,
        status: PaymentStatus,
        deadline: &OperationDeadline,
        cancellation: &dyn CancellationSignal,
    ) -> WakeDisposition {
        match status {
            PaymentStatus::Unknown | PaymentStatus::Pending => {
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
                if self
                    .ledger
                    .mark_payment_succeeded(payment_hash, amount, fee, self.clock.now())
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
        context: OperationContext<'_>,
    ) -> Result<ReadOnlyRequestResult, HostError> {
        match request.params {
            RequestParams::GetInfo => {
                let info = self.wallet.get_info(context).await?;
                let methods = info
                    .methods()
                    .filter(|method| {
                        connection.policy().allows(*method) && is_engine_supported(*method)
                    })
                    .map(protocol_method)
                    .collect();
                Ok(ReadOnlyRequestResult {
                    method: Method::GetInfo,
                    result: ResponseResult::GetInfo(GetInfoResponse {
                        alias: None,
                        color: None,
                        pubkey: info.public_key().map(|key| key.to_hex()),
                        network: None,
                        block_height: None,
                        block_hash: None,
                        methods,
                        notifications: Vec::new(),
                    }),
                })
            }
            RequestParams::GetBalance => {
                let balance = self.wallet.get_balance(context).await?;
                Ok(ReadOnlyRequestResult {
                    method: Method::GetBalance,
                    result: ResponseResult::GetBalance(GetBalanceResponse {
                        balance: balance.as_msat(),
                    }),
                })
            }
            RequestParams::LookupInvoice(request) => {
                let lookup = parse_lookup_request(request).map_err(HostError::new)?;
                let transaction = self.wallet.lookup_invoice(lookup, context).await?;
                let response = transaction
                    .map(transaction_response)
                    .transpose()
                    .map_err(HostError::new)?
                    .ok_or_else(|| HostError::new(HostErrorKind::NotFound))?;
                Ok(ReadOnlyRequestResult {
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
                Ok(ReadOnlyRequestResult {
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
            WakeDisposition::Completed { .. } => rejected(rejection),
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
        let response_json = response.as_json();
        let secret = match self.secrets.load_nwc_secret(connection.id()) {
            Ok(secret) => secret,
            Err(_) => {
                return self.release_to_application(lease, QueueReason::SecureStorageUnavailable)
            }
        };
        let event_json =
            match validated.build_response_event(&secret, &response_json, self.clock.now()) {
                Ok(event) => event,
                Err(_) => return self.reject_claim(lease, RejectionCode::InvalidRequest),
            };
        drop(secret);
        match self.ledger.complete_event_for_active_connection(
            lease,
            connection.id(),
            connection.revision(),
            &event_json,
            self.clock.now(),
        ) {
            Ok(()) => {}
            Err(error) => return self.completion_failed(lease, error),
        }
        self.republish_terminal(connection, relay, Some(&event_json), deadline, cancellation)
            .await
    }

    async fn republish_terminal(
        &self,
        connection: &ActiveConnection,
        relay: &SecureRelayUrl,
        event_json: Option<&str>,
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
            return retry(ENGINE_RETRY_DELAY, RetryReason::ResponsePublishFailed);
        };
        match self.relays.publish_event(relay, event_json, context).await {
            Ok(()) => completed(),
            Err(_) => retry(ENGINE_RETRY_DELAY, RetryReason::ResponsePublishFailed),
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
}

/// Compatibility name for the engine introduced with read-only execution.
pub type ReadOnlyWakeEngine<'a> = WakeEngine<'a>;

struct ReadOnlyRequestResult {
    method: Method,
    result: ResponseResult,
}

fn parse_lookup_request(
    request: nip47::LookupInvoiceRequest,
) -> Result<InvoiceLookup, HostErrorKind> {
    match (request.payment_hash, request.invoice) {
        (Some(hash), None) => PaymentHash::from_hex(&hash)
            .map(InvoiceLookup::PaymentHash)
            .map_err(|_| HostErrorKind::Rejected),
        (None, Some(invoice)) if !invoice.is_empty() && invoice.len() <= 16_384 => {
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

fn is_read_only(method: NwcMethod) -> bool {
    matches!(
        method,
        NwcMethod::GetInfo
            | NwcMethod::GetBalance
            | NwcMethod::LookupInvoice
            | NwcMethod::ListTransactions
    )
}

fn is_engine_supported(method: NwcMethod) -> bool {
    method == NwcMethod::PayInvoice || is_read_only(method)
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

const fn completed() -> WakeDisposition {
    WakeDisposition::Completed {
        notification: NotificationHint::Completed,
    }
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
        FeePolicy, HostFuture, MakeInvoiceRequest, NewConnection, PayInvoiceRequest, PaymentQuote,
        PublicKey, WalletInfo,
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
        fn load_nwc_secret(
            &self,
            _connection_id: &ConnectionId,
        ) -> Result<crate::NwcSecretKey, HostError> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            crate::NwcSecretKey::from_bytes(self.bytes)
                .map_err(|_| HostError::new(HostErrorKind::Internal))
        }
    }

    struct ExpiringResponseSecrets<'a> {
        clock: &'a FixedClock,
        loads: AtomicUsize,
    }

    impl SecretProvider for ExpiringResponseSecrets<'_> {
        fn load_nwc_secret(
            &self,
            _connection_id: &ConnectionId,
        ) -> Result<crate::NwcSecretKey, HostError> {
            if self.loads.fetch_add(1, Ordering::SeqCst) == 1 {
                self.clock.set(1_000);
            }
            crate::NwcSecretKey::from_bytes(WALLET_SECRET)
                .map_err(|_| HostError::new(HostErrorKind::Internal))
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
        revoke_on_balance: Mutex<Option<(&'a WakeLedger, ConnectionId, crate::ConnectionRevision)>>,
        quote: Mutex<Option<PaymentQuote>>,
        payment_statuses: Mutex<VecDeque<Result<PaymentStatus, HostError>>>,
        start_results: Mutex<VecDeque<Result<PaymentStatus, HostError>>>,
        quote_calls: AtomicUsize,
        status_calls: AtomicUsize,
        start_calls: AtomicUsize,
    }

    impl WalletBackend for TestWallet<'_> {
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
                        NwcMethod::PayInvoice,
                    ],
                ))
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
            _request: MakeInvoiceRequest,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<CreatedInvoice, HostError>> {
            unavailable()
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
            _request: PayInvoiceRequest,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<PaymentStatus, HostError>> {
            self.start_calls.fetch_add(1, Ordering::SeqCst);
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
            _request: InvoiceLookup,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<Option<WalletTransaction>, HostError>> {
            unavailable()
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
        let client = client_keys();
        let wallet = wallet_keys();
        let encrypted = nostr::nips::nip44::encrypt(
            client.secret_key(),
            &wallet.public_key(),
            request.as_json(),
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

        assert!(matches!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::Completed { .. }
        ));
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

        assert!(matches!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::Completed { .. }
        ));
        assert_eq!(wallet.balance_calls.load(Ordering::SeqCst), 1);
        assert_eq!(relay.published.lock().expect("published lock").len(), 2);
    }

    #[test]
    fn get_info_advertises_authorized_pay_invoice_support() {
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
        ));
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
        let engine = engine(&ledger, &wallet, &relay, &secrets, &clock);
        let event = request_event(Request::get_balance(), 100);

        assert!(matches!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::RetryAfter {
                reason: RetryReason::ResponsePublishFailed,
                ..
            }
        ));
        assert_eq!(wallet.balance_calls.load(Ordering::SeqCst), 1);
        clock.set(1_000);
        assert!(matches!(
            execute(&engine, wake(&event, RELAY, true)),
            WakeDisposition::Completed { .. }
        ));
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
        let engine = engine(&ledger, &wallet, &relay, &secrets, &clock);
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
        assert_eq!(wallet.status_calls.load(Ordering::SeqCst), 0);
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn read_only_request_bounds_fail_closed() {
        let hash = crate::PaymentHash::from_bytes([9_u8; 32]);
        assert!(matches!(
            parse_lookup_request(nip47::LookupInvoiceRequest {
                payment_hash: Some(hash.to_hex()),
                invoice: None,
            }),
            Ok(InvoiceLookup::PaymentHash(_))
        ));
        assert_eq!(
            parse_lookup_request(nip47::LookupInvoiceRequest {
                payment_hash: Some(hash.to_hex()),
                invoice: Some("lnbc-conflicting-selector".to_owned()),
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
