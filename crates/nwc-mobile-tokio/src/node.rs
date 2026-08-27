//! High-level Tokio facade for embedding `nwc-mobile` in a Lightning wallet.

use std::time::{Duration, Instant};

use nwc_mobile::{
    AmountMsat, CancellationSignal, CreatedInvoice, EventId, HostError, HostFuture, InvoiceLookup,
    InvoiceNotificationError, InvoiceNotificationWorker, InvoiceNotificationWorkerReport,
    LightningNode, ListTransactionsRequest, MakeInvoiceRequest, NwcWalletBackend, OperationBudget,
    OperationContext, PayInvoiceRequest, PaymentHash, PaymentQuote, PaymentStatus, RelayTransport,
    SecretProvider, SystemClock, WakeDiagnosticSink, WakeDisposition, WakeEngine, WakeInput,
    WakeLedger, WakePolicy, WalletInfo, WalletTransaction,
};

use crate::{run_with_context, sleep};

/// Default interval between settlement checks while a `make_invoice` wake remains active.
pub const DEFAULT_INVOICE_SETTLEMENT_POLL_INTERVAL: Duration = Duration::from_millis(750);

/// Stable engine configuration shared by foreground and background NWC nodes.
pub struct NwcNodeConfig<'a> {
    ledger: &'a WakeLedger,
    relays: &'a dyn RelayTransport,
    secrets: &'a dyn SecretProvider,
    wallet_info: WalletInfo,
    wake_policy: WakePolicy,
    invoice_settlement_poll_interval: Duration,
}

impl<'a> NwcNodeConfig<'a> {
    /// Creates a node configuration with the hardened default wake policy.
    #[must_use]
    pub fn new(
        ledger: &'a WakeLedger,
        relays: &'a dyn RelayTransport,
        secrets: &'a dyn SecretProvider,
        wallet_info: WalletInfo,
    ) -> Self {
        Self {
            ledger,
            relays,
            secrets,
            wallet_info,
            wake_policy: WakePolicy::default(),
            invoice_settlement_poll_interval: DEFAULT_INVOICE_SETTLEMENT_POLL_INTERVAL,
        }
    }

    /// Replaces the wake-validation policy.
    #[must_use]
    pub const fn with_wake_policy(mut self, wake_policy: WakePolicy) -> Self {
        self.wake_policy = wake_policy;
        self
    }

    /// Replaces the interval used while waiting for a newly created invoice to settle.
    #[must_use]
    pub const fn with_invoice_settlement_poll_interval(mut self, interval: Duration) -> Self {
        self.invoice_settlement_poll_interval = interval;
        self
    }
}

/// Batteries-included NWC node over one application-supplied Lightning node.
///
/// This facade owns wake-engine assembly, Tokio deadline enforcement, payment
/// and invoice-notification reconciliation, and optional diagnostics. Wallet
/// applications provide only their Lightning operations plus relay and secret
/// capabilities in [`NwcNodeConfig`].
pub struct NwcNode<'a, N> {
    config: NwcNodeConfig<'a>,
    wallet: N,
    diagnostics: Option<&'a dyn WakeDiagnosticSink>,
}

impl<'a, N> NwcNode<'a, N>
where
    N: LightningNode,
{
    /// Creates an NWC node around one configured Lightning node.
    #[must_use]
    pub const fn new(config: NwcNodeConfig<'a>, wallet: N) -> Self {
        Self {
            config,
            wallet,
            diagnostics: None,
        }
    }

    /// Attaches a bounded, non-secret diagnostic sink.
    #[must_use]
    pub fn with_diagnostics(mut self, diagnostics: &'a dyn WakeDiagnosticSink) -> Self {
        self.diagnostics = Some(diagnostics);
        self
    }

    /// Validates and executes one wake, then flushes any resulting NIP-47 notifications.
    pub async fn handle_wake(
        &self,
        input: WakeInput,
        budget: OperationBudget,
        cancellation: &dyn CancellationSignal,
    ) -> WakeDisposition {
        let started = Instant::now();
        let request_event_id = input.event_id().clone();
        let wallet = RuntimeWallet::new(&self.wallet, &self.config.wallet_info, false);
        let engine = WakeEngine::new(
            self.config.ledger,
            &wallet,
            self.config.relays,
            self.config.secrets,
            &SystemClock,
            self.config.wake_policy,
        );
        let disposition = if let Some(diagnostics) = self.diagnostics {
            engine
                .with_diagnostics(diagnostics)
                .execute(input, budget, cancellation)
                .await
        } else {
            engine.execute(input, budget, cancellation).await
        };

        if let Ok(notification_budget) =
            OperationBudget::new(budget.timeout().saturating_sub(started.elapsed()))
        {
            let worker = InvoiceNotificationWorker::new(
                self.config.ledger,
                &wallet,
                self.config.relays,
                self.config.secrets,
                &SystemClock,
            );
            let _ = self
                .run_notification_worker(
                    &worker,
                    &request_event_id,
                    lingers_for_invoice_settlement(disposition),
                    notification_budget,
                    cancellation,
                )
                .await;
        }
        disposition
    }

    /// Reconciles all pending incoming and outgoing NWC notifications once.
    pub async fn run_notifications(
        &self,
        budget: OperationBudget,
        cancellation: &dyn CancellationSignal,
    ) -> Result<InvoiceNotificationWorkerReport, InvoiceNotificationError> {
        let wallet = RuntimeWallet::new(&self.wallet, &self.config.wallet_info, false);
        InvoiceNotificationWorker::new(
            self.config.ledger,
            &wallet,
            self.config.relays,
            self.config.secrets,
            &SystemClock,
        )
        .run(budget, cancellation)
        .await
    }

    /// Reconciles one exact created invoice and publishes its settlement notification.
    pub async fn handle_settlement_wake(
        &self,
        request_event_id: &EventId,
        budget: OperationBudget,
        cancellation: &dyn CancellationSignal,
    ) -> Result<InvoiceNotificationWorkerReport, InvoiceNotificationError> {
        let wallet = RuntimeWallet::new(&self.wallet, &self.config.wallet_info, true);
        InvoiceNotificationWorker::new(
            self.config.ledger,
            &wallet,
            self.config.relays,
            self.config.secrets,
            &SystemClock,
        )
        .run_invoice(request_event_id, budget, cancellation)
        .await
    }

    async fn run_notification_worker(
        &self,
        worker: &InvoiceNotificationWorker<'_>,
        request_event_id: &EventId,
        linger: bool,
        budget: OperationBudget,
        cancellation: &dyn CancellationSignal,
    ) -> Result<InvoiceNotificationWorkerReport, InvoiceNotificationError> {
        let deadline = Instant::now() + budget.timeout();
        let mut aggregate = InvoiceNotificationWorkerReport::default();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let Ok(pass_budget) = OperationBudget::new(remaining) else {
                return Ok(aggregate);
            };
            let report = worker.run(pass_budget, cancellation).await?;
            aggregate.inspected = aggregate.inspected.saturating_add(report.inspected);
            aggregate.pending = report.pending;
            aggregate.expired = aggregate.expired.saturating_add(report.expired);
            aggregate.delivered = aggregate.delivered.saturating_add(report.delivered);
            aggregate.retryable = report.retryable;

            let target_pending = self
                .config
                .ledger
                .nwc_invoice_monitor(request_event_id)
                .map_err(|_| InvoiceNotificationError::Ledger)?
                .is_some_and(|monitor| !monitor.completed());
            if !linger || !target_pending || cancellation.is_cancelled() {
                return Ok(aggregate);
            }

            let interval = self.config.invoice_settlement_poll_interval;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if interval.is_zero() || remaining <= interval {
                return Ok(aggregate);
            }
            sleep(interval).await;
        }
    }
}

const fn lingers_for_invoice_settlement(disposition: WakeDisposition) -> bool {
    matches!(
        disposition.notification(),
        nwc_mobile::NotificationHint::Request {
            method: nwc_mobile::NwcMethod::MakeInvoice
        }
    )
}

struct RuntimeWallet<'a, N> {
    wallet: &'a N,
    wallet_info: &'a WalletInfo,
    await_settlement: bool,
}

impl<'a, N> RuntimeWallet<'a, N> {
    const fn new(wallet: &'a N, wallet_info: &'a WalletInfo, await_settlement: bool) -> Self {
        Self {
            wallet,
            wallet_info,
            await_settlement,
        }
    }
}

impl<N> NwcWalletBackend for RuntimeWallet<'_, N>
where
    N: LightningNode,
{
    fn get_info<'a>(
        &'a self,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<WalletInfo, HostError>> {
        let wallet_info = self.wallet_info.clone();
        Box::pin(run_with_context(context, async move { Ok(wallet_info) }))
    }

    fn get_balance<'a>(
        &'a self,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<AmountMsat, HostError>> {
        Box::pin(run_with_context(context, self.wallet.get_balance()))
    }

    fn make_invoice<'a>(
        &'a self,
        request: MakeInvoiceRequest,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<CreatedInvoice, HostError>> {
        Box::pin(run_with_context(
            context,
            self.wallet.create_invoice(request),
        ))
    }

    fn quote_payment<'a>(
        &'a self,
        invoice: &'a str,
        amount: Option<AmountMsat>,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<PaymentQuote, HostError>> {
        Box::pin(run_with_context(
            context,
            self.wallet.quote_invoice(invoice, amount),
        ))
    }

    fn payment_status<'a>(
        &'a self,
        payment_hash: &'a PaymentHash,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<PaymentStatus, HostError>> {
        Box::pin(run_with_context(context, async move {
            Ok(self
                .wallet
                .lookup_invoice(InvoiceLookup::PaymentHash(payment_hash.clone()), false)
                .await?
                .map_or(PaymentStatus::Unknown, |transaction| transaction.status))
        }))
    }

    fn start_payment<'a>(
        &'a self,
        request: PayInvoiceRequest,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<PaymentStatus, HostError>> {
        Box::pin(run_with_context(context, self.wallet.pay_invoice(request)))
    }

    fn lookup_invoice<'a>(
        &'a self,
        request: InvoiceLookup,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<Option<WalletTransaction>, HostError>> {
        Box::pin(run_with_context(
            context,
            self.wallet.lookup_invoice(request, self.await_settlement),
        ))
    }

    fn list_transactions<'a>(
        &'a self,
        request: ListTransactionsRequest,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<Vec<WalletTransaction>, HostError>> {
        Box::pin(run_with_context(
            context,
            self.wallet.list_transactions(request),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use nwc_mobile::{
        HostErrorKind, NeverCancelled, PaymentPreimage, TransactionDirection, UnixTimestamp,
    };

    use super::*;

    struct TestNode {
        awaited_settlement: AtomicBool,
        transaction: WalletTransaction,
    }

    impl LightningNode for TestNode {
        fn get_balance(&self) -> HostFuture<'_, Result<AmountMsat, HostError>> {
            Box::pin(async { Ok(AmountMsat::from_msat(42_000)) })
        }

        fn create_invoice(
            &self,
            _request: MakeInvoiceRequest,
        ) -> HostFuture<'_, Result<CreatedInvoice, HostError>> {
            Box::pin(async { Err(HostError::new(HostErrorKind::Internal)) })
        }

        fn quote_invoice<'a>(
            &'a self,
            _invoice: &'a str,
            _amount: Option<AmountMsat>,
        ) -> HostFuture<'a, Result<PaymentQuote, HostError>> {
            Box::pin(async { Err(HostError::new(HostErrorKind::Internal)) })
        }

        fn pay_invoice(
            &self,
            _request: PayInvoiceRequest,
        ) -> HostFuture<'_, Result<PaymentStatus, HostError>> {
            Box::pin(async { Ok(PaymentStatus::Pending) })
        }

        fn lookup_invoice(
            &self,
            _request: InvoiceLookup,
            await_settlement: bool,
        ) -> HostFuture<'_, Result<Option<WalletTransaction>, HostError>> {
            self.awaited_settlement
                .store(await_settlement, Ordering::Release);
            let transaction = self.transaction.clone();
            Box::pin(async move { Ok(Some(transaction)) })
        }

        fn list_transactions(
            &self,
            _request: ListTransactionsRequest,
        ) -> HostFuture<'_, Result<Vec<WalletTransaction>, HostError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    fn test_node() -> TestNode {
        TestNode {
            awaited_settlement: AtomicBool::new(false),
            transaction: WalletTransaction {
                payment_hash: Some(PaymentHash::from_bytes([3; 32])),
                direction: TransactionDirection::Outgoing,
                amount: AmountMsat::from_msat(10_000),
                fee: AmountMsat::from_msat(1_000),
                created_at: UnixTimestamp::from_secs(1),
                settled_at: Some(UnixTimestamp::from_secs(2)),
                status: PaymentStatus::Succeeded {
                    preimage: PaymentPreimage::from_bytes([4; 32]),
                    amount: AmountMsat::from_msat(10_000),
                    fee: AmountMsat::from_msat(1_000),
                },
            },
        }
    }

    fn context<'a>(cancellation: &'a NeverCancelled) -> OperationContext<'a> {
        OperationContext::new(
            OperationBudget::new(Duration::from_secs(1)).expect("budget"),
            cancellation,
        )
    }

    #[tokio::test]
    async fn runtime_adapter_derives_payment_status_from_lookup() {
        let node = test_node();
        let info = WalletInfo::new(None, std::iter::empty());
        let wallet = RuntimeWallet::new(&node, &info, false);
        let cancellation = NeverCancelled;

        let status = NwcWalletBackend::payment_status(
            &wallet,
            &PaymentHash::from_bytes([3; 32]),
            context(&cancellation),
        )
        .await
        .expect("status");

        assert!(matches!(status, PaymentStatus::Succeeded { .. }));
        assert!(!node.awaited_settlement.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn targeted_adapter_requests_settlement_waiting() {
        let node = test_node();
        let info = WalletInfo::new(None, std::iter::empty());
        let wallet = RuntimeWallet::new(&node, &info, true);
        let cancellation = NeverCancelled;

        NwcWalletBackend::lookup_invoice(
            &wallet,
            InvoiceLookup::PaymentHash(PaymentHash::from_bytes([3; 32])),
            context(&cancellation),
        )
        .await
        .expect("lookup");

        assert!(node.awaited_settlement.load(Ordering::Acquire));
    }
}
