use std::fmt;
use std::time::{Duration, Instant};

use crate::{
    CancellationSignal, Clock, DurablePaymentState, OperationBudget, OperationContext,
    PaymentAccountingError, PaymentStatus, WakeLedger, WalletBackend,
};

/// Maximum payment-status queries performed by one reconciliation pass.
pub const MAX_PAYMENT_RECONCILIATION_BATCH: u16 = 100;

/// A stable failure that prevents a payment reconciliation pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PaymentReconciliationError {
    /// The requested batch was zero or exceeded the hard safety cap.
    InvalidBatchSize,
    /// Durable payment accounting could not be read or updated safely.
    Accounting(PaymentAccountingError),
}

impl fmt::Display for PaymentReconciliationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBatchSize => "payment reconciliation batch size is invalid",
            Self::Accounting(_) => "payment reconciliation accounting failed",
        })
    }
}

impl std::error::Error for PaymentReconciliationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidBatchSize => None,
            Self::Accounting(error) => Some(error),
        }
    }
}

impl From<PaymentAccountingError> for PaymentReconciliationError {
    fn from(error: PaymentAccountingError) -> Self {
        Self::Accounting(error)
    }
}

/// Non-sensitive aggregate results for one bounded reconciliation pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PaymentReconciliationReport {
    examined: u16,
    succeeded: u16,
    failed: u16,
    unresolved: u16,
    deferred: u16,
    interrupted: bool,
    needs_retry: bool,
}

impl PaymentReconciliationReport {
    /// Returns the number of wallet status queries made.
    #[must_use]
    pub const fn examined(self) -> u16 {
        self.examined
    }

    /// Returns the number of observed successful payments.
    #[must_use]
    pub const fn succeeded(self) -> u16 {
        self.succeeded
    }

    /// Returns the number of observed definitive failures.
    #[must_use]
    pub const fn failed(self) -> u16 {
        self.failed
    }

    /// Returns the number of queried payments that remain ambiguous or pending.
    #[must_use]
    pub const fn unresolved(self) -> u16 {
        self.unresolved
    }

    /// Returns the number of wallet queries deferred by a host failure.
    #[must_use]
    pub const fn deferred(self) -> u16 {
        self.deferred
    }

    /// Returns whether cancellation or the operation deadline stopped the pass.
    #[must_use]
    pub const fn interrupted(self) -> bool {
        self.interrupted
    }

    /// Returns whether native code should schedule another reconciliation pass.
    #[must_use]
    pub const fn needs_retry(self) -> bool {
        self.needs_retry
    }
}

/// Reconciles already-authorized payment attempts without initiating payments.
///
/// This component is safe to run from a foreground task, an iOS background
/// task, or Android background work. It only calls `payment_status`; it never
/// calls `quote_payment` or `start_payment`. Connection revocation therefore
/// stops new authorization without preventing conservative settlement
/// accounting for payments that may already have left the wallet.
pub struct PaymentReconciler<'a> {
    ledger: &'a WakeLedger,
    wallet: &'a dyn WalletBackend,
    clock: &'a dyn Clock,
}

impl<'a> PaymentReconciler<'a> {
    /// Creates a reconciler over the durable ledger and wallet status adapter.
    #[must_use]
    pub const fn new(
        ledger: &'a WakeLedger,
        wallet: &'a dyn WalletBackend,
        clock: &'a dyn Clock,
    ) -> Self {
        Self {
            ledger,
            wallet,
            clock,
        }
    }

    /// Reconciles the oldest unresolved payments within a hard-capped batch.
    ///
    /// Wallet failures are counted as deferred work so one temporarily
    /// unavailable status does not discard other durable attempts. Accounting
    /// failures stop the pass because continuing could hide a policy mismatch.
    pub async fn reconcile(
        &self,
        max_attempts: u16,
        budget: OperationBudget,
        cancellation: &dyn CancellationSignal,
    ) -> Result<PaymentReconciliationReport, PaymentReconciliationError> {
        if max_attempts == 0 || max_attempts > MAX_PAYMENT_RECONCILIATION_BATCH {
            return Err(PaymentReconciliationError::InvalidBatchSize);
        }

        let fetch_limit = usize::from(max_attempts) + 1;
        let mut attempts = self.ledger.load_unresolved_payment_attempts(fetch_limit)?;
        let has_additional_attempts = attempts.len() > usize::from(max_attempts);
        attempts.truncate(usize::from(max_attempts));

        let deadline = ReconciliationDeadline::new(budget);
        let mut report = PaymentReconciliationReport::default();
        for attempt in attempts {
            let Some(context) = deadline.context(cancellation) else {
                report.interrupted = true;
                break;
            };
            report.examined += 1;
            let status = match self
                .wallet
                .payment_status(attempt.payment_hash(), context)
                .await
            {
                Ok(status) => status,
                Err(_) => {
                    report.deferred += 1;
                    continue;
                }
            };

            match status {
                PaymentStatus::Unknown => {
                    report.unresolved += 1;
                }
                PaymentStatus::Pending => {
                    if attempt.state() == DurablePaymentState::Reserved {
                        self.ledger
                            .mark_payment_pending(attempt.payment_hash(), self.clock.now())?;
                    }
                    report.unresolved += 1;
                }
                PaymentStatus::Succeeded { amount, fee, .. } => {
                    self.ledger.mark_payment_succeeded(
                        attempt.payment_hash(),
                        amount.as_sat(),
                        fee.as_sat(),
                        self.clock.now(),
                    )?;
                    report.succeeded += 1;
                }
                PaymentStatus::Failed { .. } => {
                    self.ledger
                        .mark_payment_failed(attempt.payment_hash(), self.clock.now())?;
                    report.failed += 1;
                }
            }
        }

        report.needs_retry = has_additional_attempts
            || report.interrupted
            || report.unresolved != 0
            || report.deferred != 0;
        Ok(report)
    }
}

struct ReconciliationDeadline {
    started: Instant,
    budget: OperationBudget,
}

impl ReconciliationDeadline {
    fn new(budget: OperationBudget) -> Self {
        Self {
            started: Instant::now(),
            budget,
        }
    }

    fn remaining(&self) -> Duration {
        self.budget.timeout().saturating_sub(self.started.elapsed())
    }

    fn context<'a>(
        &self,
        cancellation: &'a dyn CancellationSignal,
    ) -> Option<OperationContext<'a>> {
        if cancellation.is_cancelled() {
            return None;
        }
        OperationBudget::new(self.remaining())
            .ok()
            .map(|budget| OperationContext::new(budget, cancellation))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::future::Future;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Wake, Waker};

    use crate::{
        AmountMsat, AmountSat, BudgetInterval, BudgetPolicy, ConnectionId, ConnectionPolicy,
        CreatedInvoice, DurablePaymentState, EventId, FeePolicy, HostError, HostErrorKind,
        HostFuture, InvoiceLookup, ListTransactionsRequest, MakeInvoiceRequest, NewConnection,
        NwcEncryption, NwcMethod, PayInvoiceRequest, PaymentFailure, PaymentHash, PaymentPreimage,
        PaymentQuote, PublicKey, SecureRelayUrl, UnixTimestamp, WakePolicy, WalletInfo,
        WalletTransaction,
    };

    use super::*;

    const CLIENT: &str = "687dd8ece211539364549b1f32c63eceec1e0661009ba65cf8ff2e73ba000746";
    const WALLET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    struct TestDatabase {
        directory: PathBuf,
        path: PathBuf,
    }

    impl TestDatabase {
        fn new() -> Self {
            let mut random = [0_u8; 8];
            getrandom::fill(&mut random).expect("test randomness");
            let suffix = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let directory = std::env::temp_dir().join(format!(
                "nwc-mobile-reconciliation-{}-{suffix}",
                std::process::id()
            ));
            fs::create_dir(&directory).expect("create test directory");
            let path = directory.join("reconciliation.sqlite3");
            Self { directory, path }
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    struct FixedClock(UnixTimestamp);

    impl Clock for FixedClock {
        fn now(&self) -> UnixTimestamp {
            self.0
        }
    }

    #[derive(Default)]
    struct TestWallet {
        statuses: Mutex<VecDeque<Result<PaymentStatus, HostError>>>,
        status_calls: AtomicUsize,
        start_calls: AtomicUsize,
    }

    impl WalletBackend for TestWallet {
        fn get_info<'a>(
            &'a self,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<WalletInfo, HostError>> {
            unavailable()
        }

        fn get_balance<'a>(
            &'a self,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<AmountMsat, HostError>> {
            unavailable()
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
        ) -> HostFuture<'a, Result<PaymentQuote, HostError>> {
            unavailable()
        }

        fn payment_status<'a>(
            &'a self,
            _payment_hash: &'a PaymentHash,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<PaymentStatus, HostError>> {
            self.status_calls.fetch_add(1, Ordering::SeqCst);
            let status = self
                .statuses
                .lock()
                .expect("status lock")
                .pop_front()
                .unwrap_or_else(|| Err(HostError::new(HostErrorKind::Internal)));
            Box::pin(async move { status })
        }

        fn start_payment<'a>(
            &'a self,
            _request: PayInvoiceRequest,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<PaymentStatus, HostError>> {
            self.start_calls.fetch_add(1, Ordering::SeqCst);
            unavailable()
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

    fn insert_connection(ledger: &WakeLedger) -> crate::ActiveConnection {
        ledger
            .insert_connection(
                NewConnection::new(
                    ConnectionId::parse("connection:reconciliation-test").expect("connection id"),
                    PublicKey::from_hex(CLIENT).expect("client key"),
                    PublicKey::from_hex(WALLET).expect("wallet key"),
                    vec![SecureRelayUrl::parse("wss://relay.example.com").expect("relay")],
                    ConnectionPolicy::new(
                        [NwcMethod::PayInvoice],
                        BudgetPolicy::new(
                            2_000,
                            BudgetInterval::Never,
                            FeePolicy::CountTowardBudget {
                                maximum_fee_sat: 25,
                            },
                        ),
                    ),
                    NwcEncryption::Nip44V2,
                    WakePolicy::default(),
                )
                .expect("new connection"),
                UnixTimestamp::from_secs(100),
            )
            .expect("insert connection")
    }

    fn reserve(ledger: &WakeLedger, connection: &crate::ActiveConnection, byte: u8, now: u64) {
        ledger
            .reserve_payment(
                &EventId::from_bytes([byte; 32]),
                &PaymentHash::from_bytes([byte; 32]),
                connection,
                500,
                UnixTimestamp::from_secs(now),
            )
            .expect("reserve payment");
    }

    fn operation_budget() -> OperationBudget {
        OperationBudget::new(Duration::from_secs(5)).expect("operation budget")
    }

    #[test]
    fn reconciles_settlement_after_connection_tombstone_without_starting_payment() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger);
        reserve(&ledger, &connection, 1, 100);
        ledger
            .mark_payment_pending(
                &PaymentHash::from_bytes([1; 32]),
                UnixTimestamp::from_secs(101),
            )
            .expect("mark pending");
        ledger
            .tombstone_connection(
                connection.id(),
                connection.revision(),
                UnixTimestamp::from_secs(102),
            )
            .expect("tombstone connection");

        let wallet = TestWallet::default();
        wallet
            .statuses
            .lock()
            .expect("status lock")
            .push_back(Ok(PaymentStatus::Succeeded {
                preimage: PaymentPreimage::from_bytes([9; 32]),
                amount: AmountSat::from_sat(500),
                fee: AmountSat::from_sat(10),
            }));
        let clock = FixedClock(UnixTimestamp::from_secs(103));
        let report = block_on(PaymentReconciler::new(&ledger, &wallet, &clock).reconcile(
            10,
            operation_budget(),
            &crate::NeverCancelled,
        ))
        .expect("reconcile");

        assert_eq!(report.examined(), 1);
        assert_eq!(report.succeeded(), 1);
        assert!(!report.needs_retry());
        assert_eq!(wallet.start_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            ledger
                .load_payment_attempt(&PaymentHash::from_bytes([1; 32]))
                .expect("load attempt")
                .expect("attempt")
                .state(),
            DurablePaymentState::Succeeded
        );
    }

    #[test]
    fn unknown_status_remains_reserved_and_definitive_failure_refunds() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger);
        reserve(&ledger, &connection, 1, 100);
        let wallet = TestWallet::default();
        wallet.statuses.lock().expect("status lock").extend([
            Ok(PaymentStatus::Unknown),
            Ok(PaymentStatus::Failed {
                reason: PaymentFailure::NoRoute,
            }),
        ]);
        let clock = FixedClock(UnixTimestamp::from_secs(101));
        let reconciler = PaymentReconciler::new(&ledger, &wallet, &clock);

        let unresolved =
            block_on(reconciler.reconcile(1, operation_budget(), &crate::NeverCancelled))
                .expect("first reconciliation");
        assert_eq!(unresolved.unresolved(), 1);
        assert!(unresolved.needs_retry());
        assert_eq!(
            ledger
                .load_payment_attempt(&PaymentHash::from_bytes([1; 32]))
                .expect("load attempt")
                .expect("attempt")
                .state(),
            DurablePaymentState::Reserved
        );

        let failed = block_on(reconciler.reconcile(1, operation_budget(), &crate::NeverCancelled))
            .expect("second reconciliation");
        assert_eq!(failed.failed(), 1);
        assert!(!failed.needs_retry());
    }

    #[test]
    fn batch_cap_reports_additional_work_without_querying_it() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger);
        reserve(&ledger, &connection, 1, 100);
        reserve(&ledger, &connection, 2, 101);
        let wallet = TestWallet::default();
        wallet
            .statuses
            .lock()
            .expect("status lock")
            .push_back(Ok(PaymentStatus::Succeeded {
                preimage: PaymentPreimage::from_bytes([9; 32]),
                amount: AmountSat::from_sat(500),
                fee: AmountSat::from_sat(10),
            }));
        let clock = FixedClock(UnixTimestamp::from_secs(102));

        let report = block_on(PaymentReconciler::new(&ledger, &wallet, &clock).reconcile(
            1,
            operation_budget(),
            &crate::NeverCancelled,
        ))
        .expect("reconcile batch");

        assert_eq!(report.examined(), 1);
        assert_eq!(wallet.status_calls.load(Ordering::SeqCst), 1);
        assert!(report.needs_retry());
        assert_eq!(
            ledger
                .load_payment_attempt(&PaymentHash::from_bytes([2; 32]))
                .expect("load second")
                .expect("second attempt")
                .state(),
            DurablePaymentState::Reserved
        );
    }

    #[test]
    fn invalid_batch_sizes_fail_before_wallet_access() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let wallet = TestWallet::default();
        let clock = FixedClock(UnixTimestamp::from_secs(100));
        let reconciler = PaymentReconciler::new(&ledger, &wallet, &clock);

        assert_eq!(
            block_on(reconciler.reconcile(0, operation_budget(), &crate::NeverCancelled)),
            Err(PaymentReconciliationError::InvalidBatchSize)
        );
        assert_eq!(
            block_on(reconciler.reconcile(
                MAX_PAYMENT_RECONCILIATION_BATCH + 1,
                operation_budget(),
                &crate::NeverCancelled,
            )),
            Err(PaymentReconciliationError::InvalidBatchSize)
        );
        assert_eq!(wallet.status_calls.load(Ordering::SeqCst), 0);
    }

    struct AlwaysCancelled;

    impl CancellationSignal for AlwaysCancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }

    #[test]
    fn cancellation_leaves_durable_work_for_another_pass() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger);
        reserve(&ledger, &connection, 1, 100);
        let wallet = TestWallet::default();
        let clock = FixedClock(UnixTimestamp::from_secs(101));

        let report = block_on(PaymentReconciler::new(&ledger, &wallet, &clock).reconcile(
            1,
            operation_budget(),
            &AlwaysCancelled,
        ))
        .expect("cancelled report");

        assert_eq!(report.examined(), 0);
        assert!(report.interrupted());
        assert!(report.needs_retry());
        assert_eq!(wallet.status_calls.load(Ordering::SeqCst), 0);
    }

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
