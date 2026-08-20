use std::fmt;
use std::time::Duration;

use crate::time::OperationDeadline;
use crate::{
    CancellationSignal, Clock, HostError, HostErrorKind, HostFuture, OperationBudget,
    OperationContext, SecureWakeServerUrl, WakeLedger, WakeRegistrationChange,
    WakeRegistrationError,
};

const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(5);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(60 * 60);

/// Applies typed, durable wake-registration changes to a configured provider.
///
/// Implementations must use HTTPS, reject redirects, omit secrets and raw
/// server errors from returned values, and make the connection id/revision/state
/// tuple idempotent. Providers must reject revisions older than the greatest
/// revision already observed for that connection.
pub trait WakeRegistrationTransport: Send + Sync {
    /// Applies one exact desired state within the supplied native deadline.
    fn apply<'a>(
        &'a self,
        server_url: &'a SecureWakeServerUrl,
        change: &'a WakeRegistrationChange,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<(), HostError>>;
}

/// A stable failure that prevents a registration worker pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WakeRegistrationWorkerError {
    /// Durable outbox state could not be read or updated safely.
    Outbox(WakeRegistrationError),
}

impl fmt::Display for WakeRegistrationWorkerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("wake registration worker could not update its durable outbox")
    }
}

impl std::error::Error for WakeRegistrationWorkerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Outbox(error) => Some(error),
        }
    }
}

impl From<WakeRegistrationError> for WakeRegistrationWorkerError {
    fn from(error: WakeRegistrationError) -> Self {
        Self::Outbox(error)
    }
}

/// Non-sensitive aggregate results for one bounded registration worker pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WakeRegistrationWorkerReport {
    examined: usize,
    applied: usize,
    deferred: usize,
    superseded: usize,
    interrupted: bool,
    needs_retry: bool,
}

impl WakeRegistrationWorkerReport {
    /// Returns the number of provider calls made.
    #[must_use]
    pub const fn examined(self) -> usize {
        self.examined
    }

    /// Returns the number of provider changes applied and acknowledged.
    #[must_use]
    pub const fn applied(self) -> usize {
        self.applied
    }

    /// Returns the number of provider failures durably deferred.
    #[must_use]
    pub const fn deferred(self) -> usize {
        self.deferred
    }

    /// Returns changes replaced by a newer revision while I/O was in flight.
    #[must_use]
    pub const fn superseded(self) -> usize {
        self.superseded
    }

    /// Returns whether cancellation or the operation deadline stopped the pass.
    #[must_use]
    pub const fn interrupted(self) -> bool {
        self.interrupted
    }

    /// Returns whether native code should schedule another outbox pass.
    #[must_use]
    pub const fn needs_retry(self) -> bool {
        self.needs_retry
    }
}

/// Runs the durable registration outbox inside foreground or background work.
pub struct WakeRegistrationWorker<'a> {
    ledger: &'a WakeLedger,
    transport: &'a dyn WakeRegistrationTransport,
    server_url: &'a SecureWakeServerUrl,
    clock: &'a dyn Clock,
}

impl<'a> WakeRegistrationWorker<'a> {
    /// Creates a worker over one shared ledger and native transport.
    #[must_use]
    pub const fn new(
        ledger: &'a WakeLedger,
        transport: &'a dyn WakeRegistrationTransport,
        server_url: &'a SecureWakeServerUrl,
        clock: &'a dyn Clock,
    ) -> Self {
        Self {
            ledger,
            transport,
            server_url,
            clock,
        }
    }

    /// Applies a bounded due batch while preserving time for native cleanup.
    ///
    /// Every provider failure, including a permanent-looking rejection, remains
    /// durable until the provider acknowledges the desired state or the host
    /// performs a separate explicit abandonment action.
    pub async fn run(
        &self,
        maximum_rows: usize,
        budget: OperationBudget,
        cancellation: &dyn CancellationSignal,
    ) -> Result<WakeRegistrationWorkerReport, WakeRegistrationWorkerError> {
        let changes = self
            .ledger
            .load_due_wake_registrations(self.clock.now(), maximum_rows)?;
        let selected = changes.len();
        let deadline = OperationDeadline::new(budget);
        let mut report = WakeRegistrationWorkerReport::default();

        for change in changes {
            let Some(context) = deadline.context(cancellation) else {
                report.interrupted = true;
                break;
            };
            report.examined += 1;
            match self
                .transport
                .apply(self.server_url, &change, context)
                .await
            {
                Ok(()) => match self.ledger.acknowledge_wake_registration(&change) {
                    Ok(()) => report.applied += 1,
                    Err(WakeRegistrationError::StaleChange) => report.superseded += 1,
                    Err(error) => return Err(error.into()),
                },
                Err(error) => {
                    match self.ledger.retry_wake_registration(
                        &change,
                        self.clock.now(),
                        retry_delay(change.attempt_count()),
                    ) {
                        Ok(()) => report.deferred += 1,
                        Err(WakeRegistrationError::StaleChange) => report.superseded += 1,
                        Err(error) => return Err(error.into()),
                    }
                    if error.kind() == HostErrorKind::Cancelled {
                        report.interrupted = true;
                        break;
                    }
                }
            }
        }

        report.needs_retry = report.interrupted
            || report.deferred != 0
            || report.superseded != 0
            || selected == maximum_rows;
        Ok(report)
    }
}

fn retry_delay(attempt_count: u32) -> Duration {
    let exponent = attempt_count.min(16);
    let seconds = INITIAL_RETRY_DELAY
        .as_secs()
        .checked_shl(exponent)
        .unwrap_or(u64::MAX)
        .min(MAX_RETRY_DELAY.as_secs());
    Duration::from_secs(seconds)
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
        BudgetInterval, BudgetPolicy, ConnectionId, ConnectionPolicy, ConnectionRevision,
        FeePolicy, NeverCancelled, NewConnection, NwcEncryption, NwcMethod, PublicKey,
        SecureRelayUrl, UnixTimestamp, WakePolicy,
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
                "nwc-mobile-registration-worker-{}-{suffix}",
                std::process::id()
            ));
            fs::create_dir(&directory).expect("create test directory");
            let path = directory.join("worker.sqlite3");
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
    struct TestTransport {
        results: Mutex<VecDeque<Result<(), HostError>>>,
        calls: AtomicUsize,
    }

    impl WakeRegistrationTransport for TestTransport {
        fn apply<'a>(
            &'a self,
            _server_url: &'a SecureWakeServerUrl,
            _change: &'a WakeRegistrationChange,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<(), HostError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let result = self
                .results
                .lock()
                .expect("results lock")
                .pop_front()
                .unwrap_or(Ok(()));
            Box::pin(async move { result })
        }
    }

    fn insert_connection(ledger: &WakeLedger) -> crate::ActiveConnection {
        ledger
            .insert_connection(
                NewConnection::new(
                    ConnectionId::parse("connection:worker-test").expect("connection id"),
                    PublicKey::from_hex(CLIENT).expect("client key"),
                    PublicKey::from_hex(WALLET).expect("wallet key"),
                    vec![SecureRelayUrl::parse("wss://relay.example.com").expect("relay")],
                    ConnectionPolicy::new(
                        [NwcMethod::GetInfo],
                        BudgetPolicy::new(
                            0,
                            BudgetInterval::Never,
                            FeePolicy::ExcludeForCompatibility,
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

    fn operation_budget() -> OperationBudget {
        OperationBudget::new(Duration::from_secs(5)).expect("operation budget")
    }

    fn server_url() -> SecureWakeServerUrl {
        SecureWakeServerUrl::parse("https://wake.example.com/v1/register").expect("server URL")
    }

    #[test]
    fn successful_provider_apply_acknowledges_durable_change() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let transport = TestTransport::default();
        let server_url = server_url();
        let clock = FixedClock(UnixTimestamp::from_secs(100));

        let report = block_on(
            WakeRegistrationWorker::new(&ledger, &transport, &server_url, &clock).run(
                10,
                operation_budget(),
                &NeverCancelled,
            ),
        )
        .expect("worker pass");

        assert_eq!(report.examined(), 1);
        assert_eq!(report.applied(), 1);
        assert!(!report.needs_retry());
        assert!(ledger
            .load_due_wake_registrations(UnixTimestamp::from_secs(100), 1)
            .expect("empty outbox")
            .is_empty());
    }

    #[test]
    fn provider_failure_is_durably_deferred_with_bounded_backoff() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let transport = TestTransport::default();
        let server_url = server_url();
        transport
            .results
            .lock()
            .expect("results lock")
            .push_back(Err(HostError::new(HostErrorKind::Rejected)));
        let clock = FixedClock(UnixTimestamp::from_secs(100));

        let report = block_on(
            WakeRegistrationWorker::new(&ledger, &transport, &server_url, &clock).run(
                1,
                operation_budget(),
                &NeverCancelled,
            ),
        )
        .expect("worker pass");

        assert_eq!(report.deferred(), 1);
        assert!(report.needs_retry());
        assert!(ledger
            .load_due_wake_registrations(UnixTimestamp::from_secs(104), 1)
            .expect("not due")
            .is_empty());
        let due = ledger
            .load_due_wake_registrations(UnixTimestamp::from_secs(105), 1)
            .expect("due retry")
            .pop()
            .expect("change");
        assert_eq!(due.attempt_count(), 1);
    }

    struct AlwaysCancelled;

    impl CancellationSignal for AlwaysCancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }

    #[test]
    fn cancellation_stops_before_provider_io_and_keeps_outbox_durable() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        insert_connection(&ledger);
        let transport = TestTransport::default();
        let server_url = server_url();
        let clock = FixedClock(UnixTimestamp::from_secs(100));

        let report = block_on(
            WakeRegistrationWorker::new(&ledger, &transport, &server_url, &clock).run(
                1,
                operation_budget(),
                &AlwaysCancelled,
            ),
        )
        .expect("worker pass");

        assert!(report.interrupted());
        assert!(report.needs_retry());
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            ledger
                .load_due_wake_registrations(UnixTimestamp::from_secs(100), 1)
                .expect("durable outbox")
                .len(),
            1
        );
    }

    #[test]
    fn retry_delay_is_exponential_and_hard_capped() {
        assert_eq!(retry_delay(0), Duration::from_secs(5));
        assert_eq!(retry_delay(1), Duration::from_secs(10));
        assert_eq!(retry_delay(10), MAX_RETRY_DELAY);
        assert_eq!(retry_delay(u32::MAX), MAX_RETRY_DELAY);
    }

    struct SupersedingTransport<'a> {
        ledger: &'a WakeLedger,
        connection: crate::ActiveConnection,
    }

    impl WakeRegistrationTransport for SupersedingTransport<'_> {
        fn apply<'a>(
            &'a self,
            _server_url: &'a SecureWakeServerUrl,
            _change: &'a WakeRegistrationChange,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<(), HostError>> {
            self.ledger
                .tombstone_connection(
                    self.connection.id(),
                    self.connection.revision(),
                    UnixTimestamp::from_secs(101),
                )
                .expect("supersede enable with disable");
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn in_flight_enable_cannot_acknowledge_newer_disable() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger);
        let transport = SupersedingTransport {
            ledger: &ledger,
            connection,
        };
        let server_url = server_url();
        let clock = FixedClock(UnixTimestamp::from_secs(100));

        let report = block_on(
            WakeRegistrationWorker::new(&ledger, &transport, &server_url, &clock).run(
                1,
                operation_budget(),
                &NeverCancelled,
            ),
        )
        .expect("worker pass");

        assert_eq!(report.applied(), 0);
        assert_eq!(report.superseded(), 1);
        assert!(report.needs_retry());
        let disable = ledger
            .load_due_wake_registrations(UnixTimestamp::from_secs(101), 1)
            .expect("newer outbox change")
            .pop()
            .expect("disable");
        assert!(!disable.enabled());
        assert_eq!(
            disable.connection_revision(),
            ConnectionRevision::from_value(1)
        );
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
