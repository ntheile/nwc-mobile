//! Owned, batteries-included NWC runtime for native mobile applications.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use nwc_mobile::{
    CancellationSignal, EventId, HostError, HostFuture, InvoiceNotificationError,
    InvoiceNotificationWorkerReport, InvoiceSettlementMonitor, LedgerError, LightningNode,
    MobileServiceError, NotificationHint, NwcApplicationManager, OperationBudget, OperationContext,
    PublicKey, QueueReason, RejectionCode, RelayTransport, RetryReason, SecretProvider,
    WakeDiagnosticSink, WakeDisposition, WakeInput, WakeLedger, WakePolicy, WalletInfo,
};

use crate::{
    run_on_native_runtime, run_with_context, BackgroundWakeWindow, NwcNode, NwcNodeConfig,
    DEFAULT_INVOICE_SETTLEMENT_POLL_INTERVAL,
};

/// Default time retained for a post-wake completion hook.
pub const DEFAULT_NWC_MOBILE_COMPLETION_RESERVE: Duration = Duration::from_secs(5);

/// Default delay before retrying incomplete invoice-settlement work.
pub const DEFAULT_NWC_MOBILE_SETTLEMENT_RETRY_DELAY: Duration = Duration::from_secs(5);

/// Why the native host opened `NwcMobile` for this wake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NwcMobileWakeKind {
    /// Select settlement processing only when the exact wake matches a tracked invoice.
    Automatic,
    /// Execute an ordinary NIP-47 request.
    Request,
    /// Reconcile the exact invoice created by the original request.
    InvoiceSettlement,
}

impl NwcMobileWakeKind {
    /// Converts a trusted native settlement marker into the corresponding wake kind.
    #[must_use]
    pub const fn from_settlement_check(settlement_check: bool) -> Self {
        if settlement_check {
            Self::InvoiceSettlement
        } else {
            Self::Request
        }
    }
}

/// Safe settlement-notification state after one mobile wake.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum NwcMobileSettlementStatus {
    /// The request did not create a tracked invoice.
    #[default]
    NotTracked,
    /// The invoice is still pending or its notification has not reached every relay.
    Pending,
    /// The settlement notification reached every approved relay.
    Delivered,
}

/// Non-secret result of one `NwcMobile` background execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NwcMobileWakeResult {
    disposition: WakeDisposition,
    settlement_status: NwcMobileSettlementStatus,
}

impl NwcMobileWakeResult {
    /// Returns the engine's platform-neutral outcome.
    #[must_use]
    pub const fn disposition(self) -> WakeDisposition {
        self.disposition
    }

    /// Returns settlement state safe for native notification presentation.
    #[must_use]
    pub const fn settlement_status(self) -> NwcMobileSettlementStatus {
        self.settlement_status
    }
}

/// Typed context supplied when a wallet implementation is opened on cold start.
#[derive(Clone)]
pub struct LightningNodeRequest {
    wallet_service_pubkey: PublicKey,
    diagnostics: Option<Arc<dyn WakeDiagnosticSink>>,
}

impl LightningNodeRequest {
    /// Returns the public key of the wallet service selected by the wake envelope.
    #[must_use]
    pub const fn wallet_service_pubkey(&self) -> &PublicKey {
        &self.wallet_service_pubkey
    }

    /// Returns the optional bounded diagnostic sink shared with the NWC engine.
    #[must_use]
    pub fn diagnostics(&self) -> Option<Arc<dyn WakeDiagnosticSink>> {
        self.diagnostics.clone()
    }
}

/// One opened Lightning node and its advertised NIP-47 capabilities.
pub struct OpenedLightningNode {
    node: Arc<dyn LightningNode>,
    wallet_info: WalletInfo,
}

impl OpenedLightningNode {
    /// Wraps a wallet-specific Lightning node for use by `NwcMobile`.
    #[must_use]
    pub fn new<N>(node: N, wallet_info: WalletInfo) -> Self
    where
        N: LightningNode + 'static,
    {
        Self {
            node: Arc::new(node),
            wallet_info,
        }
    }

    fn into_parts(self) -> (Arc<dyn LightningNode>, WalletInfo) {
        (self.node, self.wallet_info)
    }
}

/// Opens the application-specific Lightning node when a background process starts cold.
///
/// Implementations normally load protected wallet credentials and open the existing wallet.
/// `NwcMobile` applies the supplied deadline and cancellation context to the entire operation.
pub trait LightningNodeProvider: Send + Sync {
    /// Opens one node for the selected wallet-service identity.
    fn open_node<'a>(
        &'a self,
        request: LightningNodeRequest,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<OpenedLightningNode, HostError>>;
}

/// Adapts an already-open wallet to the provider contract without host boilerplate.
pub struct ReadyLightningNodeProvider<F> {
    open: F,
}

impl<F> ReadyLightningNodeProvider<F> {
    /// Creates a provider from a synchronous factory over the typed wake request.
    #[must_use]
    pub const fn new(open: F) -> Self {
        Self { open }
    }
}

impl<F> LightningNodeProvider for ReadyLightningNodeProvider<F>
where
    F: Fn(LightningNodeRequest) -> Result<OpenedLightningNode, HostError> + Send + Sync,
{
    fn open_node<'a>(
        &'a self,
        request: LightningNodeRequest,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<OpenedLightningNode, HostError>> {
        if context.cancellation().is_cancelled() {
            return Box::pin(async { Err(HostError::new(nwc_mobile::HostErrorKind::Cancelled)) });
        }
        let opened = (self.open)(request);
        Box::pin(async move { opened })
    }
}

/// Context for optional application-specific work after NWC execution completes.
#[derive(Clone, Copy)]
pub struct NwcMobileCompletionContext<'a> {
    ledger: &'a WakeLedger,
    request_event_id: &'a EventId,
    operation: OperationContext<'a>,
}

impl<'a> NwcMobileCompletionContext<'a> {
    /// Returns the authoritative ledger containing any new settlement monitor state.
    #[must_use]
    pub const fn ledger(self) -> &'a WakeLedger {
        self.ledger
    }

    /// Returns the exact request event handled by this wake.
    #[must_use]
    pub const fn request_event_id(self) -> &'a EventId {
        self.request_event_id
    }

    /// Returns the remaining deadline and cancellation state.
    #[must_use]
    pub const fn operation(self) -> OperationContext<'a> {
        self.operation
    }
}

/// Optional application hook for bounded work after the shared NWC flow completes.
pub trait NwcMobileCompletionHandler: Send + Sync {
    /// Completes application-specific work, such as synchronizing a wake server monitor.
    fn complete<'a>(
        &'a self,
        context: NwcMobileCompletionContext<'a>,
    ) -> HostFuture<'a, Result<(), HostError>>;
}

/// Complete configuration for one owned `NwcMobile` runtime.
pub struct NwcMobileConfig {
    data_directory: PathBuf,
    node_provider: Arc<dyn LightningNodeProvider>,
    relays: Arc<dyn RelayTransport>,
    secrets: Arc<dyn SecretProvider>,
    diagnostics: Option<Arc<dyn WakeDiagnosticSink>>,
    completion_handler: Option<Arc<dyn NwcMobileCompletionHandler>>,
    completion_reserve: Duration,
    wake_policy: WakePolicy,
    invoice_settlement_poll_interval: Duration,
}

impl NwcMobileConfig {
    /// Creates a runtime configuration from the four capabilities every wallet supplies.
    #[must_use]
    pub fn new<P, R, S>(
        data_directory: impl AsRef<Path>,
        node_provider: P,
        relays: R,
        secrets: S,
    ) -> Self
    where
        P: LightningNodeProvider + 'static,
        R: RelayTransport + 'static,
        S: SecretProvider + 'static,
    {
        Self {
            data_directory: data_directory.as_ref().to_path_buf(),
            node_provider: Arc::new(node_provider),
            relays: Arc::new(relays),
            secrets: Arc::new(secrets),
            diagnostics: None,
            completion_handler: None,
            completion_reserve: DEFAULT_NWC_MOBILE_COMPLETION_RESERVE,
            wake_policy: WakePolicy::default(),
            invoice_settlement_poll_interval: DEFAULT_INVOICE_SETTLEMENT_POLL_INTERVAL,
        }
    }

    /// Shares one bounded, non-secret diagnostic sink with the provider and engine.
    #[must_use]
    pub fn with_diagnostics(mut self, diagnostics: Arc<dyn WakeDiagnosticSink>) -> Self {
        self.diagnostics = Some(diagnostics);
        self
    }

    /// Adds bounded application-specific completion work.
    #[must_use]
    pub fn with_completion_handler<H>(mut self, handler: H, reserve: Duration) -> Self
    where
        H: NwcMobileCompletionHandler + 'static,
    {
        self.completion_handler = Some(Arc::new(handler));
        self.completion_reserve = reserve;
        self
    }

    /// Replaces the wake-validation policy.
    #[must_use]
    pub const fn with_wake_policy(mut self, wake_policy: WakePolicy) -> Self {
        self.wake_policy = wake_policy;
        self
    }

    /// Replaces the interval used while waiting for an invoice to settle.
    #[must_use]
    pub const fn with_invoice_settlement_poll_interval(mut self, interval: Duration) -> Self {
        self.invoice_settlement_poll_interval = interval;
        self
    }
}

/// Owned, batteries-included NWC interface for native mobile applications.
///
/// `NwcMobile` opens the shared ledger, cold-starts the application's Lightning node, enforces
/// background deadlines, validates settlement wakes, executes NIP-47 requests, reconciles
/// notifications, and runs an optional bounded completion hook. Native iOS and Android entry
/// points only need to validate their platform envelope and call [`Self::execute_wake`].
pub struct NwcMobile {
    manager: NwcApplicationManager,
    node_provider: Arc<dyn LightningNodeProvider>,
    relays: Arc<dyn RelayTransport>,
    secrets: Arc<dyn SecretProvider>,
    diagnostics: Option<Arc<dyn WakeDiagnosticSink>>,
    completion_handler: Option<Arc<dyn NwcMobileCompletionHandler>>,
    completion_reserve: Duration,
    wake_policy: WakePolicy,
    invoice_settlement_poll_interval: Duration,
}

impl NwcMobile {
    /// Opens the shared application ledger and takes ownership of all runtime capabilities.
    pub fn open(config: NwcMobileConfig) -> Result<Self, MobileServiceError> {
        let manager = NwcApplicationManager::open(&config.data_directory)?;
        Ok(Self {
            manager,
            node_provider: config.node_provider,
            relays: config.relays,
            secrets: config.secrets,
            diagnostics: config.diagnostics,
            completion_handler: config.completion_handler,
            completion_reserve: config.completion_reserve,
            wake_policy: config.wake_policy,
            invoice_settlement_poll_interval: config.invoice_settlement_poll_interval,
        })
    }

    /// Returns the application manager for foreground connection and registration workflows.
    #[must_use]
    pub const fn application_manager(&self) -> &NwcApplicationManager {
        &self.manager
    }

    /// Returns mutable access for serialized foreground NWA and registration coordination.
    #[must_use]
    pub const fn application_manager_mut(&mut self) -> &mut NwcApplicationManager {
        &mut self.manager
    }

    /// Opens and executes one wake on the shared native Tokio runtime.
    ///
    /// This is the preferred entry point for Swift, Kotlin, and other hosts whose async executor
    /// is not Tokio. Runtime startup, ledger-open failures, and task failures are converted into
    /// stable application handoffs.
    pub async fn execute_native_wake<C>(
        config: NwcMobileConfig,
        input: WakeInput,
        kind: NwcMobileWakeKind,
        execution_time: Duration,
        cancellation: Arc<C>,
    ) -> NwcMobileWakeResult
    where
        C: CancellationSignal + 'static,
    {
        let operation = async move {
            let mobile = match Self::open(config) {
                Ok(mobile) => mobile,
                Err(_) => return queued_result(QueueReason::LedgerBusy, None),
            };
            mobile
                .execute_wake(input, kind, execution_time, cancellation.as_ref())
                .await
        };
        run_on_native_runtime(operation)
            .await
            .unwrap_or_else(|_| queued_result(QueueReason::WalletUnavailable, None))
    }

    /// Executes one native wake inside a single hard operating-system deadline.
    pub async fn execute_wake(
        &self,
        input: WakeInput,
        kind: NwcMobileWakeKind,
        execution_time: Duration,
        cancellation: &dyn CancellationSignal,
    ) -> NwcMobileWakeResult {
        if execution_time.is_zero() || cancellation.is_cancelled() {
            return queued_result(QueueReason::Deadline, None);
        }
        let window = BackgroundWakeWindow {
            started_at: std::time::Instant::now(),
            total: execution_time,
        };
        match tokio::time::timeout(
            execution_time,
            self.handle_wake(input, kind, window, cancellation),
        )
        .await
        {
            Ok(result) if !cancellation.is_cancelled() => result,
            Ok(_) | Err(_) => queued_result(QueueReason::Deadline, None),
        }
    }

    /// Executes one request inside an existing shared background window.
    ///
    /// Most applications should call [`Self::execute_wake`]. This lower-level method is useful
    /// when several application operations already share one externally bounded window.
    pub async fn handle_wake(
        &self,
        input: WakeInput,
        kind: NwcMobileWakeKind,
        window: BackgroundWakeWindow,
        cancellation: &dyn CancellationSignal,
    ) -> NwcMobileWakeResult {
        let event_id = input.event_id().clone();
        let initial_monitor = match self.invoice_monitor(&event_id) {
            Ok(monitor) => monitor,
            Err(_) => return queued_result(QueueReason::LedgerBusy, None),
        };
        let initial_settlement_status = settlement_status(initial_monitor.as_ref());
        let settlement_matches = settlement_wake_matches(initial_monitor.as_ref(), &input);
        let kind = match kind {
            NwcMobileWakeKind::Automatic if settlement_matches => {
                ResolvedWakeKind::InvoiceSettlement
            }
            NwcMobileWakeKind::Automatic | NwcMobileWakeKind::Request => ResolvedWakeKind::Request,
            NwcMobileWakeKind::InvoiceSettlement if settlement_matches => {
                ResolvedWakeKind::InvoiceSettlement
            }
            NwcMobileWakeKind::InvoiceSettlement => {
                return result(
                    WakeDisposition::rejected(RejectionCode::InvalidWakePayload),
                    NwcMobileSettlementStatus::NotTracked,
                )
            }
        };

        let Some(open_budget) = self.engine_budget(window) else {
            return queued_result(QueueReason::Deadline, initial_monitor.as_ref());
        };
        let open_context = OperationContext::new(open_budget, cancellation);
        let request = LightningNodeRequest {
            wallet_service_pubkey: input.wallet_service_pubkey().clone(),
            diagnostics: self.diagnostics.clone(),
        };
        let opened = match run_with_context(
            open_context,
            self.node_provider.open_node(request, open_context),
        )
        .await
        {
            Ok(opened) => opened,
            Err(_) => {
                return result(
                    WakeDisposition::queued(QueueReason::WalletUnavailable),
                    initial_settlement_status,
                )
            }
        };
        let Some(operation_budget) = self.engine_budget(window) else {
            return queued_result(QueueReason::Deadline, initial_monitor.as_ref());
        };
        let (lightning_node, wallet_info) = opened.into_parts();
        let node_config = NwcNodeConfig::new(
            lightning_node,
            self.manager.service().ledger(),
            self.relays.as_ref(),
            self.secrets.as_ref(),
            wallet_info,
        )
        .with_wake_policy(self.wake_policy)
        .with_invoice_settlement_poll_interval(self.invoice_settlement_poll_interval);
        let node = NwcNode::new(node_config);
        let disposition = match (kind, self.diagnostics.as_deref()) {
            (ResolvedWakeKind::Request, Some(diagnostics)) => {
                node.with_diagnostics(diagnostics)
                    .handle_wake(input, operation_budget, cancellation)
                    .await
            }
            (ResolvedWakeKind::Request, None) => {
                node.handle_wake(input, operation_budget, cancellation)
                    .await
            }
            (ResolvedWakeKind::InvoiceSettlement, _) => {
                let report = node
                    .handle_settlement_wake(&event_id, operation_budget, cancellation)
                    .await;
                settlement_disposition(report)
            }
        };

        let monitor = match self.invoice_monitor(&event_id) {
            Ok(monitor) => monitor,
            Err(_) => {
                return result(
                    WakeDisposition::queued(QueueReason::LedgerBusy),
                    initial_settlement_status,
                )
            }
        };
        let settlement_status = settlement_status(monitor.as_ref());
        let disposition = if kind == ResolvedWakeKind::InvoiceSettlement
            && settlement_status == NwcMobileSettlementStatus::Delivered
        {
            WakeDisposition::Completed {
                notification: NotificationHint::Completed,
            }
        } else {
            disposition
        };

        if monitor.is_some() {
            self.run_completion_handler(window, &event_id, cancellation)
                .await;
        }
        result(disposition, settlement_status)
    }

    fn invoice_monitor(
        &self,
        event_id: &EventId,
    ) -> Result<Option<InvoiceSettlementMonitor>, LedgerError> {
        self.manager
            .service()
            .ledger()
            .nwc_invoice_monitor(event_id)
    }

    fn engine_budget(&self, window: BackgroundWakeWindow) -> Option<OperationBudget> {
        let reserve = if self.completion_handler.is_some() {
            self.completion_reserve
        } else {
            Duration::ZERO
        };
        OperationBudget::new(window.remaining().saturating_sub(reserve)).ok()
    }

    async fn run_completion_handler(
        &self,
        window: BackgroundWakeWindow,
        event_id: &EventId,
        cancellation: &dyn CancellationSignal,
    ) {
        let Some(handler) = self.completion_handler.as_ref() else {
            return;
        };
        let Ok(budget) = OperationBudget::new(window.remaining()) else {
            return;
        };
        let operation = OperationContext::new(budget, cancellation);
        let context = NwcMobileCompletionContext {
            ledger: self.manager.service().ledger(),
            request_event_id: event_id,
            operation,
        };
        let _ = run_with_context(operation, handler.complete(context)).await;
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ResolvedWakeKind {
    Request,
    InvoiceSettlement,
}

fn settlement_wake_matches(monitor: Option<&InvoiceSettlementMonitor>, input: &WakeInput) -> bool {
    monitor.is_some_and(|monitor| {
        monitor.wallet_service_pubkey() == input.wallet_service_pubkey()
            && monitor
                .relays()
                .iter()
                .any(|relay| relay.as_str() == input.relay())
    })
}

const fn result(
    disposition: WakeDisposition,
    settlement_status: NwcMobileSettlementStatus,
) -> NwcMobileWakeResult {
    NwcMobileWakeResult {
        disposition,
        settlement_status,
    }
}

fn queued_result(
    reason: QueueReason,
    monitor: Option<&InvoiceSettlementMonitor>,
) -> NwcMobileWakeResult {
    result(WakeDisposition::queued(reason), settlement_status(monitor))
}

fn settlement_status(monitor: Option<&InvoiceSettlementMonitor>) -> NwcMobileSettlementStatus {
    monitor.map_or(NwcMobileSettlementStatus::NotTracked, |monitor| {
        if monitor.completed() {
            NwcMobileSettlementStatus::Delivered
        } else {
            NwcMobileSettlementStatus::Pending
        }
    })
}

fn settlement_disposition(
    report: Result<InvoiceNotificationWorkerReport, InvoiceNotificationError>,
) -> WakeDisposition {
    match report {
        Ok(report) if report.has_pending_work() => WakeDisposition::RetryAfter {
            delay: DEFAULT_NWC_MOBILE_SETTLEMENT_RETRY_DELAY,
            reason: RetryReason::WalletUnavailable,
            notification: NotificationHint::Processing,
        },
        Ok(_) => WakeDisposition::Completed {
            notification: NotificationHint::Processing,
        },
        Err(InvoiceNotificationError::Ledger) => WakeDisposition::queued(QueueReason::LedgerBusy),
        Err(InvoiceNotificationError::Secret) => {
            WakeDisposition::queued(QueueReason::SecureStorageUnavailable)
        }
        Err(_) => WakeDisposition::RetryAfter {
            delay: DEFAULT_NWC_MOBILE_SETTLEMENT_RETRY_DELAY,
            reason: RetryReason::WalletUnavailable,
            notification: NotificationHint::Processing,
        },
    }
}

fn _assert_runtime_traits() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<NwcMobile>();
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use nwc_mobile::{
        ConnectionId, HostErrorKind, NeverCancelled, NwcSecretKey, SecureRelayUrl, UnixTimestamp,
    };

    use super::*;

    struct UnexpectedProvider(Arc<AtomicUsize>);

    impl LightningNodeProvider for UnexpectedProvider {
        fn open_node<'a>(
            &'a self,
            _request: LightningNodeRequest,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<OpenedLightningNode, HostError>> {
            self.0.fetch_add(1, Ordering::AcqRel);
            Box::pin(async { Err(HostError::new(HostErrorKind::Internal)) })
        }
    }

    struct UnusedRelay;

    impl RelayTransport for UnusedRelay {
        fn fetch_event<'a>(
            &'a self,
            _relay: &'a SecureRelayUrl,
            _event_id: &'a EventId,
            _maximum_event_bytes: usize,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<Option<String>, HostError>> {
            Box::pin(async { Err(HostError::new(HostErrorKind::Internal)) })
        }

        fn publish_event<'a>(
            &'a self,
            _relay: &'a SecureRelayUrl,
            _event_json: &'a str,
            _context: OperationContext<'a>,
        ) -> HostFuture<'a, Result<(), HostError>> {
            Box::pin(async { Err(HostError::new(HostErrorKind::Internal)) })
        }
    }

    struct UnusedSecrets;

    impl SecretProvider for UnusedSecrets {
        fn load_nwc_secret(
            &self,
            _connection_id: &ConnectionId,
        ) -> Result<NwcSecretKey, HostError> {
            Err(HostError::new(HostErrorKind::Internal))
        }
    }

    #[tokio::test]
    async fn untracked_settlement_wake_is_rejected_before_wallet_open() {
        let opens = Arc::new(AtomicUsize::new(0));
        let directory = temporary_directory("invalid-settlement");
        std::fs::create_dir_all(&directory).expect("temporary directory");
        let config = NwcMobileConfig::new(
            &directory,
            UnexpectedProvider(Arc::clone(&opens)),
            UnusedRelay,
            UnusedSecrets,
        );
        let mobile = NwcMobile::open(config).expect("mobile runtime");
        let input = WakeInput::new(
            "wss://relay.example.com".to_owned(),
            EventId::from_bytes([1; 32]),
            PublicKey::from_bytes([2; 32]),
            None,
            UnixTimestamp::from_secs(1),
        );
        let result = mobile
            .handle_wake(
                input,
                NwcMobileWakeKind::InvoiceSettlement,
                BackgroundWakeWindow {
                    started_at: std::time::Instant::now(),
                    total: Duration::from_secs(1),
                },
                &NeverCancelled,
            )
            .await;

        assert!(matches!(
            result.disposition(),
            WakeDisposition::Rejected {
                code: RejectionCode::InvalidWakePayload,
                ..
            }
        ));
        assert_eq!(opens.load(Ordering::Acquire), 0);
        std::fs::remove_dir_all(directory).expect("remove temporary directory");
    }

    #[tokio::test]
    async fn automatic_untracked_wake_uses_request_processing() {
        let opens = Arc::new(AtomicUsize::new(0));
        let directory = temporary_directory("automatic-request");
        std::fs::create_dir_all(&directory).expect("temporary directory");
        let config = NwcMobileConfig::new(
            &directory,
            UnexpectedProvider(Arc::clone(&opens)),
            UnusedRelay,
            UnusedSecrets,
        );
        let mobile = NwcMobile::open(config).expect("mobile runtime");
        let input = WakeInput::new(
            "wss://relay.example.com".to_owned(),
            EventId::from_bytes([3; 32]),
            PublicKey::from_bytes([4; 32]),
            None,
            UnixTimestamp::from_secs(1),
        );
        let result = mobile
            .handle_wake(
                input,
                NwcMobileWakeKind::Automatic,
                BackgroundWakeWindow {
                    started_at: std::time::Instant::now(),
                    total: Duration::from_secs(1),
                },
                &NeverCancelled,
            )
            .await;

        assert!(matches!(
            result.disposition(),
            WakeDisposition::QueuedForApplication {
                reason: QueueReason::WalletUnavailable,
                ..
            }
        ));
        assert_eq!(opens.load(Ordering::Acquire), 1);
        std::fs::remove_dir_all(directory).expect("remove temporary directory");
    }

    #[test]
    fn pending_settlement_report_requests_retry() {
        let disposition = settlement_disposition(Ok(InvoiceNotificationWorkerReport {
            inspected: 1,
            retryable: 1,
            ..InvoiceNotificationWorkerReport::default()
        }));

        assert!(matches!(
            disposition,
            WakeDisposition::RetryAfter {
                delay: DEFAULT_NWC_MOBILE_SETTLEMENT_RETRY_DELAY,
                reason: RetryReason::WalletUnavailable,
                ..
            }
        ));
    }

    fn temporary_directory(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "nwc-mobile-tokio-{label}-{}-{nonce}",
            std::process::id()
        ))
    }
}
