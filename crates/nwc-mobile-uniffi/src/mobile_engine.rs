//! Long-lived native engine facade and connection lifecycle.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path};
use std::sync::Arc;
use std::time::Duration;

use nwc_mobile::{
    BudgetInterval, BudgetPolicy, Clock, ConnectionId, ConnectionPolicy, FeePolicy, LedgerError,
    NewConnection, NwcEncryption, NwcMethod, OperationBudget, PaymentAccountingError,
    PaymentReconciler, PaymentReconciliationError, PublicKey, RegistryError, SecureRelayUrl,
    SecureWakeServerUrl, StoredConnection, SystemClock, UnixTimestamp, WakeEngine, WakeLedger,
    WakePolicy, WakeRegistrationError, WakeRegistrationWorker, WakeRegistrationWorkerError,
};

use crate::host_bridge::{MobileHostBridge, MobileWakeRegistrationBridge};
use crate::{
    MobileCancellation, MobileNwcMethod, MobileRelayTransport, MobileSecretProvider,
    MobileWakeDisposition, MobileWakeRegistrationTransport, MobileWalletBackend,
    ValidatedMobileWake,
};

const MAX_DATABASE_PATH_BYTES: usize = 4_096;

/// Stable native engine and connection-management failure classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Error)]
pub enum MobileEngineError {
    /// A caller supplied an empty, relative, oversized, or otherwise invalid value.
    InvalidArgument,
    /// The shared SQLite ledger or its containing directory is unavailable.
    DatabaseUnavailable,
    /// The ledger schema is newer than this version of the library.
    UnsupportedSchema,
    /// Durable state violated an engine invariant.
    CorruptData,
    /// A connection id or permanent key pair already exists.
    AlreadyExists,
    /// The requested connection does not exist.
    NotFound,
    /// The caller attempted to modify a stale connection revision.
    StaleRevision,
    /// The connection was already permanently revoked.
    AlreadyRevoked,
}

impl fmt::Display for MobileEngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "native engine argument is invalid",
            Self::DatabaseUnavailable => "native engine database is unavailable",
            Self::UnsupportedSchema => "native engine database schema is unsupported",
            Self::CorruptData => "native engine durable state is invalid",
            Self::AlreadyExists => "NWC connection already exists",
            Self::NotFound => "NWC connection was not found",
            Self::StaleRevision => "NWC connection revision is stale",
            Self::AlreadyRevoked => "NWC connection is already revoked",
        })
    }
}

impl std::error::Error for MobileEngineError {}

/// Fixed renewal interval for one connection's spending budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum MobileBudgetInterval {
    /// The budget never renews automatically.
    Never,
    /// Renew every hour.
    Hourly,
    /// Renew every day.
    Daily,
    /// Renew every seven days.
    Weekly,
    /// Renew every 30 days.
    Monthly,
    /// Renew every 365 days.
    Yearly,
}

impl From<MobileBudgetInterval> for BudgetInterval {
    fn from(interval: MobileBudgetInterval) -> Self {
        match interval {
            MobileBudgetInterval::Never => Self::Never,
            MobileBudgetInterval::Hourly => Self::Hourly,
            MobileBudgetInterval::Daily => Self::Daily,
            MobileBudgetInterval::Weekly => Self::Weekly,
            MobileBudgetInterval::Monthly => Self::Monthly,
            MobileBudgetInterval::Yearly => Self::Yearly,
        }
    }
}

/// Whether Lightning fees consume the connection's spending budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum MobileFeePolicy {
    /// Reserve and account for at most this fee for each payment.
    CountTowardBudget { maximum_fee_sat: u64 },
    /// Exclude fees for compatibility with a pre-existing wallet policy.
    ExcludeForCompatibility,
}

impl From<MobileFeePolicy> for FeePolicy {
    fn from(policy: MobileFeePolicy) -> Self {
        match policy {
            MobileFeePolicy::CountTowardBudget { maximum_fee_sat } => {
                Self::CountTowardBudget { maximum_fee_sat }
            }
            MobileFeePolicy::ExcludeForCompatibility => Self::ExcludeForCompatibility,
        }
    }
}

/// Authenticated encryption negotiated for a new NWC connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum MobileNwcEncryption {
    /// NIP-44 version 2 authenticated encryption.
    Nip44V2,
    /// Legacy NIP-04 compatibility mode.
    LegacyNip04,
}

impl From<MobileNwcEncryption> for NwcEncryption {
    fn from(encryption: MobileNwcEncryption) -> Self {
        match encryption {
            MobileNwcEncryption::Nip44V2 => Self::Nip44V2,
            MobileNwcEncryption::LegacyNip04 => Self::LegacyNip04,
        }
    }
}

/// Fully approved connection policy supplied by the containing application.
#[derive(Clone, Eq, PartialEq, uniffi::Record)]
pub struct MobileConnectionRequest {
    /// Stable wallet-local identifier; this is never reusable after revocation.
    pub connection_id: String,
    /// Approved NWC client's 32-byte hexadecimal public key.
    pub client_public_key_hex: String,
    /// Wallet service's 32-byte hexadecimal public key.
    pub wallet_service_public_key_hex: String,
    /// Exact secure WebSocket relay allowlist.
    pub relay_urls: Vec<String>,
    /// Exact methods approved by the user.
    pub methods: Vec<MobileNwcMethod>,
    /// Maximum principal and fee spend in one interval, in satoshis.
    pub budget_limit_sat: u64,
    /// Budget renewal interval.
    pub budget_interval: MobileBudgetInterval,
    /// Fee accounting behavior.
    pub fee_policy: MobileFeePolicy,
    /// Negotiated NWC encryption.
    pub encryption: MobileNwcEncryption,
    /// Optional Unix timestamp after which new work is rejected.
    pub expires_at: Option<u64>,
}

impl fmt::Debug for MobileConnectionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MobileConnectionRequest")
            .field("connection_id", &"[redacted]")
            .field("client_public_key_hex", &"[redacted]")
            .field("wallet_service_public_key_hex", &"[redacted]")
            .field("relay_count", &self.relay_urls.len())
            .field("methods", &self.methods)
            .field("budget_limit_sat", &self.budget_limit_sat)
            .field("budget_interval", &self.budget_interval)
            .field("fee_policy", &self.fee_policy)
            .field("encryption", &self.encryption)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Non-sensitive lifecycle state for a durable NWC connection.
#[derive(Clone, Eq, PartialEq, uniffi::Record)]
pub struct MobileConnectionState {
    /// Stable wallet-local connection identifier.
    pub connection_id: String,
    /// Monotonic revision used for compare-and-revoke operations.
    pub revision: u64,
    /// Whether this exact revision may authorize new requests.
    pub active: bool,
}

/// Non-sensitive aggregate result of one payment reconciliation pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, uniffi::Record)]
pub struct MobilePaymentReconciliationReport {
    /// Wallet payment-status queries performed.
    pub examined: u16,
    /// Payments observed as settled.
    pub succeeded: u16,
    /// Payments observed as definitively failed and refunded.
    pub failed: u16,
    /// Queried payments that remain pending or ambiguous.
    pub unresolved: u16,
    /// Wallet queries deferred after a stable host failure.
    pub deferred: u16,
    /// Whether cancellation or the deadline interrupted the pass.
    pub interrupted: bool,
    /// Whether native code should schedule another pass.
    pub needs_retry: bool,
}

/// Non-sensitive aggregate result of one wake-registration outbox pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, uniffi::Record)]
pub struct MobileWakeRegistrationReport {
    /// Provider calls performed.
    pub examined: u16,
    /// Changes applied and durably acknowledged.
    pub applied: u16,
    /// Provider failures durably deferred for retry.
    pub deferred: u16,
    /// Changes superseded by a newer revision while I/O was in flight.
    pub superseded: u16,
    /// Whether cancellation or the deadline interrupted the pass.
    pub interrupted: bool,
    /// Whether native code should schedule another pass.
    pub needs_retry: bool,
}

impl fmt::Debug for MobileConnectionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MobileConnectionState")
            .field("connection_id", &"[redacted]")
            .field("revision", &self.revision)
            .field("active", &self.active)
            .finish()
    }
}

/// Long-lived, cross-process NWC engine opened over one shared SQLite ledger.
#[derive(uniffi::Object)]
pub struct MobileNwcEngine {
    ledger: WakeLedger,
    wallet: Arc<dyn MobileWalletBackend>,
    relays: Arc<dyn MobileRelayTransport>,
    secrets: Arc<dyn MobileSecretProvider>,
    policy: WakePolicy,
}

#[uniffi::export]
impl MobileNwcEngine {
    /// Opens or creates a shared engine ledger at an absolute native path.
    #[uniffi::constructor]
    pub fn open(
        database_path: String,
        wallet: Arc<dyn MobileWalletBackend>,
        relays: Arc<dyn MobileRelayTransport>,
        secrets: Arc<dyn MobileSecretProvider>,
    ) -> Result<Arc<Self>, MobileEngineError> {
        validate_database_path(&database_path)?;
        let ledger = WakeLedger::open(&database_path).map_err(MobileEngineError::from)?;
        Ok(Arc::new(Self {
            ledger,
            wallet,
            relays,
            secrets,
            policy: WakePolicy::default(),
        }))
    }

    /// Persists one fully approved connection and queues wake registration.
    pub fn add_connection(
        &self,
        request: MobileConnectionRequest,
    ) -> Result<MobileConnectionState, MobileEngineError> {
        let connection = core_connection(request, self.policy)?;
        let active = self
            .ledger
            .insert_connection(connection, SystemClock.now())
            .map_err(MobileEngineError::from)?;
        Ok(MobileConnectionState {
            connection_id: active.id().as_str().to_owned(),
            revision: active.revision().value(),
            active: true,
        })
    }

    /// Loads lifecycle state without returning relay or public-key metadata.
    pub fn connection_state(
        &self,
        connection_id: String,
    ) -> Result<Option<MobileConnectionState>, MobileEngineError> {
        let connection_id =
            ConnectionId::parse(connection_id).map_err(|_| MobileEngineError::InvalidArgument)?;
        let connection = self
            .ledger
            .load_connection(&connection_id)
            .map_err(MobileEngineError::from)?;
        connection.map(mobile_connection_state).transpose()
    }

    /// Permanently revokes the expected active connection revision.
    pub fn revoke_connection(
        &self,
        connection_id: String,
        expected_revision: u64,
    ) -> Result<MobileConnectionState, MobileEngineError> {
        let connection_id =
            ConnectionId::parse(connection_id).map_err(|_| MobileEngineError::InvalidArgument)?;
        let tombstone = self
            .ledger
            .tombstone_connection(
                &connection_id,
                nwc_mobile::ConnectionRevision::from_value(expected_revision),
                SystemClock.now(),
            )
            .map_err(MobileEngineError::from)?;
        Ok(MobileConnectionState {
            connection_id: tombstone.id().as_str().to_owned(),
            revision: tombstone.revision().value(),
            active: false,
        })
    }

    /// Executes one validated wake within the native background budget.
    pub async fn execute_wake(
        &self,
        wake: Arc<ValidatedMobileWake>,
        execution_milliseconds: u64,
        cancellation: Arc<MobileCancellation>,
    ) -> Result<MobileWakeDisposition, MobileEngineError> {
        let budget = OperationBudget::new(Duration::from_millis(execution_milliseconds))
            .map_err(|_| MobileEngineError::InvalidArgument)?;
        let host = MobileHostBridge::new(
            self.wallet.clone(),
            self.relays.clone(),
            self.secrets.clone(),
            cancellation.clone(),
        );
        let clock = SystemClock;
        let engine = WakeEngine::new(&self.ledger, &host, &host, &host, &clock, self.policy);
        Ok(engine
            .execute(wake.core_input(), budget, cancellation.as_ref())
            .await
            .into())
    }

    /// Reconciles already-reserved payments without initiating new payments.
    pub async fn reconcile_payments(
        &self,
        maximum_attempts: u16,
        execution_milliseconds: u64,
        cancellation: Arc<MobileCancellation>,
    ) -> Result<MobilePaymentReconciliationReport, MobileEngineError> {
        let budget = operation_budget(execution_milliseconds)?;
        let host = MobileHostBridge::new(
            self.wallet.clone(),
            self.relays.clone(),
            self.secrets.clone(),
            cancellation.clone(),
        );
        let report = PaymentReconciler::new(&self.ledger, &host, &SystemClock)
            .reconcile(maximum_attempts, budget, cancellation.as_ref())
            .await
            .map_err(MobileEngineError::from)?;
        Ok(MobilePaymentReconciliationReport {
            examined: report.examined(),
            succeeded: report.succeeded(),
            failed: report.failed(),
            unresolved: report.unresolved(),
            deferred: report.deferred(),
            interrupted: report.interrupted(),
            needs_retry: report.needs_retry(),
        })
    }

    /// Applies a bounded batch of durable wake-provider registration changes.
    pub async fn process_wake_registrations(
        &self,
        server_url: String,
        maximum_changes: u16,
        execution_milliseconds: u64,
        transport: Arc<dyn MobileWakeRegistrationTransport>,
        cancellation: Arc<MobileCancellation>,
    ) -> Result<MobileWakeRegistrationReport, MobileEngineError> {
        let server_url = SecureWakeServerUrl::parse(&server_url)
            .map_err(|_| MobileEngineError::InvalidArgument)?;
        let budget = operation_budget(execution_milliseconds)?;
        let bridge = MobileWakeRegistrationBridge::new(transport, cancellation.clone());
        let report = WakeRegistrationWorker::new(&self.ledger, &bridge, &server_url, &SystemClock)
            .run(usize::from(maximum_changes), budget, cancellation.as_ref())
            .await
            .map_err(MobileEngineError::from)?;
        Ok(MobileWakeRegistrationReport {
            examined: u16::try_from(report.examined())
                .map_err(|_| MobileEngineError::CorruptData)?,
            applied: u16::try_from(report.applied()).map_err(|_| MobileEngineError::CorruptData)?,
            deferred: u16::try_from(report.deferred())
                .map_err(|_| MobileEngineError::CorruptData)?,
            superseded: u16::try_from(report.superseded())
                .map_err(|_| MobileEngineError::CorruptData)?,
            interrupted: report.interrupted(),
            needs_retry: report.needs_retry(),
        })
    }
}

fn operation_budget(execution_milliseconds: u64) -> Result<OperationBudget, MobileEngineError> {
    OperationBudget::new(Duration::from_millis(execution_milliseconds))
        .map_err(|_| MobileEngineError::InvalidArgument)
}

fn core_connection(
    request: MobileConnectionRequest,
    wake_policy: WakePolicy,
) -> Result<NewConnection, MobileEngineError> {
    let connection_id = ConnectionId::parse(request.connection_id)
        .map_err(|_| MobileEngineError::InvalidArgument)?;
    let client_public_key = PublicKey::from_hex(&request.client_public_key_hex)
        .map_err(|_| MobileEngineError::InvalidArgument)?;
    let wallet_service_public_key = PublicKey::from_hex(&request.wallet_service_public_key_hex)
        .map_err(|_| MobileEngineError::InvalidArgument)?;
    let relays = request
        .relay_urls
        .into_iter()
        .map(|relay| SecureRelayUrl::parse(&relay).map_err(|_| MobileEngineError::InvalidArgument))
        .collect::<Result<Vec<_>, _>>()?;
    let method_count = request.methods.len();
    let methods = request
        .methods
        .into_iter()
        .map(NwcMethod::from)
        .collect::<BTreeSet<_>>();
    if methods.is_empty() || methods.len() != method_count {
        return Err(MobileEngineError::InvalidArgument);
    }
    let policy = ConnectionPolicy::new(
        methods,
        BudgetPolicy::new(
            request.budget_limit_sat,
            request.budget_interval.into(),
            request.fee_policy.into(),
        ),
    );
    NewConnection::new(
        connection_id,
        client_public_key,
        wallet_service_public_key,
        relays,
        policy,
        request.encryption.into(),
        wake_policy,
    )
    .map(|connection| connection.with_expiration(request.expires_at.map(UnixTimestamp::from_secs)))
    .map_err(MobileEngineError::from)
}

fn validate_database_path(database_path: &str) -> Result<(), MobileEngineError> {
    let path = Path::new(database_path);
    if database_path.is_empty()
        || database_path.len() > MAX_DATABASE_PATH_BYTES
        || !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(MobileEngineError::InvalidArgument);
    }
    Ok(())
}

fn mobile_connection_state(
    connection: StoredConnection,
) -> Result<MobileConnectionState, MobileEngineError> {
    match connection {
        StoredConnection::Active(connection) => Ok(MobileConnectionState {
            connection_id: connection.id().as_str().to_owned(),
            revision: connection.revision().value(),
            active: true,
        }),
        StoredConnection::Tombstoned(tombstone) => Ok(MobileConnectionState {
            connection_id: tombstone.id().as_str().to_owned(),
            revision: tombstone.revision().value(),
            active: false,
        }),
        _ => Err(MobileEngineError::CorruptData),
    }
}

impl From<LedgerError> for MobileEngineError {
    fn from(error: LedgerError) -> Self {
        match error {
            LedgerError::DatabaseUnavailable => Self::DatabaseUnavailable,
            LedgerError::UnsupportedSchema => Self::UnsupportedSchema,
            LedgerError::CorruptData => Self::CorruptData,
            _ => Self::CorruptData,
        }
    }
}

impl From<RegistryError> for MobileEngineError {
    fn from(error: RegistryError) -> Self {
        match error {
            RegistryError::DatabaseUnavailable => Self::DatabaseUnavailable,
            RegistryError::CorruptData => Self::CorruptData,
            RegistryError::ValueOutOfRange | RegistryError::InvalidConnection => {
                Self::InvalidArgument
            }
            RegistryError::AlreadyExists => Self::AlreadyExists,
            RegistryError::NotFound => Self::NotFound,
            RegistryError::StaleRevision => Self::StaleRevision,
            RegistryError::AlreadyTombstoned => Self::AlreadyRevoked,
            _ => Self::CorruptData,
        }
    }
}

impl From<PaymentReconciliationError> for MobileEngineError {
    fn from(error: PaymentReconciliationError) -> Self {
        match error {
            PaymentReconciliationError::InvalidBatchSize => Self::InvalidArgument,
            PaymentReconciliationError::Accounting(PaymentAccountingError::DatabaseUnavailable) => {
                Self::DatabaseUnavailable
            }
            PaymentReconciliationError::Accounting(_) => Self::CorruptData,
            _ => Self::CorruptData,
        }
    }
}

impl From<WakeRegistrationWorkerError> for MobileEngineError {
    fn from(error: WakeRegistrationWorkerError) -> Self {
        match error {
            WakeRegistrationWorkerError::Outbox(WakeRegistrationError::InvalidBatchSize) => {
                Self::InvalidArgument
            }
            WakeRegistrationWorkerError::Outbox(WakeRegistrationError::DatabaseUnavailable) => {
                Self::DatabaseUnavailable
            }
            WakeRegistrationWorkerError::Outbox(_) => Self::CorruptData,
            _ => Self::CorruptData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nwc_mobile::UnixTimestamp;

    const CLIENT_KEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const WALLET_KEY: &str = "c6047f9441ed7d6d3045406e95c07cd85a45b85e2accc4bb58601264c59f2aee";

    fn connection() -> MobileConnectionRequest {
        MobileConnectionRequest {
            connection_id: "connection-1".to_owned(),
            client_public_key_hex: CLIENT_KEY.to_owned(),
            wallet_service_public_key_hex: WALLET_KEY.to_owned(),
            relay_urls: vec!["wss://relay.example".to_owned()],
            methods: vec![MobileNwcMethod::GetInfo, MobileNwcMethod::PayInvoice],
            budget_limit_sat: 10_000,
            budget_interval: MobileBudgetInterval::Daily,
            fee_policy: MobileFeePolicy::CountTowardBudget {
                maximum_fee_sat: 100,
            },
            encryption: MobileNwcEncryption::Nip44V2,
            expires_at: None,
        }
    }

    #[test]
    fn rejects_unsafe_database_paths_before_opening() {
        assert_eq!(
            validate_database_path("relative/ledger.sqlite"),
            Err(MobileEngineError::InvalidArgument)
        );
        assert_eq!(
            validate_database_path("/tmp/../ledger.sqlite"),
            Err(MobileEngineError::InvalidArgument)
        );
        assert_eq!(validate_database_path("/tmp/ledger.sqlite"), Ok(()));
    }

    #[test]
    fn connection_request_debug_redacts_routing_and_identity() {
        let request = connection();
        let debug = format!("{request:?}");

        assert!(!debug.contains("connection-1"));
        assert!(!debug.contains(CLIENT_KEY));
        assert!(!debug.contains(WALLET_KEY));
        assert!(!debug.contains("relay.example"));
        assert!(debug.contains("relay_count: 1"));
    }

    #[test]
    fn connection_lifecycle_is_revision_bound_and_permanent() {
        let directory = std::env::temp_dir().join(format!(
            "nwc-mobile-uniffi-engine-{}-{}",
            std::process::id(),
            nwc_mobile::UnixTimestamp::from_secs(1_750_000_000).as_secs()
        ));
        std::fs::create_dir_all(&directory).expect("create test directory");
        let database = directory.join("ledger.sqlite");
        let ledger = WakeLedger::open(&database).expect("open ledger");
        let core = core_connection(connection(), WakePolicy::default()).expect("valid connection");
        let approved_at = UnixTimestamp::from_secs(1_750_000_000);
        let active = ledger
            .insert_connection(core, approved_at)
            .expect("insert connection");
        let tombstone = ledger
            .tombstone_connection(
                active.id(),
                active.revision(),
                UnixTimestamp::from_secs(approved_at.as_secs() + 1),
            )
            .expect("revoke connection");

        assert_eq!(tombstone.revision().value(), 1);
        assert!(matches!(
            ledger.load_connection(active.id()),
            Ok(Some(StoredConnection::Tombstoned(_)))
        ));
        assert_eq!(
            ledger.tombstone_connection(
                active.id(),
                tombstone.revision(),
                UnixTimestamp::from_secs(approved_at.as_secs() + 2)
            ),
            Err(RegistryError::AlreadyTombstoned)
        );

        drop(ledger);
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[test]
    fn connection_conversion_rejects_duplicate_grants_and_insecure_relays() {
        let mut duplicate = connection();
        duplicate.methods.push(MobileNwcMethod::GetInfo);
        assert!(matches!(
            core_connection(duplicate, WakePolicy::default()),
            Err(MobileEngineError::InvalidArgument)
        ));

        let mut insecure = connection();
        insecure.relay_urls = vec!["ws://relay.example".to_owned()];
        assert!(matches!(
            core_connection(insecure, WakePolicy::default()),
            Err(MobileEngineError::InvalidArgument)
        ));
    }

    #[test]
    fn maintenance_arguments_and_failures_have_stable_classifications() {
        assert_eq!(operation_budget(0), Err(MobileEngineError::InvalidArgument));
        assert_eq!(
            MobileEngineError::from(PaymentReconciliationError::InvalidBatchSize),
            MobileEngineError::InvalidArgument
        );
        assert_eq!(
            MobileEngineError::from(PaymentReconciliationError::Accounting(
                PaymentAccountingError::DatabaseUnavailable
            )),
            MobileEngineError::DatabaseUnavailable
        );
        assert_eq!(
            MobileEngineError::from(WakeRegistrationWorkerError::Outbox(
                WakeRegistrationError::InvalidBatchSize
            )),
            MobileEngineError::InvalidArgument
        );
    }
}
