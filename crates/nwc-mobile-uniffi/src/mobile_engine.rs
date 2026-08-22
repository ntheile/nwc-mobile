//! Long-lived native engine facade and connection lifecycle.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path};
use std::sync::Arc;
use std::time::Duration;

use nwc_mobile::{
    ActiveConnection, BudgetInterval, ConnectionRevision, FeePolicy, HostConnectionAuthorization,
    LedgerError, LegacyHostConnection, MobileServiceError, NwaApprovalError, NwcEncryption,
    NwcMethod, NwcMobileService, OperationBudget, PaymentAccountingError, PaymentReconciler,
    PaymentReconciliationError, RegistryError, SecureWakeServerUrl, StoredConnection, SystemClock,
    WakeEngine, WakeRegistrationError, WakeRegistrationWorker, WakeRegistrationWorkerError,
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
    /// An untrusted NWA request was invalid, expired, or outside policy.
    InvalidNwaRequest,
    /// Another NWA request is already awaiting completion.
    NwaAlreadyPending,
    /// No reviewed NWA request is available for approval.
    NoPendingNwa,
    /// The proposed NWA approval exceeded the reviewed request.
    NwaAuthorityEscalation,
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
            Self::InvalidNwaRequest => "NWA request is invalid or outside policy",
            Self::NwaAlreadyPending => "an NWA request is already pending",
            Self::NoPendingNwa => "no NWA request is pending",
            Self::NwaAuthorityEscalation => "NWA approval exceeds the reviewed request",
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

impl TryFrom<BudgetInterval> for MobileBudgetInterval {
    type Error = MobileEngineError;

    fn try_from(interval: BudgetInterval) -> Result<Self, Self::Error> {
        Ok(match interval {
            BudgetInterval::Never => Self::Never,
            BudgetInterval::Hourly => Self::Hourly,
            BudgetInterval::Daily => Self::Daily,
            BudgetInterval::Weekly => Self::Weekly,
            BudgetInterval::Monthly => Self::Monthly,
            BudgetInterval::Yearly => Self::Yearly,
            _ => return Err(MobileEngineError::CorruptData),
        })
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

/// Authoritative non-sensitive connection fields stored by the shared engine.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileConnectionPresentation {
    /// Stable wallet-local identifier.
    pub connection_id: String,
    /// Authorized client public key.
    pub client_public_key_hex: String,
    /// Wallet-service public key.
    pub wallet_service_public_key_hex: String,
    /// Canonical secure relay allowlist.
    pub relay_urls: Vec<String>,
    /// Exact implemented method allowlist.
    pub methods: Vec<MobileNwcMethod>,
    /// Budget limit for one policy interval.
    pub budget_limit_sat: u64,
    /// Budget renewal interval.
    pub budget_interval: MobileBudgetInterval,
    /// Original creation timestamp.
    pub created_at_seconds: u64,
    /// Optional authorization expiration timestamp.
    pub expires_at_seconds: Option<u64>,
    /// Latest successfully completed wake timestamp.
    pub last_used_at_seconds: Option<u64>,
}

impl TryFrom<nwc_mobile::ConnectionPresentation> for MobileConnectionPresentation {
    type Error = MobileEngineError;

    fn try_from(connection: nwc_mobile::ConnectionPresentation) -> Result<Self, Self::Error> {
        mobile_connection_presentation(connection)
    }
}

/// Complete non-sensitive connection state for native application rendering.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileConnectionView {
    /// Stable wallet-local identifier.
    pub id: String,
    /// Host-selected display name.
    pub name: String,
    /// Validated remote icon URL.
    pub icon_url: Option<String>,
    /// Host-resolved cache URL used only for rendering.
    pub icon_display_url: Option<String>,
    /// Canonical newline-delimited secure relay list.
    pub relay: String,
    /// Whether the wallet owns exportable client secret material.
    pub wallet_managed_secret: bool,
    /// Wallet-service public key.
    pub service_pubkey: String,
    /// Authorized client public key.
    pub client_pubkey: String,
    /// Budget limit for the current interval.
    pub budget_sat: u64,
    /// Durable amount consumed in the current interval.
    pub spent_sat: u64,
    /// Display-ready budget amount.
    pub budget_display: String,
    /// Display-ready consumed amount.
    pub spent_display: String,
    /// Budget renewal interval.
    pub budget_interval: MobileBudgetInterval,
    /// Display-ready renewal interval.
    pub budget_interval_display: String,
    /// Exact implemented method allowlist.
    pub permissions: Vec<MobileNwcMethod>,
    /// Original creation timestamp.
    pub created_at: u64,
    /// Latest successfully completed wake timestamp.
    pub last_used_at: Option<u64>,
    /// Optional authorization expiration timestamp.
    pub expires_at: Option<u64>,
    /// Start of the durable accounting period.
    pub budget_period_started_at: u64,
    /// Capability events still awaiting publication.
    pub pending_info_event_relays: Vec<String>,
}

impl MobileConnectionView {
    /// Returns the exact method allowlist in canonical order.
    #[must_use]
    pub fn enabled_permissions(&self) -> Vec<MobileNwcMethod> {
        self.permissions.clone()
    }
}

/// Non-sensitive fields safe for a native NWA approval screen.
#[derive(Clone, Eq, PartialEq, uniffi::Record)]
pub struct MobileNwaRequestPresentation {
    /// Random identity binding approval to the retained request.
    pub request_id_hex: String,
    /// Requesting client's public key.
    pub client_public_key_hex: String,
    /// Sanitized, unverified requester name.
    pub display_name: String,
    /// Validated HTTPS icon URL, when supplied.
    pub icon_url: Option<String>,
    /// Verified callback host, when supplied.
    pub requesting_app_description: Option<String>,
    /// Verified callback target shown to the user.
    pub callback_target_description: String,
    /// Exact secure relay list requested by the client.
    pub relay_urls: Vec<String>,
    /// Requested spending limit in satoshis.
    pub budget_limit_sat: u64,
    /// Requested budget renewal interval.
    pub budget_interval: MobileBudgetInterval,
    /// Requested NWC methods in canonical order.
    pub methods: Vec<MobileNwcMethod>,
    /// Optional request expiration timestamp.
    pub expires_at: Option<u64>,
}

impl TryFrom<nwc_mobile::NwaRequestPresentation> for MobileNwaRequestPresentation {
    type Error = MobileEngineError;

    fn try_from(request: nwc_mobile::NwaRequestPresentation) -> Result<Self, Self::Error> {
        mobile_nwa_presentation(request)
    }
}

impl fmt::Debug for MobileNwaRequestPresentation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MobileNwaRequestPresentation")
            .field("request_id_hex", &"[redacted]")
            .field("client_public_key_hex", &"[redacted]")
            .field("display_name", &"[redacted]")
            .field("has_icon", &self.icon_url.is_some())
            .field(
                "has_requesting_app_description",
                &self.requesting_app_description.is_some(),
            )
            .field("callback_target_description", &"[redacted]")
            .field("relay_count", &self.relay_urls.len())
            .field("budget_limit_sat", &self.budget_limit_sat)
            .field("budget_interval", &self.budget_interval)
            .field("methods", &self.methods)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Application-level NWA session state shared by native hosts.
#[derive(Clone, Debug, Default, Eq, PartialEq, uniffi::Record)]
pub struct MobileNwaSessionState {
    /// Validated request currently awaiting a decision.
    pub request: Option<MobileNwaRequestPresentation>,
    /// Host-resolved local icon URL used only for rendering.
    pub icon_display_url: Option<String>,
    /// Whether an approval transaction is in progress.
    pub approving: bool,
    /// Stable host-facing error message, when present.
    pub error_message: Option<String>,
    /// Whether the approved callback still needs to be opened.
    pub callback_pending: bool,
}

/// Result of an atomically persisted NWA approval.
#[derive(Clone, Eq, PartialEq, uniffi::Record)]
pub struct MobileNwaApprovalResult {
    /// Durable connection lifecycle state.
    pub connection: MobileConnectionState,
    /// Verified public callback URL, when the request supplied one.
    pub callback_url: Option<String>,
}

impl fmt::Debug for MobileNwaApprovalResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MobileNwaApprovalResult")
            .field("connection", &self.connection)
            .field("has_callback", &self.callback_url.is_some())
            .finish()
    }
}

/// One legacy host authorization and its already-consumed accounting state.
#[derive(Clone, Debug, Eq, PartialEq, uniffi::Record)]
pub struct MobileLegacyConnection {
    /// Complete trusted authorization from the host's legacy registry.
    pub authorization: MobileConnectionRequest,
    /// Original connection creation timestamp.
    pub created_at_seconds: u64,
    /// Spending already consumed in the current legacy budget period.
    pub budget_used_sat: u64,
}

/// Stale host records discovered during idempotent migration.
#[derive(Clone, Debug, Default, Eq, PartialEq, uniffi::Record)]
pub struct MobileMigrationReport {
    /// Connection identifiers that are already permanently revoked.
    pub revoked_connection_ids: Vec<String>,
    /// Client keys whose legacy secret material may be scrubbed.
    pub revoked_client_public_keys_hex: Vec<String>,
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
    service: NwcMobileService,
    wallet: Arc<dyn MobileWalletBackend>,
    relays: Arc<dyn MobileRelayTransport>,
    secrets: Arc<dyn MobileSecretProvider>,
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
        let service = NwcMobileService::open(&database_path).map_err(MobileEngineError::from)?;
        Ok(Arc::new(Self {
            service,
            wallet,
            relays,
            secrets,
        }))
    }

    /// Persists one fully approved connection and queues wake registration.
    pub fn add_connection(
        &self,
        request: MobileConnectionRequest,
    ) -> Result<MobileConnectionState, MobileEngineError> {
        let active = self
            .service
            .create_host_connection(core_authorization(request)?)
            .map_err(MobileEngineError::from)?;
        Ok(mobile_active_connection_state(&active))
    }

    /// Loads lifecycle state without returning relay or public-key metadata.
    pub fn connection_state(
        &self,
        connection_id: String,
    ) -> Result<Option<MobileConnectionState>, MobileEngineError> {
        let connection = self
            .service
            .connection(&connection_id)
            .map_err(MobileEngineError::from)?;
        connection.map(mobile_connection_state).transpose()
    }

    /// Lists active connection lifecycle states in stable creation order.
    pub fn active_connections(&self) -> Result<Vec<MobileConnectionState>, MobileEngineError> {
        self.service
            .active_connections()
            .map(|connections| {
                connections
                    .iter()
                    .map(mobile_active_connection_state)
                    .collect()
            })
            .map_err(MobileEngineError::from)
    }

    /// Lists complete non-sensitive connection presentations in stable order.
    pub fn connection_presentations(
        &self,
    ) -> Result<Vec<MobileConnectionPresentation>, MobileEngineError> {
        self.service
            .connection_presentations()
            .map(|connections| {
                connections
                    .into_iter()
                    .map(mobile_connection_presentation)
                    .collect::<Result<Vec<_>, _>>()
            })
            .map_err(MobileEngineError::from)?
    }

    /// Idempotently imports a complete legacy host registry snapshot.
    pub fn migrate_legacy_connections(
        &self,
        connections: Vec<MobileLegacyConnection>,
    ) -> Result<MobileMigrationReport, MobileEngineError> {
        let connections = connections
            .into_iter()
            .map(|legacy| {
                Ok(LegacyHostConnection::new(
                    core_authorization(legacy.authorization)?,
                    nwc_mobile::UnixTimestamp::from_secs(legacy.created_at_seconds),
                    legacy.budget_used_sat,
                ))
            })
            .collect::<Result<Vec<_>, MobileEngineError>>()?;
        let report = self
            .service
            .migrate_legacy_connections(connections)
            .map_err(MobileEngineError::from)?;
        Ok(MobileMigrationReport {
            revoked_connection_ids: report.revoked_connection_ids().to_vec(),
            revoked_client_public_keys_hex: report.revoked_client_pubkeys().to_vec(),
        })
    }

    /// Permanently and idempotently revokes a host connection identifier.
    pub fn revoke_host_connection(&self, connection_id: String) -> Result<(), MobileEngineError> {
        self.service
            .revoke_host_connection(&connection_id)
            .map_err(MobileEngineError::from)
    }

    /// Returns the latest successfully completed wake time for one connection.
    pub fn last_completed_event_at(
        &self,
        connection_id: String,
    ) -> Result<Option<u64>, MobileEngineError> {
        self.service
            .last_completed_event_at(&connection_id)
            .map(|timestamp| timestamp.map(nwc_mobile::UnixTimestamp::as_secs))
            .map_err(MobileEngineError::from)
    }

    /// Requeues active provider registrations after permission or token changes.
    pub fn refresh_wake_registrations(&self, enabled: bool) -> Result<u64, MobileEngineError> {
        self.service
            .refresh_wake_registrations(enabled)
            .and_then(|count| {
                u64::try_from(count).map_err(|_| MobileServiceError::StateUnavailable)
            })
            .map_err(MobileEngineError::from)
    }

    /// Permanently revokes the expected active connection revision.
    pub fn revoke_connection(
        &self,
        connection_id: String,
        expected_revision: u64,
    ) -> Result<MobileConnectionState, MobileEngineError> {
        let tombstone = self
            .service
            .revoke_connection(
                &connection_id,
                ConnectionRevision::from_value(expected_revision),
            )
            .map_err(MobileEngineError::from)?;
        Ok(MobileConnectionState {
            connection_id: tombstone.id().as_str().to_owned(),
            revision: tombstone.revision().value(),
            active: false,
        })
    }

    /// Validates and retains one NWA request for explicit native review.
    pub fn open_nwa_request(
        &self,
        request_uri: String,
    ) -> Result<MobileNwaRequestPresentation, MobileEngineError> {
        self.service
            .open_nwa_request(&request_uri)
            .map_err(MobileEngineError::from)
            .and_then(mobile_nwa_presentation)
    }

    /// Returns the currently retained NWA request, when present.
    pub fn pending_nwa_request(
        &self,
    ) -> Result<Option<MobileNwaRequestPresentation>, MobileEngineError> {
        self.service
            .pending_nwa_request()
            .map_err(MobileEngineError::from)
            .and_then(|request| request.map(mobile_nwa_presentation).transpose())
    }

    /// Atomically validates and persists approval of the retained NWA request.
    pub fn approve_pending_nwa(
        &self,
        request_id_hex: String,
        request: MobileConnectionRequest,
        lud16: Option<String>,
    ) -> Result<MobileNwaApprovalResult, MobileEngineError> {
        let approved = self
            .service
            .approve_pending_nwa(&request_id_hex, core_authorization(request)?, lud16)
            .map_err(MobileEngineError::from)?;
        Ok(MobileNwaApprovalResult {
            connection: mobile_active_connection_state(approved.connection()),
            callback_url: approved.callback_url().map(str::to_owned),
        })
    }

    /// Completes or cancels the current native NWA session.
    pub fn clear_pending_nwa(&self) -> Result<(), MobileEngineError> {
        self.service
            .clear_pending_nwa()
            .map_err(MobileEngineError::from)
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
        let engine = WakeEngine::new(
            self.service.ledger(),
            &host,
            &host,
            &host,
            &clock,
            Default::default(),
        );
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
        let report = PaymentReconciler::new(self.service.ledger(), &host, &SystemClock)
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
        let report =
            WakeRegistrationWorker::new(self.service.ledger(), &bridge, &server_url, &SystemClock)
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

fn core_authorization(
    request: MobileConnectionRequest,
) -> Result<HostConnectionAuthorization, MobileEngineError> {
    let method_count = request.methods.len();
    let methods = request
        .methods
        .into_iter()
        .map(NwcMethod::from)
        .collect::<BTreeSet<_>>();
    if methods.is_empty() || methods.len() != method_count {
        return Err(MobileEngineError::InvalidArgument);
    }
    Ok(HostConnectionAuthorization::new(
        request.connection_id,
        request.client_public_key_hex,
        request.wallet_service_public_key_hex,
        request.relay_urls,
        methods.into_iter().collect(),
        request.budget_limit_sat,
        request.budget_interval.into(),
        request.fee_policy.into(),
        request.encryption.into(),
        request.expires_at.map(nwc_mobile::UnixTimestamp::from_secs),
    ))
}

fn mobile_nwa_presentation(
    request: nwc_mobile::NwaRequestPresentation,
) -> Result<MobileNwaRequestPresentation, MobileEngineError> {
    Ok(MobileNwaRequestPresentation {
        request_id_hex: request.id_hex().to_owned(),
        client_public_key_hex: request.client_pubkey_hex().to_owned(),
        display_name: request.display_name().to_owned(),
        icon_url: request.icon_url().map(str::to_owned),
        requesting_app_description: request.requesting_app_description().map(str::to_owned),
        callback_target_description: request.callback_target_description().to_owned(),
        relay_urls: request.relay_urls().to_vec(),
        budget_limit_sat: request.budget_limit_sat(),
        budget_interval: request.budget_interval().try_into()?,
        methods: request
            .methods()
            .iter()
            .copied()
            .map(MobileNwcMethod::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| MobileEngineError::CorruptData)?,
        expires_at: request.expires_at().map(nwc_mobile::UnixTimestamp::as_secs),
    })
}

fn mobile_connection_presentation(
    connection: nwc_mobile::ConnectionPresentation,
) -> Result<MobileConnectionPresentation, MobileEngineError> {
    Ok(MobileConnectionPresentation {
        connection_id: connection.id().to_owned(),
        client_public_key_hex: connection.client_pubkey_hex().to_owned(),
        wallet_service_public_key_hex: connection.wallet_service_pubkey_hex().to_owned(),
        relay_urls: connection.relay_urls().to_vec(),
        methods: connection
            .methods()
            .iter()
            .copied()
            .map(MobileNwcMethod::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| MobileEngineError::CorruptData)?,
        budget_limit_sat: connection.budget_limit_sat(),
        budget_interval: connection.budget_interval().try_into()?,
        created_at_seconds: connection.created_at().as_secs(),
        expires_at_seconds: connection
            .expires_at()
            .map(nwc_mobile::UnixTimestamp::as_secs),
        last_used_at_seconds: connection
            .last_used_at()
            .map(nwc_mobile::UnixTimestamp::as_secs),
    })
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

fn mobile_active_connection_state(connection: &ActiveConnection) -> MobileConnectionState {
    MobileConnectionState {
        connection_id: connection.id().as_str().to_owned(),
        revision: connection.revision().value(),
        active: true,
    }
}

impl From<MobileServiceError> for MobileEngineError {
    fn from(error: MobileServiceError) -> Self {
        match error {
            MobileServiceError::Ledger(error) => Self::from(error),
            MobileServiceError::Registry(error) => Self::from(error),
            MobileServiceError::Nwa(_) => Self::InvalidNwaRequest,
            MobileServiceError::NwaApproval(NwaApprovalError::AuthorityEscalation) => {
                Self::NwaAuthorityEscalation
            }
            MobileServiceError::NwaApproval(NwaApprovalError::Registry(error)) => Self::from(error),
            MobileServiceError::NwaApproval(NwaApprovalError::InvalidCallback) => {
                Self::InvalidNwaRequest
            }
            MobileServiceError::Registration(WakeRegistrationError::DatabaseUnavailable) => {
                Self::DatabaseUnavailable
            }
            MobileServiceError::Registration(WakeRegistrationError::InvalidBatchSize) => {
                Self::InvalidArgument
            }
            MobileServiceError::Registration(_) => Self::CorruptData,
            MobileServiceError::NwaAlreadyPending => Self::NwaAlreadyPending,
            MobileServiceError::NoPendingNwa => Self::NoPendingNwa,
            MobileServiceError::StateUnavailable => Self::CorruptData,
            _ => Self::CorruptData,
        }
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
        let service = NwcMobileService::open(&database).expect("open service");
        let active = service
            .create_host_connection(core_authorization(connection()).expect("authorization"))
            .expect("insert connection");
        let tombstone = service
            .revoke_connection(active.id().as_str(), active.revision())
            .expect("revoke connection");

        assert_eq!(tombstone.revision().value(), 1);
        assert!(matches!(
            service.connection(active.id().as_str()),
            Ok(Some(StoredConnection::Tombstoned(_)))
        ));
        assert_eq!(
            service.revoke_connection(active.id().as_str(), tombstone.revision()),
            Err(MobileServiceError::Registry(
                RegistryError::AlreadyTombstoned
            ))
        );

        drop(service);
        std::fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[test]
    fn connection_conversion_rejects_duplicate_grants_and_insecure_relays() {
        let mut duplicate = connection();
        duplicate.methods.push(MobileNwcMethod::GetInfo);
        assert!(matches!(
            core_authorization(duplicate),
            Err(MobileEngineError::InvalidArgument)
        ));

        let mut insecure = connection();
        insecure.relay_urls = vec!["ws://relay.example".to_owned()];
        let directory = std::env::temp_dir().join(format!(
            "nwc-mobile-uniffi-validation-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).expect("create test directory");
        let service = NwcMobileService::open(directory.join("ledger.sqlite")).expect("service");
        assert_eq!(
            service.create_host_connection(core_authorization(insecure).expect("authorization")),
            Err(MobileServiceError::Registry(
                RegistryError::InvalidConnection
            ))
        );
        drop(service);
        std::fs::remove_dir_all(directory).expect("remove test directory");
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
