use std::fmt;
use std::sync::Mutex;

use crate::{
    ActiveConnection, ApplicationConnectionMetadata, ApprovedNwaConnection, BudgetInterval,
    BudgetPolicy, Clock, ConnectionId, ConnectionManager, ConnectionPolicy, ConnectionRevision,
    ConnectionTombstone, FeePolicy, LedgerError, LegacyConnectionImport, NewConnection,
    NwaApprovalError, NwaError, NwaParsePolicy, NwaRequest, NwcEncryption, NwcMethod,
    RegistryError, StoredConnection, SystemClock, UnixTimestamp, WakeLedger, WakePolicy,
    WakeRegistrationError,
};

/// Stable failure returned by the batteries-included mobile service facade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MobileServiceError {
    /// Durable storage could not be opened or read safely.
    Ledger(LedgerError),
    /// A connection input or lifecycle operation was rejected.
    Registry(RegistryError),
    /// An untrusted NWA request was rejected.
    Nwa(NwaError),
    /// An NWA approval did not match the reviewed request or could not persist.
    NwaApproval(NwaApprovalError),
    /// Durable wake-registration state could not be updated.
    Registration(WakeRegistrationError),
    /// Another NWA request is already awaiting completion.
    NwaAlreadyPending,
    /// No reviewed NWA request is available for this operation.
    NoPendingNwa,
    /// In-process service state could not be accessed safely.
    StateUnavailable,
}

impl fmt::Display for MobileServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ledger(_) => "mobile NWC storage is unavailable",
            Self::Registry(_) => "mobile NWC connection operation failed",
            Self::Nwa(_) => "NWA request was rejected",
            Self::NwaApproval(_) => "NWA approval failed",
            Self::Registration(_) => "wake registration update failed",
            Self::NwaAlreadyPending => "an NWA request is already pending",
            Self::NoPendingNwa => "no NWA request is pending",
            Self::StateUnavailable => "mobile NWC service state is unavailable",
        })
    }
}

impl std::error::Error for MobileServiceError {}

impl From<LedgerError> for MobileServiceError {
    fn from(error: LedgerError) -> Self {
        Self::Ledger(error)
    }
}

impl From<RegistryError> for MobileServiceError {
    fn from(error: RegistryError) -> Self {
        Self::Registry(error)
    }
}

impl From<NwaError> for MobileServiceError {
    fn from(error: NwaError) -> Self {
        Self::Nwa(error)
    }
}

impl From<NwaApprovalError> for MobileServiceError {
    fn from(error: NwaApprovalError) -> Self {
        Self::NwaApproval(error)
    }
}

impl From<WakeRegistrationError> for MobileServiceError {
    fn from(error: WakeRegistrationError) -> Self {
        Self::Registration(error)
    }
}

/// Non-sensitive, render-ready fields for one validated NWA request.
#[derive(Clone, Eq, PartialEq)]
pub struct NwaRequestPresentation {
    id_hex: String,
    client_pubkey_hex: String,
    display_name: String,
    icon_url: Option<String>,
    requesting_app_description: Option<String>,
    callback_target_description: String,
    relay_urls: Vec<String>,
    budget_limit_sat: u64,
    budget_interval: BudgetInterval,
    methods: Vec<NwcMethod>,
    expires_at: Option<UnixTimestamp>,
}

impl fmt::Debug for NwaRequestPresentation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NwaRequestPresentation")
            .field("id_hex", &"[redacted]")
            .field("client_pubkey_hex", &"[redacted]")
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

impl NwaRequestPresentation {
    fn from_request(request: &NwaRequest) -> Self {
        let callback = request.callback();
        let policy = request.requested_policy();
        Self {
            id_hex: request.id().to_hex(),
            client_pubkey_hex: request.client_pubkey().to_hex(),
            display_name: request.display_name().to_owned(),
            icon_url: request.icon_url().map(ToString::to_string),
            requesting_app_description: callback
                .and_then(|value| value.url().host_str().map(str::to_owned)),
            callback_target_description: callback
                .map(|value| value.target_description())
                .unwrap_or_else(|| "none".to_owned()),
            relay_urls: request.relays().to_vec(),
            budget_limit_sat: policy.budget().limit_sat(),
            budget_interval: policy.budget().interval(),
            methods: policy.methods().collect(),
            expires_at: request.expires_at(),
        }
    }

    /// Returns the random identity binding approval to this presentation.
    #[must_use]
    pub fn id_hex(&self) -> &str {
        &self.id_hex
    }

    /// Returns the requesting client's public key.
    #[must_use]
    pub fn client_pubkey_hex(&self) -> &str {
        &self.client_pubkey_hex
    }

    /// Returns the sanitized, unverified requester name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns the validated HTTPS icon URL, when present.
    #[must_use]
    pub fn icon_url(&self) -> Option<&str> {
        self.icon_url.as_deref()
    }

    /// Returns the verified callback host shown to the user, when present.
    #[must_use]
    pub fn requesting_app_description(&self) -> Option<&str> {
        self.requesting_app_description.as_deref()
    }

    /// Returns the verified callback target description.
    #[must_use]
    pub fn callback_target_description(&self) -> &str {
        &self.callback_target_description
    }

    /// Returns the exact secure relay list requested by the client.
    #[must_use]
    pub fn relay_urls(&self) -> &[String] {
        &self.relay_urls
    }

    /// Returns the requested spending limit in satoshis.
    #[must_use]
    pub const fn budget_limit_sat(&self) -> u64 {
        self.budget_limit_sat
    }

    /// Returns the requested renewal interval.
    #[must_use]
    pub const fn budget_interval(&self) -> BudgetInterval {
        self.budget_interval
    }

    /// Returns the requested NWC methods in canonical order.
    #[must_use]
    pub fn methods(&self) -> &[NwcMethod] {
        &self.methods
    }

    /// Returns when the request stops accepting approval.
    #[must_use]
    pub const fn expires_at(&self) -> Option<UnixTimestamp> {
        self.expires_at
    }
}

/// Primitive host fields for one fully reviewed connection authorization.
#[derive(Clone, Eq, PartialEq)]
pub struct HostConnectionAuthorization {
    id: String,
    client_pubkey_hex: String,
    wallet_service_pubkey_hex: String,
    relay_urls: Vec<String>,
    methods: Vec<NwcMethod>,
    budget_limit_sat: u64,
    budget_interval: BudgetInterval,
    fee_policy: FeePolicy,
    encryption: NwcEncryption,
    expires_at: Option<UnixTimestamp>,
}

impl fmt::Debug for HostConnectionAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostConnectionAuthorization")
            .field("id", &"[redacted]")
            .field("client_pubkey_hex", &"[redacted]")
            .field("wallet_service_pubkey_hex", &"[redacted]")
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

impl HostConnectionAuthorization {
    /// Creates a host authorization; validation occurs at the service boundary.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        id: String,
        client_pubkey_hex: String,
        wallet_service_pubkey_hex: String,
        relay_urls: Vec<String>,
        methods: Vec<NwcMethod>,
        budget_limit_sat: u64,
        budget_interval: BudgetInterval,
        fee_policy: FeePolicy,
        encryption: NwcEncryption,
        expires_at: Option<UnixTimestamp>,
    ) -> Self {
        Self {
            id,
            client_pubkey_hex,
            wallet_service_pubkey_hex,
            relay_urls,
            methods,
            budget_limit_sat,
            budget_interval,
            fee_policy,
            encryption,
            expires_at,
        }
    }

    /// Returns the stable host-selected connection identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the authorized client public key.
    #[must_use]
    pub fn client_pubkey_hex(&self) -> &str {
        &self.client_pubkey_hex
    }

    /// Returns the wallet service public key.
    #[must_use]
    pub fn wallet_service_pubkey_hex(&self) -> &str {
        &self.wallet_service_pubkey_hex
    }

    /// Returns the canonical secure relay allowlist.
    #[must_use]
    pub fn relay_urls(&self) -> &[String] {
        &self.relay_urls
    }

    fn into_connection(self, wake_policy: WakePolicy) -> Result<NewConnection, RegistryError> {
        let policy = ConnectionPolicy::new(
            self.methods,
            BudgetPolicy::new(self.budget_limit_sat, self.budget_interval, self.fee_policy),
        );
        NewConnection::from_host_strings(
            self.id,
            &self.client_pubkey_hex,
            &self.wallet_service_pubkey_hex,
            self.relay_urls,
            policy,
            self.encryption,
            wake_policy,
        )
        .map(|connection| connection.with_expiration(self.expires_at))
    }

    /// Validates this host authorization using the default mobile wake policy.
    pub fn validate(&self) -> Result<(), RegistryError> {
        self.clone()
            .into_connection(WakePolicy::default())
            .map(drop)
    }
}

/// One legacy host authorization and its already-consumed accounting state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyHostConnection {
    authorization: HostConnectionAuthorization,
    created_at: UnixTimestamp,
    budget_used_sat: u64,
}

impl LegacyHostConnection {
    /// Creates a trusted one-time migration record.
    #[must_use]
    pub const fn new(
        authorization: HostConnectionAuthorization,
        created_at: UnixTimestamp,
        budget_used_sat: u64,
    ) -> Self {
        Self {
            authorization,
            created_at,
            budget_used_sat,
        }
    }
}

/// Host-facing identifiers discovered during idempotent legacy migration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HostMigrationReport {
    revoked_connection_ids: Vec<String>,
    revoked_client_pubkeys: Vec<String>,
}

impl HostMigrationReport {
    /// Returns legacy connection identifiers that must be removed by the host.
    #[must_use]
    pub fn revoked_connection_ids(&self) -> &[String] {
        &self.revoked_connection_ids
    }

    /// Returns client keys whose legacy secret material may be scrubbed.
    #[must_use]
    pub fn revoked_client_pubkeys(&self) -> &[String] {
        &self.revoked_client_pubkeys
    }
}

/// Batteries-included connection and NWA lifecycle service for mobile wallets.
pub struct NwcMobileService {
    ledger: WakeLedger,
    pending_nwa: Mutex<Option<NwaRequest>>,
    nwa_policy: NwaParsePolicy,
    wake_policy: WakePolicy,
}

impl NwcMobileService {
    /// Opens the authoritative mobile ledger and uses conservative policies.
    pub fn open(database_path: impl AsRef<std::path::Path>) -> Result<Self, MobileServiceError> {
        Ok(Self::from_ledger(WakeLedger::open(database_path)?))
    }

    /// Wraps an already-opened ledger using conservative policies.
    #[must_use]
    pub fn from_ledger(ledger: WakeLedger) -> Self {
        Self {
            ledger,
            pending_nwa: Mutex::new(None),
            nwa_policy: NwaParsePolicy::default(),
            wake_policy: WakePolicy::default(),
        }
    }

    /// Returns the authoritative ledger for engine and maintenance adapters.
    #[must_use]
    pub const fn ledger(&self) -> &WakeLedger {
        &self.ledger
    }

    /// Persists one fully reviewed host authorization with a trusted timestamp.
    pub fn create_host_connection(
        &self,
        authorization: HostConnectionAuthorization,
    ) -> Result<ActiveConnection, MobileServiceError> {
        Ok(ConnectionManager::new(&self.ledger, &SystemClock)
            .create(authorization.into_connection(self.wake_policy)?)?)
    }

    /// Loads lifecycle state without requiring the host to access the ledger.
    pub fn connection(&self, id: &str) -> Result<Option<StoredConnection>, MobileServiceError> {
        let id =
            ConnectionId::parse(id.to_owned()).map_err(|_| RegistryError::InvalidConnection)?;
        Ok(ConnectionManager::new(&self.ledger, &SystemClock).connection(&id)?)
    }

    /// Lists active authorizations in stable creation order.
    pub fn active_connections(&self) -> Result<Vec<ActiveConnection>, MobileServiceError> {
        Ok(ConnectionManager::new(&self.ledger, &SystemClock).active_connections()?)
    }

    /// Lists complete non-sensitive connection presentations in stable creation order.
    pub fn connection_presentations(
        &self,
    ) -> Result<Vec<crate::ConnectionPresentation>, MobileServiceError> {
        self.active_connections()?
            .iter()
            .map(|connection| {
                let last_used_at = self.ledger.last_completed_event_at(connection.id())?;
                let metadata = self.ledger.application_metadata(connection.id())?;
                let usage = self.ledger.current_budget_usage(connection)?;
                Ok(crate::ConnectionPresentation::from_active(
                    connection,
                    last_used_at,
                    metadata,
                    usage,
                ))
            })
            .collect()
    }

    /// Persists non-sensitive display metadata and capability-publication work in the shared
    /// ledger used by foreground and background processes.
    pub fn set_connection_metadata(
        &self,
        id: &str,
        metadata: ApplicationConnectionMetadata,
    ) -> Result<(), MobileServiceError> {
        let id =
            ConnectionId::parse(id.to_owned()).map_err(|_| RegistryError::InvalidConnection)?;
        self.ledger.upsert_application_metadata(&id, &metadata)?;
        Ok(())
    }

    /// Acknowledges one successfully published NIP-47 capability event.
    pub fn acknowledge_nwc_info_event(
        &self,
        id: &str,
        relay_url: &str,
    ) -> Result<(), MobileServiceError> {
        let id =
            ConnectionId::parse(id.to_owned()).map_err(|_| RegistryError::InvalidConnection)?;
        self.ledger.acknowledge_nwc_info_event(&id, relay_url)?;
        Ok(())
    }

    /// Permanently revokes an exact active revision.
    pub fn revoke_connection(
        &self,
        id: &str,
        expected_revision: ConnectionRevision,
    ) -> Result<ConnectionTombstone, MobileServiceError> {
        let id =
            ConnectionId::parse(id.to_owned()).map_err(|_| RegistryError::InvalidConnection)?;
        Ok(ConnectionManager::new(&self.ledger, &SystemClock).revoke(&id, expected_revision)?)
    }

    /// Parses and retains one request until the host completes or cancels it.
    pub fn open_nwa_request(
        &self,
        input: &str,
    ) -> Result<NwaRequestPresentation, MobileServiceError> {
        self.open_nwa_request_at(input, SystemClock.now())
    }

    fn open_nwa_request_at(
        &self,
        input: &str,
        now: UnixTimestamp,
    ) -> Result<NwaRequestPresentation, MobileServiceError> {
        let mut pending = self
            .pending_nwa
            .lock()
            .map_err(|_| MobileServiceError::StateUnavailable)?;
        if pending.is_some() {
            return Err(MobileServiceError::NwaAlreadyPending);
        }
        let request = NwaRequest::parse(input, now, &self.nwa_policy)?;
        let presentation = NwaRequestPresentation::from_request(&request);
        *pending = Some(request);
        Ok(presentation)
    }

    /// Returns the retained request presentation without exposing authority internals.
    pub fn pending_nwa_request(
        &self,
    ) -> Result<Option<NwaRequestPresentation>, MobileServiceError> {
        self.pending_nwa
            .lock()
            .map(|pending| pending.as_ref().map(NwaRequestPresentation::from_request))
            .map_err(|_| MobileServiceError::StateUnavailable)
    }

    /// Approves the retained request while enforcing its exact authority bound.
    pub fn approve_pending_nwa(
        &self,
        expected_request_id_hex: &str,
        authorization: HostConnectionAuthorization,
        lud16: Option<String>,
    ) -> Result<ApprovedNwaConnection, MobileServiceError> {
        let mut pending = self
            .pending_nwa
            .lock()
            .map_err(|_| MobileServiceError::StateUnavailable)?;
        let request = pending
            .as_ref()
            .cloned()
            .ok_or(MobileServiceError::NoPendingNwa)?;
        if request.id().to_hex() != expected_request_id_hex {
            return Err(MobileServiceError::NwaApproval(
                NwaApprovalError::AuthorityEscalation,
            ));
        }
        let connection = authorization.into_connection(self.wake_policy)?;
        let approved = ConnectionManager::new(&self.ledger, &SystemClock)
            .approve_nwa_connection(request, connection, lud16)?;
        *pending = None;
        Ok(approved)
    }

    /// Completes or cancels the current NWA session.
    pub fn clear_pending_nwa(&self) -> Result<(), MobileServiceError> {
        let mut pending = self
            .pending_nwa
            .lock()
            .map_err(|_| MobileServiceError::StateUnavailable)?;
        *pending = None;
        Ok(())
    }

    /// Idempotently imports a complete legacy host registry snapshot.
    pub fn migrate_legacy_connections(
        &self,
        connections: Vec<LegacyHostConnection>,
    ) -> Result<HostMigrationReport, MobileServiceError> {
        let imports = connections
            .into_iter()
            .map(|legacy| {
                Ok(LegacyConnectionImport::new(
                    legacy.authorization.into_connection(self.wake_policy)?,
                    legacy.created_at,
                    legacy.budget_used_sat,
                ))
            })
            .collect::<Result<Vec<_>, RegistryError>>()?;
        let result =
            ConnectionManager::new(&self.ledger, &SystemClock).migrate_legacy_batch(imports)?;
        Ok(HostMigrationReport {
            revoked_connection_ids: result
                .revoked_connection_ids()
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect(),
            revoked_client_pubkeys: result
                .revoked_client_pubkeys()
                .iter()
                .map(|key| key.to_hex())
                .collect(),
        })
    }

    /// Imports one newly-created host record without restoring accounting state.
    pub fn import_host_connection(
        &self,
        authorization: HostConnectionAuthorization,
        created_at: UnixTimestamp,
    ) -> Result<ActiveConnection, MobileServiceError> {
        Ok(
            ConnectionManager::new(&self.ledger, &SystemClock).import_legacy(
                authorization.into_connection(self.wake_policy)?,
                created_at,
                0,
            )?,
        )
    }

    /// Permanently and idempotently revokes a host connection identifier.
    pub fn revoke_host_connection(&self, id: &str) -> Result<(), MobileServiceError> {
        ConnectionManager::new(&self.ledger, &SystemClock).revoke_host_connection(id)?;
        Ok(())
    }

    /// Returns the latest successfully completed wake time for a host connection.
    pub fn last_completed_event_at(
        &self,
        id: &str,
    ) -> Result<Option<UnixTimestamp>, MobileServiceError> {
        let id =
            ConnectionId::parse(id.to_owned()).map_err(|_| RegistryError::InvalidConnection)?;
        Ok(self.ledger.last_completed_event_at(&id)?)
    }

    /// Requeues every active wake registration for the current native permission state.
    pub fn refresh_wake_registrations(&self, enabled: bool) -> Result<usize, MobileServiceError> {
        Ok(self
            .ledger
            .requeue_active_wake_registrations_with_state(enabled, SystemClock.now())?)
    }
}

impl fmt::Debug for NwcMobileService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NwcMobileService { .. }")
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    const CLIENT: &str = "687dd8ece211539364549b1f32c63eceec1e0661009ba65cf8ff2e73ba000746";
    const CLIENT_TWO: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
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
                "nwc-mobile-service-{}-{suffix}",
                std::process::id()
            ));
            fs::create_dir(&directory).expect("create test directory");
            let path = directory.join("mobile.sqlite3");
            Self { directory, path }
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn authorization(client: &str) -> HostConnectionAuthorization {
        HostConnectionAuthorization::new(
            "connection:service".to_owned(),
            client.to_owned(),
            WALLET.to_owned(),
            vec!["wss://relay.example/nwc".to_owned()],
            vec![NwcMethod::GetInfo],
            0,
            BudgetInterval::Never,
            FeePolicy::CountTowardBudget { maximum_fee_sat: 0 },
            NwcEncryption::LegacyNip04,
            None,
        )
    }

    #[test]
    fn service_owns_nwa_session_presentation_and_approval_binding() {
        let database = TestDatabase::new();
        let service = NwcMobileService::open(&database.path).expect("service");
        let presentation = service
            .open_nwa_request_at(
                &format!("nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Frelay.example%2Fnwc&name=Example"),
                UnixTimestamp::from_secs(100),
            )
            .expect("request");
        assert_eq!(presentation.client_pubkey_hex(), CLIENT);
        assert_eq!(presentation.display_name(), "Example");
        let debug = format!("{presentation:?}");
        assert!(!debug.contains(CLIENT));
        assert!(!debug.contains("Example"));
        assert!(!debug.contains("relay.example"));
        assert_eq!(
            service.open_nwa_request_at(
                &format!("nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Frelay.example%2Fnwc"),
                UnixTimestamp::from_secs(100),
            ),
            Err(MobileServiceError::NwaAlreadyPending)
        );

        assert_eq!(
            service.approve_pending_nwa(presentation.id_hex(), authorization(CLIENT_TWO), None),
            Err(MobileServiceError::NwaApproval(
                NwaApprovalError::AuthorityEscalation
            ))
        );
        assert!(service.pending_nwa_request().expect("pending").is_some());
        assert_eq!(
            service.approve_pending_nwa("wrong-request", authorization(CLIENT), None),
            Err(MobileServiceError::NwaApproval(
                NwaApprovalError::AuthorityEscalation
            ))
        );
        let approved = service
            .approve_pending_nwa(presentation.id_hex(), authorization(CLIENT), None)
            .expect("approval");
        assert_eq!(approved.connection().id().as_str(), "connection:service");
        assert_eq!(service.pending_nwa_request().expect("pending"), None);
        assert_eq!(
            service.approve_pending_nwa(presentation.id_hex(), authorization(CLIENT), None),
            Err(MobileServiceError::NoPendingNwa)
        );
    }

    #[test]
    fn service_owns_display_accounting_and_info_publication_state() {
        let database = TestDatabase::new();
        let service = NwcMobileService::open(&database.path).expect("service");
        service
            .create_host_connection(authorization(CLIENT))
            .expect("connection");
        service
            .set_connection_metadata(
                "connection:service",
                ApplicationConnectionMetadata::new(
                    "Example App",
                    Some("https://app.example/icon.png".to_owned()),
                    vec!["wss://relay.example/nwc".to_owned()],
                )
                .expect("metadata"),
            )
            .expect("store metadata");

        let presentation = service
            .connection_presentations()
            .expect("presentations")
            .pop()
            .expect("connection presentation");
        assert_eq!(presentation.display_name(), Some("Example App"));
        assert_eq!(
            presentation.icon_url(),
            Some("https://app.example/icon.png")
        );
        assert_eq!(presentation.spent_sat(), 0);
        assert_eq!(
            presentation.pending_info_event_relays(),
            &["wss://relay.example/nwc".to_owned()]
        );

        service
            .acknowledge_nwc_info_event("connection:service", "wss://relay.example/nwc")
            .expect("acknowledge info event");
        assert!(service
            .connection_presentations()
            .expect("presentations")
            .pop()
            .expect("connection presentation")
            .pending_info_event_relays()
            .is_empty());

        let unapproved = ApplicationConnectionMetadata::new(
            "Example App",
            None,
            vec!["wss://unapproved.example/nwc".to_owned()],
        )
        .expect("well-formed metadata");
        assert!(service
            .set_connection_metadata("connection:service", unapproved)
            .is_err());
    }
}
