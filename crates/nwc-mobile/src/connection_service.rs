use crate::{
    ActiveConnection, Clock, ConnectionId, ConnectionPolicy, ConnectionRevision,
    ConnectionTombstone, NewConnection, NwaError, NwaRequest, NwcEncryption, PublicKey,
    RegistryError, SecureRelayUrl, StoredConnection, UnixTimestamp, WakeLedger, WakePolicy,
};
use std::fmt;

/// A wallet-reviewed NWA grant ready for authority-subset validation.
#[derive(Clone, Eq, PartialEq)]
pub struct NwaApproval {
    request_id: crate::NwaRequestId,
    connection_id: ConnectionId,
    wallet_service_pubkey: PublicKey,
    relays: Vec<SecureRelayUrl>,
    policy: ConnectionPolicy,
    encryption: NwcEncryption,
    lud16: Option<String>,
}

impl NwaApproval {
    /// Creates an explicit approval selected by the wallet user.
    #[must_use]
    pub fn new(
        request_id: crate::NwaRequestId,
        connection_id: ConnectionId,
        wallet_service_pubkey: PublicKey,
        relays: Vec<SecureRelayUrl>,
        policy: ConnectionPolicy,
        encryption: NwcEncryption,
        lud16: Option<String>,
    ) -> Self {
        Self {
            request_id,
            connection_id,
            wallet_service_pubkey,
            relays,
            policy,
            encryption,
            lud16,
        }
    }
}

impl fmt::Debug for NwaApproval {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NwaApproval")
            .field("request_id", &"[redacted]")
            .field("connection_id", &"[redacted]")
            .field("wallet_service_pubkey", &"[redacted]")
            .field("relay_count", &self.relays.len())
            .field("policy", &self.policy)
            .field("encryption", &self.encryption)
            .field("has_lud16", &self.lud16.is_some())
            .finish()
    }
}

/// A durably authorized NWA connection and its optional public callback.
#[derive(Clone, Eq, PartialEq)]
pub struct ApprovedNwaConnection {
    connection: ActiveConnection,
    callback_url: Option<String>,
}

impl ApprovedNwaConnection {
    /// Returns the newly persisted authorization.
    #[must_use]
    pub const fn connection(&self) -> &ActiveConnection {
        &self.connection
    }

    /// Returns the verified HTTPS callback containing public approval metadata.
    #[must_use]
    pub fn callback_url(&self) -> Option<&str> {
        self.callback_url.as_deref()
    }
}

impl fmt::Debug for ApprovedNwaConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedNwaConnection")
            .field("connection", &self.connection)
            .field("has_callback", &self.callback_url.is_some())
            .finish()
    }
}

/// Stable failure classification for one explicit NWA approval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NwaApprovalError {
    /// The approval targeted a different request or exceeded its requested authority.
    AuthorityEscalation,
    /// The already-validated callback could not encode its public result.
    InvalidCallback,
    /// The durable connection registry rejected or could not persist the grant.
    Registry(RegistryError),
}

impl fmt::Display for NwaApprovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AuthorityEscalation => "NWA approval exceeds the requested authority",
            Self::InvalidCallback => "NWA approval callback could not be constructed",
            Self::Registry(_) => "NWA approval could not be persisted",
        })
    }
}

impl std::error::Error for NwaApprovalError {}

impl From<RegistryError> for NwaApprovalError {
    fn from(error: RegistryError) -> Self {
        Self::Registry(error)
    }
}

impl From<NwaError> for NwaApprovalError {
    fn from(_: NwaError) -> Self {
        Self::InvalidCallback
    }
}

/// High-level lifecycle operations over the authoritative connection registry.
///
/// Applications should use this manager instead of coordinating direct ledger
/// writes. It owns timestamp selection and preserves revision-bound revocation.
pub struct ConnectionManager<'a> {
    ledger: &'a WakeLedger,
    clock: &'a dyn Clock,
}

impl<'a> ConnectionManager<'a> {
    /// Creates a manager over one durable wallet ledger.
    #[must_use]
    pub const fn new(ledger: &'a WakeLedger, clock: &'a dyn Clock) -> Self {
        Self { ledger, clock }
    }

    /// Persists one newly approved connection and queues its wake registration.
    pub fn create(&self, connection: NewConnection) -> Result<ActiveConnection, RegistryError> {
        self.ledger.insert_connection(connection, self.clock.now())
    }

    /// Imports one trusted legacy authorization without restoring spent budget.
    ///
    /// This is only for an application's one-time migration into the
    /// authoritative registry, before processing requests for the connection.
    pub fn import_legacy(
        &self,
        connection: NewConnection,
        created_at: UnixTimestamp,
        budget_used_sat: u64,
    ) -> Result<ActiveConnection, RegistryError> {
        self.ledger
            .import_connection(connection, created_at, budget_used_sat, self.clock.now())
    }

    /// Loads either the active authorization or its permanent tombstone.
    pub fn connection(&self, id: &ConnectionId) -> Result<Option<StoredConnection>, RegistryError> {
        self.ledger.load_connection(id)
    }

    /// Lists active authorizations in stable creation order.
    pub fn active_connections(&self) -> Result<Vec<ActiveConnection>, RegistryError> {
        self.ledger.list_active_connections()
    }

    /// Permanently revokes the exact active revision supplied by the caller.
    pub fn revoke(
        &self,
        id: &ConnectionId,
        expected_revision: ConnectionRevision,
    ) -> Result<ConnectionTombstone, RegistryError> {
        self.ledger
            .tombstone_connection(id, expected_revision, self.clock.now())
    }

    /// Validates an NWA approval as a subset of the request and persists it.
    ///
    /// The public callback is constructed before the registry changes so a
    /// callback encoding failure cannot leave an authorization half-approved.
    /// The explicit wake policy must be the same configured policy used by the
    /// wallet when accepting the request's relay set.
    pub fn approve_nwa(
        &self,
        request: NwaRequest,
        approval: NwaApproval,
        wake_policy: WakePolicy,
    ) -> Result<ApprovedNwaConnection, NwaApprovalError> {
        validate_nwa_authority_subset(&request, &approval)?;
        let callback_relays = approval
            .relays
            .iter()
            .map(|relay| relay.as_str().to_owned())
            .collect::<Vec<_>>();
        let callback_url = request
            .callback()
            .map(|callback| {
                callback.approved_url(
                    &approval.wallet_service_pubkey,
                    &callback_relays,
                    approval.lud16.as_deref(),
                )
            })
            .transpose()?
            .map(|url| url.to_string());
        let connection = NewConnection::new(
            approval.connection_id,
            request.client_pubkey().clone(),
            approval.wallet_service_pubkey,
            approval.relays,
            approval.policy,
            approval.encryption,
            wake_policy,
        )
        .map(|connection| connection.with_expiration(request.expires_at()))?;
        let connection = self.create(connection)?;
        Ok(ApprovedNwaConnection {
            connection,
            callback_url,
        })
    }
}

fn validate_nwa_authority_subset(
    request: &NwaRequest,
    approval: &NwaApproval,
) -> Result<(), NwaApprovalError> {
    let requested_policy = request.requested_policy();
    let requested_budget = requested_policy.budget();
    let approved_budget = approval.policy.budget();
    let relays_are_requested = approval.relays.iter().all(|approved| {
        request
            .relays()
            .iter()
            .any(|requested| requested == approved.as_str())
    });
    let methods_are_requested = approval
        .policy
        .methods()
        .all(|method| requested_policy.allows(method));
    if approval.request_id != request.id()
        || approval.relays.is_empty()
        || !relays_are_requested
        || approval.policy.methods().len() == 0
        || !methods_are_requested
        || approved_budget.limit_sat() > requested_budget.limit_sat()
        || approved_budget.interval() != requested_budget.interval()
        || !matches!(
            approved_budget.fee_policy(),
            crate::FeePolicy::CountTowardBudget { .. }
        )
    {
        return Err(NwaApprovalError::AuthorityEscalation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;
    use crate::{
        BudgetInterval, BudgetPolicy, ConnectionPolicy, FeePolicy, NwaParsePolicy, NwcEncryption,
        NwcMethod, PublicKey, SecureRelayUrl, WakePolicy,
    };

    const CLIENT: &str = "687dd8ece211539364549b1f32c63eceec1e0661009ba65cf8ff2e73ba000746";
    const CLIENT_TWO: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    const WALLET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    struct FixedClock(UnixTimestamp);

    impl Clock for FixedClock {
        fn now(&self) -> UnixTimestamp {
            self.0
        }
    }

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
                "nwc-mobile-manager-{}-{suffix}",
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

    fn connection(id: &str) -> NewConnection {
        let client = if id.ends_with('a') {
            CLIENT
        } else {
            CLIENT_TWO
        };
        NewConnection::new(
            ConnectionId::parse(id).expect("connection id"),
            PublicKey::from_hex(client).expect("client key"),
            PublicKey::from_hex(WALLET).expect("wallet key"),
            vec![SecureRelayUrl::parse("wss://relay.example/nwc").expect("relay")],
            ConnectionPolicy::new(
                [NwcMethod::GetInfo],
                BudgetPolicy::new(
                    0,
                    BudgetInterval::Never,
                    FeePolicy::CountTowardBudget { maximum_fee_sat: 0 },
                ),
            ),
            NwcEncryption::Nip44V2,
            WakePolicy::default(),
        )
        .expect("new connection")
    }

    #[test]
    fn manager_owns_ordered_creation_and_revision_bound_revocation() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let clock = FixedClock(UnixTimestamp::from_secs(100));
        let manager = ConnectionManager::new(&ledger, &clock);

        let second = manager.create(connection("connection:b")).expect("second");
        let first = manager.create(connection("connection:a")).expect("first");
        let active = manager.active_connections().expect("active connections");
        assert_eq!(
            active
                .iter()
                .map(|connection| connection.id().as_str())
                .collect::<Vec<_>>(),
            ["connection:a", "connection:b"]
        );

        manager
            .revoke(first.id(), first.revision())
            .expect("revoke first");
        assert_eq!(
            manager
                .active_connections()
                .expect("remaining")
                .iter()
                .map(|connection| connection.id().as_str())
                .collect::<Vec<_>>(),
            [second.id().as_str()]
        );
        assert!(matches!(
            manager.connection(first.id()).expect("load first"),
            Some(StoredConnection::Tombstoned(_))
        ));
    }

    #[test]
    fn legacy_import_uses_manager_clock_without_restoring_authority() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let clock = FixedClock(UnixTimestamp::from_secs(200));
        let manager = ConnectionManager::new(&ledger, &clock);

        let active = manager
            .import_legacy(
                connection("connection:legacy"),
                UnixTimestamp::from_secs(100),
                0,
            )
            .expect("import legacy");
        assert_eq!(active.created_at(), UnixTimestamp::from_secs(100));
        assert_eq!(active.updated_at(), UnixTimestamp::from_secs(200));
    }

    fn nwa_request() -> NwaRequest {
        NwaRequest::parse(
            &format!(
                "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Frelay.example%2Fnwc&max_amount=1000000&budget_renewal=daily&request_methods=get_info+pay_invoice&return_to=https%3A%2F%2Fapp.example%2Fnwa&state=0123456789abcdef0123456789abcdef"
            ),
            UnixTimestamp::from_secs(100),
            &NwaParsePolicy::default(),
        )
        .expect("NWA request")
    }

    fn nwa_approval(
        request: &NwaRequest,
        methods: impl IntoIterator<Item = NwcMethod>,
    ) -> NwaApproval {
        NwaApproval::new(
            request.id(),
            ConnectionId::parse("connection:nwa").expect("connection id"),
            PublicKey::from_hex(WALLET).expect("wallet key"),
            vec![SecureRelayUrl::parse("wss://relay.example/nwc").expect("relay")],
            ConnectionPolicy::new(
                methods,
                BudgetPolicy::new(
                    500,
                    BudgetInterval::Daily,
                    FeePolicy::CountTowardBudget {
                        maximum_fee_sat: 10,
                    },
                ),
            ),
            NwcEncryption::LegacyNip04,
            Some("wallet@example.com".to_owned()),
        )
    }

    #[test]
    fn nwa_approval_persists_only_a_requested_authority_subset() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let clock = FixedClock(UnixTimestamp::from_secs(101));
        let manager = ConnectionManager::new(&ledger, &clock);

        let request = nwa_request();
        let approval = nwa_approval(&request, [NwcMethod::GetInfo]);
        let approved = manager
            .approve_nwa(request, approval, WakePolicy::default())
            .expect("approve NWA");
        assert!(approved.connection().policy().allows(NwcMethod::GetInfo));
        assert!(!approved.connection().policy().allows(NwcMethod::PayInvoice));
        let callback = approved.callback_url().expect("callback");
        assert!(callback.starts_with("https://app.example/nwa#"));
        assert!(callback.contains("status=approved"));
        assert!(callback.contains("lud16=wallet%40example.com"));
    }

    #[test]
    fn nwa_approval_rejects_method_relay_budget_and_interval_escalation() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let clock = FixedClock(UnixTimestamp::from_secs(101));
        let manager = ConnectionManager::new(&ledger, &clock);

        let request = nwa_request();
        let method = nwa_approval(&request, [NwcMethod::MakeInvoice]);
        assert_eq!(
            manager.approve_nwa(request, method, WakePolicy::default()),
            Err(NwaApprovalError::AuthorityEscalation)
        );

        let request = nwa_request();
        let mut relay = nwa_approval(&request, [NwcMethod::GetInfo]);
        relay.relays = vec![SecureRelayUrl::parse("wss://other.example").expect("relay")];
        assert_eq!(
            manager.approve_nwa(request, relay, WakePolicy::default()),
            Err(NwaApprovalError::AuthorityEscalation)
        );

        let request = nwa_request();
        let mut budget = nwa_approval(&request, [NwcMethod::GetInfo]);
        budget.policy = ConnectionPolicy::new(
            [NwcMethod::GetInfo],
            BudgetPolicy::new(
                1_001,
                BudgetInterval::Daily,
                FeePolicy::CountTowardBudget { maximum_fee_sat: 0 },
            ),
        );
        assert_eq!(
            manager.approve_nwa(request, budget, WakePolicy::default()),
            Err(NwaApprovalError::AuthorityEscalation)
        );

        let request = nwa_request();
        let mut interval = nwa_approval(&request, [NwcMethod::GetInfo]);
        interval.policy = ConnectionPolicy::conservative_default();
        assert_eq!(
            manager.approve_nwa(request, interval, WakePolicy::default()),
            Err(NwaApprovalError::AuthorityEscalation)
        );

        let request = nwa_request();
        let mut stale = nwa_approval(&request, [NwcMethod::GetInfo]);
        stale.request_id = crate::NwaRequestId::from_bytes([0x55; 16]);
        assert_ne!(stale.request_id, request.id());
        assert_eq!(
            manager.approve_nwa(request, stale, WakePolicy::default()),
            Err(NwaApprovalError::AuthorityEscalation)
        );

        let request = nwa_request();
        let mut fee_exclusion = nwa_approval(&request, [NwcMethod::GetInfo]);
        fee_exclusion.policy = ConnectionPolicy::new(
            [NwcMethod::GetInfo],
            BudgetPolicy::new(
                500,
                BudgetInterval::Daily,
                FeePolicy::ExcludeForCompatibility,
            ),
        );
        assert_eq!(
            manager.approve_nwa(request, fee_exclusion, WakePolicy::default()),
            Err(NwaApprovalError::AuthorityEscalation)
        );
    }

    #[test]
    fn nwa_approval_uses_the_managers_configured_relay_bound() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let clock = FixedClock(UnixTimestamp::from_secs(101));
        let wake_policy = WakePolicy::new(
            Duration::from_secs(10 * 60),
            Duration::from_secs(30),
            Duration::from_secs(24 * 60 * 60),
            64 * 1024,
            3,
        )
        .expect("wake policy");
        let manager = ConnectionManager::new(&ledger, &clock);
        let parse_policy = NwaParsePolicy::new(
            8 * 1024,
            3,
            80,
            Duration::from_secs(30 * 24 * 60 * 60),
            1_000_000,
        );
        let request = NwaRequest::parse(
            &format!(
                "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Fone.example&relay=wss%3A%2F%2Ftwo.example&relay=wss%3A%2F%2Fthree.example&request_methods=get_info"
            ),
            UnixTimestamp::from_secs(100),
            &parse_policy,
        )
        .expect("three-relay request");
        let approval = NwaApproval::new(
            request.id(),
            ConnectionId::parse("connection:three-relays").expect("connection id"),
            PublicKey::from_hex(WALLET).expect("wallet key"),
            request
                .relays()
                .iter()
                .map(|relay| SecureRelayUrl::parse(relay).expect("relay"))
                .collect(),
            ConnectionPolicy::conservative_default(),
            NwcEncryption::LegacyNip04,
            None,
        );

        let approved = manager
            .approve_nwa(request, approval, wake_policy)
            .expect("approve three relays");
        assert_eq!(approved.connection().relays().len(), 3);
    }
}
