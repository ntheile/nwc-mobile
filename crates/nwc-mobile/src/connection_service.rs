use crate::{
    ActiveConnection, Clock, ConnectionId, ConnectionRevision, ConnectionTombstone, NewConnection,
    RegistryError, StoredConnection, UnixTimestamp, WakeLedger,
};

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
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use crate::{
        BudgetInterval, BudgetPolicy, ConnectionPolicy, FeePolicy, NwcEncryption, NwcMethod,
        PublicKey, SecureRelayUrl, WakePolicy,
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
}
