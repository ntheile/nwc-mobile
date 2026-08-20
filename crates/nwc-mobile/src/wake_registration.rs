use std::fmt;
use std::time::Duration;

use nostr::PublicKey as NostrPublicKey;
use rusqlite::{params, TransactionBehavior};

use crate::{
    ConnectionId, ConnectionRevision, PublicKey, SecureRelayUrl, UnixTimestamp, WakeLedger,
};

/// Maximum durable registration changes returned by one outbox query.
pub const MAX_WAKE_REGISTRATION_BATCH: usize = 100;
const MAX_REGISTRATION_RELAYS: usize = 8;

/// A stable, non-sensitive wake-registration outbox failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WakeRegistrationError {
    /// SQLite or the containing directory is unavailable.
    DatabaseUnavailable,
    /// Persisted registration state violated an invariant.
    CorruptData,
    /// A timestamp, revision, counter, or delay was not safely representable.
    ValueOutOfRange,
    /// A due-work query requested zero or too many rows.
    InvalidBatchSize,
    /// The change was acknowledged or superseded by a newer connection revision.
    StaleChange,
    /// A retry delay was zero or shorter than one second.
    InvalidRetryDelay,
}

impl fmt::Display for WakeRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DatabaseUnavailable => "wake registration outbox is unavailable",
            Self::CorruptData => "wake registration outbox contains invalid data",
            Self::ValueOutOfRange => "wake registration outbox value is out of range",
            Self::InvalidBatchSize => "wake registration batch size is invalid",
            Self::StaleChange => "wake registration change is stale",
            Self::InvalidRetryDelay => "wake registration retry delay is invalid",
        })
    }
}

impl std::error::Error for WakeRegistrationError {}

impl From<rusqlite::Error> for WakeRegistrationError {
    fn from(_: rusqlite::Error) -> Self {
        Self::DatabaseUnavailable
    }
}

/// The latest durable registration state a wake provider must observe.
#[derive(Clone, Eq, PartialEq)]
pub struct WakeRegistrationChange {
    connection_id: ConnectionId,
    connection_revision: ConnectionRevision,
    enabled: bool,
    client_pubkey: PublicKey,
    wallet_service_pubkey: PublicKey,
    relays: Vec<SecureRelayUrl>,
    attempt_count: u32,
    available_at: UnixTimestamp,
    updated_at: UnixTimestamp,
}

impl WakeRegistrationChange {
    /// Returns the stable connection identifier used as the idempotency scope.
    #[must_use]
    pub const fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    /// Returns the monotonic connection revision the provider must apply.
    ///
    /// Wake providers must reject an older revision after observing a newer one,
    /// even if network delivery reorders otherwise idempotent requests.
    #[must_use]
    pub const fn connection_revision(&self) -> ConnectionRevision {
        self.connection_revision
    }

    /// Returns the desired provider state for this exact revision.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the public NWC client key used for wake routing.
    #[must_use]
    pub const fn client_pubkey(&self) -> &PublicKey {
        &self.client_pubkey
    }

    /// Returns the public wallet-service key used for wake routing.
    #[must_use]
    pub const fn wallet_service_pubkey(&self) -> &PublicKey {
        &self.wallet_service_pubkey
    }

    /// Returns the approved secure relay set copied before any tombstone scrub.
    #[must_use]
    pub fn relays(&self) -> &[SecureRelayUrl] {
        &self.relays
    }

    /// Returns how many retry decisions were durably recorded.
    #[must_use]
    pub const fn attempt_count(&self) -> u32 {
        self.attempt_count
    }

    /// Returns the earliest time this change may be retried.
    #[must_use]
    pub const fn available_at(&self) -> UnixTimestamp {
        self.available_at
    }

    /// Returns when this desired state was last durably changed.
    #[must_use]
    pub const fn updated_at(&self) -> UnixTimestamp {
        self.updated_at
    }
}

impl fmt::Debug for WakeRegistrationChange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WakeRegistrationChange")
            .field("connection_id", &self.connection_id)
            .field("connection_revision", &self.connection_revision)
            .field("enabled", &self.enabled)
            .field("relay_count", &self.relays.len())
            .field("attempt_count", &self.attempt_count)
            .field("available_at", &self.available_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl WakeLedger {
    /// Loads a bounded batch of due registration changes in stable order.
    pub fn load_due_wake_registrations(
        &self,
        now: UnixTimestamp,
        maximum_rows: usize,
    ) -> Result<Vec<WakeRegistrationChange>, WakeRegistrationError> {
        if maximum_rows == 0 || maximum_rows > MAX_WAKE_REGISTRATION_BATCH {
            return Err(WakeRegistrationError::InvalidBatchSize);
        }
        let now_sql = sqlite_u64(now.as_secs())?;
        let limit =
            i64::try_from(maximum_rows).map_err(|_| WakeRegistrationError::InvalidBatchSize)?;
        let mut database = self
            .lock_connection()
            .map_err(|_| WakeRegistrationError::DatabaseUnavailable)?;
        let transaction = database.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let rows = {
            let mut statement = transaction.prepare(
                "SELECT connection_id, connection_revision, desired_enabled,
                        client_pubkey, wallet_service_pubkey, attempt_count,
                        available_at, updated_at
                 FROM wake_registration_outbox
                 WHERE available_at <= ?1
                 ORDER BY available_at ASC, connection_id ASC
                 LIMIT ?2",
            )?;
            let mapped = statement.query_map(params![now_sql, limit], |row| {
                Ok(RegistrationRow {
                    connection_id: row.get(0)?,
                    connection_revision: row.get(1)?,
                    desired_enabled: row.get(2)?,
                    client_pubkey: row.get(3)?,
                    wallet_service_pubkey: row.get(4)?,
                    attempt_count: row.get(5)?,
                    available_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            })?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };

        let mut changes = Vec::with_capacity(rows.len());
        for row in rows {
            changes.push(hydrate_change(&transaction, row)?);
        }
        transaction.commit()?;
        Ok(changes)
    }

    /// Removes a change only if it is still the latest desired revision.
    pub fn acknowledge_wake_registration(
        &self,
        change: &WakeRegistrationChange,
    ) -> Result<(), WakeRegistrationError> {
        let revision = sqlite_u64(change.connection_revision.value())?;
        let database = self
            .lock_connection()
            .map_err(|_| WakeRegistrationError::DatabaseUnavailable)?;
        let removed = database.execute(
            "DELETE FROM wake_registration_outbox
             WHERE connection_id = ?1 AND connection_revision = ?2
               AND desired_enabled = ?3",
            params![change.connection_id.as_str(), revision, change.enabled],
        )?;
        if removed == 1 {
            Ok(())
        } else {
            Err(WakeRegistrationError::StaleChange)
        }
    }

    /// Defers a change only if no newer desired revision superseded it.
    pub fn retry_wake_registration(
        &self,
        change: &WakeRegistrationChange,
        now: UnixTimestamp,
        delay: Duration,
    ) -> Result<(), WakeRegistrationError> {
        let seconds = delay.as_secs();
        if delay.is_zero() || seconds == 0 {
            return Err(WakeRegistrationError::InvalidRetryDelay);
        }
        if now < change.updated_at {
            return Err(WakeRegistrationError::ValueOutOfRange);
        }
        let available_at = now
            .as_secs()
            .checked_add(seconds)
            .ok_or(WakeRegistrationError::ValueOutOfRange)?;
        let revision = sqlite_u64(change.connection_revision.value())?;
        let database = self
            .lock_connection()
            .map_err(|_| WakeRegistrationError::DatabaseUnavailable)?;
        let updated = database.execute(
            "UPDATE wake_registration_outbox
             SET attempt_count = attempt_count + 1,
                 available_at = ?4, updated_at = ?5
             WHERE connection_id = ?1 AND connection_revision = ?2
               AND desired_enabled = ?3 AND attempt_count < 2147483647",
            params![
                change.connection_id.as_str(),
                revision,
                change.enabled,
                sqlite_u64(available_at)?,
                sqlite_u64(now.as_secs())?,
            ],
        )?;
        if updated == 1 {
            Ok(())
        } else {
            Err(WakeRegistrationError::StaleChange)
        }
    }
}

struct RegistrationRow {
    connection_id: String,
    connection_revision: i64,
    desired_enabled: i64,
    client_pubkey: Vec<u8>,
    wallet_service_pubkey: Vec<u8>,
    attempt_count: i64,
    available_at: i64,
    updated_at: i64,
}

fn hydrate_change(
    transaction: &rusqlite::Transaction<'_>,
    row: RegistrationRow,
) -> Result<WakeRegistrationChange, WakeRegistrationError> {
    let connection_id =
        ConnectionId::parse(row.connection_id).map_err(|_| WakeRegistrationError::CorruptData)?;
    let connection_revision = ConnectionRevision::from_value(decode_u64(row.connection_revision)?);
    let enabled = match row.desired_enabled {
        0 => false,
        1 => true,
        _ => return Err(WakeRegistrationError::CorruptData),
    };
    let client_pubkey = decode_public_key(row.client_pubkey)?;
    let wallet_service_pubkey = decode_public_key(row.wallet_service_pubkey)?;
    if client_pubkey == wallet_service_pubkey {
        return Err(WakeRegistrationError::CorruptData);
    }
    let attempt_count =
        u32::try_from(row.attempt_count).map_err(|_| WakeRegistrationError::CorruptData)?;
    let available_at = UnixTimestamp::from_secs(decode_u64(row.available_at)?);
    let updated_at = UnixTimestamp::from_secs(decode_u64(row.updated_at)?);
    let mut statement = transaction.prepare(
        "SELECT relay_url FROM wake_registration_relays
         WHERE connection_id = ?1 ORDER BY position ASC",
    )?;
    let relay_rows = statement.query_map(params![connection_id.as_str()], |row| row.get(0))?;
    let mut relays = Vec::new();
    for relay in relay_rows {
        let relay: String = relay?;
        relays.push(SecureRelayUrl::parse(&relay).map_err(|_| WakeRegistrationError::CorruptData)?);
    }
    if relays.is_empty() || relays.len() > MAX_REGISTRATION_RELAYS {
        return Err(WakeRegistrationError::CorruptData);
    }

    Ok(WakeRegistrationChange {
        connection_id,
        connection_revision,
        enabled,
        client_pubkey,
        wallet_service_pubkey,
        relays,
        attempt_count,
        available_at,
        updated_at,
    })
}

fn decode_public_key(value: Vec<u8>) -> Result<PublicKey, WakeRegistrationError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| WakeRegistrationError::CorruptData)?;
    NostrPublicKey::from_slice(&bytes).map_err(|_| WakeRegistrationError::CorruptData)?;
    Ok(PublicKey::from_bytes(bytes))
}

fn sqlite_u64(value: u64) -> Result<i64, WakeRegistrationError> {
    i64::try_from(value).map_err(|_| WakeRegistrationError::ValueOutOfRange)
}

fn decode_u64(value: i64) -> Result<u64, WakeRegistrationError> {
    u64::try_from(value).map_err(|_| WakeRegistrationError::CorruptData)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use crate::{
        BudgetInterval, BudgetPolicy, ConnectionPolicy, FeePolicy, NewConnection, NwcEncryption,
        NwcMethod, WakePolicy,
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
            use std::fmt::Write as _;
            let suffix = random.iter().fold(String::new(), |mut suffix, byte| {
                write!(&mut suffix, "{byte:02x}").expect("write suffix");
                suffix
            });
            let directory = std::env::temp_dir().join(format!(
                "nwc-mobile-registration-{}-{suffix}",
                std::process::id()
            ));
            fs::create_dir(&directory).expect("create test directory");
            let path = directory.join("registration.sqlite3");
            Self { directory, path }
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn connection_id() -> ConnectionId {
        ConnectionId::parse("connection:registration-test").expect("connection id")
    }

    fn new_connection() -> NewConnection {
        NewConnection::new(
            connection_id(),
            PublicKey::from_hex(CLIENT).expect("client key"),
            PublicKey::from_hex(WALLET).expect("wallet key"),
            vec![
                SecureRelayUrl::parse("wss://one.example.com/nwc").expect("relay"),
                SecureRelayUrl::parse("wss://two.example.com").expect("relay"),
            ],
            ConnectionPolicy::new(
                [NwcMethod::GetInfo],
                BudgetPolicy::new(0, BudgetInterval::Never, FeePolicy::ExcludeForCompatibility),
            ),
            NwcEncryption::Nip44V2,
            WakePolicy::default(),
        )
        .expect("new connection")
    }

    #[test]
    fn connection_creation_atomically_queues_enable_with_public_metadata() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let active = ledger
            .insert_connection(new_connection(), UnixTimestamp::from_secs(100))
            .expect("insert connection");

        let changes = ledger
            .load_due_wake_registrations(UnixTimestamp::from_secs(100), 10)
            .expect("load outbox");
        assert_eq!(changes.len(), 1);
        let change = &changes[0];
        assert_eq!(change.connection_id(), active.id());
        assert_eq!(change.connection_revision(), active.revision());
        assert!(change.enabled());
        assert_eq!(change.client_pubkey(), active.client_pubkey());
        assert_eq!(
            change.wallet_service_pubkey(),
            active.wallet_service_pubkey()
        );
        assert_eq!(change.relays(), active.relays());
        assert_eq!(change.attempt_count(), 0);
    }

    #[test]
    fn tombstone_requeues_disable_after_enable_ack_and_preserves_relays() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let active = ledger
            .insert_connection(new_connection(), UnixTimestamp::from_secs(100))
            .expect("insert connection");
        let enable = ledger
            .load_due_wake_registrations(UnixTimestamp::from_secs(100), 1)
            .expect("load enable")
            .pop()
            .expect("enable");
        ledger
            .acknowledge_wake_registration(&enable)
            .expect("ack enable");
        assert!(ledger
            .load_due_wake_registrations(UnixTimestamp::from_secs(100), 1)
            .expect("empty outbox")
            .is_empty());

        let tombstone = ledger
            .tombstone_connection(
                active.id(),
                active.revision(),
                UnixTimestamp::from_secs(110),
            )
            .expect("tombstone");
        let disable = ledger
            .load_due_wake_registrations(UnixTimestamp::from_secs(110), 1)
            .expect("load disable")
            .pop()
            .expect("disable");

        assert!(!disable.enabled());
        assert_eq!(disable.connection_revision(), tombstone.revision());
        assert_eq!(disable.relays(), active.relays());
        assert_eq!(
            ledger.acknowledge_wake_registration(&enable),
            Err(WakeRegistrationError::StaleChange)
        );
    }

    #[test]
    fn retry_backoff_survives_reopen_and_stale_enable_cannot_replace_disable() {
        let database = TestDatabase::new();
        let active;
        let enable;
        {
            let ledger = WakeLedger::open(&database.path).expect("ledger");
            active = ledger
                .insert_connection(new_connection(), UnixTimestamp::from_secs(100))
                .expect("insert connection");
            enable = ledger
                .load_due_wake_registrations(UnixTimestamp::from_secs(100), 1)
                .expect("load enable")
                .pop()
                .expect("enable");
            ledger
                .tombstone_connection(
                    active.id(),
                    active.revision(),
                    UnixTimestamp::from_secs(101),
                )
                .expect("tombstone");
            assert_eq!(
                ledger.retry_wake_registration(
                    &enable,
                    UnixTimestamp::from_secs(102),
                    Duration::from_secs(5),
                ),
                Err(WakeRegistrationError::StaleChange)
            );
            let disable = ledger
                .load_due_wake_registrations(UnixTimestamp::from_secs(102), 1)
                .expect("load disable")
                .pop()
                .expect("disable");
            ledger
                .retry_wake_registration(
                    &disable,
                    UnixTimestamp::from_secs(102),
                    Duration::from_secs(5),
                )
                .expect("defer disable");
        }

        let reopened = WakeLedger::open(&database.path).expect("reopen ledger");
        assert!(reopened
            .load_due_wake_registrations(UnixTimestamp::from_secs(106), 1)
            .expect("not due")
            .is_empty());
        let due = reopened
            .load_due_wake_registrations(UnixTimestamp::from_secs(107), 1)
            .expect("due disable")
            .pop()
            .expect("disable");
        assert!(!due.enabled());
        assert_eq!(due.attempt_count(), 1);
        assert_eq!(due.available_at(), UnixTimestamp::from_secs(107));
        reopened
            .acknowledge_wake_registration(&due)
            .expect("ack disable");
    }

    #[test]
    fn batch_and_retry_bounds_fail_closed() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        ledger
            .insert_connection(new_connection(), UnixTimestamp::from_secs(100))
            .expect("insert connection");
        assert_eq!(
            ledger.load_due_wake_registrations(UnixTimestamp::from_secs(100), 0),
            Err(WakeRegistrationError::InvalidBatchSize)
        );
        assert_eq!(
            ledger.load_due_wake_registrations(
                UnixTimestamp::from_secs(100),
                MAX_WAKE_REGISTRATION_BATCH + 1,
            ),
            Err(WakeRegistrationError::InvalidBatchSize)
        );
        let change = ledger
            .load_due_wake_registrations(UnixTimestamp::from_secs(100), 1)
            .expect("load change")
            .pop()
            .expect("change");
        assert_eq!(
            ledger.retry_wake_registration(
                &change,
                UnixTimestamp::from_secs(100),
                Duration::from_millis(500),
            ),
            Err(WakeRegistrationError::InvalidRetryDelay)
        );
    }

    #[test]
    fn debug_output_redacts_registration_routing_metadata() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        ledger
            .insert_connection(new_connection(), UnixTimestamp::from_secs(100))
            .expect("insert connection");
        let change = ledger
            .load_due_wake_registrations(UnixTimestamp::from_secs(100), 1)
            .expect("load change")
            .pop()
            .expect("change");
        let debug = format!("{change:?}");
        assert!(!debug.contains(CLIENT));
        assert!(!debug.contains(WALLET));
        assert!(!debug.contains("example.com"));
    }
}
