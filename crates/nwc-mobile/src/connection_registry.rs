use std::collections::HashSet;
use std::fmt;

use nostr::PublicKey as NostrPublicKey;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::{
    BudgetInterval, BudgetPolicy, ConnectionId, ConnectionPolicy, ConnectionRevision, FeePolicy,
    NwcEncryption, NwcMethod, PublicKey, SecureRelayUrl, UnixTimestamp, WakeLedger, WakePolicy,
};

const MAX_CONNECTION_RELAYS: usize = 8;

/// A stable, non-sensitive connection-registry error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegistryError {
    /// SQLite or the containing directory is unavailable.
    DatabaseUnavailable,
    /// Persisted connection data violated a registry invariant.
    CorruptData,
    /// A timestamp, revision, or amount could not be represented safely.
    ValueOutOfRange,
    /// A proposed connection violated a key, relay, or policy invariant.
    InvalidConnection,
    /// The connection id or active key pair already exists.
    AlreadyExists,
    /// The requested connection does not exist.
    NotFound,
    /// The expected connection revision was stale.
    StaleRevision,
    /// The connection is already permanently tombstoned.
    AlreadyTombstoned,
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DatabaseUnavailable => "connection registry is unavailable",
            Self::CorruptData => "connection registry contains invalid data",
            Self::ValueOutOfRange => "connection registry value is out of range",
            Self::InvalidConnection => "connection violates registry policy",
            Self::AlreadyExists => "connection already exists",
            Self::NotFound => "connection was not found",
            Self::StaleRevision => "connection revision is stale",
            Self::AlreadyTombstoned => "connection is already tombstoned",
        })
    }
}

impl std::error::Error for RegistryError {}

impl From<rusqlite::Error> for RegistryError {
    fn from(_: rusqlite::Error) -> Self {
        Self::DatabaseUnavailable
    }
}

/// A validated authorization snapshot ready to insert into the registry.
#[derive(Clone, Eq, PartialEq)]
pub struct NewConnection {
    id: ConnectionId,
    client_pubkey: PublicKey,
    wallet_service_pubkey: PublicKey,
    relays: Vec<SecureRelayUrl>,
    policy: ConnectionPolicy,
    encryption: NwcEncryption,
}

impl NewConnection {
    /// Validates a new connection against the wake relay bound.
    pub fn new(
        id: ConnectionId,
        client_pubkey: PublicKey,
        wallet_service_pubkey: PublicKey,
        relays: Vec<SecureRelayUrl>,
        policy: ConnectionPolicy,
        encryption: NwcEncryption,
        wake_policy: WakePolicy,
    ) -> Result<Self, RegistryError> {
        if client_pubkey == wallet_service_pubkey
            || NostrPublicKey::from_slice(client_pubkey.as_bytes()).is_err()
            || NostrPublicKey::from_slice(wallet_service_pubkey.as_bytes()).is_err()
            || relays.is_empty()
            || relays.len() > wake_policy.maximum_relays_per_connection()
            || relays.len() > MAX_CONNECTION_RELAYS
            || policy.methods().len() == 0
        {
            return Err(RegistryError::InvalidConnection);
        }
        let unique_relays = relays
            .iter()
            .map(SecureRelayUrl::as_str)
            .collect::<HashSet<_>>();
        if unique_relays.len() != relays.len() {
            return Err(RegistryError::InvalidConnection);
        }
        Ok(Self {
            id,
            client_pubkey,
            wallet_service_pubkey,
            relays,
            policy,
            encryption,
        })
    }
}

impl fmt::Debug for NewConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NewConnection")
            .field("id", &self.id)
            .field("client_pubkey", &self.client_pubkey)
            .field("wallet_service_pubkey", &self.wallet_service_pubkey)
            .field("relay_count", &self.relays.len())
            .field("method_count", &self.policy.methods().len())
            .field("encryption", &self.encryption)
            .finish()
    }
}

/// An active connection loaded atomically from the durable registry.
#[derive(Clone, Eq, PartialEq)]
pub struct ActiveConnection {
    id: ConnectionId,
    revision: ConnectionRevision,
    client_pubkey: PublicKey,
    wallet_service_pubkey: PublicKey,
    relays: Vec<SecureRelayUrl>,
    policy: ConnectionPolicy,
    encryption: NwcEncryption,
    created_at: UnixTimestamp,
    updated_at: UnixTimestamp,
}

impl ActiveConnection {
    /// Returns the stable connection identifier.
    #[must_use]
    pub const fn id(&self) -> &ConnectionId {
        &self.id
    }

    /// Returns the revision that must remain active through completion.
    #[must_use]
    pub const fn revision(&self) -> ConnectionRevision {
        self.revision
    }

    /// Returns the authorized NWC client public key.
    #[must_use]
    pub const fn client_pubkey(&self) -> &PublicKey {
        &self.client_pubkey
    }

    /// Returns the wallet-service public key.
    #[must_use]
    pub const fn wallet_service_pubkey(&self) -> &PublicKey {
        &self.wallet_service_pubkey
    }

    /// Returns the exact secure relay allowlist in approval order.
    #[must_use]
    pub fn relays(&self) -> &[SecureRelayUrl] {
        &self.relays
    }

    /// Returns the authorized methods and spending policy.
    #[must_use]
    pub const fn policy(&self) -> &ConnectionPolicy {
        &self.policy
    }

    /// Returns the negotiated NWC encryption mode.
    #[must_use]
    pub const fn encryption(&self) -> NwcEncryption {
        self.encryption
    }

    /// Returns when the connection was first persisted.
    #[must_use]
    pub const fn created_at(&self) -> UnixTimestamp {
        self.created_at
    }

    /// Returns when this revision was last changed.
    #[must_use]
    pub const fn updated_at(&self) -> UnixTimestamp {
        self.updated_at
    }

    /// Returns whether the supplied relay is exactly approved for this connection.
    #[must_use]
    pub fn allows_relay(&self, relay: &SecureRelayUrl) -> bool {
        self.relays.contains(relay)
    }
}

impl fmt::Debug for ActiveConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveConnection")
            .field("id", &self.id)
            .field("revision", &self.revision)
            .field("client_pubkey", &self.client_pubkey)
            .field("wallet_service_pubkey", &self.wallet_service_pubkey)
            .field("relay_count", &self.relays.len())
            .field("method_count", &self.policy.methods().len())
            .field("encryption", &self.encryption)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// A permanent revocation marker for a connection identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionTombstone {
    id: ConnectionId,
    revision: ConnectionRevision,
    tombstoned_at: UnixTimestamp,
}

impl ConnectionTombstone {
    /// Returns the revoked connection identifier.
    #[must_use]
    pub const fn id(&self) -> &ConnectionId {
        &self.id
    }

    /// Returns the revision created by revocation.
    #[must_use]
    pub const fn revision(&self) -> ConnectionRevision {
        self.revision
    }

    /// Returns when the connection was revoked.
    #[must_use]
    pub const fn tombstoned_at(&self) -> UnixTimestamp {
        self.tombstoned_at
    }
}

/// Either an active authorization snapshot or its permanent tombstone.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StoredConnection {
    /// The connection may authorize new work at this exact revision.
    Active(ActiveConnection),
    /// The connection is revoked and cannot be resurrected by stale work.
    Tombstoned(ConnectionTombstone),
}

struct ConnectionRow {
    id: String,
    revision: i64,
    status: String,
    client_pubkey: Vec<u8>,
    wallet_service_pubkey: Vec<u8>,
    encryption: String,
    budget_limit_sat: i64,
    budget_interval: String,
    fee_policy: String,
    maximum_fee_sat: i64,
    created_at: i64,
    updated_at: i64,
    tombstoned_at: Option<i64>,
}

impl WakeLedger {
    /// Inserts a new active connection at revision zero.
    ///
    /// A tombstoned identifier and its client/wallet key pair are never
    /// reusable, preventing old signed requests from regaining authority.
    pub fn insert_connection(
        &self,
        new_connection: NewConnection,
        now: UnixTimestamp,
    ) -> Result<ActiveConnection, RegistryError> {
        let now_sql = sqlite_u64(now.as_secs())?;
        let budget = new_connection.policy.budget();
        let budget_limit = sqlite_u64(budget.limit_sat())?;
        let (fee_policy, maximum_fee) = encode_fee_policy(budget.fee_policy())?;
        let mut connection = self
            .lock_connection()
            .map_err(|_| RegistryError::DatabaseUnavailable)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let id_exists = transaction
            .query_row(
                "SELECT 1 FROM connections WHERE connection_id = ?1",
                params![new_connection.id.as_str()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let keys_exist = transaction
            .query_row(
                "SELECT 1 FROM connections
                 WHERE client_pubkey = ?1 AND wallet_service_pubkey = ?2",
                params![
                    new_connection.client_pubkey.as_bytes().as_slice(),
                    new_connection.wallet_service_pubkey.as_bytes().as_slice()
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if id_exists || keys_exist {
            return Err(RegistryError::AlreadyExists);
        }

        transaction.execute(
            "INSERT INTO connections (
                connection_id, revision, status, client_pubkey, wallet_service_pubkey,
                encryption, budget_limit_sat, budget_interval, fee_policy,
                maximum_fee_sat, created_at, updated_at, tombstoned_at
             ) VALUES (?1, 0, 'active', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, NULL)",
            params![
                new_connection.id.as_str(),
                new_connection.client_pubkey.as_bytes().as_slice(),
                new_connection.wallet_service_pubkey.as_bytes().as_slice(),
                encryption_to_str(new_connection.encryption),
                budget_limit,
                interval_to_str(budget.interval()),
                fee_policy,
                maximum_fee,
                now_sql,
            ],
        )?;
        for method in new_connection.policy.methods() {
            transaction.execute(
                "INSERT INTO connection_methods (connection_id, method) VALUES (?1, ?2)",
                params![new_connection.id.as_str(), method.as_str()],
            )?;
        }
        for (position, relay) in new_connection.relays.iter().enumerate() {
            transaction.execute(
                "INSERT INTO connection_relays (connection_id, position, relay_url)
                 VALUES (?1, ?2, ?3)",
                params![
                    new_connection.id.as_str(),
                    i64::try_from(position).map_err(|_| RegistryError::ValueOutOfRange)?,
                    relay.as_str()
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO wake_registration_outbox (
                connection_id, connection_revision, desired_enabled,
                client_pubkey, wallet_service_pubkey, available_at, updated_at
             ) VALUES (?1, 0, 1, ?2, ?3, ?4, ?4)",
            params![
                new_connection.id.as_str(),
                new_connection.client_pubkey.as_bytes().as_slice(),
                new_connection.wallet_service_pubkey.as_bytes().as_slice(),
                now_sql,
            ],
        )?;
        transaction.execute(
            "INSERT INTO wake_registration_relays (connection_id, position, relay_url)
             SELECT connection_id, position, relay_url
             FROM connection_relays WHERE connection_id = ?1",
            params![new_connection.id.as_str()],
        )?;
        transaction.commit()?;

        Ok(ActiveConnection {
            id: new_connection.id,
            revision: ConnectionRevision::INITIAL,
            client_pubkey: new_connection.client_pubkey,
            wallet_service_pubkey: new_connection.wallet_service_pubkey,
            relays: new_connection.relays,
            policy: new_connection.policy,
            encryption: new_connection.encryption,
            created_at: now,
            updated_at: now,
        })
    }

    /// Loads an active connection by its stable identifier.
    pub fn load_active_connection(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<ActiveConnection>, RegistryError> {
        match self.load_connection(id)? {
            Some(StoredConnection::Active(connection)) => Ok(Some(connection)),
            Some(StoredConnection::Tombstoned(_)) | None => Ok(None),
        }
    }

    /// Loads an active connection by its authenticated client and wallet keys.
    pub fn load_active_connection_by_keys(
        &self,
        client_pubkey: &PublicKey,
        wallet_service_pubkey: &PublicKey,
    ) -> Result<Option<ActiveConnection>, RegistryError> {
        let mut connection = self
            .lock_connection()
            .map_err(|_| RegistryError::DatabaseUnavailable)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let row = transaction
            .query_row(
                "SELECT connection_id, revision, status, client_pubkey,
                        wallet_service_pubkey, encryption, budget_limit_sat,
                        budget_interval, fee_policy, maximum_fee_sat,
                        created_at, updated_at, tombstoned_at
                 FROM connections
                 WHERE status = 'active' AND client_pubkey = ?1 AND wallet_service_pubkey = ?2",
                params![
                    client_pubkey.as_bytes().as_slice(),
                    wallet_service_pubkey.as_bytes().as_slice()
                ],
                decode_connection_row,
            )
            .optional()?;
        let result = row
            .map(|row| hydrate_stored_connection(&transaction, row))
            .transpose()?
            .map(|stored| match stored {
                StoredConnection::Active(active) => Ok(active),
                StoredConnection::Tombstoned(_) => Err(RegistryError::CorruptData),
            })
            .transpose()?;
        transaction.commit()?;
        Ok(result)
    }

    /// Checks whether a wake relay belongs to any active connection for a
    /// wallet key before the engine performs network I/O.
    pub(crate) fn is_relay_approved_for_wallet(
        &self,
        wallet_service_pubkey: &PublicKey,
        relay: &SecureRelayUrl,
    ) -> Result<bool, RegistryError> {
        let connection = self
            .lock_connection()
            .map_err(|_| RegistryError::DatabaseUnavailable)?;
        connection
            .query_row(
                "SELECT 1
                 FROM connections AS c
                 JOIN connection_relays AS r ON r.connection_id = c.connection_id
                 WHERE c.status = 'active' AND c.wallet_service_pubkey = ?1
                   AND r.relay_url = ?2
                 LIMIT 1",
                params![wallet_service_pubkey.as_bytes().as_slice(), relay.as_str()],
                |_| Ok(()),
            )
            .optional()
            .map(|value| value.is_some())
            .map_err(Into::into)
    }

    /// Loads either the active authorization or permanent tombstone for an id.
    pub fn load_connection(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<StoredConnection>, RegistryError> {
        let mut connection = self
            .lock_connection()
            .map_err(|_| RegistryError::DatabaseUnavailable)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let row = transaction
            .query_row(
                "SELECT connection_id, revision, status, client_pubkey,
                        wallet_service_pubkey, encryption, budget_limit_sat,
                        budget_interval, fee_policy, maximum_fee_sat,
                        created_at, updated_at, tombstoned_at
                 FROM connections WHERE connection_id = ?1",
                params![id.as_str()],
                decode_connection_row,
            )
            .optional()?;
        let result = row
            .map(|row| hydrate_stored_connection(&transaction, row))
            .transpose()?;
        transaction.commit()?;
        Ok(result)
    }

    /// Returns whether the exact connection revision remains active.
    pub fn is_connection_revision_active(
        &self,
        id: &ConnectionId,
        revision: ConnectionRevision,
    ) -> Result<bool, RegistryError> {
        let revision = sqlite_u64(revision.value())?;
        let connection = self
            .lock_connection()
            .map_err(|_| RegistryError::DatabaseUnavailable)?;
        connection
            .query_row(
                "SELECT 1 FROM connections
                 WHERE connection_id = ?1 AND revision = ?2 AND status = 'active'",
                params![id.as_str(), revision],
                |_| Ok(()),
            )
            .optional()
            .map(|value| value.is_some())
            .map_err(Into::into)
    }

    /// Permanently tombstones an active connection at its expected revision.
    pub fn tombstone_connection(
        &self,
        id: &ConnectionId,
        expected_revision: ConnectionRevision,
        now: UnixTimestamp,
    ) -> Result<ConnectionTombstone, RegistryError> {
        let expected_sql = sqlite_u64(expected_revision.value())?;
        let next_revision = expected_revision
            .next()
            .map_err(|_| RegistryError::ValueOutOfRange)?;
        let next_sql = sqlite_u64(next_revision.value())?;
        let now_sql = sqlite_u64(now.as_secs())?;
        let mut connection = self
            .lock_connection()
            .map_err(|_| RegistryError::DatabaseUnavailable)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = transaction
            .query_row(
                "SELECT revision, status, created_at FROM connections WHERE connection_id = ?1",
                params![id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or(RegistryError::NotFound)?;
        if current.1 == "tombstoned" {
            return Err(RegistryError::AlreadyTombstoned);
        }
        if current.1 != "active" {
            return Err(RegistryError::CorruptData);
        }
        if current.0 != expected_sql {
            return Err(RegistryError::StaleRevision);
        }
        if now_sql < current.2 {
            return Err(RegistryError::ValueOutOfRange);
        }
        let updated = transaction.execute(
            "UPDATE connections
             SET status = 'tombstoned', revision = ?2,
                 updated_at = ?3, tombstoned_at = ?3
             WHERE connection_id = ?1 AND status = 'active' AND revision = ?4",
            params![id.as_str(), next_sql, now_sql, expected_sql],
        )?;
        if updated != 1 {
            return Err(RegistryError::StaleRevision);
        }
        transaction.execute(
            "INSERT INTO wake_registration_outbox (
                connection_id, connection_revision, desired_enabled,
                client_pubkey, wallet_service_pubkey, attempt_count,
                available_at, updated_at
             )
             SELECT connection_id, ?2, 0, client_pubkey, wallet_service_pubkey, 0, ?3, ?3
             FROM connections WHERE connection_id = ?1
             ON CONFLICT(connection_id) DO UPDATE SET
                 connection_revision = excluded.connection_revision,
                 desired_enabled = 0,
                 client_pubkey = excluded.client_pubkey,
                 wallet_service_pubkey = excluded.wallet_service_pubkey,
                 attempt_count = 0,
                 available_at = excluded.available_at,
                 updated_at = excluded.updated_at",
            params![id.as_str(), next_sql, now_sql],
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO wake_registration_relays (
                connection_id, position, relay_url
             )
             SELECT connection_id, position, relay_url
             FROM connection_relays WHERE connection_id = ?1",
            params![id.as_str()],
        )?;
        transaction.execute(
            "DELETE FROM connection_methods WHERE connection_id = ?1",
            params![id.as_str()],
        )?;
        transaction.execute(
            "DELETE FROM connection_relays WHERE connection_id = ?1",
            params![id.as_str()],
        )?;
        transaction.commit()?;
        Ok(ConnectionTombstone {
            id: id.clone(),
            revision: next_revision,
            tombstoned_at: now,
        })
    }
}

fn decode_connection_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConnectionRow> {
    Ok(ConnectionRow {
        id: row.get(0)?,
        revision: row.get(1)?,
        status: row.get(2)?,
        client_pubkey: row.get(3)?,
        wallet_service_pubkey: row.get(4)?,
        encryption: row.get(5)?,
        budget_limit_sat: row.get(6)?,
        budget_interval: row.get(7)?,
        fee_policy: row.get(8)?,
        maximum_fee_sat: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
        tombstoned_at: row.get(12)?,
    })
}

fn hydrate_stored_connection(
    connection: &Connection,
    row: ConnectionRow,
) -> Result<StoredConnection, RegistryError> {
    let id = ConnectionId::parse(row.id).map_err(|_| RegistryError::CorruptData)?;
    let revision = decode_revision(row.revision)?;
    let created_at = decode_timestamp(row.created_at)?;
    let updated_at = decode_timestamp(row.updated_at)?;
    if row.updated_at < row.created_at {
        return Err(RegistryError::CorruptData);
    }
    match row.status.as_str() {
        "tombstoned" => {
            let tombstoned_at = row
                .tombstoned_at
                .ok_or(RegistryError::CorruptData)
                .and_then(decode_timestamp)?;
            if tombstoned_at != updated_at {
                return Err(RegistryError::CorruptData);
            }
            return Ok(StoredConnection::Tombstoned(ConnectionTombstone {
                id,
                revision,
                tombstoned_at,
            }));
        }
        "active" if row.tombstoned_at.is_none() => {}
        _ => return Err(RegistryError::CorruptData),
    }

    let client_pubkey = decode_public_key(row.client_pubkey)?;
    let wallet_service_pubkey = decode_public_key(row.wallet_service_pubkey)?;
    if client_pubkey == wallet_service_pubkey {
        return Err(RegistryError::CorruptData);
    }
    let encryption = str_to_encryption(&row.encryption)?;
    let methods = load_methods(connection, &id)?;
    if methods.is_empty() {
        return Err(RegistryError::CorruptData);
    }
    let relays = load_relays(connection, &id)?;
    if relays.is_empty() || relays.len() > MAX_CONNECTION_RELAYS {
        return Err(RegistryError::CorruptData);
    }
    let limit = decode_u64(row.budget_limit_sat)?;
    let maximum_fee = decode_u64(row.maximum_fee_sat)?;
    let interval = str_to_interval(&row.budget_interval)?;
    let fee_policy = str_to_fee_policy(&row.fee_policy, maximum_fee)?;
    let policy = ConnectionPolicy::new(methods, BudgetPolicy::new(limit, interval, fee_policy));

    Ok(StoredConnection::Active(ActiveConnection {
        id,
        revision,
        client_pubkey,
        wallet_service_pubkey,
        relays,
        policy,
        encryption,
        created_at,
        updated_at,
    }))
}

fn load_methods(
    connection: &Connection,
    id: &ConnectionId,
) -> Result<Vec<NwcMethod>, RegistryError> {
    let mut statement = connection.prepare(
        "SELECT method FROM connection_methods WHERE connection_id = ?1 ORDER BY method",
    )?;
    let methods = statement
        .query_map(params![id.as_str()], |row| row.get::<_, String>(0))?
        .map(|value| {
            value
                .map_err(RegistryError::from)
                .and_then(|value| str_to_method(&value))
        })
        .collect();
    methods
}

fn load_relays(
    connection: &Connection,
    id: &ConnectionId,
) -> Result<Vec<SecureRelayUrl>, RegistryError> {
    let mut statement = connection.prepare(
        "SELECT relay_url FROM connection_relays
         WHERE connection_id = ?1 ORDER BY position",
    )?;
    let relays = statement
        .query_map(params![id.as_str()], |row| row.get::<_, String>(0))?
        .map(|value| {
            value.map_err(RegistryError::from).and_then(|value| {
                SecureRelayUrl::parse(&value).map_err(|_| RegistryError::CorruptData)
            })
        })
        .collect();
    relays
}

fn decode_public_key(value: Vec<u8>) -> Result<PublicKey, RegistryError> {
    let bytes: [u8; 32] = value.try_into().map_err(|_| RegistryError::CorruptData)?;
    NostrPublicKey::from_slice(&bytes).map_err(|_| RegistryError::CorruptData)?;
    Ok(PublicKey::from_bytes(bytes))
}

fn sqlite_u64(value: u64) -> Result<i64, RegistryError> {
    i64::try_from(value).map_err(|_| RegistryError::ValueOutOfRange)
}

fn decode_u64(value: i64) -> Result<u64, RegistryError> {
    u64::try_from(value).map_err(|_| RegistryError::CorruptData)
}

fn decode_timestamp(value: i64) -> Result<UnixTimestamp, RegistryError> {
    decode_u64(value).map(UnixTimestamp::from_secs)
}

fn decode_revision(value: i64) -> Result<ConnectionRevision, RegistryError> {
    decode_u64(value).map(ConnectionRevision::from_value)
}

fn encryption_to_str(encryption: NwcEncryption) -> &'static str {
    match encryption {
        NwcEncryption::Nip44V2 => "nip44_v2",
        NwcEncryption::LegacyNip04 => "nip04",
    }
}

fn str_to_encryption(value: &str) -> Result<NwcEncryption, RegistryError> {
    match value {
        "nip44_v2" => Ok(NwcEncryption::Nip44V2),
        "nip04" => Ok(NwcEncryption::LegacyNip04),
        _ => Err(RegistryError::CorruptData),
    }
}

fn interval_to_str(interval: BudgetInterval) -> &'static str {
    match interval {
        BudgetInterval::Never => "never",
        BudgetInterval::Hourly => "hourly",
        BudgetInterval::Daily => "daily",
        BudgetInterval::Weekly => "weekly",
        BudgetInterval::Monthly => "monthly",
        BudgetInterval::Yearly => "yearly",
    }
}

fn str_to_interval(value: &str) -> Result<BudgetInterval, RegistryError> {
    match value {
        "never" => Ok(BudgetInterval::Never),
        "hourly" => Ok(BudgetInterval::Hourly),
        "daily" => Ok(BudgetInterval::Daily),
        "weekly" => Ok(BudgetInterval::Weekly),
        "monthly" => Ok(BudgetInterval::Monthly),
        "yearly" => Ok(BudgetInterval::Yearly),
        _ => Err(RegistryError::CorruptData),
    }
}

fn encode_fee_policy(policy: FeePolicy) -> Result<(&'static str, i64), RegistryError> {
    match policy {
        FeePolicy::CountTowardBudget { maximum_fee_sat } => {
            Ok(("count", sqlite_u64(maximum_fee_sat)?))
        }
        FeePolicy::ExcludeForCompatibility => Ok(("exclude", 0)),
    }
}

fn str_to_fee_policy(value: &str, maximum_fee_sat: u64) -> Result<FeePolicy, RegistryError> {
    match value {
        "count" => Ok(FeePolicy::CountTowardBudget { maximum_fee_sat }),
        "exclude" if maximum_fee_sat == 0 => Ok(FeePolicy::ExcludeForCompatibility),
        _ => Err(RegistryError::CorruptData),
    }
}

fn str_to_method(value: &str) -> Result<NwcMethod, RegistryError> {
    match value {
        "get_info" => Ok(NwcMethod::GetInfo),
        "get_balance" => Ok(NwcMethod::GetBalance),
        "make_invoice" => Ok(NwcMethod::MakeInvoice),
        "pay_invoice" => Ok(NwcMethod::PayInvoice),
        "lookup_invoice" => Ok(NwcMethod::LookupInvoice),
        "list_transactions" => Ok(NwcMethod::ListTransactions),
        _ => Err(RegistryError::CorruptData),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;
    use crate::{ClaimOutcome, LedgerError};

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
                "nwc-mobile-connections-{}-{suffix}",
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

    fn connection_id() -> ConnectionId {
        ConnectionId::parse("connection:test").expect("connection id")
    }

    fn new_connection(id: ConnectionId) -> NewConnection {
        NewConnection::new(
            id,
            PublicKey::from_hex(CLIENT).expect("client key"),
            PublicKey::from_hex(WALLET).expect("wallet key"),
            vec![
                SecureRelayUrl::parse("wss://one.example.com/nwc/").expect("relay"),
                SecureRelayUrl::parse("wss://two.example.com").expect("relay"),
            ],
            ConnectionPolicy::new(
                [NwcMethod::GetInfo, NwcMethod::GetBalance],
                BudgetPolicy::new(
                    1_000,
                    BudgetInterval::Daily,
                    FeePolicy::CountTowardBudget {
                        maximum_fee_sat: 25,
                    },
                ),
            ),
            NwcEncryption::Nip44V2,
            WakePolicy::default(),
        )
        .expect("new connection")
    }

    #[test]
    fn active_authorization_survives_reopen_without_losing_policy() {
        let database = TestDatabase::new();
        {
            let ledger = WakeLedger::open(&database.path).expect("ledger");
            let active = ledger
                .insert_connection(
                    new_connection(connection_id()),
                    UnixTimestamp::from_secs(100),
                )
                .expect("insert connection");
            assert_eq!(active.revision(), ConnectionRevision::INITIAL);
        }

        let reopened = WakeLedger::open(&database.path).expect("reopen ledger");
        let active = reopened
            .load_active_connection(&connection_id())
            .expect("load connection")
            .expect("active connection");
        assert_eq!(active.relays().len(), 2);
        assert!(active.policy().allows(NwcMethod::GetInfo));
        assert!(active.policy().allows(NwcMethod::GetBalance));
        assert!(!active.policy().allows(NwcMethod::PayInvoice));
        assert_eq!(active.policy().budget().limit_sat(), 1_000);
        assert_eq!(active.encryption(), NwcEncryption::Nip44V2);
        assert_eq!(active.created_at(), UnixTimestamp::from_secs(100));
    }

    #[test]
    fn tombstone_advances_revision_and_blocks_stale_snapshots() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let active = ledger
            .insert_connection(
                new_connection(connection_id()),
                UnixTimestamp::from_secs(100),
            )
            .expect("insert connection");
        let tombstone = ledger
            .tombstone_connection(
                active.id(),
                active.revision(),
                UnixTimestamp::from_secs(110),
            )
            .expect("tombstone");

        assert_eq!(tombstone.revision(), ConnectionRevision::from_value(1));
        assert!(!ledger
            .is_connection_revision_active(active.id(), active.revision())
            .expect("revision check"));
        assert!(ledger
            .load_active_connection(active.id())
            .expect("active lookup")
            .is_none());
        assert!(matches!(
            ledger.load_connection(active.id()).expect("stored lookup"),
            Some(StoredConnection::Tombstoned(_))
        ));
        assert_eq!(
            ledger.tombstone_connection(
                active.id(),
                active.revision(),
                UnixTimestamp::from_secs(111),
            ),
            Err(RegistryError::AlreadyTombstoned)
        );
        assert_eq!(
            ledger.insert_connection(
                new_connection(connection_id()),
                UnixTimestamp::from_secs(120),
            ),
            Err(RegistryError::AlreadyExists)
        );
        assert_eq!(
            ledger.insert_connection(
                new_connection(ConnectionId::parse("connection:new-id").expect("new id")),
                UnixTimestamp::from_secs(120),
            ),
            Err(RegistryError::AlreadyExists)
        );

        let database = ledger.lock_connection().expect("database lock");
        for table in ["connection_methods", "connection_relays"] {
            let count: i64 = database
                .query_row(
                    &format!("SELECT count(*) FROM {table} WHERE connection_id = ?1"),
                    params![active.id().as_str()],
                    |row| row.get(0),
                )
                .expect("tombstone metadata count");
            assert_eq!(count, 0);
        }
    }

    #[test]
    fn terminal_completion_is_atomic_with_active_revision() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let active = ledger
            .insert_connection(
                new_connection(connection_id()),
                UnixTimestamp::from_secs(90),
            )
            .expect("insert connection");

        let completed_id = crate::EventId::from_bytes([9_u8; 32]);
        let ClaimOutcome::Acquired(completed_lease) = ledger
            .claim_event(
                &completed_id,
                active.id(),
                active.revision(),
                UnixTimestamp::from_secs(100),
                Duration::from_secs(10),
            )
            .expect("claim active event")
        else {
            panic!("active event was not acquired");
        };
        ledger
            .complete_event_for_active_connection(
                &completed_lease,
                active.id(),
                active.revision(),
                "encrypted-response",
                UnixTimestamp::from_secs(101),
            )
            .expect("complete active event");

        let revoked_id = crate::EventId::from_bytes([10_u8; 32]);
        let ClaimOutcome::Acquired(revoked_lease) = ledger
            .claim_event(
                &revoked_id,
                active.id(),
                active.revision(),
                UnixTimestamp::from_secs(102),
                Duration::from_secs(10),
            )
            .expect("claim event before revocation")
        else {
            panic!("event before revocation was not acquired");
        };
        assert!(ledger
            .is_connection_revision_active(active.id(), active.revision())
            .expect("pre-completion revision check"));
        ledger
            .tombstone_connection(
                active.id(),
                active.revision(),
                UnixTimestamp::from_secs(103),
            )
            .expect("tombstone between check and completion");

        assert_eq!(
            ledger.complete_event_for_active_connection(
                &revoked_lease,
                active.id(),
                active.revision(),
                "must-not-persist",
                UnixTimestamp::from_secs(104),
            ),
            Err(LedgerError::ConnectionUnavailable)
        );
        assert!(matches!(
            ledger
                .claim_event(
                    &revoked_id,
                    active.id(),
                    active.revision(),
                    UnixTimestamp::from_secs(105),
                    Duration::from_secs(10),
                )
                .expect("inspect nonterminal event"),
            ClaimOutcome::InProgress { .. }
        ));
    }

    #[test]
    fn active_key_lookup_is_exact_and_unique() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let active = ledger
            .insert_connection(
                new_connection(connection_id()),
                UnixTimestamp::from_secs(100),
            )
            .expect("insert connection");

        let found = ledger
            .load_active_connection_by_keys(active.client_pubkey(), active.wallet_service_pubkey())
            .expect("key lookup")
            .expect("active keys");
        assert_eq!(found.id(), active.id());
        let duplicate_id = ConnectionId::parse("connection:duplicate").expect("id");
        assert_eq!(
            ledger.insert_connection(new_connection(duplicate_id), UnixTimestamp::from_secs(101),),
            Err(RegistryError::AlreadyExists)
        );
    }

    #[test]
    fn new_connection_rejects_invalid_key_and_relay_sets() {
        let valid_client = PublicKey::from_hex(CLIENT).expect("client key");
        let valid_wallet = PublicKey::from_hex(WALLET).expect("wallet key");
        let policy = ConnectionPolicy::conservative_default();

        assert_eq!(
            NewConnection::new(
                connection_id(),
                valid_client.clone(),
                valid_wallet,
                Vec::new(),
                policy.clone(),
                NwcEncryption::Nip44V2,
                WakePolicy::default(),
            ),
            Err(RegistryError::InvalidConnection)
        );
        assert_eq!(
            NewConnection::new(
                connection_id(),
                valid_client.clone(),
                valid_client,
                vec![SecureRelayUrl::parse("wss://relay.example.com").expect("relay")],
                policy,
                NwcEncryption::Nip44V2,
                WakePolicy::default(),
            ),
            Err(RegistryError::InvalidConnection)
        );
    }

    #[test]
    fn registry_debug_output_redacts_authorization_details() {
        let new = new_connection(connection_id());
        let debug = format!("{new:?}");

        assert!(!debug.contains(CLIENT));
        assert!(!debug.contains(WALLET));
        assert!(!debug.contains("one.example.com"));
        assert!(!debug.contains("1000"));
    }
}
