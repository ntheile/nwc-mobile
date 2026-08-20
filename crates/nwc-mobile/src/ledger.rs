use std::fmt;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};

use crate::{ConnectionId, ConnectionRevision, EventId, UnixTimestamp};

const SCHEMA_VERSION: i64 = 4;
const CLAIM_TOKEN_BYTES: usize = 16;
const MAX_RESPONSE_EVENT_BYTES: usize = 128 * 1024;
const MAX_PRUNE_BATCH: usize = 1_000;

const CREATE_SCHEMA: &str = r#"
CREATE TABLE wake_events (
    event_id            BLOB PRIMARY KEY NOT NULL
                        CHECK(typeof(event_id) = 'blob' AND length(event_id) = 32),
    connection_id       TEXT NOT NULL,
    connection_revision INTEGER NOT NULL CHECK(connection_revision >= 0),
    state               TEXT NOT NULL CHECK(state IN ('claimed', 'retryable', 'terminal')),
    claim_token         BLOB
                        CHECK(claim_token IS NULL OR
                              (typeof(claim_token) = 'blob' AND length(claim_token) = 16)),
    available_at        INTEGER,
    updated_at          INTEGER NOT NULL CHECK(updated_at >= 0),
    terminal_kind       TEXT CHECK(terminal_kind IN ('completed', 'rejected', 'failed')),
    response_event_json TEXT,
    CHECK(response_event_json IS NULL OR
          (typeof(response_event_json) = 'text' AND
           length(CAST(response_event_json AS BLOB)) <= 131072)),
    CHECK(
        (state = 'claimed' AND claim_token IS NOT NULL AND available_at IS NOT NULL AND
         terminal_kind IS NULL AND response_event_json IS NULL) OR
        (state = 'retryable' AND claim_token IS NULL AND available_at IS NOT NULL AND
         terminal_kind IS NULL AND response_event_json IS NULL) OR
        (state = 'terminal' AND claim_token IS NULL AND available_at IS NULL AND
         terminal_kind IS NOT NULL)
    )
) STRICT;

CREATE INDEX wake_events_terminal_updated
    ON wake_events(updated_at)
    WHERE state = 'terminal';
"#;

pub(crate) const CREATE_CONNECTION_SCHEMA: &str = r#"
CREATE TABLE connections (
    connection_id        TEXT PRIMARY KEY NOT NULL
                         CHECK(length(connection_id) BETWEEN 1 AND 128),
    revision             INTEGER NOT NULL CHECK(revision >= 0),
    status               TEXT NOT NULL CHECK(status IN ('active', 'tombstoned')),
    client_pubkey        BLOB NOT NULL
                         CHECK(typeof(client_pubkey) = 'blob' AND length(client_pubkey) = 32),
    wallet_service_pubkey BLOB NOT NULL
                         CHECK(typeof(wallet_service_pubkey) = 'blob' AND
                               length(wallet_service_pubkey) = 32),
    encryption           TEXT NOT NULL CHECK(encryption IN ('nip44_v2', 'nip04')),
    budget_limit_sat     INTEGER NOT NULL CHECK(budget_limit_sat >= 0),
    budget_interval      TEXT NOT NULL
                         CHECK(budget_interval IN
                               ('never', 'hourly', 'daily', 'weekly', 'monthly', 'yearly')),
    fee_policy           TEXT NOT NULL CHECK(fee_policy IN ('count', 'exclude')),
    maximum_fee_sat      INTEGER NOT NULL CHECK(maximum_fee_sat >= 0),
    created_at           INTEGER NOT NULL CHECK(created_at >= 0),
    updated_at           INTEGER NOT NULL CHECK(updated_at >= created_at),
    tombstoned_at        INTEGER,
    CHECK(
        (status = 'active' AND tombstoned_at IS NULL) OR
        (status = 'tombstoned' AND tombstoned_at IS NOT NULL AND
         tombstoned_at = updated_at)
    ),
    CHECK(
        (fee_policy = 'count') OR
        (fee_policy = 'exclude' AND maximum_fee_sat = 0)
    )
) STRICT;

CREATE UNIQUE INDEX connections_permanent_keys
    ON connections(client_pubkey, wallet_service_pubkey);

CREATE TABLE connection_methods (
    connection_id TEXT NOT NULL REFERENCES connections(connection_id) ON DELETE RESTRICT,
    method        TEXT NOT NULL
                  CHECK(method IN
                        ('get_info', 'get_balance', 'make_invoice', 'pay_invoice',
                         'lookup_invoice', 'list_transactions')),
    PRIMARY KEY(connection_id, method)
) STRICT;

CREATE TABLE connection_relays (
    connection_id TEXT NOT NULL REFERENCES connections(connection_id) ON DELETE RESTRICT,
    position      INTEGER NOT NULL CHECK(position >= 0),
    relay_url     TEXT NOT NULL,
    PRIMARY KEY(connection_id, position),
    UNIQUE(connection_id, relay_url)
) STRICT;
"#;

pub(crate) const CREATE_PAYMENT_SCHEMA: &str = r#"
CREATE TABLE budget_periods (
    connection_id    TEXT NOT NULL REFERENCES connections(connection_id) ON DELETE RESTRICT,
    period_started_at INTEGER NOT NULL CHECK(period_started_at >= 0),
    limit_sat        INTEGER NOT NULL CHECK(limit_sat >= 0),
    used_sat         INTEGER NOT NULL CHECK(used_sat >= 0),
    updated_at       INTEGER NOT NULL CHECK(updated_at >= period_started_at),
    PRIMARY KEY(connection_id, period_started_at)
) STRICT;

CREATE TABLE payment_attempts (
    event_id            BLOB PRIMARY KEY NOT NULL
                        CHECK(typeof(event_id) = 'blob' AND length(event_id) = 32),
    payment_hash        BLOB NOT NULL UNIQUE
                        CHECK(typeof(payment_hash) = 'blob' AND length(payment_hash) = 32),
    connection_id       TEXT NOT NULL,
    connection_revision INTEGER NOT NULL CHECK(connection_revision >= 0),
    period_started_at   INTEGER NOT NULL CHECK(period_started_at >= 0),
    principal_sat       INTEGER NOT NULL CHECK(principal_sat >= 0),
    fee_reserve_sat     INTEGER NOT NULL CHECK(fee_reserve_sat >= 0),
    reserved_sat        INTEGER NOT NULL CHECK(
                            reserved_sat >= principal_sat AND
                            fee_reserve_sat = reserved_sat - principal_sat
                        ),
    state               TEXT NOT NULL
                        CHECK(state IN ('reserved', 'pending', 'succeeded', 'failed')),
    actual_principal_sat INTEGER CHECK(actual_principal_sat >= 0),
    actual_fee_sat       INTEGER CHECK(actual_fee_sat >= 0),
    charged_sat          INTEGER CHECK(charged_sat >= 0),
    authorization_exceeded INTEGER NOT NULL DEFAULT 0
                           CHECK(authorization_exceeded IN (0, 1)),
    created_at           INTEGER NOT NULL CHECK(created_at >= period_started_at),
    updated_at           INTEGER NOT NULL CHECK(updated_at >= created_at),
    FOREIGN KEY(connection_id, period_started_at)
        REFERENCES budget_periods(connection_id, period_started_at) ON DELETE RESTRICT,
    CHECK(
        (state IN ('reserved', 'pending') AND actual_principal_sat IS NULL AND
         actual_fee_sat IS NULL AND charged_sat IS NULL AND authorization_exceeded = 0) OR
        (state = 'succeeded' AND actual_principal_sat IS NOT NULL AND
         actual_fee_sat IS NOT NULL AND charged_sat IS NOT NULL) OR
        (state = 'failed' AND actual_principal_sat IS NULL AND
         actual_fee_sat IS NULL AND charged_sat IS NULL AND authorization_exceeded = 0)
    )
) STRICT;

CREATE INDEX payment_attempts_connection_state
    ON payment_attempts(connection_id, state, updated_at);
"#;

pub(crate) const CREATE_WAKE_REGISTRATION_SCHEMA: &str = r#"
CREATE TABLE wake_registration_outbox (
    connection_id        TEXT PRIMARY KEY NOT NULL
                         REFERENCES connections(connection_id) ON DELETE RESTRICT,
    connection_revision  INTEGER NOT NULL CHECK(connection_revision >= 0),
    desired_enabled      INTEGER NOT NULL CHECK(desired_enabled IN (0, 1)),
    client_pubkey        BLOB NOT NULL
                         CHECK(typeof(client_pubkey) = 'blob' AND length(client_pubkey) = 32),
    wallet_service_pubkey BLOB NOT NULL
                         CHECK(typeof(wallet_service_pubkey) = 'blob' AND
                               length(wallet_service_pubkey) = 32),
    attempt_count        INTEGER NOT NULL DEFAULT 0
                         CHECK(attempt_count BETWEEN 0 AND 2147483647),
    available_at         INTEGER NOT NULL CHECK(available_at >= 0),
    updated_at           INTEGER NOT NULL CHECK(updated_at >= 0)
) STRICT;

CREATE INDEX wake_registration_outbox_due
    ON wake_registration_outbox(available_at, connection_id);

CREATE TABLE wake_registration_relays (
    connection_id TEXT NOT NULL
                  REFERENCES wake_registration_outbox(connection_id) ON DELETE CASCADE,
    position      INTEGER NOT NULL CHECK(position >= 0),
    relay_url     TEXT NOT NULL,
    PRIMARY KEY(connection_id, position),
    UNIQUE(connection_id, relay_url)
) STRICT;

INSERT INTO wake_registration_outbox (
    connection_id, connection_revision, desired_enabled,
    client_pubkey, wallet_service_pubkey, available_at, updated_at
)
SELECT connection_id, revision, 1, client_pubkey, wallet_service_pubkey,
       updated_at, updated_at
FROM connections
WHERE status = 'active';

INSERT INTO wake_registration_relays (connection_id, position, relay_url)
SELECT r.connection_id, r.position, r.relay_url
FROM connection_relays AS r
JOIN wake_registration_outbox AS o ON o.connection_id = r.connection_id;
"#;

/// A stable, non-sensitive durable-ledger error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LedgerError {
    /// SQLite or the containing directory is unavailable.
    DatabaseUnavailable,
    /// The database schema is newer than this library understands.
    UnsupportedSchema,
    /// Persisted data violated an expected type or state invariant.
    CorruptData,
    /// A timestamp or revision could not be represented safely by SQLite.
    ValueOutOfRange,
    /// A claim lease was empty, sub-second, or overflowed its timestamp.
    InvalidLease,
    /// Secure randomness for a claim token was unavailable.
    RandomnessUnavailable,
    /// An existing event id was associated with different connection metadata.
    ClaimMetadataMismatch,
    /// The connection revision associated with a completion is no longer active.
    ConnectionUnavailable,
    /// A completion or retry attempted to use an expired or replaced lease.
    LostLease,
    /// A persisted encrypted response exceeded the storage policy bound.
    ResponseTooLarge,
    /// A prune request used an empty or excessive batch size.
    InvalidPruneBatch,
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DatabaseUnavailable => "wake ledger is unavailable",
            Self::UnsupportedSchema => "wake ledger schema is unsupported",
            Self::CorruptData => "wake ledger contains invalid data",
            Self::ValueOutOfRange => "wake ledger value is out of range",
            Self::InvalidLease => "wake ledger lease is invalid",
            Self::RandomnessUnavailable => "wake ledger randomness is unavailable",
            Self::ClaimMetadataMismatch => "wake event metadata does not match its durable claim",
            Self::ConnectionUnavailable => "wake connection revision is no longer active",
            Self::LostLease => "wake event lease is no longer owned",
            Self::ResponseTooLarge => "wake response exceeds the durable storage bound",
            Self::InvalidPruneBatch => "wake ledger prune batch is invalid",
        })
    }
}

impl std::error::Error for LedgerError {}

impl From<rusqlite::Error> for LedgerError {
    fn from(_: rusqlite::Error) -> Self {
        Self::DatabaseUnavailable
    }
}

/// A terminal state retained for replay protection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TerminalKind {
    /// The request completed and any response was durably recorded.
    Completed,
    /// Security or authorization policy rejected the request.
    Rejected,
    /// Execution failed definitively and must not be replayed.
    Failed,
}

impl TerminalKind {
    const fn as_database_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
        }
    }

    fn from_database_str(value: &str) -> Result<Self, LedgerError> {
        match value {
            "completed" => Ok(Self::Completed),
            "rejected" => Ok(Self::Rejected),
            "failed" => Ok(Self::Failed),
            _ => Err(LedgerError::CorruptData),
        }
    }
}

/// Proof that this process currently owns an event claim.
#[derive(Clone, Eq, PartialEq)]
pub struct EventLease {
    event_id: EventId,
    token: [u8; CLAIM_TOKEN_BYTES],
    resumed: bool,
}

impl EventLease {
    /// Returns the claimed event id.
    #[must_use]
    pub const fn event_id(&self) -> &EventId {
        &self.event_id
    }

    /// Returns whether this lease resumed an expired claim or scheduled retry.
    #[must_use]
    pub const fn was_resumed(&self) -> bool {
        self.resumed
    }
}

impl fmt::Debug for EventLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventLease")
            .field("event_id", &self.event_id)
            .field("token", &"[redacted]")
            .field("resumed", &self.resumed)
            .finish()
    }
}

/// A durable terminal event returned for a replayed claim.
#[derive(Clone, Eq, PartialEq)]
pub struct TerminalEvent {
    event_id: EventId,
    kind: TerminalKind,
    response_event_json: Option<String>,
    completed_at: UnixTimestamp,
}

impl TerminalEvent {
    /// Returns the terminal event id.
    #[must_use]
    pub const fn event_id(&self) -> &EventId {
        &self.event_id
    }

    /// Returns the terminal classification.
    #[must_use]
    pub const fn kind(&self) -> TerminalKind {
        self.kind
    }

    /// Returns the encrypted response event for safe republishing, when stored.
    #[must_use]
    pub fn response_event_json(&self) -> Option<&str> {
        self.response_event_json.as_deref()
    }

    /// Returns when the request entered its terminal state.
    #[must_use]
    pub const fn completed_at(&self) -> UnixTimestamp {
        self.completed_at
    }
}

impl fmt::Debug for TerminalEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TerminalEvent")
            .field("event_id", &self.event_id)
            .field("kind", &self.kind)
            .field("has_response_event", &self.response_event_json.is_some())
            .field("completed_at", &self.completed_at)
            .finish()
    }
}

/// The result of atomically claiming an event id.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClaimOutcome {
    /// This caller acquired the only active lease.
    Acquired(EventLease),
    /// Another caller owns the event or it is delayed for retry.
    InProgress {
        /// Minimum time before policy should try the claim again.
        retry_after: Duration,
    },
    /// The event already reached a retained terminal state.
    Terminal(TerminalEvent),
}

#[derive(Clone)]
struct ExistingEvent {
    connection_id: String,
    connection_revision: i64,
    state: String,
    available_at: Option<i64>,
    terminal_kind: Option<String>,
    response_event_json: Option<String>,
    updated_at: i64,
}

/// A cross-process SQLite ledger for event claims and terminal replay state.
///
/// Each method uses a short SQLite transaction. Wallet, relay, and cryptographic
/// work must happen outside those transactions while the returned lease is held.
pub struct WakeLedger {
    connection: Mutex<Connection>,
}

impl WakeLedger {
    /// Opens or creates a ledger and applies supported migrations atomically.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX;
        let mut connection = Connection::open_with_flags(path, flags)?;
        connection.busy_timeout(Duration::from_secs(2))?;
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(LedgerError::DatabaseUnavailable);
        }
        connection.execute_batch(
            "PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;",
        )?;
        migrate(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Atomically acquires, observes, or reclaims an event lease.
    pub fn claim_event(
        &self,
        event_id: &EventId,
        connection_id: &ConnectionId,
        connection_revision: ConnectionRevision,
        now: UnixTimestamp,
        lease_duration: Duration,
    ) -> Result<ClaimOutcome, LedgerError> {
        let now = sqlite_timestamp(now)?;
        let revision = sqlite_revision(connection_revision)?;
        let lease_seconds = lease_duration.as_secs();
        if lease_duration.is_zero() || lease_seconds == 0 {
            return Err(LedgerError::InvalidLease);
        }
        let lease_expires = now
            .checked_add(i64::try_from(lease_seconds).map_err(|_| LedgerError::InvalidLease)?)
            .ok_or(LedgerError::InvalidLease)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = load_existing(&transaction, event_id)?;

        let outcome = match existing {
            None => {
                let token = new_claim_token()?;
                transaction.execute(
                    "INSERT INTO wake_events (
                        event_id, connection_id, connection_revision, state,
                        claim_token, available_at, updated_at
                     ) VALUES (?1, ?2, ?3, 'claimed', ?4, ?5, ?6)",
                    params![
                        event_id.as_bytes().as_slice(),
                        connection_id.as_str(),
                        revision,
                        token.as_slice(),
                        lease_expires,
                        now
                    ],
                )?;
                ClaimOutcome::Acquired(EventLease {
                    event_id: event_id.clone(),
                    token,
                    resumed: false,
                })
            }
            Some(existing) => {
                if existing.connection_id != connection_id.as_str()
                    || existing.connection_revision != revision
                {
                    return Err(LedgerError::ClaimMetadataMismatch);
                }
                match existing.state.as_str() {
                    "terminal" => ClaimOutcome::Terminal(terminal_from_row(event_id, existing)?),
                    "claimed" | "retryable" => {
                        let available_at = existing.available_at.ok_or(LedgerError::CorruptData)?;
                        if available_at > now {
                            ClaimOutcome::InProgress {
                                retry_after: Duration::from_secs(
                                    u64::try_from(available_at - now)
                                        .map_err(|_| LedgerError::CorruptData)?,
                                ),
                            }
                        } else {
                            let token = new_claim_token()?;
                            let updated = transaction.execute(
                                "UPDATE wake_events
                                 SET state = 'claimed', claim_token = ?2,
                                     available_at = ?3, updated_at = ?4
                                 WHERE event_id = ?1 AND state IN ('claimed', 'retryable')
                                   AND available_at <= ?4",
                                params![
                                    event_id.as_bytes().as_slice(),
                                    token.as_slice(),
                                    lease_expires,
                                    now
                                ],
                            )?;
                            if updated != 1 {
                                return Err(LedgerError::DatabaseUnavailable);
                            }
                            ClaimOutcome::Acquired(EventLease {
                                event_id: event_id.clone(),
                                token,
                                resumed: true,
                            })
                        }
                    }
                    _ => return Err(LedgerError::CorruptData),
                }
            }
        };
        transaction.commit()?;
        Ok(outcome)
    }

    /// Extends a live claim using the caller's current remaining lease duration.
    pub fn renew_lease(
        &self,
        lease: &EventLease,
        now: UnixTimestamp,
        lease_duration: Duration,
    ) -> Result<(), LedgerError> {
        let now = sqlite_timestamp(now)?;
        let seconds = lease_duration.as_secs();
        if lease_duration.is_zero() || seconds == 0 {
            return Err(LedgerError::InvalidLease);
        }
        let expires = now
            .checked_add(i64::try_from(seconds).map_err(|_| LedgerError::InvalidLease)?)
            .ok_or(LedgerError::InvalidLease)?;
        let connection = self.lock_connection()?;
        let updated = connection.execute(
            "UPDATE wake_events SET available_at = ?3, updated_at = ?4
             WHERE event_id = ?1 AND state = 'claimed' AND claim_token = ?2
               AND available_at > ?4",
            params![
                lease.event_id.as_bytes().as_slice(),
                lease.token.as_slice(),
                expires,
                now
            ],
        )?;
        require_owned_lease(updated)
    }

    /// Releases a live lease into a durable not-before retry state.
    pub fn retry_later(
        &self,
        lease: &EventLease,
        now: UnixTimestamp,
        delay: Duration,
    ) -> Result<(), LedgerError> {
        let now = sqlite_timestamp(now)?;
        let seconds = delay.as_secs();
        if delay.is_zero() || seconds == 0 {
            return Err(LedgerError::InvalidLease);
        }
        let available_at = now
            .checked_add(i64::try_from(seconds).map_err(|_| LedgerError::InvalidLease)?)
            .ok_or(LedgerError::InvalidLease)?;
        let connection = self.lock_connection()?;
        let updated = connection.execute(
            "UPDATE wake_events
             SET state = 'retryable', claim_token = NULL,
                 available_at = ?3, updated_at = ?4
             WHERE event_id = ?1 AND state = 'claimed' AND claim_token = ?2
               AND available_at > ?4",
            params![
                lease.event_id.as_bytes().as_slice(),
                lease.token.as_slice(),
                available_at,
                now
            ],
        )?;
        require_owned_lease(updated)
    }

    /// Commits a terminal state if and only if the caller still owns the lease.
    pub fn complete_event(
        &self,
        lease: &EventLease,
        kind: TerminalKind,
        response_event_json: Option<&str>,
        now: UnixTimestamp,
    ) -> Result<(), LedgerError> {
        if response_event_json.is_some_and(|value| value.len() > MAX_RESPONSE_EVENT_BYTES) {
            return Err(LedgerError::ResponseTooLarge);
        }
        let now = sqlite_timestamp(now)?;
        let connection = self.lock_connection()?;
        let updated = connection.execute(
            "UPDATE wake_events
             SET state = 'terminal', claim_token = NULL, available_at = NULL,
                 updated_at = ?4, terminal_kind = ?3, response_event_json = ?5
             WHERE event_id = ?1 AND state = 'claimed' AND claim_token = ?2
               AND available_at > ?4",
            params![
                lease.event_id.as_bytes().as_slice(),
                lease.token.as_slice(),
                kind.as_database_str(),
                now,
                response_event_json
            ],
        )?;
        require_owned_lease(updated)
    }

    /// Commits a successful response only while its exact connection revision is active.
    ///
    /// The connection predicate and terminal update execute in one immediate
    /// transaction, preventing revocation from committing between the final
    /// authorization check and durable completion.
    pub fn complete_event_for_active_connection(
        &self,
        lease: &EventLease,
        connection_id: &ConnectionId,
        connection_revision: ConnectionRevision,
        response_event_json: &str,
        now: UnixTimestamp,
    ) -> Result<(), LedgerError> {
        if response_event_json.len() > MAX_RESPONSE_EVENT_BYTES {
            return Err(LedgerError::ResponseTooLarge);
        }
        let now = sqlite_timestamp(now)?;
        let revision = sqlite_revision(connection_revision)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = transaction.execute(
            "UPDATE wake_events
             SET state = 'terminal', claim_token = NULL, available_at = NULL,
                 updated_at = ?5, terminal_kind = 'completed', response_event_json = ?6
             WHERE event_id = ?1 AND state = 'claimed' AND claim_token = ?2
               AND connection_id = ?3 AND connection_revision = ?4
               AND available_at > ?5
               AND EXISTS (
                   SELECT 1 FROM connections
                   WHERE connection_id = ?3 AND revision = ?4 AND status = 'active'
               )",
            params![
                lease.event_id.as_bytes().as_slice(),
                lease.token.as_slice(),
                connection_id.as_str(),
                revision,
                now,
                response_event_json
            ],
        )?;
        if updated == 1 {
            transaction.commit()?;
            return Ok(());
        }

        let still_owns_matching_lease = transaction
            .query_row(
                "SELECT 1 FROM wake_events
                 WHERE event_id = ?1 AND state = 'claimed' AND claim_token = ?2
                   AND connection_id = ?3 AND connection_revision = ?4
                   AND available_at > ?5",
                params![
                    lease.event_id.as_bytes().as_slice(),
                    lease.token.as_slice(),
                    connection_id.as_str(),
                    revision,
                    now
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if still_owns_matching_lease {
            Err(LedgerError::ConnectionUnavailable)
        } else {
            Err(LedgerError::LostLease)
        }
    }

    /// Deletes a bounded batch of terminal entries older than the retention cutoff.
    pub fn prune_terminal(
        &self,
        completed_before: UnixTimestamp,
        maximum_rows: usize,
    ) -> Result<usize, LedgerError> {
        if maximum_rows == 0 || maximum_rows > MAX_PRUNE_BATCH {
            return Err(LedgerError::InvalidPruneBatch);
        }
        let cutoff = sqlite_timestamp(completed_before)?;
        let limit = i64::try_from(maximum_rows).map_err(|_| LedgerError::InvalidPruneBatch)?;
        let connection = self.lock_connection()?;
        connection
            .execute(
                "DELETE FROM wake_events
                 WHERE event_id IN (
                     SELECT event_id FROM wake_events
                     WHERE state = 'terminal' AND updated_at < ?1
                     ORDER BY updated_at ASC
                     LIMIT ?2
                 )",
                params![cutoff, limit],
            )
            .map_err(Into::into)
    }

    pub(crate) fn lock_connection(&self) -> Result<MutexGuard<'_, Connection>, LedgerError> {
        self.connection
            .lock()
            .map_err(|_| LedgerError::DatabaseUnavailable)
    }
}

impl fmt::Debug for WakeLedger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WakeLedger([redacted])")
    }
}

fn migrate(connection: &mut Connection) -> Result<(), LedgerError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i64 = transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let mut version = version;
    if version == 0 {
        transaction.execute_batch(CREATE_SCHEMA)?;
        version = 1;
    }
    if version == 1 {
        transaction.execute_batch(CREATE_CONNECTION_SCHEMA)?;
        version = 2;
    }
    if version == 2 {
        transaction.execute_batch(CREATE_PAYMENT_SCHEMA)?;
        version = 3;
    }
    if version == 3 {
        transaction.execute_batch(CREATE_WAKE_REGISTRATION_SCHEMA)?;
        version = 4;
    }
    if version != SCHEMA_VERSION {
        return Err(LedgerError::UnsupportedSchema);
    }
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn load_existing(
    connection: &Connection,
    event_id: &EventId,
) -> Result<Option<ExistingEvent>, LedgerError> {
    connection
        .query_row(
            "SELECT connection_id, connection_revision, state, available_at,
                    terminal_kind, response_event_json, updated_at
             FROM wake_events WHERE event_id = ?1",
            params![event_id.as_bytes().as_slice()],
            |row| {
                Ok(ExistingEvent {
                    connection_id: row.get(0)?,
                    connection_revision: row.get(1)?,
                    state: row.get(2)?,
                    available_at: row.get(3)?,
                    terminal_kind: row.get(4)?,
                    response_event_json: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn terminal_from_row(
    event_id: &EventId,
    existing: ExistingEvent,
) -> Result<TerminalEvent, LedgerError> {
    if existing.available_at.is_some() {
        return Err(LedgerError::CorruptData);
    }
    let kind = existing
        .terminal_kind
        .as_deref()
        .ok_or(LedgerError::CorruptData)
        .and_then(TerminalKind::from_database_str)?;
    let completed_at = UnixTimestamp::from_secs(
        u64::try_from(existing.updated_at).map_err(|_| LedgerError::CorruptData)?,
    );
    if existing
        .response_event_json
        .as_ref()
        .is_some_and(|value| value.len() > MAX_RESPONSE_EVENT_BYTES)
    {
        return Err(LedgerError::CorruptData);
    }
    Ok(TerminalEvent {
        event_id: event_id.clone(),
        kind,
        response_event_json: existing.response_event_json,
        completed_at,
    })
}

fn sqlite_timestamp(timestamp: UnixTimestamp) -> Result<i64, LedgerError> {
    i64::try_from(timestamp.as_secs()).map_err(|_| LedgerError::ValueOutOfRange)
}

fn sqlite_revision(revision: ConnectionRevision) -> Result<i64, LedgerError> {
    i64::try_from(revision.value()).map_err(|_| LedgerError::ValueOutOfRange)
}

fn new_claim_token() -> Result<[u8; CLAIM_TOKEN_BYTES], LedgerError> {
    let mut token = [0_u8; CLAIM_TOKEN_BYTES];
    getrandom::fill(&mut token).map_err(|_| LedgerError::RandomnessUnavailable)?;
    Ok(token)
}

const fn require_owned_lease(updated_rows: usize) -> Result<(), LedgerError> {
    if updated_rows == 1 {
        Ok(())
    } else {
        Err(LedgerError::LostLease)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;

    const EVENT_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const CLIENT_HEX: &str = "687dd8ece211539364549b1f32c63eceec1e0661009ba65cf8ff2e73ba000746";
    const WALLET_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

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
            let directory = std::env::temp_dir()
                .join(format!("nwc-mobile-ledger-{}-{suffix}", std::process::id()));
            fs::create_dir(&directory).expect("create test directory");
            let path = directory.join("wake.sqlite3");
            Self { directory, path }
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn event_id() -> EventId {
        EventId::from_hex(EVENT_HEX).expect("event id")
    }

    fn connection_id() -> ConnectionId {
        ConnectionId::parse("connection:test").expect("connection id")
    }

    fn claim(ledger: &WakeLedger, now: u64) -> ClaimOutcome {
        ledger
            .claim_event(
                &event_id(),
                &connection_id(),
                ConnectionRevision::INITIAL,
                UnixTimestamp::from_secs(now),
                Duration::from_secs(10),
            )
            .expect("claim event")
    }

    #[test]
    fn version_one_ledger_migrates_without_losing_replay_state() {
        let database = TestDatabase::new();
        {
            let connection = Connection::open(&database.path).expect("create v1 database");
            connection.execute_batch(CREATE_SCHEMA).expect("v1 schema");
            connection
                .pragma_update(None, "user_version", 1_i64)
                .expect("v1 version");
            connection
                .execute(
                    "INSERT INTO wake_events (
                        event_id, connection_id, connection_revision, state,
                        claim_token, available_at, updated_at, terminal_kind,
                        response_event_json
                     ) VALUES (?1, ?2, 0, 'terminal', NULL, NULL, 100, 'rejected', NULL)",
                    params![event_id().as_bytes().as_slice(), connection_id().as_str()],
                )
                .expect("v1 replay state");
        }

        let ledger = WakeLedger::open(&database.path).expect("migrate v1 ledger");
        assert!(matches!(claim(&ledger, 101), ClaimOutcome::Terminal(_)));
        let connection = ledger.lock_connection().expect("database lock");
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("schema version");
        let connection_table: String = connection
            .query_row(
                "SELECT name FROM sqlite_schema WHERE type = 'table' AND name = 'connections'",
                [],
                |row| row.get(0),
            )
            .expect("connection table");
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(connection_table, "connections");
    }

    #[test]
    fn version_three_migration_queues_existing_active_registration() {
        let database = TestDatabase::new();
        {
            let connection = Connection::open(&database.path).expect("create v3 database");
            connection.execute_batch(CREATE_SCHEMA).expect("v1 schema");
            connection
                .execute_batch(CREATE_CONNECTION_SCHEMA)
                .expect("v2 schema");
            connection
                .execute_batch(CREATE_PAYMENT_SCHEMA)
                .expect("v3 schema");
            connection
                .pragma_update(None, "user_version", 3_i64)
                .expect("v3 version");
            let client = crate::PublicKey::from_hex(CLIENT_HEX).expect("client key");
            let wallet = crate::PublicKey::from_hex(WALLET_HEX).expect("wallet key");
            connection
                .execute(
                    "INSERT INTO connections (
                        connection_id, revision, status, client_pubkey,
                        wallet_service_pubkey, encryption, budget_limit_sat,
                        budget_interval, fee_policy, maximum_fee_sat,
                        created_at, updated_at, tombstoned_at
                     ) VALUES (?1, 0, 'active', ?2, ?3, 'nip44_v2', 0,
                               'never', 'exclude', 0, 100, 100, NULL)",
                    params![
                        connection_id().as_str(),
                        client.as_bytes().as_slice(),
                        wallet.as_bytes().as_slice(),
                    ],
                )
                .expect("v3 connection");
            connection
                .execute(
                    "INSERT INTO connection_relays (connection_id, position, relay_url)
                     VALUES (?1, 0, 'wss://relay.example.com/')",
                    params![connection_id().as_str()],
                )
                .expect("v3 relay");
        }

        let ledger = WakeLedger::open(&database.path).expect("migrate v3 ledger");
        let change = ledger
            .load_due_wake_registrations(UnixTimestamp::from_secs(100), 1)
            .expect("load seeded registration")
            .pop()
            .expect("seeded registration");
        assert!(change.enabled());
        assert_eq!(change.connection_id(), &connection_id());
        assert_eq!(change.connection_revision(), ConnectionRevision::INITIAL);
        assert_eq!(change.relays().len(), 1);
    }

    #[test]
    fn concurrent_connections_create_only_one_active_claim() {
        let database = TestDatabase::new();
        let first = Arc::new(WakeLedger::open(&database.path).expect("first ledger"));
        let second = Arc::new(WakeLedger::open(&database.path).expect("second ledger"));
        let barrier = Arc::new(Barrier::new(2));

        let threads = [first, second].map(|ledger| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                claim(&ledger, 100)
            })
        });
        let outcomes = threads.map(|handle| handle.join().expect("claim thread"));

        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ClaimOutcome::Acquired(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ClaimOutcome::InProgress { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn expired_owner_cannot_complete_after_reclaim() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let ClaimOutcome::Acquired(first) = claim(&ledger, 100) else {
            panic!("first claim not acquired");
        };
        let ClaimOutcome::Acquired(second) = claim(&ledger, 111) else {
            panic!("expired claim not reclaimed");
        };

        assert!(second.was_resumed());
        assert_eq!(
            ledger.complete_event(
                &first,
                TerminalKind::Completed,
                Some("encrypted-response"),
                UnixTimestamp::from_secs(112),
            ),
            Err(LedgerError::LostLease)
        );
        ledger
            .complete_event(
                &second,
                TerminalKind::Completed,
                Some("encrypted-response"),
                UnixTimestamp::from_secs(112),
            )
            .expect("complete reclaimed lease");

        let ClaimOutcome::Terminal(terminal) = claim(&ledger, 113) else {
            panic!("terminal replay not returned");
        };
        assert_eq!(terminal.kind(), TerminalKind::Completed);
        assert_eq!(terminal.response_event_json(), Some("encrypted-response"));
        assert!(!format!("{terminal:?}").contains("encrypted-response"));
    }

    #[test]
    fn retry_state_enforces_not_before_time() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let ClaimOutcome::Acquired(lease) = claim(&ledger, 100) else {
            panic!("claim not acquired");
        };
        ledger
            .retry_later(
                &lease,
                UnixTimestamp::from_secs(101),
                Duration::from_secs(5),
            )
            .expect("schedule retry");

        assert_eq!(
            claim(&ledger, 102),
            ClaimOutcome::InProgress {
                retry_after: Duration::from_secs(4)
            }
        );
        let ClaimOutcome::Acquired(retry) = claim(&ledger, 106) else {
            panic!("retry claim not acquired");
        };
        assert!(retry.was_resumed());
    }

    #[test]
    fn terminal_retention_survives_reopen_and_prunes_by_time() {
        let database = TestDatabase::new();
        {
            let ledger = WakeLedger::open(&database.path).expect("ledger");
            let ClaimOutcome::Acquired(lease) = claim(&ledger, 100) else {
                panic!("claim not acquired");
            };
            ledger
                .complete_event(
                    &lease,
                    TerminalKind::Rejected,
                    None,
                    UnixTimestamp::from_secs(105),
                )
                .expect("complete event");
        }

        let reopened = WakeLedger::open(&database.path).expect("reopen ledger");
        assert!(matches!(claim(&reopened, 200), ClaimOutcome::Terminal(_)));
        assert_eq!(
            reopened
                .prune_terminal(UnixTimestamp::from_secs(105), 10)
                .expect("exclusive cutoff"),
            0
        );
        assert_eq!(
            reopened
                .prune_terminal(UnixTimestamp::from_secs(106), 10)
                .expect("prune terminal"),
            1
        );
        assert!(matches!(claim(&reopened, 201), ClaimOutcome::Acquired(_)));
    }

    #[test]
    fn claim_metadata_and_response_bounds_fail_closed() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let ClaimOutcome::Acquired(lease) = claim(&ledger, 100) else {
            panic!("claim not acquired");
        };
        let different_connection = ConnectionId::parse("connection:other").expect("connection");
        assert_eq!(
            ledger.claim_event(
                &event_id(),
                &different_connection,
                ConnectionRevision::INITIAL,
                UnixTimestamp::from_secs(101),
                Duration::from_secs(10),
            ),
            Err(LedgerError::ClaimMetadataMismatch)
        );

        let oversized = "x".repeat(MAX_RESPONSE_EVENT_BYTES + 1);
        assert_eq!(
            ledger.complete_event(
                &lease,
                TerminalKind::Completed,
                Some(&oversized),
                UnixTimestamp::from_secs(101),
            ),
            Err(LedgerError::ResponseTooLarge)
        );
    }
}
