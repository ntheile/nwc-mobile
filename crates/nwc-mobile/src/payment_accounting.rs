use std::fmt;

use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

use crate::{
    ActiveConnection, AmountMsat, ConnectionId, ConnectionRevision, EventId, PaymentHash,
    UnixTimestamp, WakeLedger,
};

/// A stable, non-sensitive payment-accounting failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PaymentAccountingError {
    /// SQLite or the containing directory is unavailable.
    DatabaseUnavailable,
    /// Persisted accounting state violated an invariant.
    CorruptData,
    /// An amount, timestamp, or revision is not safely representable.
    ValueOutOfRange,
    /// The connection is absent, revoked, stale, or lacks payment permission.
    ConnectionUnavailable,
    /// The requested principal is zero.
    InvalidAmount,
    /// The period budget cannot cover the principal and maximum fee reserve.
    BudgetExceeded,
    /// An event id was reused with different payment metadata.
    ReservationConflict,
    /// The requested state transition contradicts a durable terminal state.
    TerminalStateConflict,
}

impl fmt::Display for PaymentAccountingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DatabaseUnavailable => "payment accounting is unavailable",
            Self::CorruptData => "payment accounting contains invalid data",
            Self::ValueOutOfRange => "payment accounting value is out of range",
            Self::ConnectionUnavailable => "connection cannot authorize payment",
            Self::InvalidAmount => "payment amount is invalid",
            Self::BudgetExceeded => "connection payment budget is exceeded",
            Self::ReservationConflict => "payment reservation metadata conflicts",
            Self::TerminalStateConflict => "payment is already in a conflicting terminal state",
        })
    }
}

impl std::error::Error for PaymentAccountingError {}

impl From<rusqlite::Error> for PaymentAccountingError {
    fn from(_: rusqlite::Error) -> Self {
        Self::DatabaseUnavailable
    }
}

/// Durable payment progress used to make retries idempotent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DurablePaymentState {
    /// Budget is debited, but the host has not confirmed initiation.
    Reserved,
    /// The wallet reports an initiated or otherwise ambiguous payment.
    Pending,
    /// The wallet reports durable settlement.
    Succeeded,
    /// The wallet reports a definitive failure and the reservation is refunded.
    Failed,
}

impl DurablePaymentState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Pending => "pending",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    fn from_str(value: &str) -> Result<Self, PaymentAccountingError> {
        match value {
            "reserved" => Ok(Self::Reserved),
            "pending" => Ok(Self::Pending),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            _ => Err(PaymentAccountingError::CorruptData),
        }
    }
}

/// A durable reservation or reconciled payment result.
#[derive(Clone, Eq, PartialEq)]
pub struct PaymentAttempt {
    event_id: EventId,
    payment_hash: PaymentHash,
    connection_id: ConnectionId,
    connection_revision: ConnectionRevision,
    period_started_at: UnixTimestamp,
    principal_sat: u64,
    fee_reserve_sat: u64,
    state: DurablePaymentState,
    actual_principal_sat: Option<u64>,
    actual_fee_sat: Option<u64>,
    charged_sat: Option<u64>,
    authorization_exceeded: bool,
    initiated_at: Option<UnixTimestamp>,
    legacy_initiation_ambiguous: bool,
    created_at: UnixTimestamp,
    updated_at: UnixTimestamp,
}

impl PaymentAttempt {
    /// Returns the Nostr event id used as the host idempotency key.
    #[must_use]
    pub const fn event_id(&self) -> &EventId {
        &self.event_id
    }

    /// Returns the decoded Lightning payment hash.
    #[must_use]
    pub const fn payment_hash(&self) -> &PaymentHash {
        &self.payment_hash
    }

    /// Returns the connection that authorized the reservation.
    #[must_use]
    pub const fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    /// Returns the exact connection revision that authorized the reservation.
    #[must_use]
    pub const fn connection_revision(&self) -> ConnectionRevision {
        self.connection_revision
    }

    /// Returns the budget period charged by this attempt.
    #[must_use]
    pub const fn period_started_at(&self) -> UnixTimestamp {
        self.period_started_at
    }

    /// Returns the expected payment principal.
    #[must_use]
    pub const fn principal_sat(&self) -> u64 {
        self.principal_sat
    }

    /// Returns the maximum routing fee debited before host initiation.
    #[must_use]
    pub const fn fee_reserve_sat(&self) -> u64 {
        self.fee_reserve_sat
    }

    /// Returns the principal plus maximum fee held against the period budget.
    #[must_use]
    pub fn reserved_sat(&self) -> u64 {
        self.principal_sat + self.fee_reserve_sat
    }

    /// Returns the durable payment state.
    #[must_use]
    pub const fn state(&self) -> DurablePaymentState {
        self.state
    }

    /// Returns the reconciled principal when settled.
    #[must_use]
    pub const fn actual_principal_sat(&self) -> Option<u64> {
        self.actual_principal_sat
    }

    /// Returns the reconciled routing fee when settled.
    #[must_use]
    pub const fn actual_fee_sat(&self) -> Option<u64> {
        self.actual_fee_sat
    }

    /// Returns the amount ultimately charged to policy when settled.
    #[must_use]
    pub const fn charged_sat(&self) -> Option<u64> {
        self.charged_sat
    }

    /// Returns whether the host-reported principal or fee exceeded the reserve.
    ///
    /// The actual spend remains charged even when this is true.
    #[must_use]
    pub const fn authorization_exceeded(&self) -> bool {
        self.authorization_exceeded
    }

    /// Returns when this library durably committed to invoking the wallet.
    #[must_use]
    pub const fn initiated_at(&self) -> Option<UnixTimestamp> {
        self.initiated_at
    }

    /// Returns whether the library has a durable initiation marker.
    #[must_use]
    pub const fn was_initiated(&self) -> bool {
        self.initiated_at.is_some()
    }

    /// Returns whether an upgraded ledger cannot prove the old initiation boundary.
    #[must_use]
    pub const fn has_ambiguous_legacy_initiation(&self) -> bool {
        self.legacy_initiation_ambiguous
    }

    /// Returns whether an observed settlement may be attributed and disclosed.
    #[must_use]
    pub const fn may_disclose_settlement(&self) -> bool {
        self.was_initiated() && !self.legacy_initiation_ambiguous
    }

    /// Returns when the reservation was first committed.
    #[must_use]
    pub const fn created_at(&self) -> UnixTimestamp {
        self.created_at
    }

    /// Returns when the durable state was last reconciled.
    #[must_use]
    pub const fn updated_at(&self) -> UnixTimestamp {
        self.updated_at
    }
}

impl fmt::Debug for PaymentAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PaymentAttempt")
            .field("event_id", &self.event_id)
            .field("payment_hash", &self.payment_hash)
            .field("connection_id", &self.connection_id)
            .field("connection_revision", &self.connection_revision)
            .field("period_started_at", &self.period_started_at)
            .field("principal_sat", &self.principal_sat)
            .field("fee_reserve_sat", &self.fee_reserve_sat)
            .field("state", &self.state)
            .field("charged_sat", &self.charged_sat)
            .field("authorization_exceeded", &self.authorization_exceeded)
            .field("initiated_at", &self.initiated_at)
            .field(
                "legacy_initiation_ambiguous",
                &self.legacy_initiation_ambiguous,
            )
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Result of an idempotent reservation attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PaymentReservationOutcome {
    /// This caller created the durable debit and may inspect wallet state.
    Reserved(PaymentAttempt),
    /// The same event already owns this exact reservation.
    Existing(PaymentAttempt),
    /// Another event already tracks the payment hash and must not pay it again.
    AlreadyTracked(PaymentAttempt),
}

struct ConnectionBudget {
    created_at: u64,
    limit_sat: u64,
    interval_seconds: Option<u64>,
    fee_reserve_sat: u64,
}

impl WakeLedger {
    /// Atomically debits principal plus the maximum fee before any payment call.
    pub fn reserve_payment(
        &self,
        event_id: &EventId,
        payment_hash: &PaymentHash,
        connection: &ActiveConnection,
        principal_sat: u64,
        now: UnixTimestamp,
    ) -> Result<PaymentReservationOutcome, PaymentAccountingError> {
        if principal_sat == 0 {
            return Err(PaymentAccountingError::InvalidAmount);
        }
        let now_sql = sqlite_u64(now.as_secs())?;
        let revision_sql = sqlite_u64(connection.revision().value())?;
        let principal_sql = sqlite_u64(principal_sat)?;
        let mut database = self
            .lock_connection()
            .map_err(|_| PaymentAccountingError::DatabaseUnavailable)?;
        let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let budget = load_connection_budget(&transaction, connection, revision_sql, now_sql)?;
        let period_started_at = period_start(&budget, now.as_secs())?;

        if let Some(existing) = load_attempt_by_event(&transaction, event_id)? {
            if existing.payment_hash == *payment_hash
                && existing.connection_id == *connection.id()
                && existing.connection_revision == connection.revision()
                && existing.principal_sat == principal_sat
            {
                transaction.commit()?;
                return Ok(PaymentReservationOutcome::Existing(existing));
            }
            return Err(PaymentAccountingError::ReservationConflict);
        }
        if let Some(existing) = load_attempt_by_hash(&transaction, payment_hash)? {
            transaction.commit()?;
            return Ok(PaymentReservationOutcome::AlreadyTracked(existing));
        }

        let period_sql = sqlite_u64(period_started_at)?;
        let limit_sql = sqlite_u64(budget.limit_sat)?;
        let fee_reserve_sql = sqlite_u64(budget.fee_reserve_sat)?;
        let reserved_sat = principal_sat
            .checked_add(budget.fee_reserve_sat)
            .ok_or(PaymentAccountingError::ValueOutOfRange)?;
        let reserved_sql = sqlite_u64(reserved_sat)?;
        let maximum_reconciliation_sequence: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(reconciliation_sequence), 0) FROM payment_attempts",
            [],
            |row| row.get(0),
        )?;
        let next_reconciliation_sequence = maximum_reconciliation_sequence
            .checked_add(1)
            .ok_or(PaymentAccountingError::ValueOutOfRange)?;

        transaction.execute(
            "INSERT INTO budget_periods (
                connection_id, period_started_at, limit_sat, used_sat, updated_at
             ) VALUES (?1, ?2, ?3, 0, ?4)
             ON CONFLICT(connection_id, period_started_at) DO NOTHING",
            params![connection.id().as_str(), period_sql, limit_sql, now_sql],
        )?;
        let (stored_limit, used): (i64, i64) = transaction.query_row(
            "SELECT limit_sat, used_sat FROM budget_periods
             WHERE connection_id = ?1 AND period_started_at = ?2",
            params![connection.id().as_str(), period_sql],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if stored_limit != limit_sql {
            return Err(PaymentAccountingError::CorruptData);
        }
        let used = decode_u64(used)?;
        let next_used = used
            .checked_add(reserved_sat)
            .ok_or(PaymentAccountingError::ValueOutOfRange)?;
        if next_used > budget.limit_sat {
            return Err(PaymentAccountingError::BudgetExceeded);
        }
        transaction.execute(
            "UPDATE budget_periods SET used_sat = ?3, updated_at = ?4
             WHERE connection_id = ?1 AND period_started_at = ?2",
            params![
                connection.id().as_str(),
                period_sql,
                sqlite_u64(next_used)?,
                now_sql
            ],
        )?;
        transaction.execute(
            "INSERT INTO payment_attempts (
                event_id, payment_hash, connection_id, connection_revision,
                period_started_at, principal_sat, fee_reserve_sat, reserved_sat,
                state, created_at, updated_at, reconciliation_sequence
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'reserved', ?9, ?9, ?10)",
            params![
                event_id.as_bytes().as_slice(),
                payment_hash.as_bytes().as_slice(),
                connection.id().as_str(),
                revision_sql,
                period_sql,
                principal_sql,
                fee_reserve_sql,
                reserved_sql,
                now_sql,
                next_reconciliation_sequence,
            ],
        )?;
        transaction.commit()?;
        Ok(PaymentReservationOutcome::Reserved(PaymentAttempt {
            event_id: event_id.clone(),
            payment_hash: payment_hash.clone(),
            connection_id: connection.id().clone(),
            connection_revision: connection.revision(),
            period_started_at: UnixTimestamp::from_secs(period_started_at),
            principal_sat,
            fee_reserve_sat: budget.fee_reserve_sat,
            state: DurablePaymentState::Reserved,
            actual_principal_sat: None,
            actual_fee_sat: None,
            charged_sat: None,
            authorization_exceeded: false,
            initiated_at: None,
            legacy_initiation_ambiguous: false,
            created_at: now,
            updated_at: now,
        }))
    }

    /// Durably records that this library is about to invoke the wallet backend.
    pub fn mark_payment_initiated(
        &self,
        payment_hash: &PaymentHash,
        now: UnixTimestamp,
    ) -> Result<PaymentAttempt, PaymentAccountingError> {
        let now_sql = sqlite_u64(now.as_secs())?;
        let mut database = self
            .lock_connection()
            .map_err(|_| PaymentAccountingError::DatabaseUnavailable)?;
        let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut attempt = load_attempt_by_hash(&transaction, payment_hash)?
            .ok_or(PaymentAccountingError::ReservationConflict)?;
        validate_update_time(&attempt, now)?;
        if attempt.initiated_at.is_some() {
            transaction.commit()?;
            return Ok(attempt);
        }
        if attempt.state != DurablePaymentState::Reserved {
            return Err(PaymentAccountingError::TerminalStateConflict);
        }
        transaction.execute(
            "UPDATE payment_attempts SET initiated_at = ?2, updated_at = ?2
             WHERE payment_hash = ?1 AND state = 'reserved' AND initiated_at IS NULL",
            params![payment_hash.as_bytes().as_slice(), now_sql],
        )?;
        transaction.commit()?;
        attempt.initiated_at = Some(now);
        attempt.updated_at = now;
        Ok(attempt)
    }

    /// Releases a fresh reservation when the wallet reports an external payment.
    pub fn release_uninitiated_payment(
        &self,
        payment_hash: &PaymentHash,
        now: UnixTimestamp,
    ) -> Result<(), PaymentAccountingError> {
        let now_sql = sqlite_u64(now.as_secs())?;
        let mut database = self
            .lock_connection()
            .map_err(|_| PaymentAccountingError::DatabaseUnavailable)?;
        let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let attempt = load_attempt_by_hash(&transaction, payment_hash)?
            .ok_or(PaymentAccountingError::ReservationConflict)?;
        validate_update_time(&attempt, now)?;
        if attempt.state != DurablePaymentState::Reserved || attempt.initiated_at.is_some() {
            return Err(PaymentAccountingError::TerminalStateConflict);
        }
        adjust_period_used(&transaction, &attempt, attempt.reserved_sat(), 0, now_sql)?;
        let deleted = transaction.execute(
            "DELETE FROM payment_attempts
             WHERE payment_hash = ?1 AND state = 'reserved' AND initiated_at IS NULL",
            params![payment_hash.as_bytes().as_slice()],
        )?;
        if deleted != 1 {
            return Err(PaymentAccountingError::TerminalStateConflict);
        }
        transaction.commit()?;
        Ok(())
    }

    /// Records that the wallet may still settle this payment.
    pub fn mark_payment_pending(
        &self,
        payment_hash: &PaymentHash,
        now: UnixTimestamp,
    ) -> Result<PaymentAttempt, PaymentAccountingError> {
        self.transition_nonterminal(payment_hash, DurablePaymentState::Pending, now)
    }

    /// Refunds a reservation only after the wallet reports definitive failure.
    pub fn mark_payment_failed(
        &self,
        payment_hash: &PaymentHash,
        now: UnixTimestamp,
    ) -> Result<PaymentAttempt, PaymentAccountingError> {
        let now_sql = sqlite_u64(now.as_secs())?;
        let mut database = self
            .lock_connection()
            .map_err(|_| PaymentAccountingError::DatabaseUnavailable)?;
        let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut attempt = load_attempt_by_hash(&transaction, payment_hash)?
            .ok_or(PaymentAccountingError::ReservationConflict)?;
        validate_update_time(&attempt, now)?;
        ensure_attempt_initiated(&attempt)?;
        match attempt.state {
            DurablePaymentState::Succeeded => {
                return Err(PaymentAccountingError::TerminalStateConflict)
            }
            DurablePaymentState::Failed => {
                transaction.commit()?;
                return Ok(attempt);
            }
            DurablePaymentState::Reserved | DurablePaymentState::Pending => {}
        }
        adjust_period_used(&transaction, &attempt, attempt.reserved_sat(), 0, now_sql)?;
        transaction.execute(
            "UPDATE payment_attempts SET state = 'failed', updated_at = ?2
             WHERE payment_hash = ?1 AND state IN ('reserved', 'pending')",
            params![payment_hash.as_bytes().as_slice(), now_sql],
        )?;
        transaction.commit()?;
        attempt.state = DurablePaymentState::Failed;
        attempt.updated_at = now;
        Ok(attempt)
    }

    /// Reconciles a late or immediate settlement and charges actual fees.
    ///
    /// A host-reported amount beyond the reserve is still durably charged and
    /// surfaced through `authorization_exceeded`.
    pub fn mark_payment_succeeded(
        &self,
        payment_hash: &PaymentHash,
        actual_principal: AmountMsat,
        actual_fee: AmountMsat,
        now: UnixTimestamp,
    ) -> Result<PaymentAttempt, PaymentAccountingError> {
        let actual_principal_sat = msat_to_sat_ceil(actual_principal)?;
        let actual_fee_sat = msat_to_sat_ceil(actual_fee)?;
        let now_sql = sqlite_u64(now.as_secs())?;
        let actual_principal_sql = sqlite_u64(actual_principal_sat)?;
        let actual_fee_sql = sqlite_u64(actual_fee_sat)?;
        let mut database = self
            .lock_connection()
            .map_err(|_| PaymentAccountingError::DatabaseUnavailable)?;
        let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut attempt = load_attempt_by_hash(&transaction, payment_hash)?
            .ok_or(PaymentAccountingError::ReservationConflict)?;
        validate_update_time(&attempt, now)?;
        ensure_attempt_initiated(&attempt)?;
        if attempt.state == DurablePaymentState::Succeeded {
            if attempt.actual_principal_sat == Some(actual_principal_sat)
                && attempt.actual_fee_sat == Some(actual_fee_sat)
            {
                transaction.commit()?;
                return Ok(attempt);
            }
            return Err(PaymentAccountingError::TerminalStateConflict);
        }
        let count_fees: bool = transaction.query_row(
            "SELECT fee_policy = 'count' FROM connections WHERE connection_id = ?1",
            params![attempt.connection_id.as_str()],
            |row| row.get(0),
        )?;
        let charged_sat = if count_fees {
            actual_principal_sat
                .checked_add(actual_fee_sat)
                .ok_or(PaymentAccountingError::ValueOutOfRange)?
        } else {
            actual_principal_sat
        };
        let old_contribution = match attempt.state {
            DurablePaymentState::Reserved | DurablePaymentState::Pending => attempt.reserved_sat(),
            DurablePaymentState::Failed => 0,
            DurablePaymentState::Succeeded => return Err(PaymentAccountingError::CorruptData),
        };
        adjust_period_used(
            &transaction,
            &attempt,
            old_contribution,
            charged_sat,
            now_sql,
        )?;
        let authorization_exceeded = actual_principal_sat > attempt.principal_sat
            || (count_fees && actual_fee_sat > attempt.fee_reserve_sat);
        transaction.execute(
            "UPDATE payment_attempts
             SET state = 'succeeded', actual_principal_sat = ?2,
                 actual_fee_sat = ?3, charged_sat = ?4,
                 authorization_exceeded = ?5, updated_at = ?6
             WHERE payment_hash = ?1 AND state != 'succeeded'",
            params![
                payment_hash.as_bytes().as_slice(),
                actual_principal_sql,
                actual_fee_sql,
                sqlite_u64(charged_sat)?,
                authorization_exceeded,
                now_sql
            ],
        )?;
        transaction.commit()?;
        attempt.state = DurablePaymentState::Succeeded;
        attempt.actual_principal_sat = Some(actual_principal_sat);
        attempt.actual_fee_sat = Some(actual_fee_sat);
        attempt.charged_sat = Some(charged_sat);
        attempt.authorization_exceeded = authorization_exceeded;
        attempt.updated_at = now;
        Ok(attempt)
    }

    /// Loads one durable attempt by payment hash.
    pub fn load_payment_attempt(
        &self,
        payment_hash: &PaymentHash,
    ) -> Result<Option<PaymentAttempt>, PaymentAccountingError> {
        let database = self
            .lock_connection()
            .map_err(|_| PaymentAccountingError::DatabaseUnavailable)?;
        load_attempt_by_hash(&database, payment_hash)
    }

    pub(crate) fn load_unresolved_payment_attempts(
        &self,
        limit: usize,
    ) -> Result<(Vec<PaymentAttempt>, bool), PaymentAccountingError> {
        let fetch_limit = limit
            .checked_add(1)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(PaymentAccountingError::ValueOutOfRange)?;
        let limit_sql =
            i64::try_from(limit).map_err(|_| PaymentAccountingError::ValueOutOfRange)?;
        let mut database = self
            .lock_connection()
            .map_err(|_| PaymentAccountingError::DatabaseUnavailable)?;
        let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut maximum_sequence: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(reconciliation_sequence), 0)
             FROM payment_attempts WHERE state IN ('reserved', 'pending')
               AND legacy_initiation_ambiguous = 0",
            [],
            |row| row.get(0),
        )?;
        if maximum_sequence > i64::MAX - limit_sql {
            transaction.execute(
                "UPDATE payment_attempts SET reconciliation_sequence = 0
                 WHERE state IN ('reserved', 'pending')
                   AND legacy_initiation_ambiguous = 0",
                [],
            )?;
            maximum_sequence = 0;
        }
        let mut attempts = {
            let mut statement = transaction.prepare(
                "SELECT event_id, payment_hash, connection_id, connection_revision,
                        period_started_at, principal_sat, fee_reserve_sat, state,
                        actual_principal_sat, actual_fee_sat, charged_sat,
                        authorization_exceeded, initiated_at,
                        legacy_initiation_ambiguous, created_at, updated_at
                 FROM payment_attempts
                 WHERE state IN ('reserved', 'pending')
                   AND legacy_initiation_ambiguous = 0
                 ORDER BY reconciliation_sequence ASC, event_id ASC
                 LIMIT ?1",
            )?;
            let rows = statement.query_map(params![fetch_limit], decode_attempt_row)?;
            let mut attempts = Vec::new();
            for row in rows {
                attempts.push(hydrate_attempt(row?)?);
            }
            attempts
        };
        let has_additional = attempts.len() > limit;
        attempts.truncate(limit);
        for (position, attempt) in attempts.iter().enumerate() {
            let sequence = maximum_sequence
                .checked_add(
                    i64::try_from(position + 1)
                        .map_err(|_| PaymentAccountingError::ValueOutOfRange)?,
                )
                .ok_or(PaymentAccountingError::ValueOutOfRange)?;
            transaction.execute(
                "UPDATE payment_attempts SET reconciliation_sequence = ?2
                 WHERE payment_hash = ?1 AND state IN ('reserved', 'pending')",
                params![attempt.payment_hash().as_bytes().as_slice(), sequence],
            )?;
        }
        transaction.commit()?;
        Ok((attempts, has_additional))
    }

    fn transition_nonterminal(
        &self,
        payment_hash: &PaymentHash,
        next: DurablePaymentState,
        now: UnixTimestamp,
    ) -> Result<PaymentAttempt, PaymentAccountingError> {
        let now_sql = sqlite_u64(now.as_secs())?;
        let mut database = self
            .lock_connection()
            .map_err(|_| PaymentAccountingError::DatabaseUnavailable)?;
        let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut attempt = load_attempt_by_hash(&transaction, payment_hash)?
            .ok_or(PaymentAccountingError::ReservationConflict)?;
        validate_update_time(&attempt, now)?;
        ensure_attempt_initiated(&attempt)?;
        match attempt.state {
            DurablePaymentState::Reserved => {}
            state if state == next => {
                transaction.commit()?;
                return Ok(attempt);
            }
            DurablePaymentState::Pending
            | DurablePaymentState::Succeeded
            | DurablePaymentState::Failed => {
                return Err(PaymentAccountingError::TerminalStateConflict)
            }
        }
        transaction.execute(
            "UPDATE payment_attempts SET state = ?2, updated_at = ?3
             WHERE payment_hash = ?1 AND state = 'reserved'",
            params![payment_hash.as_bytes().as_slice(), next.as_str(), now_sql],
        )?;
        transaction.commit()?;
        attempt.state = next;
        attempt.updated_at = now;
        Ok(attempt)
    }
}

fn ensure_attempt_initiated(attempt: &PaymentAttempt) -> Result<(), PaymentAccountingError> {
    if attempt.was_initiated() {
        Ok(())
    } else {
        Err(PaymentAccountingError::TerminalStateConflict)
    }
}

fn load_connection_budget(
    transaction: &Transaction<'_>,
    connection: &ActiveConnection,
    revision_sql: i64,
    now_sql: i64,
) -> Result<ConnectionBudget, PaymentAccountingError> {
    transaction
        .query_row(
            "SELECT c.created_at, c.budget_limit_sat, c.budget_interval,
                    c.fee_policy, c.maximum_fee_sat
             FROM connections AS c
             WHERE c.connection_id = ?1 AND c.revision = ?2 AND c.status = 'active'
               AND (c.expires_at IS NULL OR c.expires_at > ?3)
               AND EXISTS (
                   SELECT 1 FROM connection_methods AS m
                   WHERE m.connection_id = c.connection_id AND m.method = 'pay_invoice'
               )",
            params![connection.id().as_str(), revision_sql, now_sql],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(PaymentAccountingError::ConnectionUnavailable)
        .and_then(|(created_at, limit, interval, fee_policy, maximum_fee)| {
            let created_at = decode_u64(created_at)?;
            let limit_sat = decode_u64(limit)?;
            let maximum_fee = decode_u64(maximum_fee)?;
            let interval_seconds = match interval.as_str() {
                "never" => None,
                "hourly" => Some(60 * 60),
                "daily" => Some(24 * 60 * 60),
                "weekly" => Some(7 * 24 * 60 * 60),
                "monthly" => Some(30 * 24 * 60 * 60),
                "yearly" => Some(365 * 24 * 60 * 60),
                _ => return Err(PaymentAccountingError::CorruptData),
            };
            let fee_reserve_sat = match fee_policy.as_str() {
                "count" => maximum_fee,
                "exclude" if maximum_fee == 0 => 0,
                _ => return Err(PaymentAccountingError::CorruptData),
            };
            Ok(ConnectionBudget {
                created_at,
                limit_sat,
                interval_seconds,
                fee_reserve_sat,
            })
        })
}

fn period_start(budget: &ConnectionBudget, now: u64) -> Result<u64, PaymentAccountingError> {
    if now < budget.created_at {
        return Err(PaymentAccountingError::ValueOutOfRange);
    }
    let Some(interval) = budget.interval_seconds else {
        return Ok(budget.created_at);
    };
    let periods = (now - budget.created_at) / interval;
    budget
        .created_at
        .checked_add(
            periods
                .checked_mul(interval)
                .ok_or(PaymentAccountingError::ValueOutOfRange)?,
        )
        .ok_or(PaymentAccountingError::ValueOutOfRange)
}

fn adjust_period_used(
    transaction: &Transaction<'_>,
    attempt: &PaymentAttempt,
    old_contribution: u64,
    new_contribution: u64,
    now_sql: i64,
) -> Result<(), PaymentAccountingError> {
    let used: i64 = transaction.query_row(
        "SELECT used_sat FROM budget_periods
         WHERE connection_id = ?1 AND period_started_at = ?2",
        params![
            attempt.connection_id.as_str(),
            sqlite_u64(attempt.period_started_at.as_secs())?
        ],
        |row| row.get(0),
    )?;
    let used = decode_u64(used)?;
    let next_used = used
        .checked_sub(old_contribution)
        .and_then(|value| value.checked_add(new_contribution))
        .ok_or(PaymentAccountingError::CorruptData)?;
    transaction.execute(
        "UPDATE budget_periods SET used_sat = ?3, updated_at = ?4
         WHERE connection_id = ?1 AND period_started_at = ?2",
        params![
            attempt.connection_id.as_str(),
            sqlite_u64(attempt.period_started_at.as_secs())?,
            sqlite_u64(next_used)?,
            now_sql
        ],
    )?;
    Ok(())
}

fn load_attempt_by_event(
    connection: &Connection,
    event_id: &EventId,
) -> Result<Option<PaymentAttempt>, PaymentAccountingError> {
    connection
        .query_row(
            &attempt_select("event_id = ?1"),
            params![event_id.as_bytes().as_slice()],
            decode_attempt_row,
        )
        .optional()?
        .map(hydrate_attempt)
        .transpose()
}

fn load_attempt_by_hash(
    connection: &Connection,
    payment_hash: &PaymentHash,
) -> Result<Option<PaymentAttempt>, PaymentAccountingError> {
    connection
        .query_row(
            &attempt_select("payment_hash = ?1"),
            params![payment_hash.as_bytes().as_slice()],
            decode_attempt_row,
        )
        .optional()?
        .map(hydrate_attempt)
        .transpose()
}

fn attempt_select(predicate: &str) -> String {
    format!(
        "SELECT event_id, payment_hash, connection_id, connection_revision,
                period_started_at, principal_sat, fee_reserve_sat, state,
                actual_principal_sat, actual_fee_sat, charged_sat,
                authorization_exceeded, initiated_at,
                legacy_initiation_ambiguous, created_at, updated_at
         FROM payment_attempts WHERE {predicate}"
    )
}

type AttemptRow = (
    Vec<u8>,
    Vec<u8>,
    String,
    i64,
    i64,
    i64,
    i64,
    String,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    bool,
    Option<i64>,
    bool,
    i64,
    i64,
);

fn decode_attempt_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AttemptRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
        row.get(15)?,
    ))
}

fn hydrate_attempt(row: AttemptRow) -> Result<PaymentAttempt, PaymentAccountingError> {
    let event_id = EventId::from_bytes(fixed_32(row.0)?);
    let payment_hash = PaymentHash::from_bytes(fixed_32(row.1)?);
    let connection_id =
        ConnectionId::parse(row.2).map_err(|_| PaymentAccountingError::CorruptData)?;
    let connection_revision = ConnectionRevision::from_value(decode_u64(row.3)?);
    let period_started_at = UnixTimestamp::from_secs(decode_u64(row.4)?);
    let principal_sat = decode_u64(row.5)?;
    let fee_reserve_sat = decode_u64(row.6)?;
    let state = DurablePaymentState::from_str(&row.7)?;
    let actual_principal_sat = row.8.map(decode_u64).transpose()?;
    let actual_fee_sat = row.9.map(decode_u64).transpose()?;
    let charged_sat = row.10.map(decode_u64).transpose()?;
    let initiated_at = row
        .12
        .map(decode_u64)
        .transpose()?
        .map(UnixTimestamp::from_secs);
    let created_at = UnixTimestamp::from_secs(decode_u64(row.14)?);
    let updated_at = UnixTimestamp::from_secs(decode_u64(row.15)?);
    if updated_at < created_at || created_at < period_started_at {
        return Err(PaymentAccountingError::CorruptData);
    }
    if initiated_at.is_some_and(|initiated_at| initiated_at < created_at) {
        return Err(PaymentAccountingError::CorruptData);
    }
    match state {
        DurablePaymentState::Reserved | DurablePaymentState::Pending
            if actual_principal_sat.is_none()
                && actual_fee_sat.is_none()
                && charged_sat.is_none()
                && !row.11 => {}
        DurablePaymentState::Succeeded
            if actual_principal_sat.is_some()
                && actual_fee_sat.is_some()
                && charged_sat.is_some() => {}
        DurablePaymentState::Failed
            if actual_principal_sat.is_none()
                && actual_fee_sat.is_none()
                && charged_sat.is_none()
                && !row.11 => {}
        _ => return Err(PaymentAccountingError::CorruptData),
    }
    Ok(PaymentAttempt {
        event_id,
        payment_hash,
        connection_id,
        connection_revision,
        period_started_at,
        principal_sat,
        fee_reserve_sat,
        state,
        actual_principal_sat,
        actual_fee_sat,
        charged_sat,
        authorization_exceeded: row.11,
        initiated_at,
        legacy_initiation_ambiguous: row.13,
        created_at,
        updated_at,
    })
}

fn validate_update_time(
    attempt: &PaymentAttempt,
    now: UnixTimestamp,
) -> Result<(), PaymentAccountingError> {
    if now < attempt.updated_at {
        Err(PaymentAccountingError::ValueOutOfRange)
    } else {
        Ok(())
    }
}

fn fixed_32(value: Vec<u8>) -> Result<[u8; 32], PaymentAccountingError> {
    value
        .try_into()
        .map_err(|_| PaymentAccountingError::CorruptData)
}

fn sqlite_u64(value: u64) -> Result<i64, PaymentAccountingError> {
    i64::try_from(value).map_err(|_| PaymentAccountingError::ValueOutOfRange)
}

fn msat_to_sat_ceil(amount: AmountMsat) -> Result<u64, PaymentAccountingError> {
    amount
        .as_msat()
        .checked_add(999)
        .map(|value| value / 1_000)
        .ok_or(PaymentAccountingError::ValueOutOfRange)
}

fn decode_u64(value: i64) -> Result<u64, PaymentAccountingError> {
    u64::try_from(value).map_err(|_| PaymentAccountingError::CorruptData)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use crate::{
        BudgetInterval, BudgetPolicy, ConnectionPolicy, FeePolicy, NewConnection, NwcEncryption,
        NwcMethod, PublicKey, SecureRelayUrl, WakePolicy,
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
                "nwc-mobile-payments-{}-{suffix}",
                std::process::id()
            ));
            fs::create_dir(&directory).expect("create test directory");
            let path = directory.join("payments.sqlite3");
            Self { directory, path }
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn connection_id() -> ConnectionId {
        ConnectionId::parse("connection:payment-test").expect("connection id")
    }

    fn insert_connection(ledger: &WakeLedger, interval: BudgetInterval) -> ActiveConnection {
        ledger
            .insert_connection(
                NewConnection::new(
                    connection_id(),
                    PublicKey::from_hex(CLIENT).expect("client key"),
                    PublicKey::from_hex(WALLET).expect("wallet key"),
                    vec![SecureRelayUrl::parse("wss://relay.example.com").expect("relay")],
                    ConnectionPolicy::new(
                        [NwcMethod::PayInvoice],
                        BudgetPolicy::new(
                            1_000,
                            interval,
                            FeePolicy::CountTowardBudget {
                                maximum_fee_sat: 25,
                            },
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

    fn event(byte: u8) -> EventId {
        EventId::from_bytes([byte; 32])
    }

    fn hash(byte: u8) -> PaymentHash {
        PaymentHash::from_bytes([byte; 32])
    }

    fn reserved_attempt(outcome: PaymentReservationOutcome) -> PaymentAttempt {
        let PaymentReservationOutcome::Reserved(attempt) = outcome else {
            panic!("new reservation expected");
        };
        attempt
    }

    fn initiate_payment(ledger: &WakeLedger, byte: u8, now: u64) {
        ledger
            .mark_payment_initiated(&hash(byte), UnixTimestamp::from_secs(now))
            .expect("mark payment initiated");
    }

    #[test]
    fn reservation_debits_principal_and_maximum_fee_immediately() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger, BudgetInterval::Never);

        let first = reserved_attempt(
            ledger
                .reserve_payment(
                    &event(1),
                    &hash(1),
                    &connection,
                    600,
                    UnixTimestamp::from_secs(100),
                )
                .expect("reserve first"),
        );
        assert_eq!(first.reserved_sat(), 625);
        assert_eq!(first.state(), DurablePaymentState::Reserved);
        assert_eq!(
            ledger.reserve_payment(
                &event(2),
                &hash(2),
                &connection,
                400,
                UnixTimestamp::from_secs(101),
            ),
            Err(PaymentAccountingError::BudgetExceeded)
        );
    }

    #[test]
    fn reservation_is_idempotent_by_event_and_global_payment_hash() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger, BudgetInterval::Never);
        let original = reserved_attempt(
            ledger
                .reserve_payment(
                    &event(1),
                    &hash(1),
                    &connection,
                    500,
                    UnixTimestamp::from_secs(100),
                )
                .expect("reserve"),
        );

        assert!(matches!(
            ledger
                .reserve_payment(
                    &event(1),
                    &hash(1),
                    &connection,
                    500,
                    UnixTimestamp::from_secs(101),
                )
                .expect("same reservation"),
            PaymentReservationOutcome::Existing(attempt) if attempt == original
        ));
        assert!(matches!(
            ledger
                .reserve_payment(
                    &event(2),
                    &hash(1),
                    &connection,
                    500,
                    UnixTimestamp::from_secs(101),
                )
                .expect("same hash"),
            PaymentReservationOutcome::AlreadyTracked(attempt) if attempt.event_id() == &event(1)
        ));
        assert_eq!(
            ledger.reserve_payment(
                &event(1),
                &hash(2),
                &connection,
                500,
                UnixTimestamp::from_secs(101),
            ),
            Err(PaymentAccountingError::ReservationConflict)
        );
    }

    #[test]
    fn initiation_marker_is_durable_and_blocks_fresh_release() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger, BudgetInterval::Never);
        let attempt = reserved_attempt(
            ledger
                .reserve_payment(
                    &event(1),
                    &hash(1),
                    &connection,
                    100,
                    UnixTimestamp::from_secs(100),
                )
                .expect("reserve"),
        );
        assert!(!attempt.was_initiated());

        let initiated = ledger
            .mark_payment_initiated(&hash(1), UnixTimestamp::from_secs(101))
            .expect("mark initiated");
        assert_eq!(
            initiated.initiated_at(),
            Some(UnixTimestamp::from_secs(101))
        );
        assert_eq!(
            ledger.release_uninitiated_payment(&hash(1), UnixTimestamp::from_secs(102)),
            Err(PaymentAccountingError::TerminalStateConflict)
        );
        assert!(ledger
            .load_payment_attempt(&hash(1))
            .expect("attempt")
            .is_some_and(|attempt| attempt.was_initiated()));
    }

    #[test]
    fn uninitiated_reservation_cannot_transition_to_wallet_reported_state() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger, BudgetInterval::Never);
        ledger
            .reserve_payment(
                &event(1),
                &hash(1),
                &connection,
                100,
                UnixTimestamp::from_secs(100),
            )
            .expect("reserve");

        assert_eq!(
            ledger.mark_payment_pending(&hash(1), UnixTimestamp::from_secs(101)),
            Err(PaymentAccountingError::TerminalStateConflict)
        );
        assert_eq!(
            ledger.mark_payment_succeeded(
                &hash(1),
                AmountMsat::from_msat(100_000),
                AmountMsat::from_msat(1_000),
                UnixTimestamp::from_secs(101),
            ),
            Err(PaymentAccountingError::TerminalStateConflict)
        );
        assert_eq!(
            ledger.mark_payment_failed(&hash(1), UnixTimestamp::from_secs(101)),
            Err(PaymentAccountingError::TerminalStateConflict)
        );
    }

    #[test]
    fn new_reservations_do_not_jump_a_rotated_reconciliation_queue() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger, BudgetInterval::Never);
        for byte in [1_u8, 2] {
            ledger
                .reserve_payment(
                    &event(byte),
                    &hash(byte),
                    &connection,
                    100,
                    UnixTimestamp::from_secs(100 + u64::from(byte)),
                )
                .expect("reserve queued payment");
        }
        let (first, _) = ledger
            .load_unresolved_payment_attempts(1)
            .expect("rotate first attempt");
        assert_eq!(first[0].event_id(), &event(1));

        ledger
            .reserve_payment(
                &event(3),
                &hash(3),
                &connection,
                100,
                UnixTimestamp::from_secs(103),
            )
            .expect("reserve new payment");
        let (next, has_additional) = ledger
            .load_unresolved_payment_attempts(2)
            .expect("load fair queue");
        assert_eq!(
            next.iter()
                .map(PaymentAttempt::event_id)
                .collect::<Vec<_>>(),
            [&event(2), &event(1)]
        );
        assert!(has_additional);
    }

    #[test]
    fn expired_connection_cannot_create_a_new_reservation() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = ledger
            .insert_connection(
                NewConnection::new(
                    connection_id(),
                    PublicKey::from_hex(CLIENT).expect("client key"),
                    PublicKey::from_hex(WALLET).expect("wallet key"),
                    vec![SecureRelayUrl::parse("wss://relay.example.com").expect("relay")],
                    ConnectionPolicy::new(
                        [NwcMethod::PayInvoice],
                        BudgetPolicy::new(
                            1_000,
                            BudgetInterval::Never,
                            FeePolicy::CountTowardBudget {
                                maximum_fee_sat: 25,
                            },
                        ),
                    ),
                    NwcEncryption::Nip44V2,
                    WakePolicy::default(),
                )
                .expect("new connection")
                .with_expiration(Some(UnixTimestamp::from_secs(110))),
                UnixTimestamp::from_secs(100),
            )
            .expect("insert connection");

        assert_eq!(
            ledger.reserve_payment(
                &event(1),
                &hash(1),
                &connection,
                100,
                UnixTimestamp::from_secs(110),
            ),
            Err(PaymentAccountingError::ConnectionUnavailable)
        );
    }

    #[test]
    fn pending_debit_survives_reopen_and_late_settlement() {
        let database = TestDatabase::new();
        let connection;
        {
            let ledger = WakeLedger::open(&database.path).expect("ledger");
            connection = insert_connection(&ledger, BudgetInterval::Never);
            ledger
                .reserve_payment(
                    &event(1),
                    &hash(1),
                    &connection,
                    600,
                    UnixTimestamp::from_secs(100),
                )
                .expect("reserve");
            initiate_payment(&ledger, 1, 100);
            ledger
                .mark_payment_pending(&hash(1), UnixTimestamp::from_secs(101))
                .expect("pending");
        }

        let reopened = WakeLedger::open(&database.path).expect("reopen ledger");
        let settled = reopened
            .mark_payment_succeeded(
                &hash(1),
                AmountMsat::from_msat(600_000),
                AmountMsat::from_msat(10_000),
                UnixTimestamp::from_secs(500),
            )
            .expect("late settlement");
        assert_eq!(settled.state(), DurablePaymentState::Succeeded);
        assert_eq!(settled.charged_sat(), Some(610));
        assert!(!settled.authorization_exceeded());
        assert_eq!(
            reopened.reserve_payment(
                &event(2),
                &hash(2),
                &connection,
                390,
                UnixTimestamp::from_secs(501),
            ),
            Err(PaymentAccountingError::BudgetExceeded)
        );
        assert!(reopened
            .reserve_payment(
                &event(3),
                &hash(3),
                &connection,
                365,
                UnixTimestamp::from_secs(501),
            )
            .is_ok());
        assert_eq!(
            reopened
                .mark_payment_succeeded(
                    &hash(1),
                    AmountMsat::from_msat(600_000),
                    AmountMsat::from_msat(10_000),
                    UnixTimestamp::from_secs(502),
                )
                .expect("idempotent settlement"),
            settled
        );
    }

    #[test]
    fn definitive_failure_refunds_but_ambiguous_pending_does_not() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger, BudgetInterval::Never);
        ledger
            .reserve_payment(
                &event(1),
                &hash(1),
                &connection,
                900,
                UnixTimestamp::from_secs(100),
            )
            .expect("reserve");
        initiate_payment(&ledger, 1, 100);
        ledger
            .mark_payment_pending(&hash(1), UnixTimestamp::from_secs(101))
            .expect("pending");
        assert_eq!(
            ledger.reserve_payment(
                &event(2),
                &hash(2),
                &connection,
                51,
                UnixTimestamp::from_secs(102),
            ),
            Err(PaymentAccountingError::BudgetExceeded)
        );
        ledger
            .mark_payment_failed(&hash(1), UnixTimestamp::from_secs(103))
            .expect("definitive failure");
        assert!(ledger
            .reserve_payment(
                &event(3),
                &hash(3),
                &connection,
                975,
                UnixTimestamp::from_secs(104),
            )
            .is_ok());
    }

    #[test]
    fn host_overspend_is_recorded_and_never_hidden() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger, BudgetInterval::Never);
        ledger
            .reserve_payment(
                &event(1),
                &hash(1),
                &connection,
                500,
                UnixTimestamp::from_secs(100),
            )
            .expect("reserve");
        initiate_payment(&ledger, 1, 100);
        let settled = ledger
            .mark_payment_succeeded(
                &hash(1),
                AmountMsat::from_msat(500_000),
                AmountMsat::from_msat(50_000),
                UnixTimestamp::from_secs(101),
            )
            .expect("settle beyond fee reserve");
        assert_eq!(settled.charged_sat(), Some(550));
        assert!(settled.authorization_exceeded());
        assert_eq!(
            ledger.reserve_payment(
                &event(2),
                &hash(2),
                &connection,
                426,
                UnixTimestamp::from_secs(102),
            ),
            Err(PaymentAccountingError::BudgetExceeded)
        );
        assert!(ledger
            .reserve_payment(
                &event(3),
                &hash(3),
                &connection,
                425,
                UnixTimestamp::from_secs(102),
            )
            .is_ok());
    }

    #[test]
    fn lower_actual_principal_refunds_reserve_without_false_authorization_alarm() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger, BudgetInterval::Never);
        ledger
            .reserve_payment(
                &event(1),
                &hash(1),
                &connection,
                500,
                UnixTimestamp::from_secs(100),
            )
            .expect("reserve");
        initiate_payment(&ledger, 1, 100);

        let settled = ledger
            .mark_payment_succeeded(
                &hash(1),
                AmountMsat::from_msat(499_000),
                AmountMsat::from_msat(500),
                UnixTimestamp::from_secs(101),
            )
            .expect("settle below authorized principal");

        assert_eq!(settled.actual_principal_sat(), Some(499));
        assert_eq!(settled.actual_fee_sat(), Some(1));
        assert_eq!(settled.charged_sat(), Some(500));
        assert!(!settled.authorization_exceeded());
    }

    #[test]
    fn rollover_keeps_pending_debits_in_their_original_period() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger, BudgetInterval::Daily);
        let first = reserved_attempt(
            ledger
                .reserve_payment(
                    &event(1),
                    &hash(1),
                    &connection,
                    900,
                    UnixTimestamp::from_secs(100),
                )
                .expect("first period"),
        );
        initiate_payment(&ledger, 1, 100);
        ledger
            .mark_payment_pending(&hash(1), UnixTimestamp::from_secs(101))
            .expect("pending");
        let second = reserved_attempt(
            ledger
                .reserve_payment(
                    &event(2),
                    &hash(2),
                    &connection,
                    900,
                    UnixTimestamp::from_secs(86_500),
                )
                .expect("second period"),
        );
        assert_ne!(first.period_started_at(), second.period_started_at());

        ledger
            .mark_payment_succeeded(
                &hash(1),
                AmountMsat::from_msat(900_000),
                AmountMsat::from_msat(10_000),
                UnixTimestamp::from_secs(86_501),
            )
            .expect("late first-period settlement");
        assert_eq!(
            ledger.reserve_payment(
                &event(3),
                &hash(3),
                &connection,
                75,
                UnixTimestamp::from_secs(86_502),
            ),
            Err(PaymentAccountingError::BudgetExceeded)
        );
    }

    #[test]
    fn tombstone_blocks_stale_snapshot_reservation() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger, BudgetInterval::Never);
        ledger
            .tombstone_connection(
                connection.id(),
                connection.revision(),
                UnixTimestamp::from_secs(101),
            )
            .expect("tombstone");
        assert_eq!(
            ledger.reserve_payment(
                &event(1),
                &hash(1),
                &connection,
                100,
                UnixTimestamp::from_secs(102),
            ),
            Err(PaymentAccountingError::ConnectionUnavailable)
        );
    }

    #[test]
    fn tombstone_blocks_resume_of_an_existing_reservation() {
        let database = TestDatabase::new();
        let ledger = WakeLedger::open(&database.path).expect("ledger");
        let connection = insert_connection(&ledger, BudgetInterval::Never);
        ledger
            .reserve_payment(
                &event(1),
                &hash(1),
                &connection,
                100,
                UnixTimestamp::from_secs(100),
            )
            .expect("reserve");
        ledger
            .tombstone_connection(
                connection.id(),
                connection.revision(),
                UnixTimestamp::from_secs(101),
            )
            .expect("tombstone");

        assert_eq!(
            ledger.reserve_payment(
                &event(1),
                &hash(1),
                &connection,
                100,
                UnixTimestamp::from_secs(102),
            ),
            Err(PaymentAccountingError::ConnectionUnavailable)
        );
        assert_eq!(
            ledger
                .load_payment_attempt(&hash(1))
                .expect("load reservation")
                .expect("reservation")
                .state(),
            DurablePaymentState::Reserved
        );
    }

    #[test]
    fn concurrent_reservations_cannot_oversubscribe_budget() {
        let database = TestDatabase::new();
        let first = Arc::new(WakeLedger::open(&database.path).expect("first ledger"));
        let connection = insert_connection(&first, BudgetInterval::Never);
        let second = Arc::new(WakeLedger::open(&database.path).expect("second ledger"));
        let barrier = Arc::new(Barrier::new(2));
        let ledgers = [first, second];
        let threads = ledgers
            .into_iter()
            .enumerate()
            .map(|(index, ledger)| {
                let barrier = Arc::clone(&barrier);
                let connection = connection.clone();
                thread::spawn(move || {
                    barrier.wait();
                    ledger.reserve_payment(
                        &event(u8::try_from(index + 1).expect("event byte")),
                        &hash(u8::try_from(index + 1).expect("hash byte")),
                        &connection,
                        600,
                        UnixTimestamp::from_secs(100),
                    )
                })
            })
            .collect::<Vec<_>>();
        let outcomes = threads
            .into_iter()
            .map(|thread| thread.join().expect("reservation thread"))
            .collect::<Vec<_>>();

        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == Err(PaymentAccountingError::BudgetExceeded))
                .count(),
            1
        );
    }
}
