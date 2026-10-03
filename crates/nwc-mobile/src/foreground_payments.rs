//! Durable user-confirmed payment handoff. No wallet operation runs from this queue.
use crate::{
    AmountMsat, EventId, LedgerError, PaymentFailure, PaymentPreimage, PaymentStatus, PublicKey,
    UnixTimestamp, WakeInput, WakeLedger,
};
use nostr::hashes::{sha256, Hash};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

type ForegroundStatusRow = (String, Option<Vec<u8>>, Option<u64>, Option<u64>);

pub(crate) const SCHEMA: &str = r#"
CREATE TABLE foreground_payment_settings (singleton INTEGER PRIMARY KEY CHECK(singleton=1)) STRICT;
CREATE TABLE foreground_payment_bindings (connection_id TEXT PRIMARY KEY, wallet_id TEXT NOT NULL, payment_hash BLOB NOT NULL, amount_msat INTEGER NOT NULL, maximum_fee_sat INTEGER NOT NULL) STRICT;
CREATE TABLE foreground_payment_requests (
 event_id BLOB PRIMARY KEY NOT NULL,
 relay TEXT NOT NULL,
 wallet_public_key BLOB NOT NULL,
 event_json TEXT NOT NULL,
 invoice TEXT,
 amount_msat INTEGER,
 state TEXT NOT NULL DEFAULT 'awaiting_approval' CHECK(state IN ('awaiting_approval','in_flight','succeeded','failed','rejected')),
 wallet_id TEXT,
 preimage BLOB,
 fee_msat INTEGER
) STRICT;
"#;

/// A payment's immutable request and durable foreground state. Contains no preimage.
#[derive(Clone)]
pub struct ForegroundPayment {
    /// Authenticated Nostr request identifier and idempotency reference.
    pub event_id_hex: String,
    /// Authorized connection identifier.
    pub connection_id: String,
    /// Exact invoice from the encrypted request.
    pub invoice: String,
    /// Invoice payment hash.
    pub payment_hash_hex: String,
    /// Exact quoted principal in millisatoshis.
    pub amount_msat: u64,
    /// Reserved maximum routing fee in satoshis.
    pub maximum_fee_sat: Option<u64>,
    /// Explicit capped or wallet_managed extra-cost policy.
    pub fee_policy: String,
    /// Actual recipient amount from successful wallet evidence.
    pub actual_amount_msat: Option<u64>,
    /// Actual routing fee from successful wallet evidence.
    pub fee_msat: Option<u64>,
    /// Durable state, including ambiguous in-flight work after a restart.
    pub state: String,
    /// Opaque host wallet selected at the one-shot execution handoff.
    pub wallet_id: Option<String>,
    /// Authenticated purchase context pinned to the exact request event.
    pub purchase_json: Option<String>,
}

impl WakeLedger {
    /// Binds one approved connection to one invoice, amount, wallet, and fee ceiling.
    /// This immutable restriction must be set before processing payment requests.
    pub fn bind_foreground_payment(
        &self,
        connection_id: &str,
        wallet_id: &str,
        hash: &crate::PaymentHash,
        amount_msat: u64,
        maximum_fee_sat: u64,
    ) -> Result<(), LedgerError> {
        self.bind_foreground_payment_policy(
            connection_id,
            wallet_id,
            hash,
            amount_msat,
            maximum_fee_sat,
            None,
        )
    }

    /// Binds explicit wallet-managed extra costs to one exact invoice and wallet.
    pub fn bind_wallet_managed_foreground_payment(
        &self,
        connection_id: &str,
        wallet_id: &str,
        hash: &crate::PaymentHash,
        amount_msat: u64,
        invoice: &str,
    ) -> Result<(), LedgerError> {
        if invoice.is_empty() || invoice.len() > 32768 {
            return Err(LedgerError::ValueOutOfRange);
        }
        self.bind_foreground_payment_policy(
            connection_id,
            wallet_id,
            hash,
            amount_msat,
            0,
            Some(invoice),
        )
    }

    fn bind_foreground_payment_policy(
        &self,
        connection_id: &str,
        wallet_id: &str,
        hash: &crate::PaymentHash,
        amount_msat: u64,
        maximum_fee_sat: u64,
        invoice: Option<&str>,
    ) -> Result<(), LedgerError> {
        if wallet_id.is_empty() || wallet_id.len() > 128 || amount_msat == 0 {
            return Err(LedgerError::ValueOutOfRange);
        }
        let mut db = self.lock_connection()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM payment_attempts WHERE connection_id=?1",
            [connection_id],
            |r| r.get(0),
        )?;
        if count != 0 {
            return Err(LedgerError::ClaimMetadataMismatch);
        }
        let policy = if invoice.is_some() {
            "wallet_managed"
        } else {
            "capped"
        };
        let changed=tx.execute("UPDATE connections SET maximum_fee_sat=?2 WHERE connection_id=?1 AND status='active' AND fee_policy='count' AND foreground_fee_policy=?3 AND budget_limit_sat>=?2 AND (?3='capped' OR (budget_limit_sat=?4 AND EXISTS(SELECT 1 FROM foreground_payment_settings))) AND NOT EXISTS(SELECT 1 FROM foreground_payment_bindings WHERE connection_id=?1)",params![connection_id,maximum_fee_sat,policy,amount_msat.div_ceil(1000)])?;
        if changed != 1 {
            return Err(LedgerError::ConnectionUnavailable);
        }
        tx.execute(
            "INSERT INTO foreground_payment_bindings(connection_id,wallet_id,payment_hash,amount_msat,maximum_fee_sat,invoice) VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                connection_id,
                wallet_id,
                hash.as_bytes().as_slice(),
                amount_msat,
                maximum_fee_sat,
                invoice
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Returns the explicit foreground fee policy retained at authorization.
    pub fn foreground_fee_policy(&self, connection_id: &str) -> Result<String, LedgerError> {
        Ok(self.lock_connection()?.query_row(
            "SELECT foreground_fee_policy FROM connections WHERE connection_id=?1",
            [connection_id],
            |r| r.get(0),
        )?)
    }

    /// Whether the foreground connection has its immutable payment binding.
    pub fn has_foreground_binding(&self, connection_id: &str) -> Result<bool, LedgerError> {
        Ok(self.lock_connection()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM foreground_payment_bindings WHERE connection_id=?1 UNION ALL SELECT 1 FROM foreground_reusable_bindings WHERE connection_id=?1)",
            [connection_id],
            |r| r.get(0),
        )?)
    }

    pub(crate) fn lookup_foreground_payment(
        &self,
        connection_id: &str,
        lookup: &crate::InvoiceLookup,
    ) -> Result<Option<crate::WalletTransaction>, LedgerError> {
        let (hash, invoice) = match lookup {
            crate::InvoiceLookup::PaymentHash(hash) => (Some(hash.to_hex()), None),
            crate::InvoiceLookup::Invoice(invoice) => (None, Some(invoice.clone())),
        };
        let row:Option<(String,String,u64,u64,u64)>=self.lock_connection()?.query_row("SELECT lower(hex(p.event_id)),lower(hex(p.payment_hash)),COALESCE(f.actual_amount_msat,f.amount_msat),p.created_at,p.updated_at FROM foreground_payment_requests f JOIN payment_attempts p USING(event_id) WHERE p.connection_id=?1 AND ((?2 IS NOT NULL AND lower(hex(p.payment_hash))=?2) OR (?3 IS NOT NULL AND f.invoice=?3))",params![connection_id,hash,invoice],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
        let Some((event, hash, amount, created, updated)) = row else {
            return Ok(None);
        };
        let event = EventId::from_hex(&event).map_err(|_| LedgerError::CorruptData)?;
        let status = self
            .foreground_payment_status(&event)?
            .ok_or(LedgerError::CorruptData)?;
        let (fee, settled_at) = match &status {
            PaymentStatus::Succeeded { fee, .. } => (*fee, Some(UnixTimestamp::from_secs(updated))),
            _ => (AmountMsat::from_msat(0), None),
        };
        Ok(Some(crate::WalletTransaction {
            payment_hash: Some(
                crate::PaymentHash::from_hex(&hash).map_err(|_| LedgerError::CorruptData)?,
            ),
            direction: crate::TransactionDirection::Outgoing,
            amount: AmountMsat::from_msat(amount),
            fee,
            created_at: UnixTimestamp::from_secs(created),
            settled_at,
            status,
        }))
    }

    pub(crate) fn matches_foreground_binding(
        &self,
        connection_id: &str,
        hash: &crate::PaymentHash,
        amount: AmountMsat,
        invoice: &str,
    ) -> Result<bool, LedgerError> {
        Ok(self.lock_connection()?.query_row("SELECT EXISTS(SELECT 1 FROM foreground_payment_bindings WHERE connection_id=?1 AND payment_hash=?2 AND amount_msat=?3 AND (invoice IS NULL OR invoice=?4))",params![connection_id,hash.as_bytes().as_slice(),amount.as_msat(),invoice],|r|r.get(0))?)
    }

    /// Permanently enables foreground handoff for payments in this shared ledger.
    /// Every native process sees this setting; omitting configuration cannot bypass it.
    pub fn enable_foreground_payments(&self) -> Result<(), LedgerError> {
        self.lock_connection()?.execute(
            "INSERT OR IGNORE INTO foreground_payment_settings VALUES (1)",
            [],
        )?;
        Ok(())
    }

    /// Returns whether all new payments require foreground confirmation.
    pub fn foreground_payments_enabled(&self) -> Result<bool, LedgerError> {
        Ok(self.lock_connection()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM foreground_payment_settings)",
            [],
            |r| r.get(0),
        )?)
    }

    pub(crate) fn retain_foreground_wake(
        &self,
        wake: &WakeInput,
        event_json: &str,
    ) -> Result<(), LedgerError> {
        self.lock_connection()?.execute("INSERT OR IGNORE INTO foreground_payment_requests(event_id,relay,wallet_public_key,event_json) VALUES (?1,?2,?3,?4)", params![wake.event_id().as_bytes().as_slice(),wake.relay(),wake.wallet_service_pubkey().as_bytes().as_slice(),event_json])?;
        Ok(())
    }

    pub(crate) fn quote_foreground_payment(
        &self,
        event: &EventId,
        invoice: &str,
        amount: AmountMsat,
    ) -> Result<(), LedgerError> {
        self.lock_connection()?.execute("UPDATE foreground_payment_requests SET invoice=?2,amount_msat=?3 WHERE event_id=?1 AND invoice IS NULL", params![event.as_bytes().as_slice(),invoice,i64::try_from(amount.as_msat()).map_err(|_| LedgerError::ValueOutOfRange)?])?;
        Ok(())
    }

    /// Lists bounded requests that hold a durable payment reservation.
    pub fn foreground_payments(&self) -> Result<Vec<ForegroundPayment>, LedgerError> {
        let db = self.lock_connection()?;
        let mut query = db.prepare("SELECT lower(hex(f.event_id)),p.connection_id,f.invoice,lower(hex(p.payment_hash)),f.amount_msat,p.fee_reserve_sat,f.state,COALESCE(f.wallet_id,b.wallet_id,r.wallet_id),c.foreground_fee_policy,f.actual_amount_msat,f.fee_msat,f.purchase_json FROM foreground_payment_requests f JOIN payment_attempts p USING(event_id) JOIN connections c ON c.connection_id=p.connection_id LEFT JOIN foreground_payment_bindings b ON b.connection_id=p.connection_id LEFT JOIN foreground_reusable_bindings r ON r.connection_id=p.connection_id WHERE f.invoice IS NOT NULL ORDER BY p.created_at DESC LIMIT 100")?;
        let rows = query
            .query_map([], |r| {
                Ok(ForegroundPayment {
                    event_id_hex: r.get(0)?,
                    connection_id: r.get(1)?,
                    invoice: r.get(2)?,
                    payment_hash_hex: r.get(3)?,
                    amount_msat: r.get(4)?,
                    maximum_fee_sat: if r.get::<_, String>(8)? == "wallet_managed" {
                        None
                    } else {
                        Some(r.get(5)?)
                    },
                    fee_policy: r.get(8)?,
                    actual_amount_msat: r.get(9)?,
                    fee_msat: r.get(10)?,
                    state: r.get(6)?,
                    wallet_id: r.get(7)?,
                    purchase_json: r.get(11)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Claims the one execution handoff. Repeated calls never return permission to pay.
    /// In-flight records must be reconciled against the selected wallet by event/hash.
    pub fn begin_foreground_payment(
        &self,
        event: &EventId,
        wallet_id: &str,
        now: UnixTimestamp,
    ) -> Result<(), LedgerError> {
        self.begin_foreground_payment_inner(event, wallet_id, now, None)
    }
    pub(crate) fn begin_foreground_payment_inner(
        &self,
        event: &EventId,
        wallet_id: &str,
        now: UnixTimestamp,
        consent: Option<&str>,
    ) -> Result<(), LedgerError> {
        if wallet_id.is_empty() || wallet_id.len() > 128 {
            return Err(LedgerError::ValueOutOfRange);
        }
        let mut db = self.lock_connection()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed=tx.execute("UPDATE foreground_payment_requests SET state='in_flight',wallet_id=?2,consent_ciphertext=?4 WHERE event_id=?1 AND state='awaiting_approval' AND EXISTS (SELECT 1 FROM payment_attempts p JOIN connections c ON c.connection_id=p.connection_id WHERE p.event_id=?1 AND p.state='reserved' AND p.initiated_at IS NULL AND c.status='active' AND c.revision=p.connection_revision AND ((?4 IS NOT NULL AND purchase_json IS NOT NULL AND EXISTS(SELECT 1 FROM foreground_reusable_bindings b WHERE b.connection_id=p.connection_id AND b.wallet_id=?2)) OR (?4 IS NULL AND EXISTS(SELECT 1 FROM foreground_payment_bindings b WHERE b.connection_id=p.connection_id AND b.wallet_id=?2 AND b.payment_hash=p.payment_hash) AND NOT EXISTS(SELECT 1 FROM payment_attempts other WHERE other.connection_id=p.connection_id AND other.event_id!=p.event_id AND other.initiated_at IS NOT NULL))) AND (c.expires_at IS NULL OR c.expires_at>?3))", params![event.as_bytes().as_slice(),wallet_id,now.as_secs(),consent])?;
        if changed != 1 {
            return Err(LedgerError::ConnectionUnavailable);
        }
        tx.execute(
            "UPDATE payment_attempts SET initiated_at=?2,updated_at=?2 WHERE event_id=?1",
            params![event.as_bytes().as_slice(), now.as_secs()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Records a verified successful foreground result. Repeating the exact result is safe.
    /// The host must obtain this from the selected wallet's durable payment record.
    pub fn complete_foreground_payment(
        &self,
        event: &EventId,
        preimage: &PaymentPreimage,
        amount: AmountMsat,
        fee: AmountMsat,
        now: UnixTimestamp,
    ) -> Result<(), LedgerError> {
        let db = self.lock_connection()?;
        let hash = sha256::Hash::hash(preimage.as_bytes()).to_byte_array();
        let changed=db.execute("UPDATE foreground_payment_requests SET state='succeeded',preimage=?2,fee_msat=?4,actual_amount_msat=?3 WHERE event_id=?1 AND ((state='in_flight') OR (state='succeeded' AND preimage=?2 AND fee_msat=?4 AND actual_amount_msat=?3)) AND (amount_msat=?3 OR (amount_msat<?3 AND EXISTS(SELECT 1 FROM payment_attempts p JOIN connections c USING(connection_id) WHERE p.event_id=?1 AND c.foreground_fee_policy='wallet_managed'))) AND EXISTS(SELECT 1 FROM payment_attempts p WHERE p.event_id=?1 AND p.payment_hash=?5)",params![event.as_bytes().as_slice(),preimage.as_bytes().as_slice(),amount.as_msat(),fee.as_msat(),hash.as_slice()])?;
        if changed != 1 {
            return Err(LedgerError::ClaimMetadataMismatch);
        }
        drop(db);
        self.mark_payment_succeeded(&crate::PaymentHash::from_bytes(hash), amount, fee, now)
            .map_err(|_| LedgerError::DatabaseUnavailable)?;
        Ok(())
    }

    /// Rejects before handoff, or records definitive wallet failure after handoff.
    /// Never report a timeout, cancellation, or unknown wallet result as failure.
    pub fn reject_foreground_payment(
        &self,
        event: &EventId,
        after_handoff: bool,
        now: UnixTimestamp,
    ) -> Result<(), LedgerError> {
        let (from, to) = if after_handoff {
            ("in_flight", "failed")
        } else {
            ("awaiting_approval", "rejected")
        };
        let changed=self.lock_connection()?.execute("UPDATE foreground_payment_requests SET state=?3 WHERE event_id=?1 AND state IN (?2,?3)",params![event.as_bytes().as_slice(),from,to])?;
        if changed != 1 {
            return Err(LedgerError::ClaimMetadataMismatch);
        }
        let attempt = self
            .load_payment_attempt_by_event(event)
            .map_err(|_| LedgerError::DatabaseUnavailable)?
            .ok_or(LedgerError::CorruptData)?;
        if !attempt.was_initiated() {
            self.mark_payment_initiated(attempt.payment_hash(), now)
                .map_err(|_| LedgerError::DatabaseUnavailable)?;
        }
        self.mark_payment_failed(attempt.payment_hash(), now)
            .map_err(|_| LedgerError::DatabaseUnavailable)?;
        Ok(())
    }

    /// Previously initiated work that still needs foreground reconciliation or response delivery.
    pub fn foreground_recovery_events(
        &self,
        connection_id: &str,
    ) -> Result<Vec<EventId>, LedgerError> {
        let db = self.lock_connection()?;
        let mut query=db.prepare("SELECT f.event_id FROM foreground_payment_requests f JOIN payment_attempts p USING(event_id) WHERE p.connection_id=?1 AND p.initiated_at IS NOT NULL AND f.state IN ('in_flight','succeeded','failed') AND f.response_published=0 ORDER BY p.created_at LIMIT 16")?;
        let rows = query
            .query_map([connection_id], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|bytes| {
                Ok(EventId::from_bytes(
                    bytes.try_into().map_err(|_| LedgerError::CorruptData)?,
                ))
            })
            .collect()
    }

    pub(crate) fn is_foreground_recovery_wake(
        &self,
        wake: &WakeInput,
    ) -> Result<bool, LedgerError> {
        let Some(json) = wake.embedded_event_json() else {
            return Ok(false);
        };
        Ok(self.lock_connection()?.query_row("SELECT EXISTS(SELECT 1 FROM foreground_payment_requests f JOIN payment_attempts p USING(event_id) JOIN connections c USING(connection_id) WHERE f.event_id=?1 AND f.relay=?2 AND f.wallet_public_key=?3 AND f.event_json=?4 AND p.initiated_at IS NOT NULL AND f.state IN ('in_flight','succeeded','failed') AND c.status='active' AND c.revision=p.connection_revision)",params![wake.event_id().as_bytes().as_slice(),wake.relay(),wake.wallet_service_pubkey().as_bytes().as_slice(),json],|r|r.get(0))?)
    }

    pub(crate) fn acknowledge_foreground_response(
        &self,
        event: &EventId,
    ) -> Result<(), LedgerError> {
        self.lock_connection()?.execute("UPDATE foreground_payment_requests SET response_published=1 WHERE event_id=?1 AND state IN ('succeeded','failed','rejected')",params![event.as_bytes().as_slice()])?;
        Ok(())
    }

    /// Reconstructs the retained encrypted wake for response publication and replay.
    pub fn foreground_payment_wake(
        &self,
        event: &EventId,
        now: UnixTimestamp,
    ) -> Result<WakeInput, LedgerError> {
        self.lock_connection()?.execute(
            "UPDATE wake_events SET available_at=?2 WHERE event_id=?1 AND state='retryable'",
            params![event.as_bytes().as_slice(), now.as_secs()],
        )?;
        let (relay,key,json):(String,Vec<u8>,String)=self.lock_connection()?.query_row("SELECT relay,wallet_public_key,event_json FROM foreground_payment_requests WHERE event_id=?1",params![event.as_bytes().as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        let bytes: [u8; 32] = key.try_into().map_err(|_| LedgerError::CorruptData)?;
        Ok(WakeInput::new(
            relay,
            event.clone(),
            PublicKey::from_bytes(bytes),
            Some(json),
            now,
        ))
    }

    pub(crate) fn foreground_payment_status(
        &self,
        event: &EventId,
    ) -> Result<Option<PaymentStatus>, LedgerError> {
        let row:Option<ForegroundStatusRow>=self.lock_connection()?.query_row("SELECT state,preimage,actual_amount_msat,fee_msat FROM foreground_payment_requests WHERE event_id=?1",params![event.as_bytes().as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        match row {
            None => Ok(None),
            Some((state, preimage, amount, fee)) => Ok(Some(match state.as_str() {
                "succeeded" => PaymentStatus::Succeeded {
                    preimage: PaymentPreimage::from_bytes(
                        preimage
                            .ok_or(LedgerError::CorruptData)?
                            .try_into()
                            .map_err(|_| LedgerError::CorruptData)?,
                    ),
                    amount: AmountMsat::from_msat(amount.ok_or(LedgerError::CorruptData)?),
                    fee: AmountMsat::from_msat(fee.ok_or(LedgerError::CorruptData)?),
                },
                "failed" | "rejected" => PaymentStatus::Failed {
                    reason: PaymentFailure::Other,
                },
                _ => PaymentStatus::Pending,
            })),
        }
    }
}
