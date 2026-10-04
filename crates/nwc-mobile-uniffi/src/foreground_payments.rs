//! Foreground handoff API used by native applications and React Native.
use crate::{
    MobileCancellation, MobileEngineError, MobileWakeDisposition, MobileWallet, ValidatedMobileWake,
};
use nwc_mobile::{AmountMsat, Clock, EventId, PaymentPreimage, SystemClock};
use std::sync::Arc;

/// Immutable payment details and durable user-confirmation state.
#[derive(Clone, uniffi::Record, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileForegroundPayment {
    pub purchase_json: Option<String>,
    /// Original Nostr event identifier.
    pub event_id_hex: String,
    /// Authorizing connection identifier.
    pub connection_id: String,
    /// Exact requested BOLT11 invoice.
    pub invoice: String,
    /// Invoice payment hash.
    pub payment_hash_hex: String,
    /// Exact principal in millisatoshis.
    pub amount_msat: u64,
    /// Maximum fee allowed at execution in satoshis.
    pub maximum_fee_sat: Option<u64>,
    /// capped or wallet_managed, bound during authorization.
    pub fee_policy: String,
    /// Actual recipient amount after successful reconciliation.
    pub actual_amount_msat: Option<u64>,
    /// Actual wallet-reported routing fee after reconciliation.
    pub fee_msat: Option<u64>,
    /// awaiting_approval, in_flight, succeeded, failed, or rejected.
    pub state: String,
    /// Opaque wallet bound by the first execution handoff.
    pub wallet_id: Option<String>,
}

#[uniffi::export]
impl MobileWallet {
    /// Restricts an explicitly approved connection before any request is processed.
    pub fn bind_connection_payment(
        &self,
        connection_id: String,
        wallet_id: String,
        payment_hash_hex: String,
        amount_msat: u64,
        maximum_fee_sat: u64,
    ) -> Result<(), MobileEngineError> {
        let hash = nwc_mobile::PaymentHash::from_hex(&payment_hash_hex)
            .map_err(|_| MobileEngineError::InvalidArgument)?;
        self.engine.service.ledger().bind_foreground_payment(
            &connection_id,
            &wallet_id,
            &hash,
            amount_msat,
            maximum_fee_sat,
        )?;
        Ok(())
    }

    /// Polls approved relays while the application is foregrounded. All candidates
    /// still pass through signature, recipient, freshness, policy, and replay checks.
    pub async fn poll_requests(
        &self,
        execution_milliseconds: u64,
    ) -> Result<u32, MobileEngineError> {
        if execution_milliseconds == 0 || execution_milliseconds > 30_000 {
            return Err(MobileEngineError::InvalidArgument);
        }
        let started = std::time::Instant::now();
        let total = std::time::Duration::from_millis(execution_milliseconds);
        // Capability announcements are retryable outbox work, not a prerequisite
        // for receiving requests on already authorized connections.
        let _ = self
            .engine
            .publish_pending_info_events(execution_milliseconds / 2)
            .await;
        let mut processed = 0;
        let connections = self.engine.service.active_connections()?;
        let now = SystemClock.now();
        for connection in pollable_connections(connections.clone(), now)
            .into_iter()
            .take(32)
        {
            for relay in connection.relays().iter().take(8) {
                let remaining = total.saturating_sub(started.elapsed());
                if remaining < std::time::Duration::from_millis(100) {
                    return Ok(processed);
                }
                let request_relay = relay.clone();
                let wallet = connection.wallet_service_pubkey().clone();
                let client = connection.client_pubkey().clone();
                let since = nwc_mobile::UnixTimestamp::from_secs(
                    SystemClock.now().as_secs().saturating_sub(600),
                );
                let budget = nwc_mobile::OperationBudget::new(
                    remaining.min(std::time::Duration::from_secs(5)),
                )
                .map_err(|_| MobileEngineError::InvalidArgument)?;
                let result = nwc_mobile_tokio::run_on_native_runtime(async move {
                    nwc_mobile_nostr::fetch_request_candidates(
                        &request_relay,
                        &wallet,
                        &client,
                        since,
                        nwc_mobile::OperationContext::new(budget, &nwc_mobile::NeverCancelled),
                    )
                    .await
                })
                .await;
                let Ok(Ok(events)) = result else {
                    continue;
                };
                for (event_id, json) in events {
                    let remaining = total.saturating_sub(started.elapsed());
                    if remaining < std::time::Duration::from_millis(100) {
                        return Ok(processed);
                    }
                    let input = nwc_mobile::WakeInput::new(
                        relay.as_str().into(),
                        event_id,
                        connection.wallet_service_pubkey().clone(),
                        Some(json),
                        SystemClock.now(),
                    );
                    self.engine
                        .execute_wake(
                            Arc::new(ValidatedMobileWake {
                                input,
                                settlement_check: false,
                            }),
                            remaining.as_millis().min(30_000) as u64,
                            MobileCancellation::new(),
                        )
                        .await?;
                    processed += 1;
                }
            }
        }
        // Expired connections never create fresh relay subscriptions. Only exact
        // retained, previously initiated work can reconcile/publish after expiry.
        for connection in connections
            .into_iter()
            .filter(|connection| connection.is_expired_at(now))
            .take(32)
        {
            for event in self
                .engine
                .service
                .ledger()
                .foreground_recovery_events(connection.id().as_str())?
            {
                let remaining = total.saturating_sub(started.elapsed());
                if remaining < std::time::Duration::from_millis(100) {
                    return Ok(processed);
                }
                self.resume_payment(event.to_hex(), remaining.as_millis().min(30_000) as u64)
                    .await?;
                processed += 1;
            }
        }
        Ok(processed)
    }

    /// Enables the shared-ledger gate before processing any requests.
    pub fn enable_foreground_payments(&self) -> Result<(), MobileEngineError> {
        self.engine
            .service
            .ledger()
            .enable_foreground_payments()
            .map_err(Into::into)
    }
    /// Lists at most 100 durable requests, including in-flight recovery records.
    pub fn list_pending_payments(&self) -> Result<Vec<MobileForegroundPayment>, MobileEngineError> {
        Ok(self
            .engine
            .service
            .ledger()
            .foreground_payments()?
            .into_iter()
            .map(|p| MobileForegroundPayment {
                purchase_json: p.purchase_json,
                event_id_hex: p.event_id_hex,
                connection_id: p.connection_id,
                invoice: p.invoice,
                payment_hash_hex: p.payment_hash_hex,
                amount_msat: p.amount_msat,
                maximum_fee_sat: p.maximum_fee_sat,
                fee_policy: p.fee_policy,
                actual_amount_msat: p.actual_amount_msat,
                fee_msat: p.fee_msat,
                state: p.state,
                wallet_id: p.wallet_id,
            })
            .collect())
    }
    /// One-shot approval and execution handoff. Never repeat payment on an error.
    pub fn begin_payment(
        &self,
        event_id_hex: String,
        wallet_id: String,
    ) -> Result<MobileForegroundPayment, MobileEngineError> {
        let event = parse_event(&event_id_hex)?;
        let mut request = self
            .list_pending_payments()?
            .into_iter()
            .find(|p| p.event_id_hex == event.to_hex())
            .ok_or(MobileEngineError::NotFound)?;
        let invoice = nwc_mobile_bolt11::parse_invoice(&request.invoice)
            .map_err(|_| MobileEngineError::InvalidArgument)?;
        let explicit_amount = if invoice.amount_milli_satoshis().is_none() {
            Some(AmountMsat::from_msat(request.amount_msat))
        } else {
            None
        };
        nwc_mobile_bolt11::payment_amount(&invoice, explicit_amount)
            .map_err(|_| MobileEngineError::InvalidArgument)?;
        self.engine.service.ledger().begin_foreground_payment(
            &event,
            &wallet_id,
            SystemClock.now(),
        )?;
        request.state = "in_flight".into();
        request.wallet_id = Some(wallet_id);
        Ok(request)
    }
    /// Validates and stores explicit per-purchase consent before claiming the handoff.
    pub fn begin_payment_with_consent(
        &self,
        event_id_hex: String,
        wallet_id: String,
        customer_data_json: String,
    ) -> Result<MobileForegroundPayment, MobileEngineError> {
        let event = parse_event(&event_id_hex)?;
        let mut request = self
            .list_pending_payments()?
            .into_iter()
            .find(|p| p.event_id_hex == event_id_hex)
            .ok_or(MobileEngineError::NotFound)?;
        let invoice = nwc_mobile_bolt11::parse_invoice(&request.invoice)
            .map_err(|_| MobileEngineError::InvalidArgument)?;
        nwc_mobile_bolt11::payment_amount(&invoice, None)
            .map_err(|_| MobileEngineError::InvalidArgument)?;
        let encoded = zeroize::Zeroizing::new(
            self.secrets
                .0
                .load("nwc-mobile/foreground/service-key".into())?
                .ok_or(MobileEngineError::InvalidArgument)?,
        );
        let (_, bytes) = nwc_mobile::service_secret_identity(&encoded)
            .map_err(|_| MobileEngineError::InvalidArgument)?;
        let bytes = zeroize::Zeroizing::new(bytes);
        let secret = nwc_mobile::NwcSecretKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| MobileEngineError::InvalidArgument)?,
        )
        .map_err(|_| MobileEngineError::InvalidArgument)?;
        self.engine
            .service
            .ledger()
            .begin_foreground_payment_with_consent(
                &event,
                &wallet_id,
                &customer_data_json,
                &secret,
                SystemClock.now(),
            )?;
        request.state = "in_flight".into();
        request.wallet_id = Some(wallet_id);
        Ok(request)
    }
    /// Stores verified payment evidence for response publication. Real fees are required.
    pub fn complete_payment(
        &self,
        event_id_hex: String,
        preimage_hex: String,
        amount_msat: u64,
        fee_msat: u64,
    ) -> Result<(), MobileEngineError> {
        let preimage = PaymentPreimage::from_hex(&preimage_hex)
            .map_err(|_| MobileEngineError::InvalidArgument)?;
        self.engine.service.ledger().complete_foreground_payment(
            &parse_event(&event_id_hex)?,
            &preimage,
            AmountMsat::from_msat(amount_msat),
            AmountMsat::from_msat(fee_msat),
            SystemClock.now(),
        )?;
        Ok(())
    }
    /// Rejects only an unsubmitted request. Cannot cancel an ambiguous payment.
    pub fn reject_payment(&self, event_id_hex: String) -> Result<(), MobileEngineError> {
        self.engine.service.ledger().reject_foreground_payment(
            &parse_event(&event_id_hex)?,
            false,
            SystemClock.now(),
        )?;
        Ok(())
    }
    /// Records definitive wallet failure. Timeouts and unknown outcomes must remain in flight.
    pub fn fail_payment(&self, event_id_hex: String) -> Result<(), MobileEngineError> {
        self.engine.service.ledger().reject_foreground_payment(
            &parse_event(&event_id_hex)?,
            true,
            SystemClock.now(),
        )?;
        Ok(())
    }
    /// Replays retained authenticated work to account and publish its result; never pays in native code.
    pub async fn resume_payment(
        &self,
        event_id_hex: String,
        execution_milliseconds: u64,
    ) -> Result<MobileWakeDisposition, MobileEngineError> {
        let input = self
            .engine
            .service
            .ledger()
            .foreground_payment_wake(&parse_event(&event_id_hex)?, SystemClock.now())?;
        self.engine
            .execute_wake(
                Arc::new(ValidatedMobileWake {
                    input,
                    settlement_check: false,
                }),
                execution_milliseconds,
                MobileCancellation::new(),
            )
            .await
    }
}
pub(crate) fn pollable_connections(
    connections: Vec<nwc_mobile::ActiveConnection>,
    now: nwc_mobile::UnixTimestamp,
) -> Vec<nwc_mobile::ActiveConnection> {
    connections
        .into_iter()
        .filter(|connection| !connection.is_expired_at(now))
        .collect()
}

fn parse_event(value: &str) -> Result<EventId, MobileEngineError> {
    EventId::from_hex(value).map_err(|_| MobileEngineError::InvalidArgument)
}
