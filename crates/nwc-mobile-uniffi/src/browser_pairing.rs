use crate::{MobileEngineError, MobileWallet};
use nwc_mobile::{Clock, RelayTransport, StoredConnection, SystemClock};

/// Verified challenge details bound to the selected existing connection.
#[derive(Clone, Debug, uniffi::Record)]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileBrowserPairingChallenge {
    pub challenge_id: String,
    pub connection_id: String,
    pub nonce: String,
    pub audience: String,
    pub expires_at_seconds: u64,
    pub client_public_key_hex: String,
    pub wallet_service_public_key_hex: String,
}
impl MobileWallet {
    pub(crate) fn pairing_secret(&self) -> Result<nwc_mobile::NwcSecretKey, MobileEngineError> {
        let encoded = zeroize::Zeroizing::new(
            self.secrets
                .0
                .load("nwc-mobile/foreground/service-key".into())?
                .ok_or(MobileEngineError::InvalidArgument)?,
        );
        let (_, bytes) = nwc_mobile::service_secret_identity(&encoded)
            .map_err(|_| MobileEngineError::InvalidArgument)?;
        let bytes = zeroize::Zeroizing::new(bytes);
        nwc_mobile::NwcSecretKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| MobileEngineError::InvalidArgument)?,
        )
        .map_err(|_| MobileEngineError::InvalidArgument)
    }
}
#[uniffi::export]
impl MobileWallet {
    /// Verifies a signed challenge without authorizing the browser.
    pub fn parse_browser_pairing_challenge(
        &self,
        connection_id: String,
        signed_encrypted_event_json: String,
    ) -> Result<MobileBrowserPairingChallenge, MobileEngineError> {
        let Some(StoredConnection::Active(connection)) =
            self.engine.service.connection(&connection_id)?
        else {
            return Err(MobileEngineError::NotFound);
        };
        let verified = self
            .engine
            .service
            .ledger()
            .parse_browser_pairing_challenge(
                &connection,
                &signed_encrypted_event_json,
                &self.pairing_secret()?,
                SystemClock.now(),
            )?;
        Ok(MobileBrowserPairingChallenge {
            challenge_id: verified.challenge_id,
            connection_id: verified.connection_id,
            nonce: verified.nonce,
            audience: verified.audience,
            expires_at_seconds: verified.expires_at.as_secs(),
            client_public_key_hex: verified.client_pubkey_hex,
            wallet_service_public_key_hex: verified.wallet_pubkey_hex,
        })
    }
    /// Explicitly approves and publishes the retained proof. False means delivery
    /// is pending; retrying uses the same proof and cannot reset spending authority.
    pub async fn approve_browser_pairing(
        &self,
        challenge_id: String,
    ) -> Result<bool, MobileEngineError> {
        let connection_id = self
            .engine
            .service
            .ledger()
            .browser_pairing_connection(&challenge_id)?;
        let Some(StoredConnection::Active(connection)) =
            self.engine.service.connection(&connection_id)?
        else {
            return Err(MobileEngineError::NotFound);
        };
        let response = self.engine.service.ledger().approve_browser_pairing(
            &connection,
            &challenge_id,
            &self.pairing_secret()?,
            SystemClock.now(),
        )?;
        let relays = connection.relays().to_vec();
        nwc_mobile_tokio::run_on_native_runtime(async move {
            let started = std::time::Instant::now();
            for relay in relays {
                let remaining =
                    std::time::Duration::from_secs(15).saturating_sub(started.elapsed());
                let Ok(budget) = nwc_mobile::OperationBudget::new(remaining) else {
                    return false;
                };
                if nwc_mobile_nostr::NostrRelayTransport
                    .publish_event(
                        &relay,
                        &response,
                        nwc_mobile::OperationContext::new(budget, &nwc_mobile::NeverCancelled),
                    )
                    .await
                    .is_ok()
                {
                    return true;
                }
            }
            false
        })
        .await
        .map_err(|_| MobileEngineError::DatabaseUnavailable)
    }
    /// Cancels a retained challenge before approval.
    pub fn cancel_browser_pairing(&self, challenge_id: String) -> Result<(), MobileEngineError> {
        self.engine
            .service
            .ledger()
            .cancel_browser_pairing(&challenge_id)?;
        Ok(())
    }
}
