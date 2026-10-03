use crate::{
    nwa::validated_public_icon_url, ActiveConnection, Clock, ConnectionId, LedgerError,
    RegistryError, SecureRelayUrl, SystemClock, UnixTimestamp, WakeLedger,
};
use rusqlite::{params, OptionalExtension};

const MAX_DISPLAY_NAME_BYTES: usize = 256;
const MAX_ICON_URL_BYTES: usize = 2_048;

/// Non-sensitive product metadata durably associated with an NWC authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationConnectionMetadata {
    display_name: String,
    icon_url: Option<String>,
    pending_info_event_relays: Vec<String>,
}

impl ApplicationConnectionMetadata {
    /// Validates host display metadata and the capability-event relay outbox.
    pub fn new(
        display_name: impl Into<String>,
        icon_url: Option<String>,
        pending_info_event_relays: Vec<String>,
    ) -> Result<Self, RegistryError> {
        let display_name = display_name.into().trim().to_owned();
        if display_name.is_empty() || display_name.len() > MAX_DISPLAY_NAME_BYTES {
            return Err(RegistryError::InvalidConnection);
        }
        let icon_url = icon_url
            .map(|icon| {
                if icon.len() > MAX_ICON_URL_BYTES {
                    return Err(RegistryError::InvalidConnection);
                }
                validated_public_icon_url(&icon).ok_or(RegistryError::InvalidConnection)
            })
            .transpose()?;
        let pending_info_event_relays = pending_info_event_relays
            .into_iter()
            .map(|relay| {
                SecureRelayUrl::parse(&relay)
                    .map(|relay| relay.as_str().to_owned())
                    .map_err(|_| RegistryError::InvalidConnection)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            display_name,
            icon_url,
            pending_info_event_relays,
        })
    }

    /// Returns the host-selected display name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns the validated HTTPS icon URL.
    #[must_use]
    pub fn icon_url(&self) -> Option<&str> {
        self.icon_url.as_deref()
    }

    /// Returns capability-event relays still awaiting acknowledgement.
    #[must_use]
    pub fn pending_info_event_relays(&self) -> &[String] {
        &self.pending_info_event_relays
    }
}

/// Identity the payer explicitly agrees to share with one approved client.
#[derive(Clone, Eq, PartialEq)]
pub struct ConnectionPayerMetadata {
    payer_username: Option<String>,
    wallet_name: Option<String>,
}
impl ConnectionPayerMetadata {
    /// Validates optional canonical identity fields without changing their value.
    pub fn new(payer_username: Option<String>, wallet_name: Option<String>) -> Result<Self, RegistryError> {
        for (value, limit) in [(&payer_username, 128), (&wallet_name, 160)] {
            if value.as_ref().is_some_and(|value| value.is_empty() || value.trim() != value || value.chars().count() > limit || value.chars().any(char::is_control)) {
                return Err(RegistryError::InvalidConnection);
            }
        }
        if payer_username.as_ref().is_some_and(|value| value.contains('@')) {
            return Err(RegistryError::InvalidConnection);
        }
        Ok(Self { payer_username, wallet_name })
    }
    /// Username disclosed to this client, without a display prefix.
    pub fn payer_username(&self) -> Option<&str> { self.payer_username.as_deref() }
    /// Selected spending wallet name, independent of payer identity.
    pub fn wallet_name(&self) -> Option<&str> { self.wallet_name.as_deref() }
}

impl WakeLedger {
    /// Stores explicitly approved identity once; later re-pairing cannot change it.
    pub fn set_connection_payer_metadata(&self, connection_id: &str, metadata: &ConnectionPayerMetadata) -> Result<(), LedgerError> {
        if metadata.payer_username.is_none() && metadata.wallet_name.is_none() { return Ok(()); }
        let changed = self.lock_connection()?.execute(
            "INSERT INTO connection_payer_metadata(connection_id,payer_username,wallet_name) SELECT connection_id,?2,?3 FROM connections WHERE connection_id=?1 AND status='active'",
            params![connection_id, metadata.payer_username, metadata.wallet_name],
        )?;
        if changed != 1 { return Err(LedgerError::ClaimMetadataMismatch); }
        Ok(())
    }
    pub(crate) fn connection_payer_metadata(&self, connection_id: &str) -> Result<Option<ConnectionPayerMetadata>, LedgerError> {
        let row = self.lock_connection()?.query_row(
            "SELECT payer_username,wallet_name FROM connection_payer_metadata WHERE connection_id=?1", [connection_id],
            |row| Ok((row.get::<_,Option<String>>(0)?, row.get::<_,Option<String>>(1)?)),
        ).optional()?;
        row.map(|(username,name)| ConnectionPayerMetadata::new(username,name).map_err(|_| LedgerError::CorruptData)).transpose()
    }
}

/// Durable accounting snapshot for the currently active budget interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionBudgetUsage {
    spent_sat: u64,
    period_started_at: UnixTimestamp,
}

impl ConnectionBudgetUsage {
    /// Returns the amount currently reserved or settled against the interval.
    #[must_use]
    pub const fn spent_sat(self) -> u64 {
        self.spent_sat
    }

    /// Returns the deterministic start of the current accounting interval.
    #[must_use]
    pub const fn period_started_at(self) -> UnixTimestamp {
        self.period_started_at
    }
}

impl WakeLedger {
    pub(crate) fn upsert_application_metadata(
        &self,
        connection_id: &ConnectionId,
        metadata: &ApplicationConnectionMetadata,
    ) -> Result<(), LedgerError> {
        let mut database = self.lock_connection()?;
        let transaction = database.transaction()?;
        let active: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM connections
             WHERE connection_id = ?1 AND status = 'active')",
            params![connection_id.as_str()],
            |row| row.get(0),
        )?;
        if !active {
            return Err(LedgerError::CorruptData);
        }
        transaction.execute(
            "INSERT INTO connection_metadata (connection_id, display_name, icon_url)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(connection_id) DO UPDATE SET
                display_name = excluded.display_name,
                icon_url = excluded.icon_url",
            params![
                connection_id.as_str(),
                metadata.display_name(),
                metadata.icon_url()
            ],
        )?;
        for relay in metadata.pending_info_event_relays() {
            let approved: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM connection_relays
                 WHERE connection_id = ?1 AND relay_url = ?2)",
                params![connection_id.as_str(), relay],
                |row| row.get(0),
            )?;
            if !approved {
                return Err(LedgerError::CorruptData);
            }
            transaction.execute(
                "INSERT INTO nwc_info_outbox (connection_id, relay_url) VALUES (?1, ?2)
                 ON CONFLICT(connection_id, relay_url) DO NOTHING",
                params![connection_id.as_str(), relay],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn application_metadata(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<Option<ApplicationConnectionMetadata>, LedgerError> {
        let database = self.lock_connection()?;
        let stored = database
            .query_row(
                "SELECT display_name, icon_url FROM connection_metadata WHERE connection_id = ?1",
                params![connection_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?;
        let Some((display_name, icon_url)) = stored else {
            return Ok(None);
        };
        let mut statement = database.prepare(
            "SELECT relay_url FROM nwc_info_outbox
             WHERE connection_id = ?1 ORDER BY relay_url",
        )?;
        let relays = statement
            .query_map(params![connection_id.as_str()], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        ApplicationConnectionMetadata::new(display_name, icon_url, relays)
            .map(Some)
            .map_err(|_| LedgerError::CorruptData)
    }

    pub(crate) fn acknowledge_nwc_info_event(
        &self,
        connection_id: &ConnectionId,
        relay_url: &str,
    ) -> Result<(), LedgerError> {
        let relay = SecureRelayUrl::parse(relay_url).map_err(|_| LedgerError::CorruptData)?;
        self.lock_connection()?.execute(
            "DELETE FROM nwc_info_outbox WHERE connection_id = ?1 AND relay_url = ?2",
            params![connection_id.as_str(), relay.as_str()],
        )?;
        Ok(())
    }

    pub(crate) fn requeue_active_nwc_info_events(&self) -> Result<usize, LedgerError> {
        Ok(self.lock_connection()?.execute(
            "INSERT INTO nwc_info_outbox (connection_id, relay_url)
             SELECT c.connection_id, r.relay_url
             FROM connections c
             JOIN connection_relays r ON r.connection_id = c.connection_id
             JOIN connection_metadata m ON m.connection_id = c.connection_id
             WHERE c.status = 'active'
             ON CONFLICT(connection_id, relay_url) DO NOTHING",
            [],
        )?)
    }

    pub(crate) fn current_budget_usage(
        &self,
        connection: &ActiveConnection,
    ) -> Result<ConnectionBudgetUsage, LedgerError> {
        let created_at = connection.created_at().as_secs();
        let now = SystemClock.now().as_secs();
        if now < created_at {
            return Err(LedgerError::CorruptData);
        }
        let period_started_at = match connection.policy().budget().interval().duration() {
            Some(duration) => created_at
                .checked_add(((now - created_at) / duration.as_secs()) * duration.as_secs())
                .ok_or(LedgerError::ValueOutOfRange)?,
            None => created_at,
        };
        let used = self
            .lock_connection()?
            .query_row(
                "SELECT used_sat FROM budget_periods
                 WHERE connection_id = ?1 AND period_started_at = ?2",
                params![
                    connection.id().as_str(),
                    i64::try_from(period_started_at).map_err(|_| LedgerError::ValueOutOfRange)?
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(0);
        Ok(ConnectionBudgetUsage {
            spent_sat: u64::try_from(used).map_err(|_| LedgerError::CorruptData)?,
            period_started_at: UnixTimestamp::from_secs(period_started_at),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payer_metadata_accepts_only_bounded_canonical_values() {
        assert!(ConnectionPayerMetadata::new(None, None).is_ok());
        assert!(ConnectionPayerMetadata::new(Some("alice".into()), Some("Lexe".into())).is_ok());
        for bad in ["".into(), " alice".into(), "alice ".into(), "ali\nce".into(), "alice@example".into(), "@alice".into(), "a".repeat(129)] {
            assert!(ConnectionPayerMetadata::new(Some(bad), None).is_err());
        }
        assert!(ConnectionPayerMetadata::new(None, Some("x".repeat(161))).is_err());
    }

    #[test]
    fn metadata_rejects_non_public_icon_targets() {
        for icon in [
            "https://127.0.0.1/icon.png",
            "https://localhost/icon.png",
            "https://app.example/icon.png#fragment",
            "https://app.example:8443/icon.png",
        ] {
            assert!(ApplicationConnectionMetadata::new(
                "Example",
                Some(icon.to_owned()),
                Vec::new(),
            )
            .is_err());
        }
    }
}

impl WakeLedger {
    /// Stores only the explicitly approved postal address, encrypted to this connection.
    pub fn set_connection_address(&self, id: &str, json: &str, secret: &crate::NwcSecretKey) -> Result<(), LedgerError> {
        use nostr::serde_json::{json, Value};
        if json.len() > 4096 { return Err(LedgerError::ClaimMetadataMismatch); }
        let data = crate::reusable_payments::validate_customer(
            &json!({"requested_customer_fields":[{"field":"address","required":true}]}),
            json!({"address": nostr::serde_json::from_str::<Value>(json).map_err(|_| LedgerError::ClaimMetadataMismatch)?}),
        )?;
        let db = self.lock_connection()?;
        let (client, wallet): (Vec<u8>, Vec<u8>) = db.query_row("SELECT client_pubkey,wallet_service_pubkey FROM connections WHERE connection_id=?1 AND status='active'", [id], |r| Ok((r.get(0)?,r.get(1)?)))?;
        if secret.public_key().map_err(|_| LedgerError::ClaimMetadataMismatch)?.as_bytes().as_slice() != wallet { return Err(LedgerError::ClaimMetadataMismatch); }
        let client = nostr::PublicKey::from_byte_array(client.try_into().map_err(|_| LedgerError::CorruptData)?);
        let plaintext = zeroize::Zeroizing::new(json!({"connection_id":id,"address":data["address"]}).to_string());
        let cipher = nostr::nips::nip44::encrypt(&secret.nostr_secret().map_err(|_| LedgerError::CorruptData)?, &client, plaintext.as_bytes(), nostr::nips::nip44::Version::V2).map_err(|_| LedgerError::CorruptData)?;
        let changed = db.execute("UPDATE connection_payer_metadata SET address_ciphertext=?2 WHERE connection_id=?1 AND address_ciphertext IS NULL", params![id,cipher])?;
        if changed != 1 { return Err(LedgerError::ClaimMetadataMismatch); }
        Ok(())
    }
    pub(crate) fn connection_address(&self, id: &str, secret: &crate::NwcSecretKey) -> Result<Option<nostr::serde_json::Value>, LedgerError> {
        let row: Option<(String,Vec<u8>)> = self.lock_connection()?.query_row("SELECT m.address_ciphertext,c.client_pubkey FROM connection_payer_metadata m JOIN connections c USING(connection_id) WHERE connection_id=?1 AND c.status='active' AND m.address_ciphertext IS NOT NULL", [id], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
        let Some((cipher,client)) = row else { return Ok(None) };
        let client = nostr::PublicKey::from_byte_array(client.try_into().map_err(|_| LedgerError::CorruptData)?);
        let plaintext = zeroize::Zeroizing::new(nostr::nips::nip44::decrypt(&secret.nostr_secret().map_err(|_| LedgerError::CorruptData)?, &client, &cipher).map_err(|_| LedgerError::CorruptData)?);
        let data: nostr::serde_json::Value = nostr::serde_json::from_str(&plaintext).map_err(|_| LedgerError::CorruptData)?;
        if data["connection_id"] != id { return Err(LedgerError::CorruptData); }
        Ok(Some(data["address"].clone()))
    }
}
