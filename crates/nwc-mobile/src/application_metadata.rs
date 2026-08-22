use rusqlite::{params, OptionalExtension};
use url::Url;

use crate::{
    ActiveConnection, Clock, ConnectionId, LedgerError, RegistryError, SecureRelayUrl, SystemClock,
    UnixTimestamp, WakeLedger,
};

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
        if let Some(icon) = icon_url.as_deref() {
            if icon.len() > MAX_ICON_URL_BYTES {
                return Err(RegistryError::InvalidConnection);
            }
            let parsed = Url::parse(icon).map_err(|_| RegistryError::InvalidConnection)?;
            if parsed.scheme() != "https"
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
            {
                return Err(RegistryError::InvalidConnection);
            }
        }
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
