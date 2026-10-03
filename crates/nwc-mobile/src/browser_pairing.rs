use crate::{
    ActiveConnection, EventId, LedgerError, NwcEventValidator, NwcSecretKey, UnixTimestamp,
    WakeLedger, WakePolicy,
};
use nostr::serde_json::{json, Value};
use nostr::{Event, JsonUtil};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

/// Verified public browser challenge details for explicit foreground consent.
#[derive(Clone)]
pub struct BrowserPairingChallenge {
    /// Server challenge identity, bound to a single signed event.
    pub challenge_id: String,
    /// Existing wallet-local connection identity.
    pub connection_id: String,
    /// Browser challenge nonce.
    pub nonce: String,
    /// Canonical HTTPS audience.
    pub audience: String,
    /// Exclusive challenge expiry.
    pub expires_at: UnixTimestamp,
    /// Existing client public key.
    pub client_pubkey_hex: String,
    /// Existing wallet public key.
    pub wallet_pubkey_hex: String,
}
fn invalid() -> LedgerError {
    LedgerError::ClaimMetadataMismatch
}
fn bounded(value: &Value, max: usize) -> Result<String, LedgerError> {
    let text = value.as_str().ok_or_else(invalid)?;
    if text.is_empty()
        || text.len() > max
        || text.trim() != text
        || text.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    Ok(text.into())
}
fn verified(
    connection: &ActiveConnection,
    event_json: &str,
    secret: &NwcSecretKey,
    now: UnixTimestamp,
) -> Result<(crate::ValidatedNwcEvent, Value, BrowserPairingChallenge), LedgerError> {
    if connection.is_expired_at(now) || event_json.len() > 16_384 {
        return Err(invalid());
    }
    let event = Event::from_json(event_json).map_err(|_| invalid())?;
    let validator = NwcEventValidator::new(WakePolicy::default());
    let validated = validator
        .validate_request(
            event_json,
            &EventId::from_bytes(*event.id.as_bytes()),
            connection.client_pubkey(),
            connection.wallet_service_pubkey(),
            connection.encryption(),
            now,
        )
        .map_err(|_| invalid())?;
    let plaintext = validated.decrypt(secret).map_err(|_| invalid())?;
    let request: Value = nostr::serde_json::from_str(plaintext.as_json()).map_err(|_| invalid())?;
    if request["method"] != "authorize_browser" {
        return Err(invalid());
    }
    let p = request["params"].clone();
    if p.as_object().ok_or_else(invalid)?.keys().any(|key| {
        ![
            "version",
            "challenge_id",
            "nonce",
            "audience",
            "expires_at",
            "client_pubkey",
            "wallet_pubkey",
        ]
        .contains(&key.as_str())
    }) || p["version"] != 1
    {
        return Err(invalid());
    }
    let challenge_id = bounded(&p["challenge_id"], 128)?;
    let nonce = bounded(&p["nonce"], 64)?;
    if nonce.len() != 64
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    let audience = bounded(&p["audience"], 2048)?;
    let url = url::Url::parse(&audience).map_err(|_| invalid())?;
    if url.scheme() != "https" || url.origin().ascii_serialization() != audience {
        return Err(invalid());
    }
    let expiry = p["expires_at"].as_u64().ok_or_else(invalid)?;
    if expiry <= now.as_secs()
        || expiry > now.as_secs().saturating_add(300)
        || connection
            .expires_at()
            .is_none_or(|until| expiry > until.as_secs())
        || p["client_pubkey"] != connection.client_pubkey().to_hex()
        || p["wallet_pubkey"] != connection.wallet_service_pubkey().to_hex()
    {
        return Err(invalid());
    }
    let details = BrowserPairingChallenge {
        challenge_id,
        connection_id: connection.id().as_str().into(),
        nonce,
        audience,
        expires_at: UnixTimestamp::from_secs(expiry),
        client_pubkey_hex: connection.client_pubkey().to_hex(),
        wallet_pubkey_hex: connection.wallet_service_pubkey().to_hex(),
    };
    Ok((validated, p, details))
}
impl WakeLedger {
    /// Verifies and retains a challenge without granting browser authority.
    pub fn parse_browser_pairing_challenge(
        &self,
        connection: &ActiveConnection,
        event_json: &str,
        secret: &NwcSecretKey,
        now: UnixTimestamp,
    ) -> Result<BrowserPairingChallenge, LedgerError> {
        if !self.is_reusable_foreground(connection.id().as_str())? {
            return Err(invalid());
        }
        let (event, p, details) = verified(connection, event_json, secret, now)?;
        let mut db = self.lock_connection()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM connections WHERE connection_id=?1 AND revision=?2 AND status='active' AND expires_at>?3)",params![connection.id().as_str(),connection.revision().value(),now.as_secs()],|r|r.get(0))?;
        if !active {
            return Err(invalid());
        }
        let existing:Option<(Vec<u8>,String,i64,bool)>=tx.query_row("SELECT event_id,connection_id,connection_revision,cancelled FROM browser_pairing_challenges WHERE challenge_id=?1",[&details.challenge_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        if let Some((id, connection_id, revision, cancelled)) = existing {
            if id != event.id().as_bytes()
                || connection_id != connection.id().as_str()
                || revision as u64 != connection.revision().value()
                || cancelled
            {
                return Err(invalid());
            }
        } else {
            tx.execute("INSERT INTO browser_pairing_challenges(challenge_id,connection_id,connection_revision,event_id,event_json,params_json,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![details.challenge_id,connection.id().as_str(),connection.revision().value(),event.id().as_bytes().as_slice(),event_json,p.to_string(),details.expires_at.as_secs()])?;
        }
        tx.commit()?;
        Ok(details)
    }
    /// Returns only the local connection associated with a retained challenge.
    pub fn browser_pairing_connection(&self, challenge_id: &str) -> Result<String, LedgerError> {
        Ok(self.lock_connection()?.query_row(
            "SELECT connection_id FROM browser_pairing_challenges WHERE challenge_id=?1",
            [challenge_id],
            |r| r.get(0),
        )?)
    }
    /// Explicitly approves a retained challenge and durably caches its exact proof.
    pub fn approve_browser_pairing(
        &self,
        connection: &ActiveConnection,
        challenge_id: &str,
        secret: &NwcSecretKey,
        now: UnixTimestamp,
    ) -> Result<String, LedgerError> {
        let mut db = self.lock_connection()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row:(String,Option<String>)=tx.query_row("SELECT b.event_json,b.response_json FROM browser_pairing_challenges b JOIN connections c USING(connection_id) JOIN foreground_reusable_bindings r USING(connection_id) WHERE b.challenge_id=?1 AND b.connection_id=?2 AND b.connection_revision=?3 AND c.revision=b.connection_revision AND c.status='active' AND c.expires_at>?4 AND b.expires_at>?4 AND b.cancelled=0",params![challenge_id,connection.id().as_str(),connection.revision().value(),now.as_secs()],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if let Some(response) = row.1 {
            return Ok(response);
        }
        let (event, mut p, _) = verified(connection, &row.0, secret, now)?;
        p["approved"] = true.into();
        let response = event
            .build_response_event(
                secret,
                &json!({"result_type":"authorize_browser","result":p}).to_string(),
                now,
            )
            .map_err(|_| invalid())?;
        tx.execute("UPDATE browser_pairing_challenges SET response_json=?2 WHERE challenge_id=?1 AND response_json IS NULL",params![challenge_id,response])?;
        tx.commit()?;
        Ok(response)
    }
    /// Cancels only an unapproved challenge; never silently retracts an issued proof.
    pub fn cancel_browser_pairing(&self, challenge_id: &str) -> Result<(), LedgerError> {
        let changed=self.lock_connection()?.execute("UPDATE browser_pairing_challenges SET cancelled=1 WHERE challenge_id=?1 AND response_json IS NULL",[challenge_id])?;
        if changed != 1 {
            return Err(invalid());
        }
        Ok(())
    }
}
