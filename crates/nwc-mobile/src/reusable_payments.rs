use crate::{
    AmountMsat, EventId, LedgerError, NwcSecretKey, PaymentHash, UnixTimestamp, WakeLedger,
};
use nostr::serde_json::{json, Value};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

pub(crate) const SCHEMA: &str = "
CREATE TABLE browser_pairing_challenges(challenge_id TEXT PRIMARY KEY, connection_id TEXT NOT NULL, connection_revision INTEGER NOT NULL, event_id BLOB UNIQUE NOT NULL, event_json TEXT NOT NULL, params_json TEXT NOT NULL, expires_at INTEGER NOT NULL, response_json TEXT, cancelled INTEGER NOT NULL DEFAULT 0) STRICT;
CREATE TABLE foreground_reusable_bindings(connection_id TEXT PRIMARY KEY, wallet_id TEXT NOT NULL) STRICT;
ALTER TABLE foreground_payment_requests ADD COLUMN purchase_json TEXT;
ALTER TABLE foreground_payment_requests ADD COLUMN consent_ciphertext TEXT;
";

fn invalid() -> LedgerError {
    LedgerError::ClaimMetadataMismatch
}
fn text(value: &Value, max: usize) -> Result<&str, LedgerError> {
    let s = value.as_str().ok_or_else(invalid)?;
    if s.is_empty() || s != s.trim() || s.chars().count() > max || s.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(s)
}
fn exact_keys(value: &Value, allowed: &[&str]) -> Result<(), LedgerError> {
    if value
        .as_object()
        .ok_or_else(invalid)?
        .keys()
        .any(|k| !allowed.contains(&k.as_str()))
    {
        return Err(invalid());
    }
    Ok(())
}
fn validate_purchase(
    value: &Value,
    hash: &PaymentHash,
    amount: AmountMsat,
) -> Result<(), LedgerError> {
    exact_keys(
        value,
        &[
            "version",
            "id",
            "merchant",
            "invoice_binding",
            "requested_customer_fields",
        ],
    )?;
    if value["version"] != 1 {
        return Err(invalid());
    }
    text(&value["id"], 128)?;
    let merchant = &value["merchant"];
    exact_keys(merchant, &["id", "name", "origin"])?;
    text(&merchant["id"], 128)?;
    text(&merchant["name"], 160)?;
    let origin = text(&merchant["origin"], 2048)?;
    let url = url::Url::parse(origin).map_err(|_| invalid())?;
    if url.scheme() != "https" || url.origin().ascii_serialization() != origin {
        return Err(invalid());
    }
    let binding = &value["invoice_binding"];
    exact_keys(binding, &["payment_hash", "principal_msats"])?;
    if binding["payment_hash"].as_str() != Some(hash.to_hex().as_str())
        || binding["principal_msats"].as_str() != Some(amount.as_msat().to_string().as_str())
    {
        return Err(invalid());
    }
    let fields = value["requested_customer_fields"]
        .as_array()
        .ok_or_else(invalid)?;
    let mut seen = std::collections::HashSet::new();
    if fields.len() > 3 {
        return Err(invalid());
    }
    for field in fields {
        exact_keys(field, &["field", "required"])?;
        let name = field["field"].as_str().ok_or_else(invalid)?;
        if !matches!(name, "email" | "phone" | "address")
            || !seen.insert(name)
            || !field["required"].is_boolean()
        {
            return Err(invalid());
        }
    }
    Ok(())
}
pub(crate) fn validate_customer(purchase: &Value, mut data: Value) -> Result<Value, LedgerError> {
    exact_keys(&data, &["email", "phone", "address"])?;
    let requested = purchase["requested_customer_fields"]
        .as_array()
        .ok_or_else(invalid)?;
    for (name, value) in data.as_object().ok_or_else(invalid)? {
        if !requested.iter().any(|f| f["field"] == name.as_str()) || value.is_null() {
            return Err(invalid());
        }
    }
    for field in requested {
        let name = field["field"].as_str().ok_or_else(invalid)?;
        if field["required"] == true && data.get(name).is_none() {
            return Err(invalid());
        }
    }
    if let Some(email) = data.get("email") {
        let email = text(email, 254)?;
        let Some((local, domain)) = email.split_once('@') else {
            return Err(invalid());
        };
        if local.is_empty()
            || local.starts_with('.')
            || local.ends_with('.')
            || local.contains("..")
            || !local
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&c))
            || !domain.contains('.')
            || domain.split('.').any(|part| {
                part.is_empty()
                    || part.starts_with('-')
                    || part.ends_with('-')
                    || !part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
        {
            return Err(invalid());
        }
    }
    if let Some(phone) = data.get("phone") {
        let phone = text(phone, 16)?;
        let bytes = phone.as_bytes();
        if !(8..=16).contains(&bytes.len())
            || bytes[0] != b'+'
            || !(b'1'..=b'9').contains(&bytes[1])
            || !bytes[2..].iter().all(u8::is_ascii_digit)
        {
            return Err(invalid());
        }
    }
    if let Some(address) = data.get_mut("address") {
        exact_keys(
            address,
            &[
                "line1",
                "line2",
                "line3",
                "zipCode",
                "city",
                "state",
                "countryCode",
            ],
        )?;
        for (key, max) in [("line1", 200), ("zipCode", 32), ("city", 100)] {
            text(&address[key], max)?;
        }
        let country = text(&address["countryCode"], 2)?;
        if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(invalid());
        }
        for (key, max) in [("line2", 200), ("line3", 200), ("state", 100)] {
            if address.get(key).is_some_and(Value::is_null) {
                address.as_object_mut().ok_or_else(invalid)?.remove(key);
            }
            if let Some(v) = address.get(key) {
                text(v, max)?;
            }
        }
    }
    Ok(data)
}
impl WakeLedger {
    /// Pins the selected wallet before announcing a reusable foreground grant.
    pub fn bind_reusable_foreground_wallet(
        &self,
        connection_id: &str,
        wallet_id: &str,
    ) -> Result<(), LedgerError> {
        if wallet_id.is_empty() || wallet_id.len() > 128 {
            return Err(invalid());
        }
        let mut db = self.lock_connection()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed=tx.execute("UPDATE connections SET maximum_fee_sat=0 WHERE connection_id=?1 AND status='active' AND foreground_fee_policy='wallet_managed' AND budget_interval='monthly' AND expires_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM foreground_payment_bindings WHERE connection_id=?1) AND NOT EXISTS(SELECT 1 FROM payment_attempts WHERE connection_id=?1)",[connection_id])?;
        if changed != 1 {
            return Err(invalid());
        }
        tx.execute(
            "INSERT INTO foreground_reusable_bindings VALUES(?1,?2)",
            params![connection_id, wallet_id],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Returns whether this connection has explicit reusable foreground authority.
    pub fn is_reusable_foreground(&self, connection_id: &str) -> Result<bool, LedgerError> {
        Ok(self.lock_connection()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM foreground_reusable_bindings WHERE connection_id=?1)",
            [connection_id],
            |r| r.get(0),
        )?)
    }
    pub(crate) fn retain_purchase(
        &self,
        event: &EventId,
        purchase: &str,
        hash: &PaymentHash,
        amount: AmountMsat,
    ) -> Result<(), LedgerError> {
        if purchase.len() > 8192 {
            return Err(invalid());
        }
        let value: Value = nostr::serde_json::from_str(purchase).map_err(|_| invalid())?;
        validate_purchase(&value, hash, amount)?;
        let changed=self.lock_connection()?.execute("UPDATE foreground_payment_requests SET purchase_json=?2 WHERE event_id=?1 AND (purchase_json IS NULL OR purchase_json=?2)",params![event.as_bytes().as_slice(),value.to_string()])?;
        if changed != 1 {
            return Err(invalid());
        }
        Ok(())
    }
    /// Encrypts validated per-purchase consent and atomically claims one handoff.
    pub fn begin_foreground_payment_with_consent(
        &self,
        event: &EventId,
        wallet_id: &str,
        data_json: &str,
        secret: &NwcSecretKey,
        now: UnixTimestamp,
    ) -> Result<(), LedgerError> {
        if data_json.len() > 4096 {
            return Err(invalid());
        }
        let (purchase,client,wallet):(String,Vec<u8>,Vec<u8>)=self.lock_connection()?.query_row("SELECT f.purchase_json,c.client_pubkey,c.wallet_service_pubkey FROM foreground_payment_requests f JOIN payment_attempts p USING(event_id) JOIN connections c USING(connection_id) JOIN foreground_reusable_bindings b USING(connection_id) WHERE f.event_id=?1 AND b.wallet_id=?2",params![event.as_bytes().as_slice(),wallet_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        if secret
            .public_key()
            .map_err(|_| invalid())?
            .as_bytes()
            .as_slice()
            != wallet
        {
            return Err(invalid());
        }
        let purchase: Value = nostr::serde_json::from_str(&purchase).map_err(|_| invalid())?;
        let data = validate_customer(
            &purchase,
            nostr::serde_json::from_str(data_json).map_err(|_| invalid())?,
        )?;
        let client = nostr::PublicKey::from_byte_array(client.try_into().map_err(|_| invalid())?);
        let payload = zeroize::Zeroizing::new(
            json!({"event_id":event.to_hex(),"id":purchase["id"],"customer_data":data}).to_string(),
        );
        let encrypted = nostr::nips::nip44::encrypt(
            &secret.nostr_secret().map_err(|_| invalid())?,
            &client,
            payload.as_bytes(),
            nostr::nips::nip44::Version::V2,
        )
        .map_err(|_| invalid())?;
        self.begin_foreground_payment_inner(event, wallet_id, now, Some(&encrypted))
    }
    pub(crate) fn purchase_response(
        &self,
        event: &EventId,
        secret: &NwcSecretKey,
    ) -> Result<Option<Value>, LedgerError> {
        let row:Option<(String,Vec<u8>)>=self.lock_connection()?.query_row("SELECT f.consent_ciphertext,c.client_pubkey FROM foreground_payment_requests f JOIN payment_attempts p USING(event_id) JOIN connections c USING(connection_id) WHERE f.event_id=?1 AND f.state='succeeded' AND f.consent_ciphertext IS NOT NULL",[event.as_bytes().as_slice()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let Some((cipher, client)) = row else {
            return Ok(None);
        };
        let client = nostr::PublicKey::from_byte_array(client.try_into().map_err(|_| invalid())?);
        let plaintext = zeroize::Zeroizing::new(
            nostr::nips::nip44::decrypt(
                &secret.nostr_secret().map_err(|_| invalid())?,
                &client,
                &cipher,
            )
            .map_err(|_| invalid())?,
        );
        let mut data: Value = nostr::serde_json::from_str(&plaintext).map_err(|_| invalid())?;
        if data["event_id"] != event.to_hex() {
            return Err(invalid());
        }
        data.as_object_mut().ok_or_else(invalid)?.remove("event_id");
        Ok(Some(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn purchase() -> Value {
        json!({"version":1,"id":"attempt","merchant":{"id":"merchant","name":"Name","origin":"https://pay.example"},"invoice_binding":{"payment_hash":"01".repeat(32),"principal_msats":"1000"},"requested_customer_fields":[{"field":"email","required":true},{"field":"phone","required":false},{"field":"address","required":false}]})
    }
    #[test]
    fn purchase_context_rejects_invoice_substitution_duplicate_scope_and_bad_origin() {
        let hash = PaymentHash::from_bytes([1; 32]);
        let amount = AmountMsat::from_msat(1000);
        let valid = purchase();
        assert!(validate_purchase(&valid, &hash, amount).is_ok());
        for key in ["payment_hash", "principal_msats"] {
            let mut invalid = valid.clone();
            invalid["invoice_binding"][key] = "wrong".into();
            assert!(validate_purchase(&invalid, &hash, amount).is_err());
        }
        let mut invalid = valid.clone();
        invalid["merchant"]["origin"] = "https://pay.example/path".into();
        assert!(validate_purchase(&invalid, &hash, amount).is_err());
        let mut invalid = valid;
        invalid["requested_customer_fields"] =
            json!([{"field":"email","required":true},{"field":"email","required":false}]);
        assert!(validate_purchase(&invalid, &hash, amount).is_err());
    }
    #[test]
    fn explicit_consent_validates_required_subset_and_address_without_automatic_sharing() {
        let purchase = purchase();
        assert!(validate_customer(&purchase, json!({})).is_err());
        assert!(validate_customer(
            &purchase,
            json!({"email":"a@example.com","name":"Unrequested"})
        )
        .is_err());
        assert!(validate_customer(&purchase, json!({"email":"bad","phone":"555"})).is_err());
        let data=validate_customer(&purchase,json!({"email":"a@example.com","phone":"+15555550123","address":{"line1":"1 Main","zipCode":"12345","city":"Town","countryCode":"US","line2":null}})).unwrap();
        assert!(data["address"].get("line2").is_none());
        assert_eq!(
            validate_customer(&purchase, json!({"email":"a@example.com"})).unwrap(),
            json!({"email":"a@example.com"})
        );
    }
}
