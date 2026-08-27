use std::fmt;

use nostr::serde_json::{self, Map, Value};

use crate::{EventId, PublicKey, SecureRelayUrl, UnixTimestamp, WakeInput};

/// Maximum serialized push payload accepted at the native boundary.
pub const MAX_WAKE_PAYLOAD_JSON_BYTES: usize = 128 * 1024;

/// Maximum embedded Nostr event accepted inside a wake envelope.
pub const MAX_EMBEDDED_WAKE_EVENT_BYTES: usize = 64 * 1024;

/// Untrusted platform fields decoded from an APNs or FCM notification.
#[derive(Clone, Eq, PartialEq)]
pub struct WakeEnvelope {
    relay_url: String,
    event_id_hex: String,
    wallet_service_public_key_hex: String,
    embedded_event_json: Option<String>,
    received_at_seconds: u64,
    settlement_check: bool,
}

impl WakeEnvelope {
    /// Creates an untrusted envelope from already-decoded platform fields.
    #[must_use]
    pub fn new(
        relay_url: String,
        event_id_hex: String,
        wallet_service_public_key_hex: String,
        embedded_event_json: Option<String>,
        received_at_seconds: u64,
    ) -> Self {
        Self {
            relay_url,
            event_id_hex,
            wallet_service_public_key_hex,
            embedded_event_json,
            received_at_seconds,
            settlement_check: false,
        }
    }

    /// Parses canonical or legacy wake-provider JSON and validates every field.
    pub fn parse_json(
        payload_json: &str,
        received_at_seconds: u64,
    ) -> Result<Self, WakeEnvelopeError> {
        if payload_json.len() > MAX_WAKE_PAYLOAD_JSON_BYTES {
            return Err(WakeEnvelopeError::PayloadTooLarge);
        }
        let payload: Value =
            serde_json::from_str(payload_json).map_err(|_| WakeEnvelopeError::InvalidJson)?;
        let object = payload.as_object().ok_or(WakeEnvelopeError::InvalidJson)?;
        if let Some(protocol) = object.get("protocol") {
            if protocol.as_str() != Some("nwc_wake") {
                return Err(WakeEnvelopeError::WrongProtocol);
            }
        }

        let mut envelope = Self::new(
            string_field(object, "nwc_relay", "relay")?,
            string_field(object, "nwc_event_id", "event_id")?,
            string_field(object, "nwc_wallet_service_pubkey", "wallet_service_pubkey")?,
            optional_string_field(object, "nwc_event_json", "nwc_event")?,
            received_at_seconds,
        );
        envelope.settlement_check = optional_boolean_field(object, "settlement_check")?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// Validates and seals the untrusted fields into a core wake input.
    pub fn validate(&self) -> Result<WakeInput, WakeEnvelopeError> {
        let relay =
            SecureRelayUrl::parse(&self.relay_url).map_err(|_| WakeEnvelopeError::InvalidRelay)?;
        let event_id =
            EventId::from_hex(&self.event_id_hex).map_err(|_| WakeEnvelopeError::InvalidEventId)?;
        let wallet_service_pubkey = PublicKey::from_hex(&self.wallet_service_public_key_hex)
            .map_err(|_| WakeEnvelopeError::InvalidWalletServicePublicKey)?;
        if self
            .embedded_event_json
            .as_ref()
            .is_some_and(|event| event.len() > MAX_EMBEDDED_WAKE_EVENT_BYTES)
        {
            return Err(WakeEnvelopeError::EmbeddedEventTooLarge);
        }
        Ok(WakeInput::new(
            relay.as_str().to_owned(),
            event_id,
            wallet_service_pubkey,
            self.embedded_event_json.clone(),
            UnixTimestamp::from_secs(self.received_at_seconds),
        ))
    }

    /// Returns the validated secure relay string.
    #[must_use]
    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    /// Returns the event identifier encoding supplied by the provider.
    #[must_use]
    pub fn event_id_hex(&self) -> &str {
        &self.event_id_hex
    }

    /// Returns the wallet-service public-key encoding supplied by the provider.
    #[must_use]
    pub fn wallet_service_public_key_hex(&self) -> &str {
        &self.wallet_service_public_key_hex
    }

    /// Returns the optional embedded serialized event.
    #[must_use]
    pub fn embedded_event_json(&self) -> Option<&str> {
        self.embedded_event_json.as_deref()
    }

    /// Returns when the platform received the notification.
    #[must_use]
    pub const fn received_at_seconds(&self) -> u64 {
        self.received_at_seconds
    }

    /// Returns whether the provider marked this as a targeted invoice-settlement check.
    #[must_use]
    pub const fn settlement_check(&self) -> bool {
        self.settlement_check
    }
}

impl fmt::Debug for WakeEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WakeEnvelope")
            .field("relay_url", &"[redacted]")
            .field("event_id_hex", &"[redacted]")
            .field("wallet_service_public_key_hex", &"[redacted]")
            .field("has_embedded_event", &self.embedded_event_json.is_some())
            .field("received_at_seconds", &self.received_at_seconds)
            .field("settlement_check", &self.settlement_check)
            .finish()
    }
}

/// Stable parsing or validation failure that never includes provider input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WakeEnvelopeError {
    /// The serialized platform payload exceeded its hard bound.
    PayloadTooLarge,
    /// The payload was not a JSON object.
    InvalidJson,
    /// A protocol discriminator was present but did not identify NWC wake.
    WrongProtocol,
    /// A required canonical and legacy field were both absent.
    MissingField,
    /// A present field had the wrong JSON type.
    InvalidField,
    /// The relay was malformed, oversized, or did not use secure WebSockets.
    InvalidRelay,
    /// The event identifier did not encode exactly 32 bytes of hexadecimal.
    InvalidEventId,
    /// The wallet-service key did not encode exactly 32 bytes of hexadecimal.
    InvalidWalletServicePublicKey,
    /// The optional serialized event exceeded the hard bound.
    EmbeddedEventTooLarge,
}

impl fmt::Display for WakeEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PayloadTooLarge => "wake payload exceeds the size limit",
            Self::InvalidJson => "wake payload is not a JSON object",
            Self::WrongProtocol => "wake payload protocol is not supported",
            Self::MissingField => "wake payload is missing a required field",
            Self::InvalidField => "wake payload contains an invalid field",
            Self::InvalidRelay => "wake relay is invalid or insecure",
            Self::InvalidEventId => "wake event id is invalid",
            Self::InvalidWalletServicePublicKey => "wallet service public key is invalid",
            Self::EmbeddedEventTooLarge => "embedded wake event exceeds the payload limit",
        })
    }
}

impl std::error::Error for WakeEnvelopeError {}

fn string_field(
    object: &Map<String, Value>,
    canonical: &str,
    legacy: &str,
) -> Result<String, WakeEnvelopeError> {
    match object.get(canonical) {
        Some(value) => value
            .as_str()
            .map(str::to_owned)
            .ok_or(WakeEnvelopeError::InvalidField),
        None => object
            .get(legacy)
            .ok_or(WakeEnvelopeError::MissingField)?
            .as_str()
            .map(str::to_owned)
            .ok_or(WakeEnvelopeError::InvalidField),
    }
}

fn optional_string_field(
    object: &Map<String, Value>,
    canonical: &str,
    legacy: &str,
) -> Result<Option<String>, WakeEnvelopeError> {
    match object.get(canonical).or_else(|| object.get(legacy)) {
        Some(value) => value
            .as_str()
            .map(str::to_owned)
            .map(Some)
            .ok_or(WakeEnvelopeError::InvalidField),
        None => Ok(None),
    }
}

fn optional_boolean_field(
    object: &Map<String, Value>,
    field: &str,
) -> Result<bool, WakeEnvelopeError> {
    match object.get(field) {
        Some(value) => value.as_bool().ok_or(WakeEnvelopeError::InvalidField),
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn canonical_and_legacy_json_are_accepted_and_sealed() {
        let canonical = format!(
            r#"{{"nwc_relay":"wss://relay.example/path","nwc_event_id":"{HEX}","nwc_wallet_service_pubkey":"{HEX}","nwc_event_json":"{{}}"}}"#
        );
        let envelope = WakeEnvelope::parse_json(&canonical, 42).expect("canonical");
        let input = envelope.validate().expect("input");
        assert_eq!(input.relay(), "wss://relay.example/path");
        assert_eq!(input.event_id().to_hex(), HEX);
        assert_eq!(input.received_at(), UnixTimestamp::from_secs(42));
        assert!(!envelope.settlement_check());

        let settlement = format!(
            r#"{{"nwc_relay":"wss://relay.example/path","nwc_event_id":"{HEX}","nwc_wallet_service_pubkey":"{HEX}","settlement_check":true}}"#
        );
        assert!(WakeEnvelope::parse_json(&settlement, 42)
            .expect("settlement check")
            .settlement_check());

        let legacy = format!(
            r#"{{"protocol":"nwc_wake","relay":"wss://relay.example/path","event_id":"{HEX}","wallet_service_pubkey":"{HEX}"}}"#
        );
        assert!(WakeEnvelope::parse_json(&legacy, 42).is_ok());
    }

    #[test]
    fn invalid_protocol_types_relays_and_sizes_fail_closed() {
        for payload in [
            "{}".to_string(),
            format!(
                r#"{{"protocol":"other","nwc_relay":"wss://relay.example","nwc_event_id":"{HEX}","nwc_wallet_service_pubkey":"{HEX}"}}"#
            ),
            format!(
                r#"{{"nwc_relay":7,"relay":"wss://relay.example","nwc_event_id":"{HEX}","nwc_wallet_service_pubkey":"{HEX}"}}"#
            ),
            format!(
                r#"{{"nwc_relay":"ws://relay.example","nwc_event_id":"{HEX}","nwc_wallet_service_pubkey":"{HEX}"}}"#
            ),
            format!(
                r#"{{"nwc_relay":"wss://relay.example","nwc_event_id":"{HEX}","nwc_wallet_service_pubkey":"{HEX}","settlement_check":"true"}}"#
            ),
        ] {
            assert!(WakeEnvelope::parse_json(&payload, 42).is_err());
        }

        assert_eq!(
            WakeEnvelope::parse_json(&"x".repeat(MAX_WAKE_PAYLOAD_JSON_BYTES + 1), 42),
            Err(WakeEnvelopeError::PayloadTooLarge)
        );
        let oversized = WakeEnvelope::new(
            "wss://relay.example".to_string(),
            HEX.to_string(),
            HEX.to_string(),
            Some("x".repeat(MAX_EMBEDDED_WAKE_EVENT_BYTES + 1)),
            42,
        );
        assert_eq!(
            oversized.validate(),
            Err(WakeEnvelopeError::EmbeddedEventTooLarge)
        );
    }

    #[test]
    fn debug_output_redacts_transport_content() {
        let envelope = WakeEnvelope::new(
            "wss://relay.example".to_string(),
            HEX.to_string(),
            HEX.to_string(),
            Some("secret-event".to_string()),
            42,
        );
        let debug = format!("{envelope:?}");
        assert!(!debug.contains("relay.example"));
        assert!(!debug.contains(HEX));
        assert!(!debug.contains("secret-event"));
        assert!(debug.contains("has_embedded_event: true"));
    }
}
