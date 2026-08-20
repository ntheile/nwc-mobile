use std::fmt;

use crate::{DomainError, UnixTimestamp};

const MAX_CONNECTION_ID_BYTES: usize = 128;
const HEX_32_LENGTH: usize = 64;

/// A stable wallet-local identifier for an NWC connection.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(String);

impl ConnectionId {
    /// Parses an identifier using a conservative ASCII allowlist.
    pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.is_empty() {
            return Err(DomainError::EmptyIdentifier);
        }
        if value.len() > MAX_CONNECTION_ID_BYTES {
            return Err(DomainError::IdentifierTooLong {
                maximum: MAX_CONNECTION_ID_BYTES,
            });
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        {
            return Err(DomainError::InvalidIdentifierCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the encoded identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectionId([redacted])")
    }
}

/// A monotonically increasing revision for connection state.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionRevision(u64);

impl ConnectionRevision {
    /// The initial persisted revision.
    pub const INITIAL: Self = Self(0);

    /// Creates a revision from a persisted value.
    #[must_use]
    pub const fn from_value(value: u64) -> Self {
        Self(value)
    }

    /// Returns the persisted integer value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Returns the next revision, failing closed on overflow.
    pub fn next(self) -> Result<Self, DomainError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(DomainError::RevisionOverflow)
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct Hex32([u8; 32]);

impl Hex32 {
    fn from_hex(value: &str) -> Result<Self, DomainError> {
        if value.len() != HEX_32_LENGTH {
            return Err(DomainError::InvalidHexLength {
                expected: HEX_32_LENGTH,
                actual: value.len(),
            });
        }

        let mut decoded = [0_u8; 32];
        for (output, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            let high = decode_hex_nibble(pair[0]).ok_or(DomainError::InvalidHex)?;
            let low = decode_hex_nibble(pair[1]).ok_or(DomainError::InvalidHex)?;
            *output = (high << 4) | low;
        }
        Ok(Self(decoded))
    }

    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(HEX_32_LENGTH);
        for byte in self.0 {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }
}

const fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

macro_rules! hex_32_type {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Hex32);

        impl $name {
            /// Parses a 32-byte hexadecimal value.
            pub fn from_hex(value: &str) -> Result<Self, DomainError> {
                Hex32::from_hex(value).map(Self)
            }

            /// Creates the value from its 32-byte representation.
            #[must_use]
            pub fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(Hex32::from_bytes(bytes))
            }

            /// Returns the 32-byte representation.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }

            /// Encodes the value as lowercase hexadecimal.
            #[must_use]
            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

hex_32_type!(EventId, "A Nostr event identifier.");
hex_32_type!(PublicKey, "A Nostr public key.");
hex_32_type!(PaymentHash, "A Lightning payment hash.");
hex_32_type!(PaymentPreimage, "A Lightning payment preimage.");

/// An NIP-47 method understood by the mobile engine.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum NwcMethod {
    /// Return wallet and capability information.
    GetInfo,
    /// Return the wallet balance.
    GetBalance,
    /// Create a Lightning invoice.
    MakeInvoice,
    /// Pay a Lightning invoice.
    PayInvoice,
    /// Look up an invoice or payment.
    LookupInvoice,
    /// List wallet transactions.
    ListTransactions,
}

impl NwcMethod {
    /// Returns the NIP-47 wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetInfo => "get_info",
            Self::GetBalance => "get_balance",
            Self::MakeInvoice => "make_invoice",
            Self::PayInvoice => "pay_invoice",
            Self::LookupInvoice => "lookup_invoice",
            Self::ListTransactions => "list_transactions",
        }
    }
}

/// The platform-independent fields carried by an NWC wake notification.
#[derive(Clone, Eq, PartialEq)]
pub struct WakeInput {
    relay: String,
    event_id: EventId,
    wallet_service_pubkey: PublicKey,
    embedded_event_json: Option<String>,
    received_at: UnixTimestamp,
}

impl WakeInput {
    /// Creates a wake input.
    ///
    /// Relay and embedded-event validation occurs at the Nostr boundary; this
    /// constructor only preserves the typed envelope.
    #[must_use]
    pub fn new(
        relay: String,
        event_id: EventId,
        wallet_service_pubkey: PublicKey,
        embedded_event_json: Option<String>,
        received_at: UnixTimestamp,
    ) -> Self {
        Self {
            relay,
            event_id,
            wallet_service_pubkey,
            embedded_event_json,
            received_at,
        }
    }

    /// Returns the unvalidated relay string supplied by the wake transport.
    #[must_use]
    pub fn relay(&self) -> &str {
        &self.relay
    }

    /// Returns the requested event identifier.
    #[must_use]
    pub const fn event_id(&self) -> &EventId {
        &self.event_id
    }

    /// Returns the expected wallet-service public key.
    #[must_use]
    pub const fn wallet_service_pubkey(&self) -> &PublicKey {
        &self.wallet_service_pubkey
    }

    /// Returns the optional encrypted Nostr event JSON.
    #[must_use]
    pub fn embedded_event_json(&self) -> Option<&str> {
        self.embedded_event_json.as_deref()
    }

    /// Returns when the native adapter received the wake.
    #[must_use]
    pub const fn received_at(&self) -> UnixTimestamp {
        self.received_at
    }
}

impl fmt::Debug for WakeInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WakeInput")
            .field("relay", &"[redacted]")
            .field("event_id", &self.event_id)
            .field("wallet_service_pubkey", &self.wallet_service_pubkey)
            .field("has_embedded_event", &self.embedded_event_json.is_some())
            .field("received_at", &self.received_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn connection_id_uses_conservative_characters() {
        let id = ConnectionId::parse("wallet:nwc-1_test.example").expect("valid id");
        assert_eq!(id.as_str(), "wallet:nwc-1_test.example");

        assert_eq!(
            ConnectionId::parse("wallet id"),
            Err(DomainError::InvalidIdentifierCharacter)
        );
        assert_eq!(
            ConnectionId::parse("wallet\u{202e}id"),
            Err(DomainError::InvalidIdentifierCharacter)
        );
    }

    #[test]
    fn fixed_hex_values_round_trip_and_accept_uppercase() {
        let event = EventId::from_hex(&HEX.to_ascii_uppercase()).expect("valid event id");
        assert_eq!(event.to_hex(), HEX);
        assert_eq!(event.as_bytes().len(), 32);
    }

    #[test]
    fn fixed_hex_errors_do_not_echo_input() {
        let secret_like_input = "not-a-valid-secret";
        let error = PaymentHash::from_hex(secret_like_input).expect_err("invalid hash");
        assert!(!error.to_string().contains(secret_like_input));
    }

    #[test]
    fn connection_revision_fails_closed_on_overflow() {
        assert_eq!(
            ConnectionRevision::from_value(u64::MAX).next(),
            Err(DomainError::RevisionOverflow)
        );
    }

    #[test]
    fn wake_input_debug_redacts_transport_values() {
        let wake = WakeInput::new(
            "wss://private-relay.example".to_string(),
            EventId::from_hex(HEX).expect("event id"),
            PublicKey::from_hex(HEX).expect("public key"),
            Some("secret-like-ciphertext".to_string()),
            UnixTimestamp::from_secs(1),
        );

        let debug = format!("{wake:?}");
        assert!(!debug.contains("private-relay"));
        assert!(!debug.contains("secret-like-ciphertext"));
        assert!(!debug.contains(HEX));
    }
}
