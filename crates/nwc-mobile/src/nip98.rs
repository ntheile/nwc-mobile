use std::fmt;

use base64::engine::{general_purpose, Engine};
use nostr::hashes::{sha256, Hash};
use nostr::nips::nip98::{HttpData, HttpMethod};
use nostr::{EventBuilder, JsonUtil, Keys, SecretKey, Tag, Timestamp, Url};
use zeroize::Zeroize;

use crate::{PublicKey, SecureWakeServerUrl, UnixTimestamp};

const AUTHORIZATION_LIFETIME_SECONDS: u64 = 60;
const MAX_AUTHORIZED_PAYLOAD_BYTES: usize = 64 * 1024;

/// A stable, non-sensitive NIP-98 authorization construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Nip98AuthorizationError {
    /// The provided signing key was not a valid secp256k1 secret.
    InvalidSigningKey,
    /// The request payload exceeded the authorization bound.
    PayloadTooLarge,
    /// The authorization expiration timestamp overflowed.
    TimestampOverflow,
    /// The already-validated endpoint could not be converted for NIP-98.
    InvalidEndpoint,
    /// The Nostr event could not be signed.
    SigningFailed,
}

impl fmt::Display for Nip98AuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSigningKey => "NIP-98 signing key is invalid",
            Self::PayloadTooLarge => "NIP-98 payload is too large",
            Self::TimestampOverflow => "NIP-98 expiration overflowed",
            Self::InvalidEndpoint => "NIP-98 endpoint is invalid",
            Self::SigningFailed => "NIP-98 authorization signing failed",
        })
    }
}

impl std::error::Error for Nip98AuthorizationError {}

/// Ephemeral Nostr key material used only to sign one HTTP authorization.
pub struct Nip98SigningKey([u8; 32]);

impl Nip98SigningKey {
    /// Validates and wraps 32 bytes loaded from platform-protected storage.
    pub fn from_bytes(mut bytes: [u8; 32]) -> Result<Self, Nip98AuthorizationError> {
        if SecretKey::from_slice(&bytes).is_err() {
            bytes.zeroize();
            return Err(Nip98AuthorizationError::InvalidSigningKey);
        }
        Ok(Self(bytes))
    }

    fn nostr_secret(&self) -> Result<SecretKey, Nip98AuthorizationError> {
        SecretKey::from_slice(&self.0).map_err(|_| Nip98AuthorizationError::InvalidSigningKey)
    }

    /// Derives the public key used by authorizations signed with this key.
    pub fn public_key(&self) -> Result<PublicKey, Nip98AuthorizationError> {
        let keys = Keys::new(self.nostr_secret()?);
        Ok(PublicKey::from_bytes(*keys.public_key().as_bytes()))
    }
}

impl fmt::Debug for Nip98SigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Nip98SigningKey([redacted])")
    }
}

impl Drop for Nip98SigningKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A short-lived `Authorization` header value bound to one exact POST request.
pub struct Nip98Authorization(String);

impl Nip98Authorization {
    /// Signs a registration POST authorization with a fixed 60-second expiry.
    ///
    /// The event binds the canonical HTTPS endpoint, HTTP method, SHA-256 body
    /// hash, creation time, and an explicit NIP-40 expiration tag.
    pub fn for_registration_post(
        endpoint: &SecureWakeServerUrl,
        body: &[u8],
        signing_key: &Nip98SigningKey,
        now: UnixTimestamp,
    ) -> Result<Self, Nip98AuthorizationError> {
        if body.len() > MAX_AUTHORIZED_PAYLOAD_BYTES {
            return Err(Nip98AuthorizationError::PayloadTooLarge);
        }
        let expires_at = now
            .as_secs()
            .checked_add(AUTHORIZATION_LIFETIME_SECONDS)
            .ok_or(Nip98AuthorizationError::TimestampOverflow)?;
        let url =
            Url::parse(endpoint.as_str()).map_err(|_| Nip98AuthorizationError::InvalidEndpoint)?;
        let payload_hash = sha256::Hash::hash(body);
        let http_data = HttpData::new(url, HttpMethod::POST).payload(payload_hash);
        let secret = signing_key.nostr_secret()?;
        let keys = Keys::new(secret);
        let event = EventBuilder::http_auth(http_data)
            .tag(Tag::expiration(Timestamp::from(expires_at)))
            .custom_created_at(Timestamp::from(now.as_secs()))
            .sign_with_keys(&keys)
            .map_err(|_| Nip98AuthorizationError::SigningFailed)?;
        let encoded = general_purpose::STANDARD.encode(event.as_json().as_bytes());
        Ok(Self(format!("Nostr {encoded}")))
    }

    /// Returns the complete value for the HTTP `Authorization` header.
    #[must_use]
    pub fn as_header_value(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Nip98Authorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Nip98Authorization([redacted])")
    }
}

impl Drop for Nip98Authorization {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use nostr::nips::nip98::verify_auth_header;
    use nostr::{Event, Kind, TagStandard};

    use super::*;

    fn endpoint() -> SecureWakeServerUrl {
        SecureWakeServerUrl::parse("https://wake.example.com/v1/register?tenant=wallet")
            .expect("endpoint")
    }

    fn signing_key() -> Nip98SigningKey {
        Nip98SigningKey::from_bytes([7_u8; 32]).expect("signing key")
    }

    fn decode_event(authorization: &Nip98Authorization) -> Event {
        let encoded = authorization
            .as_header_value()
            .strip_prefix("Nostr ")
            .expect("Nostr prefix");
        let json = general_purpose::STANDARD
            .decode(encoded)
            .expect("base64 event");
        Event::from_json(json).expect("event JSON")
    }

    #[test]
    fn authorization_binds_endpoint_method_payload_and_expiration() {
        let body = br#"{"enabled":false,"revision":4}"#;
        let now = UnixTimestamp::from_secs(1_000);
        let authorization =
            Nip98Authorization::for_registration_post(&endpoint(), body, &signing_key(), now)
                .expect("authorization");
        let event = decode_event(&authorization);

        assert_eq!(event.kind, Kind::HttpAuth);
        assert_eq!(event.created_at, Timestamp::from(1_000));
        event.verify().expect("valid signature");
        let expiration = event
            .tags
            .iter()
            .find_map(|tag| match tag.as_standardized() {
                Some(TagStandard::Expiration(timestamp)) => Some(*timestamp),
                _ => None,
            });
        assert_eq!(expiration, Some(Timestamp::from(1_060)));
        let url = Url::parse(endpoint().as_str()).expect("NIP-98 URL");
        verify_auth_header(
            authorization.as_header_value(),
            &url,
            HttpMethod::POST,
            Timestamp::from(1_000),
            Some(body),
        )
        .expect("verified request binding");
    }

    #[test]
    fn payload_or_endpoint_substitution_fails_verification() {
        let authorization = Nip98Authorization::for_registration_post(
            &endpoint(),
            b"original",
            &signing_key(),
            UnixTimestamp::from_secs(1_000),
        )
        .expect("authorization");
        let url = Url::parse(endpoint().as_str()).expect("NIP-98 URL");
        assert!(verify_auth_header(
            authorization.as_header_value(),
            &url,
            HttpMethod::POST,
            Timestamp::from(1_000),
            Some(b"substituted"),
        )
        .is_err());
        let other = Url::parse("https://wake.example.com/v1/other").expect("other URL");
        assert!(verify_auth_header(
            authorization.as_header_value(),
            &other,
            HttpMethod::POST,
            Timestamp::from(1_000),
            Some(b"original"),
        )
        .is_err());
    }

    #[test]
    fn payload_and_timestamp_bounds_fail_closed() {
        assert!(matches!(
            Nip98Authorization::for_registration_post(
                &endpoint(),
                &vec![0; MAX_AUTHORIZED_PAYLOAD_BYTES + 1],
                &signing_key(),
                UnixTimestamp::from_secs(1_000),
            ),
            Err(Nip98AuthorizationError::PayloadTooLarge)
        ));
        assert!(matches!(
            Nip98Authorization::for_registration_post(
                &endpoint(),
                b"body",
                &signing_key(),
                UnixTimestamp::from_secs(u64::MAX),
            ),
            Err(Nip98AuthorizationError::TimestampOverflow)
        ));
    }

    #[test]
    fn debug_output_redacts_key_and_authorization_header() {
        let key = signing_key();
        let authorization = Nip98Authorization::for_registration_post(
            &endpoint(),
            b"body",
            &key,
            UnixTimestamp::from_secs(1_000),
        )
        .expect("authorization");
        assert_eq!(format!("{key:?}"), "Nip98SigningKey([redacted])");
        assert_eq!(
            format!("{authorization:?}"),
            "Nip98Authorization([redacted])"
        );
        assert!(!format!("{authorization:?}").contains("Nostr "));
    }

    #[test]
    fn signing_key_exposes_only_its_public_identity() {
        let key = signing_key();
        assert_eq!(key.public_key().expect("public key").as_bytes().len(), 32);
        assert_ne!(
            key.public_key().expect("public key").as_bytes(),
            &[7_u8; 32]
        );
    }
}
