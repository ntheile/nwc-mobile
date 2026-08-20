use std::fmt;

use nostr::{Event, JsonUtil, Kind, PublicKey as NostrPublicKey, SecretKey, TagKind};
use zeroize::Zeroize;

use crate::{EventId, PublicKey, UnixTimestamp, WakePolicy};

/// A stable, non-sensitive failure at the authenticated Nostr boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NostrEventError {
    /// The serialized event exceeds the configured wake payload bound.
    PayloadTooLarge,
    /// The serialized event is not valid Nostr event JSON.
    MalformedEvent,
    /// The event identifier or Schnorr signature is invalid.
    InvalidSignature,
    /// The event does not match the event identifier requested by the wake.
    EventIdMismatch,
    /// The event is not an NIP-47 wallet-connect request.
    UnexpectedKind,
    /// The event author is not the authorized connection client.
    UnexpectedAuthor,
    /// The event does not have exactly one expected wallet-service recipient.
    UnexpectedRecipient,
    /// The event is stale or too far in the future.
    InvalidCreatedAt,
    /// The encrypted content is empty or does not match the negotiated scheme.
    InvalidCiphertext,
    /// The supplied wallet secret is not a valid secp256k1 secret key.
    InvalidSecretKey,
    /// Authenticated decryption failed.
    DecryptionFailed,
    /// The decrypted request exceeds the configured payload bound.
    PlaintextTooLarge,
}

impl fmt::Display for NostrEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PayloadTooLarge => "Nostr event exceeds the payload limit",
            Self::MalformedEvent => "Nostr event is malformed",
            Self::InvalidSignature => "Nostr event identity or signature is invalid",
            Self::EventIdMismatch => "Nostr event does not match the requested event id",
            Self::UnexpectedKind => "Nostr event kind is not an NWC request",
            Self::UnexpectedAuthor => "Nostr event author is not authorized",
            Self::UnexpectedRecipient => "Nostr event recipient is invalid",
            Self::InvalidCreatedAt => "Nostr event timestamp is outside the accepted window",
            Self::InvalidCiphertext => "Nostr event ciphertext is invalid",
            Self::InvalidSecretKey => "wallet service secret key is invalid",
            Self::DecryptionFailed => "NWC request decryption failed",
            Self::PlaintextTooLarge => "decrypted NWC request exceeds the payload limit",
        })
    }
}

impl std::error::Error for NostrEventError {}

/// The encryption negotiated for one NWC connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NwcEncryption {
    /// NIP-44 version 2 authenticated encryption with padded plaintext.
    Nip44V2,
    /// NIP-04 compatibility mode. New connections should prefer NIP-44.
    LegacyNip04,
}

/// An ephemeral wallet-service secret that is zeroized when dropped.
///
/// Hosts should load this value only for the bounded operation that needs it
/// and retain the durable copy in platform-protected storage.
pub struct NwcSecretKey([u8; 32]);

impl NwcSecretKey {
    /// Validates and wraps 32 bytes of wallet-service key material.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, NostrEventError> {
        SecretKey::from_slice(&bytes).map_err(|_| NostrEventError::InvalidSecretKey)?;
        Ok(Self(bytes))
    }

    fn nostr_secret(&self) -> Result<SecretKey, NostrEventError> {
        SecretKey::from_slice(&self.0).map_err(|_| NostrEventError::InvalidSecretKey)
    }
}

impl fmt::Debug for NwcSecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NwcSecretKey([redacted])")
    }
}

impl Drop for NwcSecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A decrypted NIP-47 request whose debug representation never reveals its
/// payment metadata.
pub struct DecryptedNwcRequest(String);

impl DecryptedNwcRequest {
    /// Returns the decrypted NIP-47 JSON for typed request parsing.
    #[must_use]
    pub fn as_json(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DecryptedNwcRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecryptedNwcRequest([redacted])")
    }
}

impl Drop for DecryptedNwcRequest {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A signed NIP-47 request that has been rebound to the wake and connection.
pub struct ValidatedNwcEvent {
    id: EventId,
    author: PublicKey,
    created_at: UnixTimestamp,
    encryption: NwcEncryption,
    ciphertext: String,
    maximum_plaintext_bytes: usize,
}

impl ValidatedNwcEvent {
    /// Returns the verified event identifier that must be used for replay state.
    #[must_use]
    pub const fn id(&self) -> &EventId {
        &self.id
    }

    /// Returns the verified, authorized client public key.
    #[must_use]
    pub const fn author(&self) -> &PublicKey {
        &self.author
    }

    /// Returns the verified event timestamp.
    #[must_use]
    pub const fn created_at(&self) -> UnixTimestamp {
        self.created_at
    }

    /// Returns the connection-negotiated encryption mode.
    #[must_use]
    pub const fn encryption(&self) -> NwcEncryption {
        self.encryption
    }

    /// Decrypts the request only after all event and connection checks passed.
    pub fn decrypt(
        &self,
        wallet_secret: &NwcSecretKey,
    ) -> Result<DecryptedNwcRequest, NostrEventError> {
        let secret = wallet_secret.nostr_secret()?;
        let author = NostrPublicKey::from_byte_array(*self.author.as_bytes());
        let mut plaintext = match self.encryption {
            NwcEncryption::Nip44V2 => {
                nostr::nips::nip44::decrypt(&secret, &author, &self.ciphertext)
                    .map_err(|_| NostrEventError::DecryptionFailed)?
            }
            NwcEncryption::LegacyNip04 => {
                nostr::nips::nip04::decrypt(&secret, &author, &self.ciphertext)
                    .map_err(|_| NostrEventError::DecryptionFailed)?
            }
        };
        if plaintext.len() > self.maximum_plaintext_bytes {
            plaintext.zeroize();
            return Err(NostrEventError::PlaintextTooLarge);
        }
        Ok(DecryptedNwcRequest(plaintext))
    }
}

impl fmt::Debug for ValidatedNwcEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedNwcEvent")
            .field("id", &self.id)
            .field("author", &self.author)
            .field("created_at", &self.created_at)
            .field("encryption", &self.encryption)
            .field("ciphertext", &"[redacted]")
            .finish()
    }
}

/// Validates untrusted Nostr request events before decryption or side effects.
#[derive(Clone, Copy, Debug)]
pub struct NwcEventValidator {
    policy: WakePolicy,
}

impl NwcEventValidator {
    /// Creates a validator with the wake freshness and payload policy.
    #[must_use]
    pub const fn new(policy: WakePolicy) -> Self {
        Self { policy }
    }

    /// Parses, verifies, and binds an NWC request event to its wake and
    /// authorized connection.
    pub fn validate_request(
        &self,
        event_json: &str,
        expected_event_id: &EventId,
        expected_client_pubkey: &PublicKey,
        expected_wallet_service_pubkey: &PublicKey,
        encryption: NwcEncryption,
        now: UnixTimestamp,
    ) -> Result<ValidatedNwcEvent, NostrEventError> {
        if event_json.len() > self.policy.maximum_payload_bytes() {
            return Err(NostrEventError::PayloadTooLarge);
        }
        let event = Event::from_json(event_json).map_err(|_| NostrEventError::MalformedEvent)?;
        event
            .verify()
            .map_err(|_| NostrEventError::InvalidSignature)?;

        if event.id.as_bytes() != expected_event_id.as_bytes() {
            return Err(NostrEventError::EventIdMismatch);
        }
        if event.kind != Kind::WalletConnectRequest {
            return Err(NostrEventError::UnexpectedKind);
        }
        if event.pubkey.as_bytes() != expected_client_pubkey.as_bytes() {
            return Err(NostrEventError::UnexpectedAuthor);
        }
        if !has_exact_recipient(&event, expected_wallet_service_pubkey) {
            return Err(NostrEventError::UnexpectedRecipient);
        }

        let created_at = UnixTimestamp::from_secs(event.created_at.as_secs());
        if !self.policy.accepts_event_time(created_at, now) {
            return Err(NostrEventError::InvalidCreatedAt);
        }
        if !ciphertext_matches(encryption, &event.content) {
            return Err(NostrEventError::InvalidCiphertext);
        }

        Ok(ValidatedNwcEvent {
            id: EventId::from_bytes(*event.id.as_bytes()),
            author: PublicKey::from_bytes(*event.pubkey.as_bytes()),
            created_at,
            encryption,
            ciphertext: event.content,
            maximum_plaintext_bytes: self.policy.maximum_payload_bytes(),
        })
    }
}

fn has_exact_recipient(event: &Event, expected: &PublicKey) -> bool {
    let mut recipient_tags = event.tags.iter().filter(|tag| tag.kind() == TagKind::p());
    let Some(recipient) = recipient_tags.next() else {
        return false;
    };
    if recipient_tags.next().is_some() {
        return false;
    }
    recipient
        .content()
        .and_then(|value| NostrPublicKey::from_hex(value).ok())
        .is_some_and(|public_key| public_key.as_bytes() == expected.as_bytes())
}

fn ciphertext_matches(encryption: NwcEncryption, content: &str) -> bool {
    if content.is_empty() {
        return false;
    }
    match encryption {
        NwcEncryption::Nip44V2 => !content.contains("?iv=") && content.len() >= 132,
        NwcEncryption::LegacyNip04 => {
            content
                .split_once("?iv=")
                .is_some_and(|(ciphertext, initialization_vector)| {
                    !ciphertext.is_empty()
                        && !initialization_vector.is_empty()
                        && !initialization_vector.contains("?iv=")
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use nostr::{EventBuilder, Keys, Tag, Timestamp};

    use super::*;

    const CLIENT_SECRET: &str = "5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a";
    const WALLET_SECRET: &str = "4b22aa260e4acb7021e32f38a6cdf4b673c6a277755bfce287e370c924dc936d";
    const NOW: u64 = 10_000;

    fn keys(secret: &str) -> Keys {
        Keys::parse(secret).expect("test key")
    }

    fn domain_public_key(public_key: NostrPublicKey) -> PublicKey {
        PublicKey::from_bytes(*public_key.as_bytes())
    }

    fn signed_request(
        encryption: NwcEncryption,
        created_at: u64,
        recipient: NostrPublicKey,
        author: &Keys,
    ) -> Event {
        let wallet = keys(WALLET_SECRET);
        let plaintext = r#"{"method":"get_info","params":{}}"#;
        let content = match encryption {
            NwcEncryption::Nip44V2 => nostr::nips::nip44::encrypt(
                author.secret_key(),
                &wallet.public_key(),
                plaintext,
                nostr::nips::nip44::Version::V2,
            )
            .expect("encrypt NIP-44"),
            NwcEncryption::LegacyNip04 => {
                nostr::nips::nip04::encrypt(author.secret_key(), &wallet.public_key(), plaintext)
                    .expect("encrypt NIP-04")
            }
        };
        EventBuilder::new(Kind::WalletConnectRequest, content)
            .tags([Tag::public_key(recipient)])
            .custom_created_at(Timestamp::from_secs(created_at))
            .sign_with_keys(author)
            .expect("sign request")
    }

    fn validate(
        event: &Event,
        expected_id: &EventId,
        expected_client: &PublicKey,
        expected_wallet: &PublicKey,
        encryption: NwcEncryption,
        now: u64,
    ) -> Result<ValidatedNwcEvent, NostrEventError> {
        NwcEventValidator::new(WakePolicy::default()).validate_request(
            &event.as_json(),
            expected_id,
            expected_client,
            expected_wallet,
            encryption,
            UnixTimestamp::from_secs(now),
        )
    }

    #[test]
    fn verifies_all_bindings_before_decrypting_nip44() {
        let client = keys(CLIENT_SECRET);
        let wallet = keys(WALLET_SECRET);
        let event = signed_request(NwcEncryption::Nip44V2, NOW, wallet.public_key(), &client);
        let event_id = EventId::from_bytes(*event.id.as_bytes());
        let validated = validate(
            &event,
            &event_id,
            &domain_public_key(client.public_key()),
            &domain_public_key(wallet.public_key()),
            NwcEncryption::Nip44V2,
            NOW,
        )
        .expect("validated event");
        let wallet_secret = NwcSecretKey::from_bytes(
            wallet
                .secret_key()
                .as_secret_bytes()
                .try_into()
                .expect("32-byte secret"),
        )
        .expect("wallet secret");

        assert_eq!(
            validated
                .decrypt(&wallet_secret)
                .expect("decrypt")
                .as_json(),
            r#"{"method":"get_info","params":{}}"#
        );
    }

    #[test]
    fn decrypts_legacy_nip04_only_when_connection_selected_it() {
        let client = keys(CLIENT_SECRET);
        let wallet = keys(WALLET_SECRET);
        let event = signed_request(
            NwcEncryption::LegacyNip04,
            NOW,
            wallet.public_key(),
            &client,
        );
        let event_id = EventId::from_bytes(*event.id.as_bytes());
        let expected_client = domain_public_key(client.public_key());
        let expected_wallet = domain_public_key(wallet.public_key());

        assert_eq!(
            validate(
                &event,
                &event_id,
                &expected_client,
                &expected_wallet,
                NwcEncryption::Nip44V2,
                NOW,
            )
            .expect_err("scheme mismatch"),
            NostrEventError::InvalidCiphertext
        );
        assert!(validate(
            &event,
            &event_id,
            &expected_client,
            &expected_wallet,
            NwcEncryption::LegacyNip04,
            NOW,
        )
        .is_ok());
    }

    #[test]
    fn rejects_substituted_id_author_kind_and_recipient() {
        let client = keys(CLIENT_SECRET);
        let other = Keys::parse("6b22aa260e4acb7021e32f38a6cdf4b673c6a277755bfce287e370c924dc936d")
            .expect("other key");
        let wallet = keys(WALLET_SECRET);
        let event = signed_request(NwcEncryption::Nip44V2, NOW, wallet.public_key(), &client);
        let event_id = EventId::from_bytes(*event.id.as_bytes());
        let expected_client = domain_public_key(client.public_key());
        let expected_wallet = domain_public_key(wallet.public_key());
        let wrong_id = EventId::from_bytes([7; 32]);

        assert_eq!(
            validate(
                &event,
                &wrong_id,
                &expected_client,
                &expected_wallet,
                NwcEncryption::Nip44V2,
                NOW,
            )
            .expect_err("substituted event"),
            NostrEventError::EventIdMismatch
        );
        assert_eq!(
            validate(
                &event,
                &event_id,
                &domain_public_key(other.public_key()),
                &expected_wallet,
                NwcEncryption::Nip44V2,
                NOW,
            )
            .expect_err("wrong author"),
            NostrEventError::UnexpectedAuthor
        );

        let wrong_recipient =
            signed_request(NwcEncryption::Nip44V2, NOW, other.public_key(), &client);
        assert_eq!(
            validate(
                &wrong_recipient,
                &EventId::from_bytes(*wrong_recipient.id.as_bytes()),
                &expected_client,
                &expected_wallet,
                NwcEncryption::Nip44V2,
                NOW,
            )
            .expect_err("wrong recipient"),
            NostrEventError::UnexpectedRecipient
        );

        let wrong_kind = EventBuilder::new(Kind::WalletConnectResponse, event.content.clone())
            .tags([Tag::public_key(wallet.public_key())])
            .custom_created_at(Timestamp::from_secs(NOW))
            .sign_with_keys(&client)
            .expect("sign response");
        assert_eq!(
            validate(
                &wrong_kind,
                &EventId::from_bytes(*wrong_kind.id.as_bytes()),
                &expected_client,
                &expected_wallet,
                NwcEncryption::Nip44V2,
                NOW,
            )
            .expect_err("wrong kind"),
            NostrEventError::UnexpectedKind
        );
    }

    #[test]
    fn rejects_tampering_and_out_of_window_events() {
        let client = keys(CLIENT_SECRET);
        let wallet = keys(WALLET_SECRET);
        let mut tampered =
            signed_request(NwcEncryption::Nip44V2, NOW, wallet.public_key(), &client);
        let original_id = EventId::from_bytes(*tampered.id.as_bytes());
        tampered.content.push('x');
        assert_eq!(
            validate(
                &tampered,
                &original_id,
                &domain_public_key(client.public_key()),
                &domain_public_key(wallet.public_key()),
                NwcEncryption::Nip44V2,
                NOW,
            )
            .expect_err("tampered event"),
            NostrEventError::InvalidSignature
        );

        for created_at in [NOW - 601, NOW + 31] {
            let event = signed_request(
                NwcEncryption::Nip44V2,
                created_at,
                wallet.public_key(),
                &client,
            );
            assert_eq!(
                validate(
                    &event,
                    &EventId::from_bytes(*event.id.as_bytes()),
                    &domain_public_key(client.public_key()),
                    &domain_public_key(wallet.public_key()),
                    NwcEncryption::Nip44V2,
                    NOW,
                )
                .expect_err("out-of-window event"),
                NostrEventError::InvalidCreatedAt
            );
        }
    }
}
