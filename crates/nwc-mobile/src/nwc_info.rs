use std::collections::BTreeSet;
use std::fmt;

use nostr::{
    EventBuilder, JsonUtil, Keys, Kind, PublicKey as NostrPublicKey, Tag, TagKind, Timestamp,
};

use crate::{NwcEncryption, NwcMethod, NwcSecretKey, PublicKey, UnixTimestamp};

/// A stable failure while constructing a signed NIP-47 info event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NwcInfoEventError {
    /// At least one supported method must be advertised.
    NoMethods,
    /// The supplied wallet-service secret was invalid.
    InvalidSecretKey,
    /// The event could not be signed or serialized.
    BuildFailed,
}

impl fmt::Display for NwcInfoEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NoMethods => "NWC info event requires at least one method",
            Self::InvalidSecretKey => "NWC info event signing key is invalid",
            Self::BuildFailed => "NWC info event could not be built",
        })
    }
}

impl std::error::Error for NwcInfoEventError {}

/// Builds and signs a deterministic NIP-47 wallet-info event.
///
/// Methods are de-duplicated and emitted in canonical [`NwcMethod`] order. A
/// targeted event includes exactly one `p` tag for the authorized client.
pub fn build_nwc_info_event(
    wallet_secret: &NwcSecretKey,
    client_pubkey: Option<&PublicKey>,
    methods: impl IntoIterator<Item = NwcMethod>,
    encryption: NwcEncryption,
    created_at: UnixTimestamp,
) -> Result<String, NwcInfoEventError> {
    let methods = methods.into_iter().collect::<BTreeSet<_>>();
    if methods.is_empty() {
        return Err(NwcInfoEventError::NoMethods);
    }
    let content = methods
        .into_iter()
        .map(NwcMethod::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    let mut tags = Vec::new();
    if encryption == NwcEncryption::Nip44V2 {
        tags.push(Tag::custom(
            TagKind::custom("encryption"),
            [encryption.as_str()],
        ));
    }
    if let Some(client_pubkey) = client_pubkey {
        tags.push(Tag::public_key(NostrPublicKey::from_byte_array(
            *client_pubkey.as_bytes(),
        )));
    }
    let secret = wallet_secret
        .nostr_secret()
        .map_err(|_| NwcInfoEventError::InvalidSecretKey)?;
    EventBuilder::new(Kind::WalletConnectInfo, content)
        .tags(tags)
        .custom_created_at(Timestamp::from(created_at.as_secs()))
        .sign_with_keys(&Keys::new(secret))
        .map(|event| event.as_json())
        .map_err(|_| NwcInfoEventError::BuildFailed)
}

#[cfg(test)]
mod tests {
    use nostr::{Event, JsonUtil};

    use super::*;

    #[test]
    fn targeted_info_event_is_signed_bounded_and_canonical() {
        let wallet_secret = NwcSecretKey::from_bytes([7_u8; 32]).expect("wallet secret");
        let client =
            PublicKey::from_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .expect("client key");

        let json = build_nwc_info_event(
            &wallet_secret,
            Some(&client),
            [
                NwcMethod::PayInvoice,
                NwcMethod::GetInfo,
                NwcMethod::GetInfo,
                NwcMethod::GetBalance,
            ],
            NwcEncryption::LegacyNip04,
            UnixTimestamp::from_secs(1_700_000_000),
        )
        .expect("info event");
        let event = Event::from_json(json).expect("event json");

        event.verify().expect("valid signature");
        assert_eq!(event.kind, Kind::WalletConnectInfo);
        assert_eq!(event.created_at.as_secs(), 1_700_000_000);
        assert_eq!(event.content, "get_info get_balance pay_invoice");
        assert!(event.tags.iter().any(|tag| {
            let fields = tag.as_slice();
            fields.first().is_some_and(|field| field == "p")
                && fields.get(1).is_some_and(|field| field == &client.to_hex())
        }));
        assert!(!event.tags.iter().any(|tag| {
            let fields = tag.as_slice();
            fields.first().is_some_and(|field| field == "encryption")
        }));
    }

    #[test]
    fn nip44_info_event_advertises_encryption() {
        let wallet_secret = NwcSecretKey::from_bytes([7_u8; 32]).expect("wallet secret");
        let json = build_nwc_info_event(
            &wallet_secret,
            None,
            [NwcMethod::GetInfo],
            NwcEncryption::Nip44V2,
            UnixTimestamp::from_secs(1_700_000_000),
        )
        .expect("info event");
        let event = Event::from_json(json).expect("event json");

        event.verify().expect("valid signature");
        assert!(event.tags.iter().any(|tag| {
            let fields = tag.as_slice();
            fields.first().is_some_and(|field| field == "encryption")
                && fields.get(1).is_some_and(|field| field == "nip44_v2")
        }));
    }

    #[test]
    fn info_event_rejects_empty_method_set() {
        let wallet_secret = NwcSecretKey::from_bytes([7_u8; 32]).expect("wallet secret");
        assert_eq!(
            build_nwc_info_event(
                &wallet_secret,
                None,
                [],
                NwcEncryption::Nip44V2,
                UnixTimestamp::from_secs(1),
            ),
            Err(NwcInfoEventError::NoMethods)
        );
    }
}
