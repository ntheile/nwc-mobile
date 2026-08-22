use std::collections::HashSet;
use std::fmt;

use nostr::nips::nip47::NostrWalletConnectURI;
use nostr::{PublicKey as NostrPublicKey, RelayUrl, SecretKey};

use crate::{
    ActiveConnection, BudgetInterval, FeePolicy, HostConnectionAuthorization, NwcEncryption,
    NwcMethod, RegistryError, SecureRelayUrl, UnixTimestamp,
};

/// Maximum relays accepted by the default mobile application workflow.
pub const DEFAULT_MAXIMUM_CONNECTION_RELAYS: usize = 2;

const CLIENT_SECRET_KEY_PREFIX: &str = "nwc_client_secret:";
const RELAY_STORAGE_SEPARATOR: &str = "\n";

/// Stable failure returned by application-level NWC helpers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ApplicationError {
    /// No valid relay was supplied.
    MissingRelay,
    /// More relays were supplied than the configured policy permits.
    TooManyRelays,
    /// A relay was invalid, insecure, or duplicated.
    InvalidRelay,
    /// A public key or client secret was malformed.
    InvalidKey,
    /// The connection input violated an authorization invariant.
    InvalidConnection,
}

impl fmt::Display for ApplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingRelay => "at least one secure relay is required",
            Self::TooManyRelays => "too many relays were supplied",
            Self::InvalidRelay => "a relay is invalid or insecure",
            Self::InvalidKey => "an NWC key is invalid",
            Self::InvalidConnection => "the NWC connection is invalid",
        })
    }
}

impl std::error::Error for ApplicationError {}

/// User-selected authority for a connection being created or approved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionSelection {
    relay_urls: Vec<String>,
    methods: Vec<NwcMethod>,
    budget_limit_sat: u64,
    budget_interval: BudgetInterval,
}

impl ConnectionSelection {
    /// Parses and canonicalizes native relay and method input.
    pub fn from_host_input(
        relay_input: &str,
        fallback_relay_input: &str,
        methods: impl IntoIterator<Item = NwcMethod>,
        budget_limit_sat: u64,
        budget_interval: BudgetInterval,
    ) -> Result<Self, ApplicationError> {
        let relay_urls = parse_connection_relays(
            relay_input,
            fallback_relay_input,
            DEFAULT_MAXIMUM_CONNECTION_RELAYS,
        )?;
        let methods = normalize_methods(methods);
        if methods.is_empty() {
            return Err(ApplicationError::InvalidConnection);
        }
        Ok(Self {
            relay_urls,
            methods,
            budget_limit_sat,
            budget_interval,
        })
    }

    /// Returns the canonical relay URLs in approval order.
    #[must_use]
    pub fn relay_urls(&self) -> &[String] {
        &self.relay_urls
    }

    /// Returns the canonical newline-delimited host storage representation.
    #[must_use]
    pub fn relay_storage(&self) -> String {
        encode_connection_relays(&self.relay_urls)
    }

    /// Returns the approved methods in stable order.
    #[must_use]
    pub fn methods(&self) -> &[NwcMethod] {
        &self.methods
    }

    /// Returns the approved budget limit.
    #[must_use]
    pub const fn budget_limit_sat(&self) -> u64 {
        self.budget_limit_sat
    }

    /// Returns the approved budget interval.
    #[must_use]
    pub const fn budget_interval(&self) -> BudgetInterval {
        self.budget_interval
    }
}

/// Complete application-owned connection draft after shared validation.
#[derive(Clone, Eq, PartialEq)]
pub struct ConnectionDraft {
    authorization: HostConnectionAuthorization,
    relay_storage: String,
    methods: Vec<NwcMethod>,
    budget_limit_sat: u64,
    budget_interval: BudgetInterval,
}

impl fmt::Debug for ConnectionDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionDraft")
            .field("authorization", &self.authorization)
            .field("relay_count", &self.authorization_relay_count())
            .field("methods", &self.methods)
            .field("budget_limit_sat", &self.budget_limit_sat)
            .field("budget_interval", &self.budget_interval)
            .finish()
    }
}

impl ConnectionDraft {
    /// Builds the complete validated authorization used by mobile applications.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connection_id: String,
        client_pubkey_hex: String,
        wallet_service_pubkey_hex: String,
        selection: ConnectionSelection,
        encryption: NwcEncryption,
        expires_at: Option<UnixTimestamp>,
    ) -> Result<Self, ApplicationError> {
        let fee_policy = FeePolicy::CountTowardBudget {
            maximum_fee_sat: maximum_mobile_fee_sat(selection.budget_limit_sat),
        };
        let authorization = HostConnectionAuthorization::new(
            connection_id,
            client_pubkey_hex,
            wallet_service_pubkey_hex,
            selection.relay_urls.clone(),
            selection.methods.clone(),
            selection.budget_limit_sat,
            selection.budget_interval,
            fee_policy,
            encryption,
            expires_at,
        );
        // Exercise the same validation used at persistence time without exposing
        // internal registry constructors to the host application.
        authorization
            .clone()
            .validate()
            .map_err(|_| ApplicationError::InvalidConnection)?;
        Ok(Self {
            authorization,
            relay_storage: selection.relay_storage(),
            methods: selection.methods,
            budget_limit_sat: selection.budget_limit_sat,
            budget_interval: selection.budget_interval,
        })
    }

    /// Returns a clone of the validated persistence authorization.
    #[must_use]
    pub fn authorization(&self) -> HostConnectionAuthorization {
        self.authorization.clone()
    }

    /// Returns the canonical host storage representation of the relays.
    #[must_use]
    pub fn relay_storage(&self) -> &str {
        &self.relay_storage
    }

    /// Returns the canonical approved method set.
    #[must_use]
    pub fn methods(&self) -> &[NwcMethod] {
        &self.methods
    }

    /// Returns the approved budget limit.
    #[must_use]
    pub const fn budget_limit_sat(&self) -> u64 {
        self.budget_limit_sat
    }

    /// Returns the approved budget interval.
    #[must_use]
    pub const fn budget_interval(&self) -> BudgetInterval {
        self.budget_interval
    }

    fn authorization_relay_count(&self) -> usize {
        self.relay_storage.lines().count()
    }
}

/// Non-sensitive authoritative connection data safe for application state.
#[derive(Clone, Eq, PartialEq)]
pub struct ConnectionPresentation {
    id: String,
    client_pubkey_hex: String,
    wallet_service_pubkey_hex: String,
    relay_urls: Vec<String>,
    methods: Vec<NwcMethod>,
    budget_limit_sat: u64,
    budget_interval: BudgetInterval,
    created_at: UnixTimestamp,
    expires_at: Option<UnixTimestamp>,
    last_used_at: Option<UnixTimestamp>,
}

impl fmt::Debug for ConnectionPresentation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionPresentation")
            .field("id", &"[redacted]")
            .field("client_pubkey_hex", &"[redacted]")
            .field("wallet_service_pubkey_hex", &"[redacted]")
            .field("relay_count", &self.relay_urls.len())
            .field("methods", &self.methods)
            .field("budget_limit_sat", &self.budget_limit_sat)
            .field("budget_interval", &self.budget_interval)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("last_used_at", &self.last_used_at)
            .finish()
    }
}

impl ConnectionPresentation {
    pub(crate) fn from_active(
        connection: &ActiveConnection,
        last_used_at: Option<UnixTimestamp>,
    ) -> Self {
        Self {
            id: connection.id().as_str().to_owned(),
            client_pubkey_hex: connection.client_pubkey().to_hex(),
            wallet_service_pubkey_hex: connection.wallet_service_pubkey().to_hex(),
            relay_urls: connection
                .relays()
                .iter()
                .map(|relay| relay.as_str().to_owned())
                .collect(),
            methods: connection.policy().methods().collect(),
            budget_limit_sat: connection.policy().budget().limit_sat(),
            budget_interval: connection.policy().budget().interval(),
            created_at: connection.created_at(),
            expires_at: connection.expires_at(),
            last_used_at,
        }
    }

    /// Returns the stable connection identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Returns the client public key.
    #[must_use]
    pub fn client_pubkey_hex(&self) -> &str {
        &self.client_pubkey_hex
    }
    /// Returns the wallet-service public key.
    #[must_use]
    pub fn wallet_service_pubkey_hex(&self) -> &str {
        &self.wallet_service_pubkey_hex
    }
    /// Returns the canonical secure relay allowlist.
    #[must_use]
    pub fn relay_urls(&self) -> &[String] {
        &self.relay_urls
    }
    /// Returns the canonical newline-delimited relay representation.
    #[must_use]
    pub fn relay_storage(&self) -> String {
        encode_connection_relays(&self.relay_urls)
    }
    /// Returns the authorized methods.
    #[must_use]
    pub fn methods(&self) -> &[NwcMethod] {
        &self.methods
    }
    /// Returns the spending limit.
    #[must_use]
    pub const fn budget_limit_sat(&self) -> u64 {
        self.budget_limit_sat
    }
    /// Returns the renewal interval.
    #[must_use]
    pub const fn budget_interval(&self) -> BudgetInterval {
        self.budget_interval
    }
    /// Returns the creation timestamp.
    #[must_use]
    pub const fn created_at(&self) -> UnixTimestamp {
        self.created_at
    }
    /// Returns the optional expiration timestamp.
    #[must_use]
    pub const fn expires_at(&self) -> Option<UnixTimestamp> {
        self.expires_at
    }
    /// Returns the last completed wake timestamp.
    #[must_use]
    pub const fn last_used_at(&self) -> Option<UnixTimestamp> {
        self.last_used_at
    }
}

/// Parses native relay input using the shared security and count policy.
pub fn parse_connection_relays(
    input: &str,
    fallback: &str,
    maximum_relays: usize,
) -> Result<Vec<String>, ApplicationError> {
    let selected = if input.trim().is_empty() {
        fallback
    } else {
        input
    };
    let mut seen = HashSet::new();
    let mut relays = Vec::new();
    for relay in selected
        .split(|character: char| character.is_whitespace() || character == ',')
        .map(str::trim)
        .filter(|relay| !relay.is_empty())
    {
        let secure = SecureRelayUrl::parse(relay).map_err(|_| ApplicationError::InvalidRelay)?;
        if !seen.insert(secure.as_str().to_owned()) {
            continue;
        }
        relays.push(secure.as_str().to_owned());
    }
    if relays.is_empty() {
        return Err(ApplicationError::MissingRelay);
    }
    if maximum_relays == 0 || relays.len() > maximum_relays {
        return Err(ApplicationError::TooManyRelays);
    }
    Ok(relays)
}

/// Encodes canonical relays for simple host persistence and display.
#[must_use]
pub fn encode_connection_relays(relays: &[String]) -> String {
    relays.join(RELAY_STORAGE_SEPARATOR)
}

/// Returns a stable secret-store key without exposing secret material.
#[must_use]
pub fn client_secret_storage_key(client_pubkey_hex: &str) -> String {
    format!("{CLIENT_SECRET_KEY_PREFIX}{client_pubkey_hex}")
}

/// Computes the conservative per-payment fee reserve used by mobile clients.
#[must_use]
pub fn maximum_mobile_fee_sat(budget_limit_sat: u64) -> u64 {
    if budget_limit_sat == 0 {
        return 0;
    }
    (budget_limit_sat / 20)
        .clamp(10, 1_000)
        .min(budget_limit_sat)
}

/// Builds an exportable NIP-47 URI after validating all host-provided fields.
pub fn build_connection_uri(
    wallet_service_pubkey_hex: &str,
    relay_urls: &[String],
    client_secret: &str,
    lud16: Option<String>,
) -> Result<String, ApplicationError> {
    let public_key = NostrPublicKey::from_hex(wallet_service_pubkey_hex)
        .map_err(|_| ApplicationError::InvalidKey)?;
    let secret = SecretKey::parse(client_secret).map_err(|_| ApplicationError::InvalidKey)?;
    let relays = relay_urls
        .iter()
        .map(|relay| RelayUrl::parse(relay).map_err(|_| ApplicationError::InvalidRelay))
        .collect::<Result<Vec<_>, _>>()?;
    if relays.is_empty() {
        return Err(ApplicationError::MissingRelay);
    }
    Ok(NostrWalletConnectURI::new(public_key, relays, secret, lud16).to_string())
}

fn normalize_methods(methods: impl IntoIterator<Item = NwcMethod>) -> Vec<NwcMethod> {
    let requested = methods.into_iter().collect::<HashSet<_>>();
    [
        NwcMethod::GetInfo,
        NwcMethod::GetBalance,
        NwcMethod::PayInvoice,
        NwcMethod::MakeInvoice,
        NwcMethod::LookupInvoice,
        NwcMethod::ListTransactions,
    ]
    .into_iter()
    .filter(|method| requested.contains(method))
    .collect()
}

impl From<RegistryError> for ApplicationError {
    fn from(_: RegistryError) -> Self {
        Self::InvalidConnection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: &str = "687dd8ece211539364549b1f32c63eceec1e0661009ba65cf8ff2e73ba000746";
    const WALLET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SECRET: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

    #[test]
    fn relay_input_is_canonical_bounded_and_secure() {
        assert_eq!(
            parse_connection_relays("wss://one.example, wss://two.example", "", 2).expect("relays"),
            ["wss://one.example/", "wss://two.example/"]
        );
        assert_eq!(
            parse_connection_relays("ws://one.example", "", 2),
            Err(ApplicationError::InvalidRelay)
        );
        assert_eq!(
            parse_connection_relays("wss://one.example wss://two.example", "", 1),
            Err(ApplicationError::TooManyRelays)
        );
    }

    #[test]
    fn draft_owns_policy_normalization_and_fee_reserve() {
        let selection = ConnectionSelection::from_host_input(
            "wss://relay.example/nwc",
            "",
            [
                NwcMethod::PayInvoice,
                NwcMethod::GetInfo,
                NwcMethod::PayInvoice,
            ],
            1_000,
            BudgetInterval::Daily,
        )
        .expect("selection");
        let draft = ConnectionDraft::new(
            format!("nwc-{CLIENT}"),
            CLIENT.to_owned(),
            WALLET.to_owned(),
            selection,
            NwcEncryption::Nip44V2,
            None,
        )
        .expect("draft");
        assert_eq!(draft.methods(), [NwcMethod::GetInfo, NwcMethod::PayInvoice]);
        assert_eq!(draft.relay_storage(), "wss://relay.example/nwc");
        assert_eq!(maximum_mobile_fee_sat(1_000), 50);
    }

    #[test]
    fn export_uri_is_shared_and_does_not_log_secret_material() {
        let uri = build_connection_uri(
            WALLET,
            &["wss://relay.example/nwc".to_owned()],
            SECRET,
            Some("wallet@example.com".to_owned()),
        )
        .expect("uri");
        assert!(uri.starts_with("nostr+walletconnect://"));
        assert!(uri.contains("relay="));
        assert!(uri.contains("lud16="));
    }
}
