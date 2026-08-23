use std::collections::HashSet;
use std::fmt;

use nostr::nips::nip47::NostrWalletConnectURI;
use nostr::{Keys, PublicKey as NostrPublicKey, RelayUrl, SecretKey};
use zeroize::Zeroizing;

use crate::{
    ActiveConnection, ApprovedNwaConnection, BudgetInterval, FeePolicy,
    HostConnectionAuthorization, MobileServiceError, NwcEncryption, NwcMethod, NwcMobileService,
    RegistryError, SecureRelayUrl, UnixTimestamp,
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

/// Stable failure returned by the batteries-included application workflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ApplicationWorkflowError {
    /// Native input could not be converted into a safe connection policy.
    InvalidInput(ApplicationError),
    /// The authoritative connection service rejected or could not persist the operation.
    Service(MobileServiceError),
    /// The platform secret store could not complete the requested operation.
    SecretStoreUnavailable,
    /// No wallet-managed client secret exists for the requested connection.
    ClientSecretUnavailable,
    /// A previously approved native callback still awaits completion.
    CallbackPending,
}

impl fmt::Display for ApplicationWorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput(_) => "the NWC application input is invalid",
            Self::Service(_) => "the NWC application service is unavailable",
            Self::SecretStoreUnavailable => "the secure client-secret store is unavailable",
            Self::ClientSecretUnavailable => "the wallet-managed NWC client secret is unavailable",
            Self::CallbackPending => "the previous NWA callback is still pending",
        })
    }
}

impl std::error::Error for ApplicationWorkflowError {}

impl From<ApplicationError> for ApplicationWorkflowError {
    fn from(error: ApplicationError) -> Self {
        Self::InvalidInput(error)
    }
}

impl From<MobileServiceError> for ApplicationWorkflowError {
    fn from(error: MobileServiceError) -> Self {
        Self::Service(error)
    }
}

/// Platform-owned storage for wallet-managed NWC client secrets.
///
/// Implementations must use hardware- or OS-protected storage, must not log
/// values, and must treat deletion of a missing key as success.
pub trait ClientSecretStore: Send + Sync {
    /// Loads a secret without caching it beyond the operation that requested it.
    fn load_client_secret(
        &self,
        storage_key: &str,
    ) -> Result<Option<String>, ClientSecretStoreError>;

    /// Stores a newly-generated secret using device-only protection.
    fn store_client_secret(
        &self,
        storage_key: &str,
        secret: &str,
    ) -> Result<(), ClientSecretStoreError>;

    /// Deletes secret material. Missing values must be treated as already deleted.
    fn delete_client_secret(&self, storage_key: &str) -> Result<(), ClientSecretStoreError>;
}

/// Redacted platform secret-store failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientSecretStoreError;

impl fmt::Display for ClientSecretStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the platform secret store is unavailable")
    }
}

impl std::error::Error for ClientSecretStoreError {}

/// Complete input for a wallet-created, exportable NWC connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletConnectionRequest {
    wallet_service_pubkey_hex: String,
    relay_input: String,
    fallback_relay_input: String,
    methods: Vec<NwcMethod>,
    budget_limit_sat: u64,
    budget_interval: BudgetInterval,
    encryption: NwcEncryption,
    expires_at: Option<UnixTimestamp>,
    lud16: Option<String>,
}

impl WalletConnectionRequest {
    /// Creates an application request; parsing and policy validation occur atomically at creation.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        wallet_service_pubkey_hex: String,
        relay_input: String,
        fallback_relay_input: String,
        methods: Vec<NwcMethod>,
        budget_limit_sat: u64,
        budget_interval: BudgetInterval,
        encryption: NwcEncryption,
        expires_at: Option<UnixTimestamp>,
        lud16: Option<String>,
    ) -> Self {
        Self {
            wallet_service_pubkey_hex,
            relay_input,
            fallback_relay_input,
            methods,
            budget_limit_sat,
            budget_interval,
            encryption,
            expires_at,
            lud16,
        }
    }
}

/// Complete input for approving the currently retained Nostr Wallet Auth request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NwaApprovalSelection {
    request_id_hex: String,
    wallet_service_pubkey_hex: String,
    relay_input: String,
    fallback_relay_input: String,
    methods: Vec<NwcMethod>,
    budget_limit_sat: u64,
    budget_interval: BudgetInterval,
    encryption: NwcEncryption,
    expires_at: Option<UnixTimestamp>,
    lud16: Option<String>,
}

impl NwaApprovalSelection {
    /// Creates an approval selection bound to the exact reviewed request identifier.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        request_id_hex: String,
        wallet_service_pubkey_hex: String,
        relay_input: String,
        fallback_relay_input: String,
        methods: Vec<NwcMethod>,
        budget_limit_sat: u64,
        budget_interval: BudgetInterval,
        encryption: NwcEncryption,
        expires_at: Option<UnixTimestamp>,
        lud16: Option<String>,
    ) -> Self {
        Self {
            request_id_hex,
            wallet_service_pubkey_hex,
            relay_input,
            fallback_relay_input,
            methods,
            budget_limit_sat,
            budget_interval,
            encryption,
            expires_at,
            lud16,
        }
    }
}

/// Atomically persisted wallet-created connection plus its one-time export URI.
pub struct CreatedWalletConnection {
    draft: ConnectionDraft,
    connection: ActiveConnection,
    uri: String,
}

impl CreatedWalletConnection {
    /// Returns the canonical connection draft used for rendering host metadata.
    #[must_use]
    pub const fn draft(&self) -> &ConnectionDraft {
        &self.draft
    }

    /// Returns the authoritative durable connection state.
    #[must_use]
    pub const fn connection(&self) -> &ActiveConnection {
        &self.connection
    }

    /// Returns the NIP-47 URI containing the wallet-managed client secret.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }
}

impl fmt::Debug for CreatedWalletConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedWalletConnection")
            .field("draft", &self.draft)
            .field("connection", &self.connection)
            .field("uri", &"[redacted]")
            .finish()
    }
}

/// Atomically persisted NWA approval together with its validated draft.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedApplicationConnection {
    draft: ConnectionDraft,
    approval: ApprovedNwaConnection,
}

impl ApprovedApplicationConnection {
    /// Returns the exact validated authority selected by the user.
    #[must_use]
    pub const fn draft(&self) -> &ConnectionDraft {
        &self.draft
    }

    /// Returns the durable connection and verified callback result.
    #[must_use]
    pub const fn approval(&self) -> &ApprovedNwaConnection {
        &self.approval
    }
}

/// Result of an idempotent application-level revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationRevocation {
    client_secret_deleted: bool,
}

impl ApplicationRevocation {
    /// Returns whether the platform confirmed deletion of any wallet-managed secret.
    #[must_use]
    pub const fn client_secret_deleted(self) -> bool {
        self.client_secret_deleted
    }
}

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

    /// Returns the stable application connection identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        self.authorization.id()
    }

    /// Returns the wallet-managed or requesting client public key.
    #[must_use]
    pub fn client_pubkey_hex(&self) -> &str {
        self.authorization.client_pubkey_hex()
    }

    /// Returns the wallet service public key.
    #[must_use]
    pub fn wallet_service_pubkey_hex(&self) -> &str {
        self.authorization.wallet_service_pubkey_hex()
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

impl NwcMobileService {
    /// Generates, securely stores, validates, and atomically persists a wallet-created connection.
    pub fn create_wallet_connection(
        &self,
        request: WalletConnectionRequest,
        secrets: &dyn ClientSecretStore,
    ) -> Result<CreatedWalletConnection, ApplicationWorkflowError> {
        let client_keys = Keys::generate();
        let client_pubkey_hex = client_keys.public_key().to_hex();
        let client_secret = Zeroizing::new(client_keys.secret_key().to_secret_hex());
        let selection = ConnectionSelection::from_host_input(
            &request.relay_input,
            &request.fallback_relay_input,
            request.methods,
            request.budget_limit_sat,
            request.budget_interval,
        )?;
        let draft = ConnectionDraft::new(
            format!("nwc-{client_pubkey_hex}"),
            client_pubkey_hex.clone(),
            request.wallet_service_pubkey_hex,
            selection,
            request.encryption,
            request.expires_at,
        )?;
        let uri = build_connection_uri(
            draft.wallet_service_pubkey_hex(),
            draft.authorization.relay_urls(),
            client_secret.as_str(),
            request.lud16,
        )?;
        let storage_key = client_secret_storage_key(&client_pubkey_hex);
        secrets
            .store_client_secret(&storage_key, client_secret.as_str())
            .map_err(|_| ApplicationWorkflowError::SecretStoreUnavailable)?;
        let connection = match self.create_host_connection(draft.authorization()) {
            Ok(connection) => connection,
            Err(error) => {
                let _ = secrets.delete_client_secret(&storage_key);
                return Err(error.into());
            }
        };
        Ok(CreatedWalletConnection {
            draft,
            connection,
            uri,
        })
    }

    /// Applies a user selection to the exact retained NWA request and persists it atomically.
    pub fn approve_application_nwa(
        &self,
        selection: NwaApprovalSelection,
    ) -> Result<ApprovedApplicationConnection, ApplicationWorkflowError> {
        let request = self
            .pending_nwa_request()?
            .ok_or(MobileServiceError::NoPendingNwa)?;
        let authority = ConnectionSelection::from_host_input(
            &selection.relay_input,
            &selection.fallback_relay_input,
            selection.methods,
            selection.budget_limit_sat,
            selection.budget_interval,
        )?;
        let client_pubkey_hex = request.client_pubkey_hex().to_owned();
        let draft = ConnectionDraft::new(
            format!("nwc-{client_pubkey_hex}"),
            client_pubkey_hex,
            selection.wallet_service_pubkey_hex,
            authority,
            selection.encryption,
            selection.expires_at,
        )?;
        let approval = self.approve_pending_nwa(
            &selection.request_id_hex,
            draft.authorization(),
            selection.lud16,
        )?;
        Ok(ApprovedApplicationConnection { draft, approval })
    }

    /// Builds an export URI without exposing secret handling to application orchestration.
    pub fn export_wallet_connection_uri(
        &self,
        connection_id: &str,
        lud16: Option<String>,
        secrets: &dyn ClientSecretStore,
    ) -> Result<String, ApplicationWorkflowError> {
        let connection = self
            .connection_presentations()?
            .into_iter()
            .find(|connection| connection.id() == connection_id)
            .ok_or(MobileServiceError::Registry(RegistryError::NotFound))?;
        let storage_key = client_secret_storage_key(connection.client_pubkey_hex());
        let secret = Zeroizing::new(
            secrets
                .load_client_secret(&storage_key)
                .map_err(|_| ApplicationWorkflowError::SecretStoreUnavailable)?
                .ok_or(ApplicationWorkflowError::ClientSecretUnavailable)?,
        );
        build_connection_uri(
            connection.wallet_service_pubkey_hex(),
            connection.relay_urls(),
            secret.as_str(),
            lud16,
        )
        .map_err(Into::into)
    }

    /// Revokes a connection before best-effort removal of wallet-managed secret material.
    pub fn revoke_application_connection(
        &self,
        connection_id: &str,
        secrets: &dyn ClientSecretStore,
    ) -> Result<ApplicationRevocation, ApplicationWorkflowError> {
        let client_pubkey_hex = self
            .connection_presentations()?
            .into_iter()
            .find(|connection| connection.id() == connection_id)
            .map(|connection| connection.client_pubkey_hex().to_owned())
            .or_else(|| application_client_pubkey_from_id(connection_id));
        self.revoke_host_connection(connection_id)?;
        let client_secret_deleted = client_pubkey_hex.is_some_and(|client_pubkey_hex| {
            secrets
                .delete_client_secret(&client_secret_storage_key(&client_pubkey_hex))
                .is_ok()
        });
        Ok(ApplicationRevocation {
            client_secret_deleted,
        })
    }
}

fn application_client_pubkey_from_id(connection_id: &str) -> Option<String> {
    let client_pubkey_hex = connection_id.strip_prefix("nwc-")?;
    NostrPublicKey::from_hex(client_pubkey_hex)
        .ok()
        .map(|public_key| public_key.to_hex())
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
    display_name: Option<String>,
    icon_url: Option<String>,
    spent_sat: u64,
    budget_period_started_at: UnixTimestamp,
    pending_info_event_relays: Vec<String>,
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
        metadata: Option<crate::ApplicationConnectionMetadata>,
        usage: crate::ConnectionBudgetUsage,
    ) -> Self {
        let (display_name, icon_url, pending_info_event_relays) = metadata.map_or_else(
            || (None, None, Vec::new()),
            |metadata| {
                (
                    Some(metadata.display_name().to_owned()),
                    metadata.icon_url().map(str::to_owned),
                    metadata.pending_info_event_relays().to_vec(),
                )
            },
        );
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
            display_name,
            icon_url,
            spent_sat: usage.spent_sat(),
            budget_period_started_at: usage.period_started_at(),
            pending_info_event_relays,
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

    /// Returns the optional host-selected display name stored in the shared ledger.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Returns the optional validated HTTPS icon URL stored in the shared ledger.
    #[must_use]
    pub fn icon_url(&self) -> Option<&str> {
        self.icon_url.as_deref()
    }

    /// Returns the durable amount consumed in the current accounting interval.
    #[must_use]
    pub const fn spent_sat(&self) -> u64 {
        self.spent_sat
    }

    /// Returns the deterministic start of the current accounting interval.
    #[must_use]
    pub const fn budget_period_started_at(&self) -> UnixTimestamp {
        self.budget_period_started_at
    }

    /// Returns capability-event relays still awaiting acknowledgement.
    #[must_use]
    pub fn pending_info_event_relays(&self) -> &[String] {
        &self.pending_info_event_relays
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
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use super::*;

    const CLIENT: &str = "687dd8ece211539364549b1f32c63eceec1e0661009ba65cf8ff2e73ba000746";
    const WALLET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SECRET: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

    #[derive(Default)]
    struct TestSecrets(Mutex<HashMap<String, String>>);

    impl ClientSecretStore for TestSecrets {
        fn load_client_secret(
            &self,
            storage_key: &str,
        ) -> Result<Option<String>, ClientSecretStoreError> {
            Ok(self
                .0
                .lock()
                .map_err(|_| ClientSecretStoreError)?
                .get(storage_key)
                .cloned())
        }

        fn store_client_secret(
            &self,
            storage_key: &str,
            secret: &str,
        ) -> Result<(), ClientSecretStoreError> {
            self.0
                .lock()
                .map_err(|_| ClientSecretStoreError)?
                .insert(storage_key.to_owned(), secret.to_owned());
            Ok(())
        }

        fn delete_client_secret(&self, storage_key: &str) -> Result<(), ClientSecretStoreError> {
            self.0
                .lock()
                .map_err(|_| ClientSecretStoreError)?
                .remove(storage_key);
            Ok(())
        }
    }

    struct FlakyDeleteSecrets {
        values: Mutex<HashMap<String, String>>,
        remaining_delete_failures: AtomicUsize,
        delete_attempts: AtomicUsize,
    }

    impl FlakyDeleteSecrets {
        fn fail_next_delete() -> Self {
            Self {
                values: Mutex::new(HashMap::new()),
                remaining_delete_failures: AtomicUsize::new(1),
                delete_attempts: AtomicUsize::new(0),
            }
        }
    }

    impl ClientSecretStore for FlakyDeleteSecrets {
        fn load_client_secret(
            &self,
            storage_key: &str,
        ) -> Result<Option<String>, ClientSecretStoreError> {
            Ok(self
                .values
                .lock()
                .map_err(|_| ClientSecretStoreError)?
                .get(storage_key)
                .cloned())
        }

        fn store_client_secret(
            &self,
            storage_key: &str,
            secret: &str,
        ) -> Result<(), ClientSecretStoreError> {
            self.values
                .lock()
                .map_err(|_| ClientSecretStoreError)?
                .insert(storage_key.to_owned(), secret.to_owned());
            Ok(())
        }

        fn delete_client_secret(&self, storage_key: &str) -> Result<(), ClientSecretStoreError> {
            self.delete_attempts.fetch_add(1, Ordering::Relaxed);
            if self
                .remaining_delete_failures
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                return Err(ClientSecretStoreError);
            }
            self.values
                .lock()
                .map_err(|_| ClientSecretStoreError)?
                .remove(storage_key);
            Ok(())
        }
    }

    struct TestDatabase {
        directory: PathBuf,
        path: PathBuf,
    }

    impl TestDatabase {
        fn new() -> Self {
            let mut random = [0_u8; 8];
            getrandom::fill(&mut random).expect("test randomness");
            let directory = std::env::temp_dir().join(format!(
                "nwc-mobile-application-{}",
                u64::from_le_bytes(random)
            ));
            std::fs::create_dir_all(&directory).expect("test directory");
            let path = directory.join("ledger.sqlite3");
            Self { directory, path }
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

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

    #[test]
    fn service_owns_wallet_connection_secret_lifecycle_and_export() {
        let database = TestDatabase::new();
        let service = NwcMobileService::open(&database.path).expect("service");
        let secrets = TestSecrets::default();
        let created = service
            .create_wallet_connection(
                WalletConnectionRequest::new(
                    WALLET.to_owned(),
                    "wss://relay.example/nwc".to_owned(),
                    String::new(),
                    vec![NwcMethod::GetInfo, NwcMethod::PayInvoice],
                    1_000,
                    BudgetInterval::Daily,
                    NwcEncryption::Nip44V2,
                    None,
                    Some("wallet@example.com".to_owned()),
                ),
                &secrets,
            )
            .expect("created");
        let connection_id = created.connection().id().as_str().to_owned();
        assert_eq!(created.connection().id().as_str(), created.draft().id());
        assert_eq!(
            created.uri(),
            service
                .export_wallet_connection_uri(
                    &connection_id,
                    Some("wallet@example.com".to_owned()),
                    &secrets,
                )
                .expect("export")
        );

        let revoked = service
            .revoke_application_connection(&connection_id, &secrets)
            .expect("revoked");
        assert!(revoked.client_secret_deleted());
        assert_eq!(
            service.export_wallet_connection_uri(&connection_id, None, &secrets),
            Err(ApplicationWorkflowError::Service(
                MobileServiceError::Registry(RegistryError::NotFound)
            ))
        );
    }

    #[test]
    fn revocation_retries_secret_deletion_after_the_connection_is_tombstoned() {
        let database = TestDatabase::new();
        let service = NwcMobileService::open(&database.path).expect("service");
        let secrets = FlakyDeleteSecrets::fail_next_delete();
        let created = service
            .create_wallet_connection(
                WalletConnectionRequest::new(
                    WALLET.to_owned(),
                    "wss://relay.example/nwc".to_owned(),
                    String::new(),
                    vec![NwcMethod::GetInfo],
                    1_000,
                    BudgetInterval::Daily,
                    NwcEncryption::Nip44V2,
                    None,
                    None,
                ),
                &secrets,
            )
            .expect("created");
        let connection_id = created.connection().id().as_str().to_owned();
        let storage_key = client_secret_storage_key(created.draft().client_pubkey_hex());

        let first = service
            .revoke_application_connection(&connection_id, &secrets)
            .expect("authorization revoked");
        assert!(!first.client_secret_deleted());
        assert!(secrets
            .load_client_secret(&storage_key)
            .expect("secret store")
            .is_some());

        let second = service
            .revoke_application_connection(&connection_id, &secrets)
            .expect("idempotent retry");
        assert!(second.client_secret_deleted());
        assert_eq!(secrets.delete_attempts.load(Ordering::Relaxed), 2);
        assert!(secrets
            .load_client_secret(&storage_key)
            .expect("secret store")
            .is_none());
    }
}
