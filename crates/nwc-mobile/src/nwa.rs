use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::Duration;

use url::{form_urlencoded, Url};

use crate::{
    maximum_mobile_fee_sat, BudgetInterval, BudgetPolicy, ConnectionPolicy, FeePolicy, NwcMethod,
    PublicKey, UnixTimestamp,
};

const CLIENT_PUBLIC_KEY_HEX_LENGTH: usize = 64;

/// A stable, non-sensitive failure produced while parsing an NWA request.
///
/// Variants never contain attacker-provided input and are safe to record in
/// diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NwaError {
    /// The encoded request exceeded the configured bound.
    RequestTooLarge,
    /// The input was not a valid URL.
    InvalidUrl,
    /// The request used an unsupported wallet-auth scheme.
    UnsupportedScheme,
    /// The URI authority was not a 32-byte hexadecimal client public key.
    InvalidClientPublicKey,
    /// A single-value parameter appeared more than once.
    DuplicateParameter,
    /// The request selected an unsupported NWA version.
    UnsupportedVersion,
    /// The request did not use the client-created-secret mode.
    UnsupportedSecretMode,
    /// The request did not use relay-based completion.
    UnsupportedResponseMode,
    /// The authorization URI contained a field that may carry secret material.
    SecretMaterialPresent,
    /// The request omitted its relay list.
    MissingRelay,
    /// The request included more relays than policy allows.
    TooManyRelays,
    /// A relay URL was malformed or used an insecure scheme.
    InvalidRelay,
    /// An expiration timestamp was malformed.
    InvalidExpiration,
    /// The request has expired.
    Expired,
    /// The request expiration exceeds the configured lifetime.
    LifetimeTooLong,
    /// The requested budget was malformed or not a whole number of satoshis.
    InvalidBudget,
    /// The requested budget exceeds wallet policy.
    BudgetTooHigh,
    /// The budget renewal value was not recognized.
    InvalidBudgetInterval,
    /// The request named a method the engine does not understand.
    UnknownMethod,
    /// The callback was malformed or was not a safe HTTPS app-link target.
    InvalidCallback,
    /// A callback was supplied without a correlation state value.
    MissingCallbackState,
    /// The callback correlation state failed length or character checks.
    InvalidCallbackState,
    /// The operating system could not provide random request-id bytes.
    RandomnessUnavailable,
    /// Callback construction failed after a request had been validated.
    CallbackConstructionFailed,
}

impl fmt::Display for NwaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RequestTooLarge => "NWA request is too large",
            Self::InvalidUrl => "NWA request is not a valid URL",
            Self::UnsupportedScheme => "NWA wallet-auth scheme is not supported",
            Self::InvalidClientPublicKey => "NWA client public key is invalid",
            Self::DuplicateParameter => "NWA request contains a duplicate parameter",
            Self::UnsupportedVersion => "NWA version is not supported",
            Self::UnsupportedSecretMode => "NWA secret mode is not supported",
            Self::UnsupportedResponseMode => "NWA response mode is not supported",
            Self::SecretMaterialPresent => "NWA request contains forbidden secret material",
            Self::MissingRelay => "NWA request does not include a relay",
            Self::TooManyRelays => "NWA request contains too many relays",
            Self::InvalidRelay => "NWA relay is invalid or insecure",
            Self::InvalidExpiration => "NWA expiration is invalid",
            Self::Expired => "NWA request has expired",
            Self::LifetimeTooLong => "NWA request lifetime is too long",
            Self::InvalidBudget => "NWA budget is invalid",
            Self::BudgetTooHigh => "NWA budget exceeds wallet policy",
            Self::InvalidBudgetInterval => "NWA budget interval is invalid",
            Self::UnknownMethod => "NWA request contains an unsupported method",
            Self::InvalidCallback => "NWA callback is invalid or unverified",
            Self::MissingCallbackState => "NWA callback requires correlation state",
            Self::InvalidCallbackState => "NWA callback state is invalid",
            Self::RandomnessUnavailable => "secure randomness is unavailable",
            Self::CallbackConstructionFailed => "NWA callback could not be constructed",
        })
    }
}

impl std::error::Error for NwaError {}

/// A cryptographically random identifier binding approval to the displayed NWA
/// request.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NwaRequestId([u8; 16]);

impl NwaRequestId {
    /// Generates a request identifier from the operating system RNG.
    pub fn generate() -> Result<Self, NwaError> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| NwaError::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }

    /// Creates an identifier from 128 bits supplied by a trusted host or test.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Encodes the identifier as lowercase hexadecimal.
    #[must_use]
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }
}

impl fmt::Debug for NwaRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NwaRequestId([redacted])")
    }
}

/// Bounds NWA parsing and the authority a request may ask the user to grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NwaParsePolicy {
    maximum_request_bytes: usize,
    maximum_relays: usize,
    maximum_display_name_chars: usize,
    maximum_lifetime: Duration,
    maximum_budget_sat: u64,
}

impl NwaParsePolicy {
    /// Creates explicit NWA parsing limits.
    #[must_use]
    pub const fn new(
        maximum_request_bytes: usize,
        maximum_relays: usize,
        maximum_display_name_chars: usize,
        maximum_lifetime: Duration,
        maximum_budget_sat: u64,
    ) -> Self {
        Self {
            maximum_request_bytes,
            maximum_relays,
            maximum_display_name_chars,
            maximum_lifetime,
            maximum_budget_sat,
        }
    }

    /// Returns the maximum encoded request size.
    #[must_use]
    pub const fn maximum_request_bytes(&self) -> usize {
        self.maximum_request_bytes
    }

    /// Returns the maximum accepted relay count.
    #[must_use]
    pub const fn maximum_relays(&self) -> usize {
        self.maximum_relays
    }

    /// Returns the maximum sanitized requester-name length.
    #[must_use]
    pub const fn maximum_display_name_chars(&self) -> usize {
        self.maximum_display_name_chars
    }

    /// Returns the maximum accepted request lifetime.
    #[must_use]
    pub const fn maximum_lifetime(&self) -> Duration {
        self.maximum_lifetime
    }

    /// Returns the maximum budget a request may ask the user to approve.
    #[must_use]
    pub const fn maximum_budget_sat(&self) -> u64 {
        self.maximum_budget_sat
    }
}

impl Default for NwaParsePolicy {
    fn default() -> Self {
        Self::new(
            8 * 1024,
            2,
            80,
            Duration::from_secs(30 * 24 * 60 * 60),
            1_000_000,
        )
    }
}

/// A validated HTTPS mobile callback and its correlation value.
#[derive(Clone, Eq, PartialEq)]
pub struct NwaCallback {
    url: Url,
    state: String,
}

impl NwaCallback {
    /// Returns a display-safe callback target without query or fragment values.
    #[must_use]
    pub fn target_description(&self) -> String {
        let host = self.url.host_str().unwrap_or_default();
        format!("https://{host}{}", self.url.path())
    }

    /// Returns the validated HTTPS callback URL without result fields.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Returns the opaque correlation state.
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Builds the approved callback with public completion metadata in the URL
    /// fragment.
    pub fn approved_url(
        &self,
        wallet_service_pubkey: &PublicKey,
        relays: &[String],
        lud16: Option<&str>,
    ) -> Result<Url, NwaError> {
        let mut fields = vec![
            ("state", self.state.clone()),
            ("status", "approved".to_string()),
            ("wallet_pubkey", wallet_service_pubkey.to_hex()),
        ];
        fields.extend(relays.iter().cloned().map(|relay| ("relay", relay)));
        if let Some(lud16) = lud16.filter(|value| !value.trim().is_empty()) {
            fields.push(("lud16", lud16.to_string()));
        }
        self.url_with_fragment(&fields)
    }

    /// Builds a cancellation callback. Native code should open it only through
    /// a verified app-link-only API and an explicit wallet policy.
    pub fn cancelled_url(&self) -> Result<Url, NwaError> {
        self.url_with_fragment(&[
            ("state", self.state.clone()),
            ("status", "cancelled".to_string()),
        ])
    }

    /// Builds an error callback containing a stable public error code.
    pub fn error_url(&self, code: &str) -> Result<Url, NwaError> {
        self.url_with_fragment(&[
            ("state", self.state.clone()),
            ("status", "error".to_string()),
            ("error", sanitize_callback_error(code)),
        ])
    }

    fn url_with_fragment(&self, fields: &[(&str, String)]) -> Result<Url, NwaError> {
        let mut callback = self.url.clone();
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        for (name, value) in fields {
            serializer.append_pair(name, value);
        }
        callback.set_fragment(Some(&serializer.finish()));
        Ok(callback)
    }
}

impl fmt::Debug for NwaCallback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NwaCallback")
            .field("target", &self.target_description())
            .field("state", &"[redacted]")
            .finish()
    }
}

/// A validated Nostr Wallet Auth request ready for explicit user review.
#[derive(Clone, Eq, PartialEq)]
pub struct NwaRequest {
    id: NwaRequestId,
    client_pubkey: PublicKey,
    display_name: String,
    icon_url: Option<Url>,
    relays: Vec<String>,
    requested_policy: ConnectionPolicy,
    expires_at: Option<UnixTimestamp>,
    callback: Option<NwaCallback>,
}

impl NwaRequest {
    /// Parses and validates an NWA URI using a fresh random approval identifier.
    pub fn parse(
        input: &str,
        now: UnixTimestamp,
        policy: &NwaParsePolicy,
    ) -> Result<Self, NwaError> {
        let id = NwaRequestId::generate()?;
        Self::parse_with_id(input, now, policy, id)
    }

    fn parse_with_id(
        input: &str,
        now: UnixTimestamp,
        policy: &NwaParsePolicy,
        id: NwaRequestId,
    ) -> Result<Self, NwaError> {
        if input.len() > policy.maximum_request_bytes || policy.maximum_request_bytes == 0 {
            return Err(NwaError::RequestTooLarge);
        }
        let url = Url::parse(input).map_err(|_| NwaError::InvalidUrl)?;
        if !matches!(
            url.scheme(),
            "nostr+walletauth" | "nostr+walletauth+rebelwallet"
        ) {
            return Err(NwaError::UnsupportedScheme);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(NwaError::SecretMaterialPresent);
        }
        if url.fragment().is_some() {
            return Err(NwaError::SecretMaterialPresent);
        }

        let client_hex = url.host_str().ok_or(NwaError::InvalidClientPublicKey)?;
        if client_hex.len() != CLIENT_PUBLIC_KEY_HEX_LENGTH {
            return Err(NwaError::InvalidClientPublicKey);
        }
        let client_pubkey =
            PublicKey::from_hex(client_hex).map_err(|_| NwaError::InvalidClientPublicKey)?;

        let query = NwaQuery::parse(&url)?;
        if query.value("version").unwrap_or("1") != "1" {
            return Err(NwaError::UnsupportedVersion);
        }
        if query.value("pubkey").is_some() {
            return Err(NwaError::InvalidClientPublicKey);
        }
        if !query
            .value("secret_mode")
            .unwrap_or("client")
            .eq_ignore_ascii_case("client")
        {
            return Err(NwaError::UnsupportedSecretMode);
        }
        if !query
            .value("response_mode")
            .unwrap_or("relay")
            .eq_ignore_ascii_case("relay")
        {
            return Err(NwaError::UnsupportedResponseMode);
        }
        if ["secret", "nwc_uri", "value"]
            .iter()
            .any(|name| query.value(name).is_some())
        {
            return Err(NwaError::SecretMaterialPresent);
        }

        let relays = parse_relays(&query, policy)?;
        let expires_at = parse_expiration(&query, now, policy)?;
        let budget = parse_budget(&query, policy)?;
        let methods = parse_methods(&query)?;
        if methods.contains(&NwcMethod::PayInvoice)
            && budget.limit_sat() <= maximum_mobile_fee_sat(budget.limit_sat())
        {
            return Err(NwaError::InvalidBudget);
        }
        let requested_policy = ConnectionPolicy::new(methods, budget);
        let callback = parse_callback(&query)?;

        let raw_name = query
            .value("name")
            .or_else(|| query.value("appname"))
            .unwrap_or("External App");
        let display_name = sanitize_display_text(raw_name, policy.maximum_display_name_chars);
        let display_name = if display_name.is_empty() {
            "External App".to_string()
        } else {
            display_name
        };
        let icon_url = parse_icon_url(query.value("icon"));

        Ok(Self {
            id,
            client_pubkey,
            display_name,
            icon_url,
            relays,
            requested_policy,
            expires_at,
            callback,
        })
    }

    /// Returns the random identity that approval and async completion must echo.
    #[must_use]
    pub const fn id(&self) -> NwaRequestId {
        self.id
    }

    /// Returns the requesting client's public key.
    #[must_use]
    pub const fn client_pubkey(&self) -> &PublicKey {
        &self.client_pubkey
    }

    /// Returns sanitized, unverified requester display text.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Returns a validated HTTPS icon URL, when present.
    #[must_use]
    pub fn icon_url(&self) -> Option<&Url> {
        self.icon_url.as_ref()
    }

    /// Returns the requested secure relays.
    #[must_use]
    pub fn relays(&self) -> &[String] {
        &self.relays
    }

    /// Returns the exact requested permission and budget policy.
    #[must_use]
    pub const fn requested_policy(&self) -> &ConnectionPolicy {
        &self.requested_policy
    }

    /// Returns the validated expiration timestamp.
    #[must_use]
    pub const fn expires_at(&self) -> Option<UnixTimestamp> {
        self.expires_at
    }

    /// Returns the optional validated but unverified callback description.
    ///
    /// Native hosts must independently verify any claimed app-link association.
    #[must_use]
    pub const fn callback(&self) -> Option<&NwaCallback> {
        self.callback.as_ref()
    }
}

impl fmt::Debug for NwaRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NwaRequest")
            .field("id", &self.id)
            .field("client_pubkey", &self.client_pubkey)
            .field("display_name", &"[unverified]")
            .field("relay_count", &self.relays.len())
            .field("requested_policy", &self.requested_policy)
            .field("expires_at", &self.expires_at)
            .field("callback", &self.callback)
            .finish()
    }
}

struct NwaQuery {
    values: HashMap<String, Vec<String>>,
}

impl NwaQuery {
    fn parse(url: &Url) -> Result<Self, NwaError> {
        let mut values = HashMap::<String, Vec<String>>::new();
        for (name, value) in url.query_pairs() {
            values
                .entry(name.into_owned())
                .or_default()
                .push(value.into_owned());
        }
        if values
            .iter()
            .any(|(name, values)| name != "relay" && values.len() > 1)
        {
            return Err(NwaError::DuplicateParameter);
        }
        Ok(Self { values })
    }

    fn value(&self, name: &str) -> Option<&str> {
        self.values
            .get(name)
            .and_then(|values| values.first())
            .map(String::as_str)
    }

    fn values(&self, name: &str) -> &[String] {
        self.values.get(name).map(Vec::as_slice).unwrap_or_default()
    }
}

fn parse_relays(query: &NwaQuery, policy: &NwaParsePolicy) -> Result<Vec<String>, NwaError> {
    let values = query.values("relay");
    if values.is_empty() {
        return Err(NwaError::MissingRelay);
    }
    if values.len() > policy.maximum_relays || policy.maximum_relays == 0 {
        return Err(NwaError::TooManyRelays);
    }

    let mut relays = Vec::with_capacity(values.len());
    let mut seen = HashSet::new();
    for value in values {
        let mut relay = Url::parse(value).map_err(|_| NwaError::InvalidRelay)?;
        if relay.scheme() != "wss"
            || relay.host_str().is_none()
            || !relay.username().is_empty()
            || relay.password().is_some()
            || relay.fragment().is_some()
        {
            return Err(NwaError::InvalidRelay);
        }
        relay.set_fragment(None);
        let normalized = relay.to_string();
        if seen.insert(normalized.clone()) {
            relays.push(normalized);
        }
    }
    if relays.is_empty() {
        return Err(NwaError::MissingRelay);
    }
    Ok(relays)
}

fn parse_expiration(
    query: &NwaQuery,
    now: UnixTimestamp,
    policy: &NwaParsePolicy,
) -> Result<Option<UnixTimestamp>, NwaError> {
    let Some(raw) = query.value("expires_at") else {
        return Ok(None);
    };
    let expires_at = raw
        .parse::<u64>()
        .map_err(|_| NwaError::InvalidExpiration)?;
    if expires_at <= now.as_secs() {
        return Err(NwaError::Expired);
    }
    if expires_at - now.as_secs() > policy.maximum_lifetime.as_secs() {
        return Err(NwaError::LifetimeTooLong);
    }
    Ok(Some(UnixTimestamp::from_secs(expires_at)))
}

fn parse_budget(query: &NwaQuery, policy: &NwaParsePolicy) -> Result<BudgetPolicy, NwaError> {
    let budget_sat = match query.value("max_amount") {
        Some(raw) => {
            let amount_msat = raw.parse::<u64>().map_err(|_| NwaError::InvalidBudget)?;
            if amount_msat % 1_000 != 0 {
                return Err(NwaError::InvalidBudget);
            }
            amount_msat / 1_000
        }
        None => 0,
    };
    if budget_sat > policy.maximum_budget_sat {
        return Err(NwaError::BudgetTooHigh);
    }
    let interval = match query.value("budget_renewal") {
        None | Some("") | Some("never") => BudgetInterval::Never,
        Some("hourly") => BudgetInterval::Hourly,
        Some("daily") => BudgetInterval::Daily,
        Some("weekly") => BudgetInterval::Weekly,
        Some("monthly") => BudgetInterval::Monthly,
        Some("yearly") => BudgetInterval::Yearly,
        Some(_) => return Err(NwaError::InvalidBudgetInterval),
    };
    Ok(BudgetPolicy::new(
        budget_sat,
        interval,
        FeePolicy::CountTowardBudget {
            maximum_fee_sat: maximum_mobile_fee_sat(budget_sat),
        },
    ))
}

fn parse_methods(query: &NwaQuery) -> Result<Vec<NwcMethod>, NwaError> {
    let Some(raw) = query
        .value("request_methods")
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(vec![NwcMethod::GetInfo]);
    };
    let mut methods = Vec::new();
    for method in raw.split(|character: char| character.is_whitespace() || character == ',') {
        if method.is_empty() {
            continue;
        }
        let method = match method {
            "get_info" => NwcMethod::GetInfo,
            "get_balance" => NwcMethod::GetBalance,
            "make_invoice" => NwcMethod::MakeInvoice,
            "pay_invoice" => NwcMethod::PayInvoice,
            "lookup_invoice" => NwcMethod::LookupInvoice,
            "list_transactions" => NwcMethod::ListTransactions,
            _ => return Err(NwaError::UnknownMethod),
        };
        if !methods.contains(&method) {
            methods.push(method);
        }
    }
    if methods.is_empty() {
        methods.push(NwcMethod::GetInfo);
    }
    Ok(methods)
}

fn parse_callback(query: &NwaQuery) -> Result<Option<NwaCallback>, NwaError> {
    let Some(raw_url) = query.value("return_to") else {
        if query.value("state").is_some() {
            return Err(NwaError::InvalidCallback);
        }
        return Ok(None);
    };
    if raw_url.len() > 2_048 {
        return Err(NwaError::InvalidCallback);
    }
    let state = query.value("state").ok_or(NwaError::MissingCallbackState)?;
    if state.len() < 32
        || state.len() > 256
        || state.chars().any(|character| character.is_control())
    {
        return Err(NwaError::InvalidCallbackState);
    }
    let url = Url::parse(raw_url).map_err(|_| NwaError::InvalidCallback)?;
    let host = url.host_str().ok_or(NwaError::InvalidCallback)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port().is_some_and(|port| port != 443)
        || url.path().is_empty()
        || !is_public_domain(host)
    {
        return Err(NwaError::InvalidCallback);
    }
    Ok(Some(NwaCallback {
        url,
        state: state.to_string(),
    }))
}

fn parse_icon_url(raw: Option<&str>) -> Option<Url> {
    let raw = raw?.trim();
    if raw.is_empty() || raw.len() > 2_048 {
        return None;
    }
    let url = Url::parse(raw).ok()?;
    let host = url.host_str()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port().is_some_and(|port| port != 443)
        || !is_public_domain(host)
    {
        return None;
    }
    Some(url)
}

pub(crate) fn validated_public_icon_url(raw: &str) -> Option<String> {
    parse_icon_url(Some(raw)).map(Into::into)
}

fn is_public_domain(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    if !host.contains('.') || host == "localhost" || host.ends_with(".local") || host.contains(':')
    {
        return false;
    }
    let parts = host.split('.').collect::<Vec<_>>();
    !(parts.len() == 4 && parts.iter().all(|part| part.parse::<u8>().is_ok()))
}

fn sanitize_display_text(value: &str, maximum_chars: usize) -> String {
    let mut result = String::new();
    let mut pending_space = false;
    for character in value.chars() {
        if character.is_control() || is_bidi_formatting(character) {
            continue;
        }
        if character.is_whitespace() {
            pending_space = !result.is_empty();
            continue;
        }
        if result.chars().count() >= maximum_chars {
            break;
        }
        if pending_space {
            result.push(' ');
            pending_space = false;
        }
        result.push(character);
    }
    result
}

const fn is_bidi_formatting(character: char) -> bool {
    matches!(
        character,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

fn sanitize_callback_error(code: &str) -> String {
    let sanitized = code
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        .take(64)
        .map(char::from)
        .collect::<String>();
    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: &str = "687dd8ece211539364549b1f32c63eceec1e0661009ba65cf8ff2e73ba000746";
    const WALLET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const STATE: &str = "8d2a91f43bc941778a4b9985274c0a54";

    fn parse(input: &str) -> Result<NwaRequest, NwaError> {
        NwaRequest::parse_with_id(
            input,
            UnixTimestamp::from_secs(1_000),
            &NwaParsePolicy::default(),
            NwaRequestId::from_bytes([7; 16]),
        )
    }

    #[test]
    fn omitted_methods_and_budget_are_read_only_and_zero_spend() {
        let request = parse(&format!(
            "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Frelay.example.com"
        ))
        .expect("valid request");

        assert!(request.requested_policy().allows(NwcMethod::GetInfo));
        assert!(!request.requested_policy().allows(NwcMethod::PayInvoice));
        assert_eq!(request.requested_policy().budget().limit_sat(), 0);
    }

    #[test]
    fn parses_explicit_methods_budget_relays_and_expiration() {
        let request = parse(&format!(
            "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Frelay.example.com&relay=wss%3A%2F%2Frelay2.example.com&request_methods=get_info%20pay_invoice&max_amount=500000000&budget_renewal=monthly&expires_at=2000"
        ))
        .expect("valid request");

        assert_eq!(request.relays().len(), 2);
        assert!(request.requested_policy().allows(NwcMethod::PayInvoice));
        assert_eq!(request.requested_policy().budget().limit_sat(), 500_000);
        assert_eq!(
            request.requested_policy().budget().fee_policy(),
            FeePolicy::CountTowardBudget {
                maximum_fee_sat: 1_000,
            }
        );
        assert_eq!(request.expires_at(), Some(UnixTimestamp::from_secs(2_000)));
    }

    #[test]
    fn rejects_duplicate_single_value_parameters() {
        let error = parse(&format!(
            "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Frelay.example.com&max_amount=1000&max_amount=2000"
        ))
        .expect_err("duplicate budget");
        assert_eq!(error, NwaError::DuplicateParameter);
    }

    #[test]
    fn requires_client_secret_and_relay_response_modes() {
        assert_eq!(
            parse(&format!(
                "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Frelay.example.com&secret_mode=wallet"
            )),
            Err(NwaError::UnsupportedSecretMode)
        );
        assert_eq!(
            parse(&format!(
                "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Frelay.example.com&response_mode=callback"
            )),
            Err(NwaError::UnsupportedResponseMode)
        );
    }

    #[test]
    fn rejects_secret_material_in_authorization_uri() {
        for parameter in ["secret", "nwc_uri", "value"] {
            assert_eq!(
                parse(&format!(
                    "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Frelay.example.com&{parameter}=private"
                )),
                Err(NwaError::SecretMaterialPresent)
            );
        }
        assert_eq!(
            parse(&format!(
                "nostr+walletauth://leaked-secret@{CLIENT}?relay=wss%3A%2F%2Frelay.example.com"
            )),
            Err(NwaError::SecretMaterialPresent)
        );
        assert_eq!(
            parse(&format!(
                "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Frelay.example.com#secret=private"
            )),
            Err(NwaError::SecretMaterialPresent)
        );
    }

    #[test]
    fn rejects_insecure_and_excess_relays_instead_of_truncating() {
        assert_eq!(
            parse(&format!(
                "nostr+walletauth://{CLIENT}?relay=ws%3A%2F%2Frelay.example.com"
            )),
            Err(NwaError::InvalidRelay)
        );
        assert_eq!(
            parse(&format!(
                "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Fa.example.com&relay=wss%3A%2F%2Fb.example.com&relay=wss%3A%2F%2Fc.example.com"
            )),
            Err(NwaError::TooManyRelays)
        );
    }

    #[test]
    fn preserves_meaningful_trailing_slashes_on_relay_paths() {
        let request = parse(&format!(
            "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Frelay.example.com%2Fnwc%2F"
        ))
        .expect("valid relay path");

        assert_eq!(request.relays(), ["wss://relay.example.com/nwc/"]);
    }

    #[test]
    fn rejects_fractional_satoshi_and_excessive_budget() {
        assert_eq!(
            parse(&format!(
                "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Frelay.example.com&max_amount=1001"
            )),
            Err(NwaError::InvalidBudget)
        );
        assert_eq!(
            parse(&format!(
                "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Frelay.example.com&max_amount=1000001000"
            )),
            Err(NwaError::BudgetTooHigh)
        );
        assert_eq!(
            parse(&format!(
                "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Frelay.example.com&max_amount=10000&request_methods=pay_invoice"
            )),
            Err(NwaError::InvalidBudget)
        );
        assert!(parse(&format!(
            "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Frelay.example.com&max_amount=11000&request_methods=pay_invoice"
        ))
        .is_ok());
    }

    #[test]
    fn callback_requires_https_public_domain_and_correlation_state() {
        assert_eq!(
            parse(&format!(
                "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Frelay.example.com&return_to=wallet%3A%2F%2Fcallback&state={STATE}"
            )),
            Err(NwaError::InvalidCallback)
        );
        assert_eq!(
            parse(&format!(
                "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Frelay.example.com&return_to=https%3A%2F%2Fapp.example%2Fnwa"
            )),
            Err(NwaError::MissingCallbackState)
        );
    }

    #[test]
    fn callback_keeps_public_results_in_fragment() {
        let request = parse(&format!(
            "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Frelay.example.com&return_to=https%3A%2F%2Fapp.example%2Fnwa%2Fcallback&state={STATE}"
        ))
        .expect("valid callback request");
        let callback = request.callback().expect("callback");
        let url = callback
            .approved_url(
                &PublicKey::from_hex(WALLET).expect("wallet key"),
                request.relays(),
                Some("user@example.com"),
            )
            .expect("callback URL");

        assert!(url.query().is_none());
        let fragment = url.fragment().expect("fragment");
        assert!(fragment.contains("status=approved"));
        assert!(fragment.contains("wallet_pubkey="));
        assert!(!url.as_str().contains("secret="));
    }

    #[test]
    fn requester_display_text_removes_control_and_bidi_characters() {
        let request = parse(&format!(
            "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Frelay.example.com&name=Trusted%E2%80%AEevil%0AApp"
        ))
        .expect("valid request");

        assert_eq!(request.display_name(), "TrustedevilApp");
    }

    #[test]
    fn debug_output_redacts_requester_and_transport_metadata() {
        let request = parse(&format!(
            "nostr+walletauth://{CLIENT}?relay=wss%3A%2F%2Fprivate.example.com&name=PrivateName&return_to=https%3A%2F%2Fapp.example%2Fnwa&state={STATE}"
        ))
        .expect("valid request");
        let debug = format!("{request:?}");

        assert!(!debug.contains(CLIENT));
        assert!(!debug.contains("PrivateName"));
        assert!(!debug.contains("private.example"));
        assert!(!debug.contains(STATE));
    }
}
