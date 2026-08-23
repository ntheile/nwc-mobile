//! Secure HTTPS wake-registration transport for `nwc-mobile` hosts.
//!
//! This crate owns endpoint construction, payload serialization, NIP-98 request
//! authorization, redirect rejection, provider response classification, and the
//! bounded durable registration worker pass.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use nwc_mobile::{
    ApplicationIconUrl, Clock, EventId, HostError, HostErrorKind, HostFuture, LedgerError,
    NeverCancelled, Nip98Authorization, Nip98SigningKey, OperationBudget, OperationContext,
    SecureWakeServerUrl, SystemClock, WakeLedger, WakeRegistrationChange, WakeRegistrationError,
    WakeRegistrationTransport, WakeRegistrationWorker, WakeRegistrationWorkerError,
    MAX_APPLICATION_ICON_BYTES,
};
use nwc_mobile_tokio::{resolve_socket_addresses, run_with_context};
use serde::Serialize;

const REGISTRATION_BATCH_SIZE: usize = 20;
const REGISTRATION_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONFIG_VALUE_BYTES: usize = 2_048;
const APPLICATION_ICON_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_SETTLEMENT_MONITOR_DURATION: Duration = Duration::from_secs(2 * 60 * 60);

/// Downloads one validated application icon with redirects and oversized bodies rejected.
pub async fn download_application_icon(
    remote_url: &ApplicationIconUrl,
) -> Result<Vec<u8>, ApplicationIconDownloadError> {
    let parsed_url = reqwest::Url::parse(remote_url.as_str())
        .map_err(|_| ApplicationIconDownloadError::RejectedResponse)?;
    let host = parsed_url
        .host_str()
        .ok_or(ApplicationIconDownloadError::RejectedResponse)?;
    let port = parsed_url
        .port_or_known_default()
        .ok_or(ApplicationIconDownloadError::RejectedResponse)?;
    let addresses = resolve_socket_addresses(host.to_owned(), port)
        .await
        .map_err(|_| ApplicationIconDownloadError::Unavailable)?;
    let mut public_addresses = addresses
        .into_iter()
        .filter(|address| is_public_socket_address(*address))
        .collect::<Vec<_>>();
    public_addresses.sort_unstable();
    public_addresses.dedup();
    if public_addresses.is_empty() {
        return Err(ApplicationIconDownloadError::PrivateAddress);
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(APPLICATION_ICON_TIMEOUT)
        .resolve_to_addrs(host, &public_addresses)
        .build()
        .map_err(|_| ApplicationIconDownloadError::ClientUnavailable)?;
    let mut response = client
        .get(remote_url.as_str())
        .send()
        .await
        .map_err(classify_icon_request_error)?;
    if !response.status().is_success() {
        return Err(ApplicationIconDownloadError::RejectedResponse);
    }
    let is_image = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().to_ascii_lowercase().starts_with("image/"));
    if !is_image {
        return Err(ApplicationIconDownloadError::RejectedResponse);
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_APPLICATION_ICON_BYTES as u64)
    {
        return Err(ApplicationIconDownloadError::TooLarge);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(classify_icon_request_error)?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_APPLICATION_ICON_BYTES {
            return Err(ApplicationIconDownloadError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Err(ApplicationIconDownloadError::RejectedResponse);
    }
    Ok(bytes)
}

/// Stable application icon transport failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ApplicationIconDownloadError {
    /// The hardened HTTP client could not be constructed.
    ClientUnavailable,
    /// The request timed out.
    TimedOut,
    /// The network is temporarily unavailable.
    Unavailable,
    /// Every resolved target was private or otherwise non-routable.
    PrivateAddress,
    /// The server rejected the request or returned a non-image response.
    RejectedResponse,
    /// The encoded response exceeded the shared byte bound.
    TooLarge,
}

impl fmt::Display for ApplicationIconDownloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ClientUnavailable => "application icon HTTP client is unavailable",
            Self::TimedOut => "application icon request timed out",
            Self::Unavailable => "application icon request is unavailable",
            Self::PrivateAddress => "application icon address was rejected",
            Self::RejectedResponse => "application icon response was rejected",
            Self::TooLarge => "application icon response is too large",
        })
    }
}

impl std::error::Error for ApplicationIconDownloadError {}

fn classify_icon_request_error(error: reqwest::Error) -> ApplicationIconDownloadError {
    if error.is_timeout() {
        ApplicationIconDownloadError::TimedOut
    } else {
        ApplicationIconDownloadError::Unavailable
    }
}

fn is_public_socket_address(address: SocketAddr) -> bool {
    match address.ip() {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [first, second, third, _] = address.octets();
    !address.is_private()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_broadcast()
        && !address.is_documentation()
        && !address.is_multicast()
        && !address.is_unspecified()
        && first != 0
        && first < 240
        && !(first == 100 && (64..=127).contains(&second))
        && !(first == 192 && second == 0 && third == 0)
        && !(first == 198 && matches!(second, 18 | 19))
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    let is_global_unicast = segments[0] & 0xe000 == 0x2000;
    let is_documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let is_benchmarking = segments[0] == 0x2001 && segments[1] == 0x0002;
    let is_orchid = segments[0] == 0x2001 && matches!(segments[1] & 0xfff0, 0x0010 | 0x0020);
    let is_additional_documentation = segments[0] == 0x3fff && segments[1] & 0xf000 == 0;
    is_global_unicast
        && !is_documentation
        && !is_benchmarking
        && !is_orchid
        && !is_additional_documentation
}

/// Native APNs values used to configure the shared registration transport.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct ApnsWakeRegistrationConfig {
    server_url: Option<String>,
    push_token: Option<String>,
    app_id: String,
    environment: String,
    install_id: String,
    enabled: bool,
}

impl ApnsWakeRegistrationConfig {
    /// Creates configuration from values supplied by the native APNs bridge.
    #[must_use]
    pub fn new(
        server_url: Option<String>,
        push_token: Option<String>,
        app_id: String,
        environment: String,
        install_id: String,
        enabled: bool,
    ) -> Self {
        Self {
            server_url,
            push_token,
            app_id,
            environment,
            install_id,
            enabled,
        }
    }

    /// Validates and bounds every provider value before network use.
    pub fn ready(&self) -> Result<ReadyApnsWakeRegistrationConfig, WakeHttpConfigError> {
        let server_url = required_bounded(self.server_url.as_deref())?;
        let push_token = required_bounded(self.push_token.as_deref())?;
        let app_id = required_bounded(Some(&self.app_id))?;
        let environment = required_bounded(Some(&self.environment))?;
        let install_id = required_bounded(Some(&self.install_id))?;
        if !matches!(environment, "sandbox" | "production") {
            return Err(WakeHttpConfigError::InvalidEnvironment);
        }
        Ok(ReadyApnsWakeRegistrationConfig {
            server_url: SecureWakeServerUrl::parse(server_url)
                .map_err(|_| WakeHttpConfigError::InsecureServerUrl)?,
            push_token: push_token.to_owned(),
            app_id: app_id.to_owned(),
            environment: environment.to_owned(),
            install_id: install_id.to_owned(),
            enabled: self.enabled,
        })
    }
}

impl fmt::Debug for ApnsWakeRegistrationConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApnsWakeRegistrationConfig")
            .field("configured", &self.server_url.is_some())
            .field("has_push_token", &self.push_token.is_some())
            .finish_non_exhaustive()
    }
}

/// Validated APNs registration configuration safe to pass to the transport.
#[derive(Clone)]
pub struct ReadyApnsWakeRegistrationConfig {
    server_url: SecureWakeServerUrl,
    push_token: String,
    app_id: String,
    environment: String,
    install_id: String,
    enabled: bool,
}

impl ReadyApnsWakeRegistrationConfig {
    /// Returns whether active connections should request push delivery.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }
}

impl fmt::Debug for ReadyApnsWakeRegistrationConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadyApnsWakeRegistrationConfig")
            .field("server_url", &self.server_url)
            .finish_non_exhaustive()
    }
}

/// Validated public routing values used to schedule invoice settlement checks.
#[derive(Clone, Eq, PartialEq)]
pub struct InvoiceSettlementMonitorConfig {
    server_url: SecureWakeServerUrl,
    install_id: String,
}

impl InvoiceSettlementMonitorConfig {
    /// Validates the wake-server URL and stable native installation identifier.
    pub fn new(
        server_url: Option<String>,
        install_id: String,
    ) -> Result<Self, WakeHttpConfigError> {
        let server_url = required_bounded(server_url.as_deref())?;
        let install_id = required_bounded(Some(&install_id))?;
        Ok(Self {
            server_url: SecureWakeServerUrl::parse(server_url)
                .map_err(|_| WakeHttpConfigError::InsecureServerUrl)?,
            install_id: install_id.to_owned(),
        })
    }
}

impl fmt::Debug for InvoiceSettlementMonitorConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvoiceSettlementMonitorConfig")
            .field("server_url", &self.server_url)
            .finish_non_exhaustive()
    }
}

/// A stable, non-sensitive configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WakeHttpConfigError {
    /// A required provider value is absent or blank.
    MissingValue,
    /// A provider value exceeds the conservative input bound.
    ValueTooLong,
    /// The wake server is not a secure HTTPS URL.
    InsecureServerUrl,
    /// The APNs environment is neither sandbox nor production.
    InvalidEnvironment,
}

impl fmt::Display for WakeHttpConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingValue => "wake registration configuration is incomplete",
            Self::ValueTooLong => "wake registration configuration is too long",
            Self::InsecureServerUrl => "wake registration server must use HTTPS",
            Self::InvalidEnvironment => "APNs environment is invalid",
        })
    }
}

impl std::error::Error for WakeHttpConfigError {}

fn required_bounded(value: Option<&str>) -> Result<&str, WakeHttpConfigError> {
    match value.filter(|value| !value.trim().is_empty()) {
        Some(value) if value.len() <= MAX_CONFIG_VALUE_BYTES => Ok(value),
        Some(_) => Err(WakeHttpConfigError::ValueTooLong),
        None => Err(WakeHttpConfigError::MissingValue),
    }
}

/// Non-sensitive aggregate results for one durable registration pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationPass {
    applied: usize,
    deferred: usize,
    next_attempt_at: Option<u64>,
}

impl RegistrationPass {
    /// Returns successfully acknowledged provider changes.
    #[must_use]
    pub const fn applied(self) -> usize {
        self.applied
    }

    /// Returns provider changes durably deferred for retry.
    #[must_use]
    pub const fn deferred(self) -> usize {
        self.deferred
    }

    /// Returns the earliest durable retry timestamp, if work remains.
    #[must_use]
    pub const fn next_attempt_at(self) -> Option<u64> {
        self.next_attempt_at
    }
}

/// A stable, non-sensitive registration transport or worker failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WakeHttpRegistrationError {
    /// The hardened HTTP client could not be created.
    ClientUnavailable,
    /// The worker operation budget could not be constructed.
    InvalidBudget,
    /// Durable registration processing failed.
    Worker(WakeRegistrationWorkerError),
    /// The next durable registration timestamp could not be read.
    Outbox(WakeRegistrationError),
    /// Invoice settlement-monitor metadata could not be read.
    Ledger(LedgerError),
}

impl fmt::Display for WakeHttpRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ClientUnavailable => "wake registration HTTP client is unavailable",
            Self::InvalidBudget => "wake registration operation budget is invalid",
            Self::Worker(_) => "wake registration worker failed",
            Self::Outbox(_) => "wake registration outbox is unavailable",
            Self::Ledger(_) => "invoice settlement monitor storage is unavailable",
        })
    }
}

impl std::error::Error for WakeHttpRegistrationError {}

/// Runs one bounded APNs registration pass using secure HTTPS and NIP-98.
pub async fn run_registration_worker(
    ledger: &WakeLedger,
    config: ReadyApnsWakeRegistrationConfig,
    signing_key: Nip98SigningKey,
) -> Result<RegistrationPass, WakeHttpRegistrationError> {
    let transport = NwcPushTransport::new(config.clone(), signing_key)?;
    let worker = WakeRegistrationWorker::new(ledger, &transport, &config.server_url, &SystemClock);
    let budget = OperationBudget::new(REGISTRATION_OPERATION_TIMEOUT)
        .map_err(|_| WakeHttpRegistrationError::InvalidBudget)?;
    let report = worker
        .run(REGISTRATION_BATCH_SIZE, budget, &NeverCancelled)
        .await
        .map_err(WakeHttpRegistrationError::Worker)?;
    let next_attempt_at = ledger
        .next_wake_registration_at()
        .map_err(WakeHttpRegistrationError::Outbox)?
        .map(|timestamp| timestamp.as_secs());
    Ok(RegistrationPass {
        applied: report.applied(),
        deferred: report.deferred(),
        next_attempt_at,
    })
}

/// Enables or disables the server's opaque settlement checks for one NWC invoice.
///
/// The request deliberately excludes invoice, amount, memo, payment hash, and
/// settlement data. A completed notification disables the idempotent monitor.
pub async fn update_invoice_settlement_monitor(
    ledger: &WakeLedger,
    config: InvoiceSettlementMonitorConfig,
    event_id: &EventId,
    signing_key: Nip98SigningKey,
) -> Result<bool, WakeHttpRegistrationError> {
    let monitor = ledger
        .nwc_invoice_monitor(event_id)
        .map_err(WakeHttpRegistrationError::Ledger)?;
    let Some(monitor) = monitor else {
        return Ok(false);
    };
    if signing_key
        .public_key()
        .map_err(|_| WakeHttpRegistrationError::ClientUnavailable)?
        != *monitor.wallet_service_pubkey()
    {
        return Err(WakeHttpRegistrationError::ClientUnavailable);
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REGISTRATION_OPERATION_TIMEOUT)
        .build()
        .map_err(|_| WakeHttpRegistrationError::ClientUnavailable)?;
    let url = settlement_monitor_endpoint_url(&config.server_url)
        .map_err(|_| WakeHttpRegistrationError::ClientUnavailable)?;
    let endpoint = SecureWakeServerUrl::parse(url.as_str())
        .map_err(|_| WakeHttpRegistrationError::ClientUnavailable)?;
    let monitor_until = monitor.expires_at().as_secs().min(
        SystemClock
            .now()
            .as_secs()
            .saturating_add(MAX_SETTLEMENT_MONITOR_DURATION.as_secs()),
    );
    for relay in monitor.relays() {
        let payload = InvoiceSettlementMonitorPayload {
            id: &config.install_id,
            request_event_id: &monitor.request_event_id().to_hex(),
            client_pubkey: &monitor.client_pubkey().to_hex(),
            wallet_service_pubkey: &monitor.wallet_service_pubkey().to_hex(),
            relay: relay.as_str(),
            expires_at: monitor_until,
            enabled: !monitor.completed(),
        };
        let body = serde_json::to_vec(&payload)
            .map_err(|_| WakeHttpRegistrationError::ClientUnavailable)?;
        let auth = Nip98Authorization::for_registration_post(
            &endpoint,
            &body,
            &signing_key,
            SystemClock.now(),
        )
        .map_err(|_| WakeHttpRegistrationError::ClientUnavailable)?;
        let response = client
            .post(url.clone())
            .header(reqwest::header::AUTHORIZATION, auth.as_header_value())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| WakeHttpRegistrationError::ClientUnavailable)?;
        if !response.status().is_success() {
            return Err(WakeHttpRegistrationError::ClientUnavailable);
        }
    }
    Ok(true)
}

struct NwcPushTransport {
    client: reqwest::Client,
    config: ReadyApnsWakeRegistrationConfig,
    signing_key: Nip98SigningKey,
}

impl NwcPushTransport {
    fn new(
        config: ReadyApnsWakeRegistrationConfig,
        signing_key: Nip98SigningKey,
    ) -> Result<Self, WakeHttpRegistrationError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| WakeHttpRegistrationError::ClientUnavailable)?;
        Ok(Self {
            client,
            config,
            signing_key,
        })
    }

    async fn apply_change(
        &self,
        server_url: &SecureWakeServerUrl,
        change: &WakeRegistrationChange,
    ) -> Result<(), HostError> {
        let url = registration_endpoint_url(server_url)?;
        let endpoint = SecureWakeServerUrl::parse(url.as_str())
            .map_err(|_| HostError::new(HostErrorKind::Internal))?;
        let client_pubkey = change.client_pubkey().to_hex();
        let wallet_service_pubkey = change.wallet_service_pubkey().to_hex();
        let signing_pubkey = self
            .signing_key
            .public_key()
            .map_err(|_| HostError::new(HostErrorKind::Internal))?;
        if signing_pubkey != *change.wallet_service_pubkey() {
            return Err(HostError::new(HostErrorKind::Rejected));
        }
        for relay in change.relays() {
            let payload = RegisterNwcPushPayload {
                id: &self.config.install_id,
                connection_id: change.connection_id().as_str(),
                connection_revision: change.connection_revision().value(),
                push_service: "apns",
                push_token: &self.config.push_token,
                app_id: &self.config.app_id,
                environment: &self.config.environment,
                client_pubkey: &client_pubkey,
                wallet_service_pubkey: &wallet_service_pubkey,
                relay: relay.as_str(),
                name: "NWC connection",
                enabled: change.enabled(),
            };
            let body = serde_json::to_vec(&payload)
                .map_err(|_| HostError::new(HostErrorKind::Internal))?;
            let auth = Nip98Authorization::for_registration_post(
                &endpoint,
                &body,
                &self.signing_key,
                SystemClock.now(),
            )
            .map_err(|_| HostError::new(HostErrorKind::Internal))?;
            let response = self
                .client
                .post(url.clone())
                .header(reqwest::header::AUTHORIZATION, auth.as_header_value())
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body)
                .send()
                .await
                .map_err(classify_request_error)?;
            let status = response.status();
            if !status.is_success() {
                let kind = if status.is_server_error()
                    || status == reqwest::StatusCode::TOO_MANY_REQUESTS
                {
                    HostErrorKind::Unavailable
                } else {
                    HostErrorKind::Rejected
                };
                return Err(HostError::new(kind));
            }
        }
        Ok(())
    }
}

fn registration_endpoint_url(server_url: &SecureWakeServerUrl) -> Result<reqwest::Url, HostError> {
    let mut base_url = reqwest::Url::parse(server_url.as_str())
        .map_err(|_| HostError::new(HostErrorKind::Internal))?;
    if !base_url.path().ends_with('/') {
        let mut path = base_url.path().to_owned();
        path.push('/');
        base_url.set_path(&path);
    }
    base_url
        .join("register-nwc-push")
        .map_err(|_| HostError::new(HostErrorKind::Internal))
}

fn settlement_monitor_endpoint_url(
    server_url: &SecureWakeServerUrl,
) -> Result<reqwest::Url, HostError> {
    let mut base_url = reqwest::Url::parse(server_url.as_str())
        .map_err(|_| HostError::new(HostErrorKind::Internal))?;
    if !base_url.path().ends_with('/') {
        let mut path = base_url.path().to_owned();
        path.push('/');
        base_url.set_path(&path);
    }
    base_url
        .join("monitor-nwc-invoice")
        .map_err(|_| HostError::new(HostErrorKind::Internal))
}

impl WakeRegistrationTransport for NwcPushTransport {
    fn apply<'a>(
        &'a self,
        server_url: &'a SecureWakeServerUrl,
        change: &'a WakeRegistrationChange,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(
            async move { run_with_context(context, self.apply_change(server_url, change)).await },
        )
    }
}

fn classify_request_error(error: reqwest::Error) -> HostError {
    let kind = if error.is_timeout() {
        HostErrorKind::TimedOut
    } else if error.is_builder() {
        HostErrorKind::Internal
    } else {
        HostErrorKind::Unavailable
    };
    HostError::new(kind)
}

#[derive(Serialize)]
struct RegisterNwcPushPayload<'a> {
    id: &'a str,
    connection_id: &'a str,
    connection_revision: u64,
    push_service: &'static str,
    push_token: &'a str,
    app_id: &'a str,
    environment: &'a str,
    client_pubkey: &'a str,
    wallet_service_pubkey: &'a str,
    relay: &'a str,
    name: &'static str,
    enabled: bool,
}

#[derive(Serialize)]
struct InvoiceSettlementMonitorPayload<'a> {
    id: &'a str,
    request_event_id: &'a str,
    client_pubkey: &'a str,
    wallet_service_pubkey: &'a str,
    relay: &'a str,
    expires_at: u64,
    enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_download_targets_must_be_globally_routable() {
        for public in ["1.1.1.1:443", "8.8.8.8:443", "[2606:4700:4700::1111]:443"] {
            assert!(is_public_socket_address(
                public.parse().expect("public address")
            ));
        }
        for private in [
            "0.0.0.0:443",
            "10.0.0.1:443",
            "100.64.0.1:443",
            "127.0.0.1:443",
            "169.254.1.1:443",
            "172.16.0.1:443",
            "192.0.0.1:443",
            "192.168.0.1:443",
            "198.18.0.1:443",
            "224.0.0.1:443",
            "[::1]:443",
            "[fe80::1]:443",
            "[fd00::1]:443",
            "[2001:db8::1]:443",
        ] {
            assert!(!is_public_socket_address(
                private.parse().expect("private address")
            ));
        }
    }

    fn config(server_url: &str) -> ApnsWakeRegistrationConfig {
        ApnsWakeRegistrationConfig::new(
            Some(server_url.to_owned()),
            Some("super-secret-token".to_owned()),
            "com.example.wallet".to_owned(),
            "sandbox".to_owned(),
            "install".to_owned(),
            true,
        )
    }

    #[test]
    fn config_requires_https_and_known_apns_environment() {
        assert!(config("https://wake.example.com").ready().is_ok());
        assert!(config("http://wake.example.com").ready().is_err());
        let invalid_environment = ApnsWakeRegistrationConfig::new(
            Some("https://wake.example.com".to_owned()),
            Some("token".to_owned()),
            "com.example.wallet".to_owned(),
            "development".to_owned(),
            "install".to_owned(),
            true,
        );
        assert_eq!(
            invalid_environment.ready().expect_err("environment"),
            WakeHttpConfigError::InvalidEnvironment
        );
    }

    #[test]
    fn settlement_config_requires_only_public_routing_values() {
        let config = InvoiceSettlementMonitorConfig::new(
            Some("https://wake.example.com/base".to_owned()),
            "install-123".to_owned(),
        )
        .expect("settlement config");
        let debug = format!("{config:?}");
        assert!(!debug.contains("wake.example.com"));
        assert!(!debug.contains("install-123"));
        assert!(InvoiceSettlementMonitorConfig::new(
            Some("http://wake.example.com".to_owned()),
            "install-123".to_owned(),
        )
        .is_err());
        assert!(InvoiceSettlementMonitorConfig::new(
            Some("https://wake.example.com".to_owned()),
            String::new(),
        )
        .is_err());
    }

    #[test]
    fn config_debug_output_redacts_provider_metadata() {
        let config = config("https://private.example.com/wake");
        let debug = format!("{config:?}");
        assert!(!debug.contains("private.example.com"));
        assert!(!debug.contains("super-secret-token"));
        assert!(!debug.contains("com.example.wallet"));
        assert!(!debug.contains("install"));
    }

    #[test]
    fn registration_endpoint_preserves_server_path_prefix() {
        let server = SecureWakeServerUrl::parse("https://wake.example.com/wake")
            .expect("secure wake server");
        let endpoint = registration_endpoint_url(&server).expect("registration endpoint");
        assert_eq!(
            endpoint.as_str(),
            "https://wake.example.com/wake/register-nwc-push"
        );
    }

    #[test]
    fn settlement_endpoint_preserves_server_path_prefix() {
        let server = SecureWakeServerUrl::parse("https://wake.example.com/wake")
            .expect("secure wake server");
        let endpoint = settlement_monitor_endpoint_url(&server).expect("settlement endpoint");
        assert_eq!(
            endpoint.as_str(),
            "https://wake.example.com/wake/monitor-nwc-invoice"
        );
    }
}
