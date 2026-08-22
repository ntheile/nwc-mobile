//! Secure HTTPS wake-registration transport for `nwc-mobile` hosts.
//!
//! This crate owns endpoint construction, payload serialization, NIP-98 request
//! authorization, redirect rejection, provider response classification, and the
//! bounded durable registration worker pass.

#![forbid(unsafe_code)]

use std::fmt;
use std::time::Duration;

use nwc_mobile::{
    Clock, HostError, HostErrorKind, HostFuture, NeverCancelled, Nip98Authorization,
    Nip98SigningKey, OperationBudget, OperationContext, SecureWakeServerUrl, SystemClock,
    WakeLedger, WakeRegistrationChange, WakeRegistrationError, WakeRegistrationTransport,
    WakeRegistrationWorker, WakeRegistrationWorkerError,
};
use nwc_mobile_tokio::run_with_context;
use serde::Serialize;

const REGISTRATION_BATCH_SIZE: usize = 20;
const REGISTRATION_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONFIG_VALUE_BYTES: usize = 2_048;

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
}

impl fmt::Display for WakeHttpRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ClientUnavailable => "wake registration HTTP client is unavailable",
            Self::InvalidBudget => "wake registration operation budget is invalid",
            Self::Worker(_) => "wake registration worker failed",
            Self::Outbox(_) => "wake registration outbox is unavailable",
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
