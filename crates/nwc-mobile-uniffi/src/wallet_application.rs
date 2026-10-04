//! Native-configured application workflows reused by React Native.

use crate::{
    MobileBudgetInterval, MobileConnectionPresentation, MobileConnectionState, MobileEngineError,
    MobileNwaApprovalResult, MobileNwaRequestPresentation, MobileNwcEncryption, MobileNwcEngine,
    MobileNwcMethod,
};
use nwc_mobile::{
    ApplicationWorkflowError, ClientSecretStore, ClientSecretStoreError, NwaApprovalSelection,
    UnixTimestamp, WalletConnectionRequest,
};
use std::sync::Arc;

/// Device-protected storage implemented by the native wallet, not JavaScript.
/// Secret values must never be logged, backed up insecurely, or cached in JS.
#[uniffi::export(with_foreign)]
pub trait MobileClientSecretStore: Send + Sync {
    /// Load a wallet-managed client secret from secure storage.
    fn load(&self, key: String) -> Result<Option<String>, MobileEngineError>;
    /// Store a new client secret with device-only protection.
    fn store(&self, key: String, secret: String) -> Result<(), MobileEngineError>;
    /// Delete a client secret; a missing value counts as success.
    fn delete(&self, key: String) -> Result<(), MobileEngineError>;
}

pub(crate) struct Secrets(pub(crate) Arc<dyn MobileClientSecretStore>);
impl ClientSecretStore for Secrets {
    fn load_client_secret(&self, key: &str) -> Result<Option<String>, ClientSecretStoreError> {
        self.0.load(key.into()).map_err(|_| ClientSecretStoreError)
    }
    fn store_client_secret(&self, key: &str, secret: &str) -> Result<(), ClientSecretStoreError> {
        self.0
            .store(key.into(), secret.into())
            .map_err(|_| ClientSecretStoreError)
    }
    fn delete_client_secret(&self, key: &str) -> Result<(), ClientSecretStoreError> {
        self.0
            .delete(key.into())
            .map_err(|_| ClientSecretStoreError)
    }
}

/// Stable native wallet identity and connection defaults. No private keys.
#[derive(Clone, uniffi::Record)]
pub struct MobileWalletConfig {
    /// Public key corresponding to the native engine's service secret provider.
    pub wallet_service_public_key_hex: String,
    /// Default secure relays, configured by the wallet provider.
    pub relay_urls: Vec<String>,
    /// Optional wallet Lightning address.
    pub lud16: Option<String>,
}

/// Authority explicitly approved by the user. Monetary values are satoshis.
#[derive(Clone, uniffi::Record)]
pub struct MobileConnectionOptions {
    /// Approved methods; never silently grant all methods.
    pub methods: Vec<MobileNwcMethod>,
    /// Principal plus fee spending limit per interval.
    pub budget_limit_sat: u64,
    /// Spending-limit renewal interval.
    pub budget_interval: MobileBudgetInterval,
    /// Negotiated encryption, normally NIP-44 v2.
    pub encryption: MobileNwcEncryption,
    /// Optional Unix expiry in seconds.
    pub expires_at: Option<u64>,
    /// Username explicitly disclosed to this NWA client; omitted for old connections.
    pub payer_username: Option<String>,
    /// Selected spending wallet name, separate from payer identity.
    pub wallet_name: Option<String>,
    /// Postal address snapshot explicitly disclosed during connection approval.
    pub payer_address_json: Option<String>,
}

/// Non-sensitive durable FCM registration pass result.
#[derive(Clone, Copy, Debug, uniffi::Record)]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileFcmRegistrationReport {
    /// Successfully applied changes.
    pub applied: u64,
    /// Provider failures retained for retry.
    pub deferred: u64,
    /// Earliest remaining retry time in Unix seconds.
    pub next_attempt_at: Option<u64>,
}

/// Non-sensitive durable APNs registration pass result.
#[derive(Clone, Copy, Debug, uniffi::Record)]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileApnsRegistrationReport {
    /// Successfully applied changes.
    pub applied: u64,
    /// Provider failures retained for retry.
    pub deferred: u64,
    /// Earliest remaining retry time in Unix seconds.
    pub next_attempt_at: Option<u64>,
}

/// Native-configured connection/NWA facade; the same engine handles wakes.
#[derive(uniffi::Object)]
pub struct MobileWallet {
    pub(crate) engine: Arc<MobileNwcEngine>,
    config: MobileWalletConfig,
    pub(crate) secrets: Secrets,
}

impl MobileWallet {
    fn wake_registration_signing_key(
        &self,
    ) -> Result<nwc_mobile::Nip98SigningKey, MobileEngineError> {
        let encoded = zeroize::Zeroizing::new(
            self.secrets
                .0
                .load("nwc-mobile/foreground/service-key".into())?
                .ok_or(MobileEngineError::InvalidArgument)?,
        );
        let (public_key, bytes) = nwc_mobile::service_secret_identity(&encoded)
            .map_err(|_| MobileEngineError::InvalidArgument)?;
        let bytes = zeroize::Zeroizing::new(bytes);
        if public_key != self.config.wallet_service_public_key_hex {
            return Err(MobileEngineError::InvalidArgument);
        }
        let bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| MobileEngineError::InvalidArgument)?;
        nwc_mobile::Nip98SigningKey::from_bytes(bytes)
            .map_err(|_| MobileEngineError::InvalidArgument)
    }
}

#[uniffi::export]
impl MobileWallet {
    /// Processes pending FCM registration/removal changes. Inputs contain no signing secrets.
    /// Call refresh_wake_registrations when routing configuration changes; retry this
    /// method to honor durable backoff. Native hosts should retain the installation ID.
    pub async fn process_fcm_wake_registrations(
        &self,
        server_url: String,
        push_token: String,
        app_id: String,
        install_id: String,
    ) -> Result<MobileFcmRegistrationReport, MobileEngineError> {
        let config = nwc_mobile_http::ReadyFcmWakeRegistrationConfig::new(
            server_url, push_token, app_id, install_id,
        )
        .map_err(|_| MobileEngineError::InvalidArgument)?;
        let signing_key = self.wake_registration_signing_key()?;
        let engine = self.engine.clone();
        nwc_mobile_tokio::run_on_native_runtime(async move {
            let report = nwc_mobile_http::run_fcm_registration_worker(
                engine.service.ledger(),
                config,
                signing_key,
            )
            .await
            .map_err(|_| MobileEngineError::DatabaseUnavailable)?;
            Ok(MobileFcmRegistrationReport {
                applied: report.applied() as u64,
                deferred: report.deferred() as u64,
                next_attempt_at: report.next_attempt_at(),
            })
        })
        .await
        .map_err(|_| MobileEngineError::DatabaseUnavailable)?
    }

    /// Processes APNs registration/removal with an explicit sandbox or production environment.
    /// Signing credentials remain in the native secret store.
    pub async fn process_apns_wake_registrations(
        &self,
        server_url: String,
        push_token: String,
        app_id: String,
        install_id: String,
        environment: String,
    ) -> Result<MobileApnsRegistrationReport, MobileEngineError> {
        let config = nwc_mobile_http::ApnsWakeRegistrationConfig::new(
            Some(server_url),
            Some(push_token),
            app_id,
            environment,
            install_id,
            true,
        )
        .ready()
        .map_err(|_| MobileEngineError::InvalidArgument)?;
        let signing_key = self.wake_registration_signing_key()?;
        let engine = self.engine.clone();
        nwc_mobile_tokio::run_on_native_runtime(async move {
            let report = nwc_mobile_http::run_registration_worker(
                engine.service.ledger(),
                config,
                signing_key,
            )
            .await
            .map_err(|_| MobileEngineError::DatabaseUnavailable)?;
            Ok(MobileApnsRegistrationReport {
                applied: report.applied() as u64,
                deferred: report.deferred() as u64,
                next_attempt_at: report.next_attempt_at(),
            })
        })
        .await
        .map_err(|_| MobileEngineError::DatabaseUnavailable)?
    }

    /// Construct in native bootstrap with an engine, public defaults, and an
    /// OS-protected client-secret store. No JavaScript callback is required.
    #[uniffi::constructor]
    pub fn new(
        engine: Arc<MobileNwcEngine>,
        config: MobileWalletConfig,
        secrets: Arc<dyn MobileClientSecretStore>,
    ) -> Arc<Self> {
        Arc::new(Self {
            engine,
            config,
            secrets: Secrets(secrets),
        })
    }

    /// Returns the native wake/maintenance engine, not a React Native bridge.
    pub fn engine(&self) -> Arc<MobileNwcEngine> {
        self.engine.clone()
    }

    /// Public service identity for a native owner registry. Never trust a push payload
    /// to select an owner without matching this identity against the native registry.
    pub fn service_public_key(&self) -> String {
        self.config.wallet_service_public_key_hex.clone()
    }

    /// Lists non-secret connection presentations.
    pub fn list_connections(&self) -> Result<Vec<MobileConnectionPresentation>, MobileEngineError> {
        self.engine.connection_presentations()
    }

    /// Generate and securely store a client key using the shared Rust workflow.
    /// The returned state deliberately omits the secret-bearing URI.
    pub fn create_connection(
        &self,
        options: MobileConnectionOptions,
    ) -> Result<MobileConnectionState, MobileEngineError> {
        let created = self
            .engine
            .service
            .create_wallet_connection(
                WalletConnectionRequest::new(
                    self.config.wallet_service_public_key_hex.clone(),
                    self.config.relay_urls.join("\n"),
                    String::new(),
                    options.methods.into_iter().map(Into::into).collect(),
                    options.budget_limit_sat,
                    options.budget_interval.into(),
                    options.encryption.into(),
                    options.expires_at.map(UnixTimestamp::from_secs),
                    self.config.lud16.clone(),
                ),
                &self.secrets,
            )
            .map_err(workflow_error)?;
        let connection = created.connection();
        Ok(MobileConnectionState {
            connection_id: connection.id().as_str().into(),
            revision: connection.revision().value(),
            active: true,
        })
    }

    /// Explicitly export a secret-bearing URI for a user-requested QR/share UI.
    /// Never send it to analytics, logs, or an unverified callback destination.
    pub fn export_connection_uri(
        &self,
        connection_id: String,
    ) -> Result<String, MobileEngineError> {
        self.engine
            .service
            .export_wallet_connection_uri(&connection_id, self.config.lud16.clone(), &self.secrets)
            .map_err(workflow_error)
    }

    /// Revoke before attempting secure deletion. False means authorization was
    /// revoked but secret cleanup needs retrying; it never means still active.
    pub fn revoke_connection(&self, connection_id: String) -> Result<bool, MobileEngineError> {
        self.engine
            .service
            .revoke_application_connection(&connection_id, &self.secrets)
            .map(|result| result.client_secret_deleted())
            .map_err(workflow_error)
    }

    /// Validate and retain an untrusted NWA URI for explicit user review.
    pub fn parse_nwa_request(
        &self,
        uri: String,
    ) -> Result<MobileNwaRequestPresentation, MobileEngineError> {
        self.engine.open_nwa_request(uri)
    }

    /// Read the request currently awaiting review.
    pub fn pending_nwa_request(
        &self,
    ) -> Result<Option<MobileNwaRequestPresentation>, MobileEngineError> {
        self.engine.pending_nwa_request()
    }

    /// Approve only the reviewed request with the selected authority. Rust
    /// verifies it does not exceed the retained request. Delivery stays native.
    pub fn approve_nwa_request(
        &self,
        request_id: String,
        options: MobileConnectionOptions,
    ) -> Result<MobileNwaApprovalResult, MobileEngineError> {
        approve_nwa_internal(self, request_id, options, "capped")
    }

    /// Authorizes reusable per-purchase confirmation without binding an initial invoice.
    pub fn approve_nwa_reusable_payment(
        &self,
        request_id: String,
        options: MobileConnectionOptions,
        wallet_id: String,
    ) -> Result<MobileNwaApprovalResult, MobileEngineError> {
        if !self.engine.service.ledger().foreground_payments_enabled()?
            || wallet_id.is_empty()
            || wallet_id.len() > 128
            || !matches!(options.budget_interval, MobileBudgetInterval::Monthly)
            || options.expires_at.is_none()
        {
            return Err(MobileEngineError::InvalidArgument);
        }
        let approved = approve_nwa_internal(self, request_id, options, "reusable")?;
        if let Err(error) = self
            .engine
            .service
            .ledger()
            .bind_reusable_foreground_wallet(&approved.connection.connection_id, &wallet_id)
        {
            let _ = self.revoke_connection(approved.connection.connection_id.clone());
            return Err(error.into());
        }
        Ok(approved)
    }

    /// Approves an exact invoice once with explicit wallet-managed extra costs.
    /// Capability publication remains blocked until the immutable binding commits.
    pub fn approve_nwa_wallet_managed_payment(
        &self,
        request_id: String,
        options: MobileConnectionOptions,
        wallet_id: String,
        invoice: String,
        payment_hash_hex: String,
        invoice_amount_msat: u64,
    ) -> Result<MobileNwaApprovalResult, MobileEngineError> {
        if !self.engine.service.ledger().foreground_payments_enabled()?
            || wallet_id.is_empty()
            || wallet_id.len() > 128
            || invoice_amount_msat == 0
            || options.budget_limit_sat != invoice_amount_msat.div_ceil(1000)
            || !matches!(options.budget_interval, MobileBudgetInterval::Never)
        {
            return Err(MobileEngineError::InvalidArgument);
        }
        let quote = nwc_mobile_bolt11::quote_invoice(&invoice, None)
            .map_err(|_| MobileEngineError::InvalidArgument)?;
        if quote.principal().as_msat() != invoice_amount_msat
            || quote.payment_hash().to_hex() != payment_hash_hex.to_ascii_lowercase()
        {
            return Err(MobileEngineError::InvalidArgument);
        }
        let approved = approve_nwa_internal(self, request_id, options, "wallet_managed")?;
        if let Err(error) = self
            .engine
            .service
            .ledger()
            .bind_wallet_managed_foreground_payment(
                &approved.connection.connection_id,
                &wallet_id,
                quote.payment_hash(),
                invoice_amount_msat,
                &invoice,
            )
        {
            let _ = self.revoke_connection(approved.connection.connection_id.clone());
            return Err(error.into());
        }
        Ok(approved)
    }

    /// Cancel the retained request; does not invoke a callback.
    pub fn cancel_nwa_request(&self) -> Result<(), MobileEngineError> {
        self.engine.clear_pending_nwa()
    }

    /// Queue registration changes for native maintenance to deliver.
    pub fn refresh_wake_registrations(&self, enabled: bool) -> Result<u64, MobileEngineError> {
        self.engine.refresh_wake_registrations(enabled)
    }
}

fn approve_nwa_internal(
    wallet: &MobileWallet,
    request_id: String,
    options: MobileConnectionOptions,
    expected_policy: &str,
) -> Result<MobileNwaApprovalResult, MobileEngineError> {
    let metadata = nwc_mobile::ConnectionPayerMetadata::new(options.payer_username, options.wallet_name)
        .map_err(MobileEngineError::from)?;
    let request = wallet
        .engine
        .pending_nwa_request()?
        .ok_or(MobileEngineError::NoPendingNwa)?;
    if request.request_id_hex != request_id
        || (if expected_policy == "reusable" {
            request.payment_mode != "confirm_each" || request.fee_policy != "wallet_managed"
        } else {
            request.payment_mode != "one_time" || request.fee_policy != expected_policy
        })
    {
        return Err(MobileEngineError::InvalidArgument);
    }
    let approved = wallet
        .engine
        .service
        .approve_application_nwa(NwaApprovalSelection::new(
            request_id,
            wallet.config.wallet_service_public_key_hex.clone(),
            request.relay_urls.join("\n"),
            String::new(),
            options.methods.into_iter().map(Into::into).collect(),
            options.budget_limit_sat,
            options.budget_interval.into(),
            options.encryption.into(),
            options.expires_at.map(UnixTimestamp::from_secs),
            wallet.config.lud16.clone(),
        ))
        .map_err(workflow_error)?;
    let connection = approved.approval().connection();
    if let Err(error) = wallet.engine.service.ledger().set_connection_payer_metadata(connection.id().as_str(), &metadata) {
        let _ = wallet.revoke_connection(connection.id().as_str().into());
        return Err(error.into());
    }
    if let Some(address) = options.payer_address_json {
        let stored = wallet.pairing_secret().and_then(|secret| wallet.engine.service.ledger().set_connection_address(connection.id().as_str(), &address, &secret).map_err(Into::into));
        if let Err(error) = stored {
            let _ = wallet.revoke_connection(connection.id().as_str().into());
            return Err(error);
        }
    }
    Ok(MobileNwaApprovalResult {
        connection: MobileConnectionState {
            connection_id: connection.id().as_str().into(),
            revision: connection.revision().value(),
            active: true,
        },
        callback_url: approved.approval().callback_url().map(str::to_owned),
    })
}

fn workflow_error(error: ApplicationWorkflowError) -> MobileEngineError {
    match error {
        ApplicationWorkflowError::Service(error) => error.into(),
        ApplicationWorkflowError::InvalidInput(_) => MobileEngineError::InvalidArgument,
        ApplicationWorkflowError::ClientSecretUnavailable => MobileEngineError::NotFound,
        _ => MobileEngineError::DatabaseUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex,
    };

    #[derive(Default)]
    struct Store {
        entries: Mutex<HashMap<String, String>>,
        unavailable: AtomicBool,
    }
    impl MobileClientSecretStore for Store {
        fn load(&self, key: String) -> Result<Option<String>, MobileEngineError> {
            Ok(self.entries.lock().unwrap().get(&key).cloned())
        }
        fn store(&self, key: String, secret: String) -> Result<(), MobileEngineError> {
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(MobileEngineError::DatabaseUnavailable);
            }
            self.entries.lock().unwrap().insert(key, secret);
            Ok(())
        }
        fn delete(&self, key: String) -> Result<(), MobileEngineError> {
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(MobileEngineError::DatabaseUnavailable);
            }
            self.entries.lock().unwrap().remove(&key);
            Ok(())
        }
    }

    fn options() -> MobileConnectionOptions {
        MobileConnectionOptions {
            methods: vec![MobileNwcMethod::GetInfo],
            budget_limit_sat: 100,
            budget_interval: MobileBudgetInterval::Daily,
            encryption: MobileNwcEncryption::Nip44V2,
            expires_at: None,
            payer_address_json: None,
            payer_username: None,
            wallet_name: None,
        }
    }

    fn with_wallet(test: impl FnOnce(Arc<MobileWallet>, Arc<Store>)) {
        with_wallet_relay(None, test);
    }
    fn with_wallet_relay(
        relay: Option<Arc<dyn crate::MobileRelayTransport>>,
        test: impl FnOnce(Arc<MobileWallet>, Arc<Store>),
    ) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "nwc-rn-workflow-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("ledger.sqlite").to_str().unwrap().to_owned();
        let engine = match relay {
            Some(relay) => {
                crate::host_bridge::tests::application_test_engine_with_relay(path, relay)
            }
            None => crate::host_bridge::tests::application_test_engine(path),
        };
        let store = Arc::new(Store::default());
        let wallet = MobileWallet::new(
            engine,
            MobileWalletConfig {
                wallet_service_public_key_hex: nwc_mobile::service_secret_identity(
                    &"01".repeat(32),
                )
                .unwrap()
                .0,
                relay_urls: vec!["wss://relay.example".into()],
                lud16: None,
            },
            store.clone(),
        );
        test(wallet, store);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn native_workflow_creates_exports_and_revokes_without_js_key_provisioning() {
        with_wallet(|wallet, store| {
            let created = wallet.create_connection(options()).unwrap();
            assert!(created.active);
            assert_eq!(store.entries.lock().unwrap().len(), 1);
            let presentations = wallet.list_connections().unwrap();
            assert_eq!(presentations.len(), 1);
            assert_eq!(presentations[0].connection_id, created.connection_id);
            assert_eq!(presentations[0].budget_limit_sat, 100);
            let uri = wallet
                .export_connection_uri(created.connection_id.clone())
                .unwrap();
            assert!(uri.starts_with("nostr+walletconnect://"));
            assert!(uri.contains("secret="));
            assert!(wallet
                .revoke_connection(created.connection_id.clone())
                .unwrap());
            assert!(store.entries.lock().unwrap().is_empty());
            assert!(wallet.list_connections().unwrap().is_empty());
            assert!(wallet.export_connection_uri(created.connection_id).is_err());
        });
    }

    #[test]
    fn unavailable_secure_storage_never_creates_authority() {
        with_wallet(|wallet, store| {
            store.unavailable.store(true, Ordering::SeqCst);
            assert!(wallet.create_connection(options()).is_err());
            assert!(wallet.list_connections().unwrap().is_empty());
        });
    }

    #[test]
    fn failed_secret_cleanup_does_not_keep_connection_active() {
        with_wallet(|wallet, store| {
            let created = wallet.create_connection(options()).unwrap();
            store.unavailable.store(true, Ordering::SeqCst);
            assert!(!wallet
                .revoke_connection(created.connection_id.clone())
                .unwrap());
            assert!(wallet.list_connections().unwrap().is_empty());
            store.unavailable.store(false, Ordering::SeqCst);
            assert!(wallet.revoke_connection(created.connection_id).unwrap());
            assert!(store.entries.lock().unwrap().is_empty());
        });
    }

    #[test]
    fn approval_without_a_retained_request_is_rejected() {
        with_wallet(|wallet, _| {
            assert!(matches!(
                wallet.approve_nwa_request("unreviewed".into(), options()),
                Err(MobileEngineError::NoPendingNwa)
            ));
            assert!(wallet.list_connections().unwrap().is_empty());
        });
    }
    #[derive(Default)]
    struct RecordingRelay {
        fail: AtomicBool,
        events: Mutex<Vec<String>>,
    }
    #[async_trait::async_trait]
    impl crate::MobileRelayTransport for RecordingRelay {
        async fn fetch_event(
            &self,
            _relay: String,
            _event: String,
            _max: u64,
            _timeout: u64,
            _cancel: Arc<crate::MobileCancellation>,
        ) -> Result<Option<String>, crate::MobileHostError> {
            Ok(None)
        }
        async fn publish_event(
            &self,
            _relay: String,
            event: String,
            _timeout: u64,
            _cancel: Arc<crate::MobileCancellation>,
        ) -> Result<(), crate::MobileHostError> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(crate::MobileHostError::Unavailable);
            }
            self.events.lock().unwrap().push(event);
            Ok(())
        }
    }
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                std::task::Poll::Ready(value) => return value,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }
    #[test]
    fn apns_registration_rejects_missing_environment_and_insecure_endpoint() {
        with_wallet(|wallet, _| {
            for environment in ["", "development", "Production"] {
                assert!(matches!(
                    block_on(wallet.process_apns_wake_registrations(
                        "https://wake.example".into(),
                        "device-token".into(),
                        "app.example".into(),
                        "install-id".into(),
                        environment.into(),
                    )),
                    Err(MobileEngineError::InvalidArgument)
                ));
            }
            assert!(matches!(
                block_on(wallet.process_apns_wake_registrations(
                    "http://wake.example".into(),
                    "device-token".into(),
                    "app.example".into(),
                    "install-id".into(),
                    "sandbox".into(),
                )),
                Err(MobileEngineError::InvalidArgument)
            ));
        });
    }

    #[test]
    fn expired_first_connection_does_not_consume_live_connection_poll_budget() {
        use nwc_mobile::Clock;
        with_wallet(|wallet, _| {
            let now = nwc_mobile::SystemClock.now().as_secs();
            let mut first_options = options();
            first_options.expires_at = Some(now + 10);
            let first = wallet.create_connection(first_options).unwrap();
            let second = wallet.create_connection(options()).unwrap();
            let active = wallet.engine.service.active_connections().unwrap();
            assert_eq!(active.len(), 2);
            let selected = crate::foreground_payments::pollable_connections(
                active,
                nwc_mobile::UnixTimestamp::from_secs(now + 11),
            );
            assert_eq!(selected.len(), 1);
            assert_eq!(selected[0].id().as_str(), second.connection_id);
            assert!(wallet
                .engine
                .service
                .ledger()
                .foreground_recovery_events(&first.connection_id)
                .unwrap()
                .is_empty());
        });
    }

    #[test]
    fn historical_connections_do_not_consume_pending_info_publication_limit() {
        let relay = Arc::new(RecordingRelay::default());
        with_wallet_relay(Some(relay.clone()), |wallet, _| {
            for _ in 0..33 {
                let historical = wallet.create_connection(options()).unwrap();
                wallet
                    .engine
                    .service
                    .set_connection_metadata(
                        &historical.connection_id,
                        nwc_mobile::ApplicationConnectionMetadata::new(
                            "Announced",
                            None,
                            vec!["wss://relay.example".into()],
                        )
                        .unwrap(),
                    )
                    .unwrap();
                wallet
                    .engine
                    .service
                    .acknowledge_nwc_info_event(&historical.connection_id, "wss://relay.example")
                    .unwrap();
            }
            let live = wallet.create_connection(options()).unwrap();
            assert_eq!(
                wallet
                    .engine
                    .service
                    .connection_presentations()
                    .unwrap()
                    .len(),
                34
            );
            block_on(wallet.engine.publish_pending_info_events(1000)).unwrap();
            assert_eq!(relay.events.lock().unwrap().len(), 1);
            let presentations = wallet.engine.service.connection_presentations().unwrap();
            let live = presentations
                .iter()
                .find(|view| view.id() == live.connection_id)
                .unwrap();
            assert!(live.pending_info_event_relays().is_empty());
        });
    }

    #[test]
    fn reusable_approval_is_bounded_and_announced_only_after_wallet_binding() {
        use nwc_mobile::Clock;
        let relay = Arc::new(RecordingRelay::default());
        with_wallet_relay(Some(relay.clone()), |wallet, _| {
            wallet.enable_foreground_payments().unwrap();
            let now = nwc_mobile::SystemClock.now().as_secs();
            let client = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
            let request=wallet.parse_nwa_request(format!("nostr+walletauth://{client}?relay=wss%3A%2F%2Frelay.example&payment_mode=confirm_each&budget_basis=invoice_principal&fee_policy=wallet_managed&max_amount=500000000&budget_renewal=monthly&expires_at={}&request_methods=get_info%20pay_invoice",now+90*86400)).unwrap();
            assert_eq!(request.payment_mode, "confirm_each");
            assert_eq!(request.budget_basis, "invoice_principal");
            assert!(request.metadata_json.is_none());
            let approval = MobileConnectionOptions {
                methods: vec![MobileNwcMethod::GetInfo, MobileNwcMethod::PayInvoice],
                budget_limit_sat: 500_001,
                budget_interval: MobileBudgetInterval::Monthly,
                encryption: MobileNwcEncryption::Nip44V2,
                expires_at: Some(now + 90 * 86400),
            payer_address_json: None,
            payer_username: None,
            wallet_name: None,
            };
            assert!(wallet
                .approve_nwa_reusable_payment(
                    request.request_id_hex.clone(),
                    approval.clone(),
                    "wallet-a".into()
                )
                .is_err());
            let approval = MobileConnectionOptions {
                budget_limit_sat: 400_000,
                expires_at: Some(now + 30 * 86400),
            payer_address_json: None,
            payer_username: None,
            wallet_name: None,
                ..approval
            };
            assert!(wallet
                .approve_nwa_request(request.request_id_hex.clone(), approval.clone())
                .is_err());
            let approved = wallet
                .approve_nwa_reusable_payment(request.request_id_hex, approval, "wallet-a".into())
                .unwrap();
            let view = &wallet.list_connections().unwrap()[0];
            assert_eq!(view.payment_mode, "confirm_each");
            assert_eq!(view.budget_limit_sat, 400_000);
            assert_eq!(view.expires_at_seconds, Some(now + 30 * 86400));
            assert!(wallet
                .engine
                .service
                .ledger()
                .is_reusable_foreground(&approved.connection.connection_id)
                .unwrap());
            block_on(wallet.engine.publish_pending_info_events(1000)).unwrap();
            assert_eq!(relay.events.lock().unwrap().len(), 1);
            assert!(wallet
                .engine
                .service
                .ledger()
                .bind_reusable_foreground_wallet(&approved.connection.connection_id, "wallet-b")
                .is_err());
        });
    }

    #[test]
    fn wallet_managed_approval_validates_policy_and_exact_invoice_before_announcing() {
        let relay = Arc::new(RecordingRelay::default());
        with_wallet_relay(Some(relay.clone()), |wallet, _| {
            wallet.enable_foreground_payments().unwrap();
            let client = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
            let request=wallet.parse_nwa_request(format!("nostr+walletauth://{client}?relay=wss%3A%2F%2Frelay.example&fee_policy=wallet_managed&budget_renewal=never&request_methods=get_info%20pay_invoice")).unwrap();
            assert_eq!(request.fee_policy, "wallet_managed");
            let options = MobileConnectionOptions {
                methods: vec![MobileNwcMethod::GetInfo, MobileNwcMethod::PayInvoice],
                budget_limit_sat: 600,
                budget_interval: MobileBudgetInterval::Never,
                encryption: MobileNwcEncryption::Nip44V2,
                expires_at: None,
            payer_address_json: None,
            payer_username: None,
            wallet_name: None,
            };
            assert!(wallet
                .approve_nwa_request(request.request_id_hex.clone(), options.clone())
                .is_err());
            let invoice="lnbc6u1pj48ugqdqlwaskcmr9wskk6ctwv9nk2epqw3jhxaqpp5fwcxlrjw8fm3t5sp64eap2jzxa3w2hdt6cdzcq3837jke3kjjnsqsp59g4z52329g4z52329g4z52329g4z52329g4z52329g4z52329g4q9qrsgqxqxae4jsqcqpjjkg760lxz8kmgpnjkmdxj3xsjx6xtwvpqf2zjy3kr8cjk2xgvtvjevw7enfpnn7t5fyufhfjxylgn7tt3d3excd8e0ycse0phtf20zsqf9656q";
            let quote = nwc_mobile_bolt11::quote_invoice(invoice, None).unwrap();
            assert!(wallet
                .approve_nwa_wallet_managed_payment(
                    request.request_id_hex.clone(),
                    options.clone(),
                    "wallet-a".into(),
                    invoice.into(),
                    "00".repeat(32),
                    600_000
                )
                .is_err());
            assert!(wallet
                .approve_nwa_wallet_managed_payment(
                    request.request_id_hex.clone(),
                    options.clone(),
                    "wallet-a".into(),
                    invoice.into(),
                    quote.payment_hash().to_hex(),
                    599_999
                )
                .is_err());
            assert!(wallet.list_connections().unwrap().is_empty());
            let approved = wallet
                .approve_nwa_wallet_managed_payment(
                    request.request_id_hex,
                    options,
                    "wallet-a".into(),
                    invoice.into(),
                    quote.payment_hash().to_hex(),
                    600_000,
                )
                .unwrap();
            assert!(wallet
                .engine
                .service
                .ledger()
                .has_foreground_binding(&approved.connection.connection_id)
                .unwrap());
            assert_eq!(
                wallet.list_connections().unwrap()[0].fee_policy,
                "wallet_managed"
            );
            block_on(wallet.engine.publish_pending_info_events(1000)).unwrap();
            assert_eq!(relay.events.lock().unwrap().len(), 1);
        });
    }

    #[test]
    fn foreground_approval_publishes_targeted_info_and_retries_before_acknowledging() {
        let relay = Arc::new(RecordingRelay::default());
        relay.fail.store(true, Ordering::SeqCst);
        with_wallet_relay(Some(relay.clone()), |wallet, _| {
            wallet.enable_foreground_payments().unwrap();
            let client = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
            let request=wallet.parse_nwa_request(format!("nostr+walletauth+zapritep2p://{client}?relay=wss%3A%2F%2Frelay.example&max_amount=3000&budget_renewal=never&request_methods=get_info%20pay_invoice")).unwrap();
            let approved = wallet
                .approve_nwa_request(
                    request.request_id_hex,
                    MobileConnectionOptions {
                        methods: vec![MobileNwcMethod::GetInfo, MobileNwcMethod::PayInvoice],
                        budget_limit_sat: 3,
                        budget_interval: MobileBudgetInterval::Never,
                        encryption: MobileNwcEncryption::Nip44V2,
                        expires_at: None,
            payer_address_json: None,
            payer_username: None,
            wallet_name: None,
                    },
                )
                .unwrap();
            block_on(wallet.engine.publish_pending_info_events(1000)).unwrap();
            assert!(relay.events.lock().unwrap().is_empty());
            wallet
                .bind_connection_payment(
                    approved.connection.connection_id,
                    "host-wallet".into(),
                    "05".repeat(32),
                    1000,
                    2,
                )
                .unwrap();
            block_on(wallet.engine.publish_pending_info_events(1000)).unwrap();
            assert!(relay.events.lock().unwrap().is_empty());
            assert_eq!(
                wallet.engine.service.connection_presentations().unwrap()[0]
                    .pending_info_event_relays()
                    .len(),
                1
            );
            relay.fail.store(false, Ordering::SeqCst);
            block_on(wallet.engine.publish_pending_info_events(1000)).unwrap();
            let events = relay.events.lock().unwrap();
            assert_eq!(events.len(), 1);
            assert!(events[0].contains("\"kind\":13194"));
            assert!(events[0].contains(&format!("[\"p\",\"{client}\"]")));
            assert!(events[0].contains("[\"encryption\",\"nip44_v2\"]"));
            assert!(events[0].contains("get_info pay_invoice"));
            drop(events);
            assert!(wallet.engine.service.connection_presentations().unwrap()[0]
                .pending_info_event_relays()
                .is_empty());
            block_on(wallet.engine.publish_pending_info_events(1000)).unwrap();
            assert_eq!(relay.events.lock().unwrap().len(), 1);
        });
    }
}
