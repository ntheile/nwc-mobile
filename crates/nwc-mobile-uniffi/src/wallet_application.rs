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

struct Secrets(Arc<dyn MobileClientSecretStore>);
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
}

/// Native-configured connection/NWA facade; the same engine handles wakes.
#[derive(uniffi::Object)]
pub struct MobileWallet {
    engine: Arc<MobileNwcEngine>,
    config: MobileWalletConfig,
    secrets: Secrets,
}

#[uniffi::export]
impl MobileWallet {
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
        let request = self
            .engine
            .pending_nwa_request()?
            .ok_or(MobileEngineError::NoPendingNwa)?;
        let approved = self
            .engine
            .service
            .approve_application_nwa(NwaApprovalSelection::new(
                request_id,
                self.config.wallet_service_public_key_hex.clone(),
                request.relay_urls.join("\n"),
                String::new(),
                options.methods.into_iter().map(Into::into).collect(),
                options.budget_limit_sat,
                options.budget_interval.into(),
                options.encryption.into(),
                options.expires_at.map(UnixTimestamp::from_secs),
                self.config.lud16.clone(),
            ))
            .map_err(workflow_error)?;
        let connection = approved.approval().connection();
        Ok(MobileNwaApprovalResult {
            connection: MobileConnectionState {
                connection_id: connection.id().as_str().into(),
                revision: connection.revision().value(),
                active: true,
            },
            callback_url: approved.approval().callback_url().map(str::to_owned),
        })
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
        }
    }

    fn with_wallet(test: impl FnOnce(Arc<MobileWallet>, Arc<Store>)) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "nwc-rn-workflow-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&dir).unwrap();
        let engine = crate::host_bridge::tests::application_test_engine(
            dir.join("ledger.sqlite").to_str().unwrap().into(),
        );
        let store = Arc::new(Store::default());
        let wallet = MobileWallet::new(
            engine,
            MobileWalletConfig {
                wallet_service_public_key_hex:
                    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
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
}
