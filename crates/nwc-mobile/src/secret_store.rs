//! Reusable adapters for platform-protected NWC secret storage.

use std::sync::Arc;

use nostr::SecretKey;
use zeroize::Zeroizing;

use crate::{ClientSecretStore, ClientSecretStoreError, HostError, HostErrorKind, Nip98SigningKey};

/// Minimal platform-protected key-value storage required by NWC hosts.
///
/// Native applications normally implement this over Keychain or Android Keystore-backed
/// storage. Values must never be logged or retained beyond the operation using them.
pub trait ProtectedSecretStore: Send + Sync {
    /// Loads one protected value.
    fn load_secret(&self, key: &str) -> Result<Option<String>, HostError>;

    /// Stores one protected value.
    fn store_secret(&self, key: &str, value: &str) -> Result<(), HostError>;

    /// Deletes one protected value, treating a missing value as success.
    fn delete_secret(&self, key: &str) -> Result<(), HostError>;
}

/// Loads the wallet-service signing key used by authenticated wake-server requests.
pub trait WalletServiceSigningKeyProvider: Send + Sync {
    /// Loads fresh ephemeral signing material from protected storage.
    fn load_wallet_service_signing_key(&self) -> Result<Nip98SigningKey, HostError>;
}

/// Adapts a synchronous protected store to foreground secret lifecycle contracts.
///
/// This type deliberately does not implement [`crate::SecretProvider`]: a
/// synchronous Keychain or Keystore read cannot honor an async operation
/// deadline. Background hosts should use the bounded native bridge or provide
/// their own context-aware asynchronous implementation.
pub struct StoredNwcSecrets<S: ?Sized> {
    store: Arc<S>,
    wallet_service_secret_key: String,
}

impl<S: ?Sized> Clone for StoredNwcSecrets<S> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            wallet_service_secret_key: self.wallet_service_secret_key.clone(),
        }
    }
}

impl<S: ProtectedSecretStore + ?Sized> StoredNwcSecrets<S> {
    /// Creates an adapter using the supplied protected-storage key for the wallet identity.
    #[must_use]
    pub fn new(store: Arc<S>, wallet_service_secret_key: impl Into<String>) -> Self {
        Self {
            store,
            wallet_service_secret_key: wallet_service_secret_key.into(),
        }
    }

    fn wallet_service_secret_bytes(&self) -> Result<[u8; 32], HostError> {
        let encoded = self
            .store
            .load_secret(&self.wallet_service_secret_key)?
            .map(Zeroizing::new)
            .ok_or_else(unavailable)?;
        SecretKey::parse(encoded.as_str())
            .map(|secret| secret.to_secret_bytes())
            .map_err(|_| HostError::new(HostErrorKind::Internal))
    }
}

impl<S: ProtectedSecretStore + ?Sized> ClientSecretStore for StoredNwcSecrets<S> {
    fn load_client_secret(
        &self,
        storage_key: &str,
    ) -> Result<Option<String>, ClientSecretStoreError> {
        self.store
            .load_secret(storage_key)
            .map_err(|_| ClientSecretStoreError)
    }

    fn store_client_secret(
        &self,
        storage_key: &str,
        secret: &str,
    ) -> Result<(), ClientSecretStoreError> {
        self.store
            .store_secret(storage_key, secret)
            .map_err(|_| ClientSecretStoreError)
    }

    fn delete_client_secret(&self, storage_key: &str) -> Result<(), ClientSecretStoreError> {
        self.store
            .delete_secret(storage_key)
            .map_err(|_| ClientSecretStoreError)
    }
}

impl<S: ProtectedSecretStore + ?Sized> WalletServiceSigningKeyProvider for StoredNwcSecrets<S> {
    fn load_wallet_service_signing_key(&self) -> Result<Nip98SigningKey, HostError> {
        Nip98SigningKey::from_bytes(self.wallet_service_secret_bytes()?)
            .map_err(|_| HostError::new(HostErrorKind::Internal))
    }
}

const fn unavailable() -> HostError {
    HostError::new(HostErrorKind::Unavailable)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct MemorySecrets(Mutex<BTreeMap<String, String>>);

    impl ProtectedSecretStore for MemorySecrets {
        fn load_secret(&self, key: &str) -> Result<Option<String>, HostError> {
            Ok(self.0.lock().expect("secret store").get(key).cloned())
        }

        fn store_secret(&self, key: &str, value: &str) -> Result<(), HostError> {
            self.0
                .lock()
                .expect("secret store")
                .insert(key.to_owned(), value.to_owned());
            Ok(())
        }

        fn delete_secret(&self, key: &str) -> Result<(), HostError> {
            self.0.lock().expect("secret store").remove(key);
            Ok(())
        }
    }

    #[test]
    fn adapter_serves_foreground_client_and_wallet_identity_contracts() {
        let store = Arc::new(MemorySecrets::default());
        store
            .store_secret(
                "wallet-key",
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .expect("wallet key");
        let secrets = StoredNwcSecrets::new(store, "wallet-key");

        secrets
            .store_client_secret("client", "secret")
            .expect("store client secret");
        assert_eq!(
            secrets.load_client_secret("client").expect("load secret"),
            Some("secret".to_owned())
        );
        assert!(secrets.load_wallet_service_signing_key().is_ok());
    }
}
