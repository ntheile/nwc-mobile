//! Process-local native bootstrap shared by React Native and native hosts.

use std::sync::{Arc, OnceLock};

use crate::{MobileEngineError, MobileWallet};

/// Native wallet bootstrap, implemented in Rust, Swift, or Kotlin, never in JS
/// when background execution is required.
///
/// Resolve identifiers against the host's wallet registry, not a filesystem
/// path supplied by the caller. Reconstruct secrets from secure native storage.
/// The app and its extension must register independently in each process and
/// open the same App Group ledger. Registration is not persisted.
#[uniffi::export(with_foreign)]
pub trait MobileWalletFactory: Send + Sync {
    /// Opens an existing wallet's engine and native backend. Do not create or
    /// restore a wallet implicitly. Unknown identifiers must return `NotFound`.
    fn open_wallet(&self, wallet_id: String) -> Result<Arc<MobileWallet>, MobileEngineError>;
}

static FACTORY: OnceLock<Arc<dyn MobileWalletFactory>> = OnceLock::new();

/// Installs the host's native factory once, before starting React Native or
/// processing a wake. Replacement is rejected to avoid changing backend
/// identity underneath an existing engine. Call from trusted native bootstrap.
#[uniffi::export]
pub fn register_mobile_wallet_factory(
    factory: Arc<dyn MobileWalletFactory>,
) -> Result<(), MobileEngineError> {
    install_factory(&FACTORY, factory)
}

fn install_factory(
    registry: &OnceLock<Arc<dyn MobileWalletFactory>>,
    factory: Arc<dyn MobileWalletFactory>,
) -> Result<(), MobileEngineError> {
    registry
        .set(factory)
        .map_err(|_| MobileEngineError::AlreadyExists)
}

/// Opens a native-registered wallet without passing credentials or foreign JS
/// callback objects. Missing bootstrap or an unknown wallet fails closed.
#[uniffi::export]
pub fn open_registered_mobile_wallet(
    wallet_id: String,
) -> Result<Arc<MobileWallet>, MobileEngineError> {
    open_wallet(&FACTORY, wallet_id)
}

fn open_wallet(
    registry: &OnceLock<Arc<dyn MobileWalletFactory>>,
    wallet_id: String,
) -> Result<Arc<MobileWallet>, MobileEngineError> {
    if wallet_id.is_empty() || wallet_id.len() > 256 || wallet_id.chars().any(char::is_control) {
        return Err(MobileEngineError::InvalidArgument);
    }
    // No registry lock is held across the foreign callback.
    registry
        .get()
        .ok_or(MobileEngineError::NotFound)?
        .open_wallet(wallet_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MissingWallet(AtomicUsize);

    impl MobileWalletFactory for MissingWallet {
        fn open_wallet(&self, _: String) -> Result<Arc<MobileWallet>, MobileEngineError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(MobileEngineError::NotFound)
        }
    }

    #[test]
    fn missing_bootstrap_fails_closed() {
        assert!(matches!(
            open_wallet(&OnceLock::new(), "primary".into()),
            Err(MobileEngineError::NotFound)
        ));
    }

    #[test]
    fn registration_cannot_replace_an_existing_factory() {
        let registry = OnceLock::new();
        let factory = Arc::new(MissingWallet(AtomicUsize::new(0)));
        install_factory(&registry, factory.clone()).unwrap();
        assert_eq!(
            install_factory(&registry, Arc::new(MissingWallet(AtomicUsize::new(0)))),
            Err(MobileEngineError::AlreadyExists)
        );
        assert!(matches!(
            open_wallet(&registry, "primary".into()),
            Err(MobileEngineError::NotFound)
        ));
        assert_eq!(factory.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn malformed_identifiers_do_not_call_the_native_host() {
        let registry = OnceLock::new();
        let factory = Arc::new(MissingWallet(AtomicUsize::new(0)));
        install_factory(&registry, factory.clone()).unwrap();
        for id in [String::new(), "a".repeat(257), "wallet\n".into()] {
            assert!(matches!(
                open_wallet(&registry, id),
                Err(MobileEngineError::InvalidArgument)
            ));
        }
        assert_eq!(factory.0.load(Ordering::SeqCst), 0);
    }
}
