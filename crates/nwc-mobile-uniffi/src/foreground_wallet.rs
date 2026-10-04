//! Native composition for wallets that execute user-approved payments in their foreground UI.
use crate::*;
use nwc_mobile::{
    AmountMsat, EventId, OperationBudget, OperationContext, RelayTransport, SecureRelayUrl,
};
use nwc_mobile_nostr::NostrRelayTransport;
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;
const SERVICE_KEY: &str = "nwc-mobile/foreground/service-key";

/// Opens a real native NWC service with BOLT11 validation and bounded Nostr transport.
/// Native bootstrap must serialize first-time key creation and share the protected store.
/// It never initiates Lightning payments. Register the returned wallet in the native factory.
#[uniffi::export]
pub fn open_foreground_mobile_wallet(
    database_path: String,
    relay_urls: Vec<String>,
    secrets: Arc<dyn MobileClientSecretStore>,
) -> Result<Arc<MobileWallet>, MobileEngineError> {
    for relay in &relay_urls {
        SecureRelayUrl::parse(relay).map_err(|_| MobileEngineError::InvalidArgument)?;
    }
    if relay_urls.is_empty() {
        return Err(MobileEngineError::InvalidArgument);
    }
    let encoded = Zeroizing::new(match secrets.load(SERVICE_KEY.into())? {
        Some(key) => key,
        None => {
            let key = nwc_mobile::generate_service_secret();
            secrets.store(SERVICE_KEY.into(), key.clone())?;
            key
        }
    });
    let (public_key, bytes) = nwc_mobile::service_secret_identity(&encoded)
        .map_err(|_| MobileEngineError::InvalidArgument)?;
    let _bytes = Zeroizing::new(bytes);
    let engine = MobileNwcEngine::open(
        database_path,
        Arc::new(ForegroundBackend),
        Arc::new(NativeRelays(
            nwc_mobile::PublicKey::from_hex(&public_key)
                .map_err(|_| MobileEngineError::InvalidArgument)?,
        )),
        Arc::new(NativeSecrets(secrets.clone())),
    )?;
    let wallet = MobileWallet::new(
        engine,
        MobileWalletConfig {
            wallet_service_public_key_hex: public_key,
            relay_urls,
            lud16: None,
        },
        secrets,
    );
    wallet.enable_foreground_payments()?;
    Ok(wallet)
}
struct NativeSecrets(Arc<dyn MobileClientSecretStore>);
impl MobileSecretProvider for NativeSecrets {
    fn load_nwc_secret(&self, _connection_id: String) -> Result<Vec<u8>, MobileHostError> {
        let key = Zeroizing::new(
            self.0
                .load(SERVICE_KEY.into())
                .map_err(|_| MobileHostError::Unavailable)?
                .ok_or(MobileHostError::Unavailable)?,
        );
        nwc_mobile::service_secret_identity(&key)
            .map(|(_, bytes)| bytes)
            .map_err(|_| MobileHostError::Rejected)
    }
}
struct NativeRelays(nwc_mobile::PublicKey);
#[async_trait::async_trait]
impl MobileRelayTransport for NativeRelays {
    async fn fetch_event(
        &self,
        relay_url: String,
        event_id_hex: String,
        maximum_event_bytes: u64,
        timeout_milliseconds: u64,
        cancellation: Arc<MobileCancellation>,
    ) -> Result<Option<String>, MobileHostError> {
        let recipient = self.0.clone();
        nwc_mobile_tokio::run_on_native_runtime(async move {
            let relay = SecureRelayUrl::parse(&relay_url)
                .map_err(|_| nwc_mobile::HostError::new(nwc_mobile::HostErrorKind::Rejected))?;
            let event = EventId::from_hex(&event_id_hex)
                .map_err(|_| nwc_mobile::HostError::new(nwc_mobile::HostErrorKind::Rejected))?;
            let budget = OperationBudget::new(Duration::from_millis(timeout_milliseconds))
                .map_err(|_| nwc_mobile::HostError::new(nwc_mobile::HostErrorKind::Rejected))?;
            NostrRelayTransport
                .fetch_event_for_recipient(
                    &relay,
                    &event,
                    &recipient,
                    usize::try_from(maximum_event_bytes).map_err(|_| {
                        nwc_mobile::HostError::new(nwc_mobile::HostErrorKind::Rejected)
                    })?,
                    OperationContext::new(budget, cancellation.as_ref()),
                )
                .await
        })
        .await
        .map_err(|_| MobileHostError::Unavailable)?
        .map_err(|_| MobileHostError::Unavailable)
    }
    async fn publish_event(
        &self,
        relay_url: String,
        event_json: String,
        timeout_milliseconds: u64,
        cancellation: Arc<MobileCancellation>,
    ) -> Result<(), MobileHostError> {
        nwc_mobile_tokio::run_on_native_runtime(async move {
            let relay = SecureRelayUrl::parse(&relay_url)
                .map_err(|_| nwc_mobile::HostError::new(nwc_mobile::HostErrorKind::Rejected))?;
            let budget = OperationBudget::new(Duration::from_millis(timeout_milliseconds))
                .map_err(|_| nwc_mobile::HostError::new(nwc_mobile::HostErrorKind::Rejected))?;
            NostrRelayTransport
                .publish_event(
                    &relay,
                    &event_json,
                    OperationContext::new(budget, cancellation.as_ref()),
                )
                .await
        })
        .await
        .map_err(|_| MobileHostError::Unavailable)?
        .map_err(|_| MobileHostError::Unavailable)
    }
}
struct ForegroundBackend;
#[async_trait::async_trait]
impl MobileWalletBackend for ForegroundBackend {
    async fn get_info(
        &self,
        _timeout_milliseconds: u64,
        _cancellation: Arc<MobileCancellation>,
    ) -> Result<MobileWalletInfo, MobileHostError> {
        Ok(MobileWalletInfo {
            public_key_hex: None,
            methods: vec![
                MobileNwcMethod::GetInfo,
                MobileNwcMethod::PayInvoice,
                MobileNwcMethod::LookupInvoice,
            ],
            notifications: vec![],
        })
    }
    async fn get_balance(
        &self,
        _timeout_milliseconds: u64,
        _cancellation: Arc<MobileCancellation>,
    ) -> Result<u64, MobileHostError> {
        Err(MobileHostError::Rejected)
    }
    async fn make_invoice(
        &self,
        _request: MobileMakeInvoiceRequest,
        _timeout_milliseconds: u64,
        _cancellation: Arc<MobileCancellation>,
    ) -> Result<MobileCreatedInvoice, MobileHostError> {
        Err(MobileHostError::Rejected)
    }
    async fn quote_payment(
        &self,
        invoice: String,
        amount_msat: Option<u64>,
        _timeout_milliseconds: u64,
        _cancellation: Arc<MobileCancellation>,
    ) -> Result<MobilePaymentQuote, MobileHostError> {
        let quote =
            nwc_mobile_bolt11::quote_invoice(&invoice, amount_msat.map(AmountMsat::from_msat))
                .map_err(|_| MobileHostError::Rejected)?;
        Ok(MobilePaymentQuote {
            payment_hash_hex: quote.payment_hash().to_hex(),
            principal_msat: quote.principal().as_msat(),
        })
    }
    async fn payment_status(
        &self,
        _payment_hash_hex: String,
        _timeout_milliseconds: u64,
        _cancellation: Arc<MobileCancellation>,
    ) -> Result<MobilePaymentStatus, MobileHostError> {
        Ok(MobilePaymentStatus::Unknown)
    }
    async fn start_payment(
        &self,
        _request: MobilePayInvoiceRequest,
        _timeout_milliseconds: u64,
        _cancellation: Arc<MobileCancellation>,
    ) -> Result<MobilePaymentStatus, MobileHostError> {
        Err(MobileHostError::Rejected)
    }
    async fn lookup_invoice(
        &self,
        _request: MobileInvoiceLookup,
        _timeout_milliseconds: u64,
        _cancellation: Arc<MobileCancellation>,
    ) -> Result<Option<MobileWalletTransaction>, MobileHostError> {
        Err(MobileHostError::Rejected)
    }
    async fn list_transactions(
        &self,
        _request: MobileListTransactionsRequest,
        _timeout_milliseconds: u64,
        _cancellation: Arc<MobileCancellation>,
    ) -> Result<Vec<MobileWalletTransaction>, MobileHostError> {
        Err(MobileHostError::Rejected)
    }
}
