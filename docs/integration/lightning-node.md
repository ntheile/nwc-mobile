# Implementing `NwcLightningNode`

`NwcLightningNode` is the only wallet-specific Lightning behavior required by
the high-level runtime. It deliberately contains ordinary wallet operations,
not Nostr, NWA, wake, replay, or budget policy.

## Contract

```rust,ignore
pub trait NwcLightningNode: Send + Sync {
    fn get_balance(&self)
        -> HostFuture<'_, Result<AmountMsat, HostError>>;

    fn create_invoice(&self, request: MakeInvoiceRequest)
        -> HostFuture<'_, Result<CreatedInvoice, HostError>>;

    fn quote_invoice<'a>(&'a self, invoice: &'a str, amount: Option<AmountMsat>)
        -> HostFuture<'a, Result<PaymentQuote, HostError>>;

    fn pay_invoice(&self, request: PayInvoiceRequest)
        -> HostFuture<'_, Result<PaymentStatus, HostError>>;

    fn lookup_invoice(
        &self,
        request: InvoiceLookup,
        settlement_timeout: Option<Duration>,
    ) -> HostFuture<'_, Result<Option<WalletTransaction>, HostError>>;

    fn list_transactions(&self, request: ListTransactionsRequest)
        -> HostFuture<'_, Result<Vec<WalletTransaction>, HostError>>;
}
```

## Operation semantics

### Balance

Return the spendable Lightning balance in millisatoshis. Do not include funds
that the wallet cannot currently use for a Lightning payment.

### Create invoice

Honor the validated amount, description, and expiry. Return the encoded invoice,
payment hash, exact amount, and expiration through `CreatedInvoice`.

### Quote invoice

This operation must be side-effect free. Parse the invoice, resolve any
amountless value, and return the principal and required fee estimate. The engine
uses the quote to reserve authorized principal and maximum fee before it calls
`pay_invoice`.

### Pay invoice

Treat `PayInvoiceRequest::idempotency_key()` and the invoice payment hash as
replay inputs. Repeating the call after a timeout must resume or return the
existing payment, never start a second payment.

Return:

- `PaymentStatus::Succeeded` only with the real preimage, amount, and fee;
- `PaymentStatus::Pending` for an ambiguous or in-progress payment; or
- `PaymentStatus::Failed` only for a definite terminal failure.

A transport error after payment initiation is ambiguous. Return a host error or
pending result and preserve wallet-side state so `lookup_invoice` can reconcile
it later.

### Lookup invoice

Support lookup by payment hash and invoice. Normalize both incoming and outgoing
payments to `WalletTransaction`.

Ordinary NIP-47 lookups receive `settlement_timeout: None` and should perform one
bounded refresh. A trusted targeted settlement wake supplies a timeout; the
adapter may keep driving that exact incoming invoice until it settles or the
timeout expires.

### List transactions

Convert wallet-specific history into `WalletTransaction`, then use
`prepare_transaction_page` to apply the shared direction, time, unpaid,
pagination, sort, and result limits unless the wallet query already guarantees
identical semantics.

## Wallet-specific translation belongs here

Different SDKs model history differently. A Bark integration, for example,
converts generic Bark `Movement` records into NWC transaction direction,
amount, fee, status, timestamps, payment hash, and preimage. That translation
belongs in the Bark adapter because `nwc-mobile` must not depend on Bark.

The same rule applies to LDK payment records, an LND RPC response, or a
custodial service's transaction schema.

## Cold-start provider

Background execution also requires `LightningNodeProvider`:

```rust,ignore
let provider = LightningNodeProviderFn::new(move |request, context| {
    let wallet_config = wallet_config.clone();
    let secrets = secrets.clone();

    Box::pin(async move {
        if context.cancellation().is_cancelled() {
            return Err(HostError::new(HostErrorKind::Cancelled));
        }

        let wallet = open_existing_wallet(wallet_config, secrets, context).await?;
        let info = wallet_info(request.wallet_service_pubkey().clone());
        Ok(OpenedLightningNode::new(MyLightningNode::new(wallet), info))
    })
});
```

The provider must open an existing wallet. It must not silently create a new
wallet, select a different network, or depend on foreground in-memory state.
`ReadyLightningNodeProvider` is available when the application already owns an
open, cloneable wallet.

## Adapter test checklist

- Exact satoshi/millisatoshi conversion, including amountless invoices.
- Fee-limit rejection before payment initiation.
- Duplicate `pay_invoice` calls result in one payment.
- Pending payment recovery after recreating the adapter.
- Incoming settlement lookup after wallet synchronization.
- Successful status always contains the matching preimage.
- Direction, amount, fee, timestamps, and pagination for history conversion.
- Cancellation and timeout do not corrupt wallet state.

See the [Rebel Wallet reference](../rebel-wallet-example.md) for a concrete Bark
adapter.
