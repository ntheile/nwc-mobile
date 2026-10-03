# React Native

The React Native integration is under development in `bindings/react-native`.
It uses `uniffi-bindgen-react-native` to call the existing Rust engine through
JSI. It does not implement NIP-47 or payment policy in JavaScript.

## The integration boundary

React Native owns connection screens and explicit NWA approval. Rust owns
authorization, durable request processing, budgets, replay protection, payment
reconciliation, and connection persistence. The wallet supplies its Lightning
backend and native secure storage. Native code handles push delivery and OS
execution deadlines.

Use a native `MobileWalletFactory` to open an existing wallet's
`MobileWallet`, which wraps a `MobileNwcEngine`, native defaults, and a
`MobileClientSecretStore`. Register it before starting React Native. The public JS
facade selects an opaque wallet identifier, not a database path or credentials.
The factory must resolve that identifier against the host's own registry and
reject unknown wallets. It must not implicitly create or restore a wallet.

Register independently in the application and background process. An iOS NSE
cannot use a JavaScript object, a Rust pointer, or a factory registration from
the containing application process. Both processes must reconstruct their
native backend and open the same App Group ledger and Keychain access group.
On Android, bootstrap the factory from application/service initialization even
when React Native has never started.

The native defaults contain the service public key, relays, and optional
Lightning address. The UI passes `MobileConnectionOptions`: approved methods,
budget, renewal interval, encryption, and expiry. Rust generates and securely
stores client keys through the existing application workflow. The normal
creation result contains no secret. Export a URI only for an explicit user
QR/share interaction, and never persist that URI in application state storage.

Registration is one-time per process. Duplicate registration is an error, not
a hot-swap operation. Opened engines keep their native dependencies alive.
Do not register a TypeScript callback factory for a background-capable wallet.
The generated callback interface is internal. This package removes automatic
JS callback registration during generation because UniFFI's vtables are
process-global: JS registration would overwrite the Swift/Kotlin implementation.
The transformation checks the exact callback inventory and keeps all ABI
version/checksum validation. Do not initialize an unmodified generated JS
module alongside the native bindings.

## Wallet-specific code

Implement `MobileWalletBackend` in Swift/Kotlin, or compose the Rust engine with
your own native backend. A Rust `NwcLightningNode` adapter can remain in your
wallet's Rust crate. Neither a Lexe nor an LNI dependency is required by this
package.

The current UniFFI engine constructor also takes `MobileRelayTransport` and
`MobileSecretProvider`. Keep these native and reuse them in your factory;
do not pass NWC secrets through JS for background execution. A JS-only Lightning
adapter would require a separate foreground-only integration; this package
intentionally does not register JavaScript callback implementations.

When linking a wallet-specific Rust composition crate, use a single copy of
the nwc-mobile UniFFI symbols in each process. Do not link a second static copy
of the same engine into the React Native module. On Android, the generated
Kotlin bridge and JSI wrapper must load the same Rust shared library so they
see the same factory registry. All generated bindings and native libraries
must come from the same source revision.

## Background integration

Use [the Apple helpers](../../apple/NwcMobileApple/README.md) for NSE expiration,
sanitized presentation, completion, and shared inbox handling. Use
[the Android helpers](../../android/nwc-mobile/README.md) for bounded wake work
and maintenance scheduling. The app still supplies its APNs/FCM configuration,
push provider registration, signing, entitlements, and native wallet factory.

Never start a React Native bridge inside the NSE. Parse and validate the push
through Rust, execute the native engine with an OS-bounded deadline and
cancellation, and finish via the platform helper. Push delivery and completion
within the execution window are not guaranteed by either mobile OS.

## Approval and secrets

Parsing an NWA link is not approval. Display the requesting identity as
unverified unless the native host has independently verified it; show the
methods, budget, expiry, and callback destination. Persist only an explicit
approval of the exact retained request. Callback delivery belongs to native
code. Do not use a generic browser-opening operation for secret-bearing
callbacks or log callback URLs, connection URIs, payment preimages, or secrets.

Generated 64-bit integer fields use `bigint`, including satoshi limits,
revisions, and timestamps. Do not silently convert them to JavaScript `number`.

## Verification status

The local example has been built for both iOS and Android. The iOS simulator
flow has exercised opening the native wallet, creating/listing/revoking a
read-only connection, and Keychain storage. Native Swift and Android API 35
arm64 smoke tests exercise connection export, NWA review/cancellation/approval,
revocation, and offline wake execution without starting JavaScript. Android's
test uses the real Keystore and can be repeated without reauthorizing a revoked
fixture identity. TypeScript tests additionally check bigint preservation,
explicit approval, and native callback-table ownership with ABI checks enabled.

Generated sources are deliberately excluded from Git. CI regenerates them;
the package's prepack check requires generated bindings and native libraries.
The distribution file allowlist excludes Android build caches. See the
[example instructions](../../bindings/react-native/example/README.md) to rerun
the native tests. These checks use an offline, read-only wallet, not real funds.

## Host acceptance checks before shipping

- Generate TS/C++ and Swift/Kotlin from the same Rust artifact and verify checksums.
- Compile the package and consuming native example on iOS and Android.
- Verify connection creation, explicit NWA approval, revocation, and UI refresh.
- With the React Native app terminated, deliver a real push and verify that
  the native backend processes it without starting JavaScript.
- Deliver duplicate requests concurrently to foreground/background processes;
  verify a payment is submitted once and its response can be replayed.
- Exercise extension expiration, cancellation, locked secure storage, network
  failure, ambiguous payment outcomes, and resume-time reconciliation.

TypeScript unit tests do not prove NSE or Android background execution works.
Use a native development build; this package cannot run inside Expo Go.

## Foreground payment handoff

A wallet whose payment adapters run in JavaScript can register the result of
`openForegroundMobileWallet(databasePath, relayUrls, secrets)` from native
bootstrap. This composition uses the real bounded Nostr transport and BOLT11
validator. It stores a random service key through `MobileClientSecretStore`,
using `nwc-mobile/foreground/service-key`. Serialize first-time construction and
use the same protected store and ledger in every native process.

This constructor permanently enables the foreground payment gate for its
ledger. It advertises `get_info`, `pay_invoice`, and connection-scoped
`lookup_invoice`. It does not implement balance queries or initiate Lightning
payments. Native push processing can authenticate and enqueue a payment while
JavaScript is stopped. `pollRequests()` provides bounded foreground relay
polling when push delivery is unavailable.

The host validates `metadataJson` from the exact retained NWA presentation
using its own application schema. These fields are unverified requester claims.
After explicit NWA approval, call
`bindConnectionPayment(connectionId, walletId, paymentHashHex, amountMsat,
maximumFeeSat)`. This immutable restriction binds the approved connection to
one invoice hash, exact principal, opaque host wallet, and explicit fee ceiling.
The total approved budget must cover principal plus the maximum fee. Requests
arriving before binding remain queued. A mismatched invoice is rejected.

The foreground execution sequence is:

1. Read `listPendingPayments()` and display the immutable payment details.
2. On explicit confirmation, call `beginPayment(eventIdHex, walletId)`. It
   commits a one-shot execution handoff before returning the request.
3. Execute through the selected wallet with the returned invoice, amount, and
   fee ceiling. Persist the event ID and payment hash in the wallet's durable
   payment record before submission.
4. Pass the wallet's verified preimage, exact principal, and actual routing fee
   to `completePayment`. Rust checks the preimage hash and principal and records
   the debit. An actual fee exceeding approval remains accounted and marked as
   a violation; a payment already made must not be reported as unpaid.
5. Call `resumePayment(eventIdHex)` to construct, persist, and publish the NIP-47
   response. Publication can be retried without paying again.

`rejectPayment` only works before handoff. `failPayment` requires authoritative
wallet evidence that the attempted payment definitively failed and cannot
later settle. Neither timeout nor cancellation proves failure. Both operations
refund their reservation and need `resumePayment` for response publication.

After a crash, an `in_flight` record retains the selected wallet, invoice,
event ID, payment hash, and fee ceiling. Reconcile it against the wallet's
existing durable payment. Never call the payment operation again merely
because the UI or transport lost its result. If the adapter cannot establish a
result, retain the ambiguous record for review. Complete with actual fees only;
do not invent zero fees or substitute the approved fee ceiling.

Successful results remain available to authorized `lookup_invoice` requests
for the same connection. Ordinary native automatic-payment compositions are
unchanged unless they explicitly enable the foreground gate. Use a separate
ledger when an application needs both modes.

### Android FCM registration

Foreground wallets expose
`processFcmWakeRegistrations(serverUrl, pushToken, appId, installId)`.
Supply the public HTTPS wake-server URL, native FCM token, application ID,
and a stable native installation ID. The method loads the service signing key
from protected native storage and sends NIP-98 authenticated, connection-scoped
registration changes. It never returns the key to JavaScript.

Approval and revocation enqueue registration and removal changes automatically.
On token or server configuration changes, call `refreshWakeRegistrations(true)`
then drain the outbox. Regular drains honor durable retry backoff; do not refresh
on every poll. The returned `applied` and `deferred` counts are bigint values;
`nextAttemptAt`, when present, is the earliest retry time in Unix seconds.
The pass handles at most 20 changes in 30 seconds. Keep the previous routing
configuration long enough to process removals if switching servers.

FCM data uses `protocol: "nwc_wake"`, `version: "v1"`, `nwc_relay`,
`nwc_event_id`, `nwc_wallet_service_pubkey`, and optional `nwc_event_json`.
Native wake handling must validate that the service public key belongs to the
locally registered account before executing the wake. The encrypted event is
verified by the engine; a push never authorizes spending. Post a generic visible
notification only after the engine has persisted an awaiting foreground payment.

### Exact invoice with wallet-managed extra costs

An explicitly approved wallet-managed flow uses NWA `fee_policy=wallet_managed`,
no `max_amount`, and `budget_renewal=never`. Automatic wallet compositions reject
this policy. Existing requests default to `capped`; `fee_policy=capped` is also
accepted. Applications must verify their display metadata agrees with the retained
native request's `feePolicy`.

Call `approveNwaWalletManagedPayment(requestId, options, walletId, invoice,
paymentHashHex, invoiceAmountMsat)`. Set `options.budgetLimitSat` to the invoice
principal rounded up to satoshis. This is an internal reservation, not a total
spending ceiling. The app must explicitly explain that the selected wallet
controls routing fees and any receiver overpayment required by its payment
implementation. The library does not invent a maximum cost.

The native method validates the signed BOLT11 amount/hash and retained NWA policy,
then binds the exact invoice bytes, principal, wallet, and one execution. A
foreground pay connection cannot publish its capability event before binding.
An interruption between connection creation and binding leaves an unbound,
unannounced connection that cannot spend; revoke it before starting a fresh
approval. A binding failure attempts revocation before returning the error.

Pending records retain `amountMsat` as the original invoice principal and expose
`feePolicy`; `maximumFeeSat` is absent for wallet-managed requests. After the
one-shot handoff, reconcile by the exact payment hash against the selected wallet.
Supply the actual recipient amount and actual routing fees separately to
`completePayment`. Wallet-managed results may have a recipient amount greater
than the invoice amount. Capped results still require exact recipient principal;
a verified successful payment exceeding its fee ceiling is recorded honestly
and marked as an authorization violation. Never turn a settled payment into a
reported failure because its fee exceeded approval.

Successful records expose `actualAmountMsat` and `feeMsat`. Migration from schema
14 backfills actual recipient amount only for existing successes because the old
completion contract required equality with invoice principal. Unsettled rows
remain unknown; later opens preserve recorded actual evidence.

Native WebSocket transport shares HTTP 429 cooldowns across polling, fetching,
and publication. It honors `Retry-After` seconds or an IMF-fixdate deadline,
with a one-second floor and five-minute maximum; missing or invalid headers use
60 seconds. This process-local cooldown preserves pending registration and
publication work. Restarting the process clears it, so avoid repeated restarts
while investigating relay throttling.

Expired connections are excluded from fresh relay polling. Expiry does not
prevent recovery of a byte-for-byte retained foreground payment event that
already has an initiation marker and still matches its active connection
revision. Recovery can reconcile the stored result and publish its response;
it cannot hand off payment again or authorize new pay, lookup, or info events.
The ledger records successful response publication after the relay ACK so
expired recovery work stops polling once delivered. Schema 16 defaults older
rows to unacknowledged because historical delivery cannot be proven; replaying
an already delivered response once is safe and does not repeat payment.

The native relay transport serializes work per relay and reuses a bounded idle
WebSocket session for foreground polls and publications. Each fetch uses a unique
subscription ID and sends `CLOSE` before returning the session to the pool.
Cancellation, incomplete subscriptions, transport failures, and rejected
publication acknowledgements discard that socket. Existing HTTP 429 cooldowns
still apply across all operations. Idle sessions are retired on the next access
after two minutes; no background listener or automatic payment is introduced.

For iOS, call
`processApnsWakeRegistrations(serverUrl, deviceToken, appId, installId, environment)`
with the native APNs token and an explicit `sandbox` or `production` environment.
There is no development-mode inference or default. The native facade signs the
registration using its secure service key and returns `applied`, `deferred`, and
optional `nextAttemptAt`, matching the FCM worker's retry behavior. Refresh the
registration outbox when routing values change. Provider secrets stay on the
notification server; the app supplies only its token and public routing values.

### Reusable foreground connections

Reusable grants are explicitly requested with `payment_mode=confirm_each`,
`budget_basis=invoice_principal`, `fee_policy=wallet_managed`, a `max_amount` in
millisatoshis, `budget_renewal=monthly`, and an expiration. The suggested app
policy is 500,000 sats per 30 days for 90 days; the native parser caps requests at
1,000,000 sats and 90 days. Native monthly periods are 30 days, not calendar
months. `approveNwaReusablePayment(requestId, options, walletId)` may reduce the
requested budget or expiry and pins the selected wallet before announcement.
Existing one-time connections keep their invoice restriction and single handoff.

Each reusable `pay_invoice` carries the signed encrypted `params.purchase` v1
context: `id`, `merchant` (`id`, `name`, HTTPS `origin`), `invoice_binding`
(`payment_hash`, decimal `principal_msats`), and unique
`requested_customer_fields` entries (`field`: email, phone, or address;
`required`: boolean). Merchant details are assertions by the authenticated
client, not independent identity verification. The native gate verifies the
invoice binding and exposes validated `purchaseJson` on the pending record.

Call `beginPaymentWithConsent(eventId, walletId, customerDataJson)` only after
explicit confirmation, including `{}` when no data was requested. It rejects
missing required or unsolicited fields, encrypts the selected values at rest,
and atomically claims one payment handoff. `completePayment` is unchanged.
Successful responses add `result.purchase = {id, customer_data}`; failed responses
contain no customer data. Replay uses the same cached signed response and consent.
The budget reserves and charges the requested invoice principal; actual recipient
amount and routing fees remain separately recorded even when the wallet pays more.

Browser repair does not create or renew a spending grant. Pass the selected
connection and the server's signed encrypted `authorize_browser` event to
`parseBrowserPairingChallenge(connectionId, signedEncryptedEventJson)`. Compare
the returned nonce and audience to the initiating app link, display the verified
challenge, then call `approveBrowserPairing(challengeId)` only after approval.
Its boolean reports relay delivery: false retains the same approved proof for
retry until challenge expiry. `cancelBrowserPairing` only cancels an unapproved
challenge. The native challenge is bound to the existing client, wallet,
connection revision, canonical HTTPS audience, nonce, and a maximum five-minute
expiry. Normal polling retains a challenge but cannot approve it. Signed
`get_info` results advertise purchase and browser-pairing version support and the
actual reusable policy; they are not browser-authorization proofs.

An NWA URI may also include `request_expires_at`, an optional decimal Unix timestamp
for approving the request. It is separate from the connection's `expires_at` and
cannot exceed that grant expiry. Native validates it when scanning and again
before creating authority. Hosts should observe `requestExpiresAtSeconds` on the
request presentation to disable stale approval screens and request a fresh QR.
Omitting it preserves existing NWA behavior.

NWA approval options may include `payerUsername` and `walletName` after explicit
review disclosure. These immutable per-connection fields appear only in encrypted
`get_info` as `payer_username` and `alias`, respectively. They never enter public
kind-13194 announcements. Existing connections have no username disclosure;
migration intentionally leaves it absent because prior consent cannot be inferred.
Revocation and browser re-pairing preserve the stored metadata and grant history.
