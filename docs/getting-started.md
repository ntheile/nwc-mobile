# Getting started

An `nwc-mobile` integration is complete when the same Rust-owned connection and
wake state can be used by the foreground application and by a cold-started iOS
or Android background process.

The application supplies six integration pieces. Implement them in the order
below so each layer can be tested before push delivery is introduced.

## 1. Define the application boundary

Choose one application-owned module as the composition root. It should:

- locate the shared application data directory;
- construct the secure secret provider;
- construct the approved Nostr relay transport;
- provide a way to open the existing Lightning wallet; and
- construct `NwcMobileConfig` and foreground `NwcApplicationManager` access.

Do not spread NWC policy across view models, platform callbacks, and wallet
SDK files. See [Configuring `NwcMobile`](integration/nwc-mobile.md).

## 2. Implement the Lightning node

Implement the six ordinary operations in `NwcLightningNode`:

1. get the spendable balance;
2. create an invoice;
3. quote an invoice without side effects;
4. start or resume an idempotent payment;
5. look up an invoice or payment; and
6. list normalized transactions.

Then implement `LightningNodeProvider` so a background process can open the
existing wallet without foreground state. The adapter owns wallet-specific
concepts such as Bark movements, LDK payment records, or custodial API models.
See [Implementing `NwcLightningNode`](integration/lightning-node.md).

## 3. Add foreground NWA and NWC workflows

The host renders library-provided presentation values and dispatches explicit
actions. At minimum, provide:

- a connection list and detail screen;
- manual connection creation and export, if the product supports it;
- connection revocation;
- an NWA approval screen; and
- app navigation for incoming NWA links.

The host does not parse NWA authority, construct connection secrets, expand
permissions, or build callbacks. See [Nostr Wallet Auth](integration/nwa.md) and
[NWA and NWC screens](integration/nwc-ui.md).

## 4. Wire the native background process

For iOS, the main application and NSE must use the same App Group data directory
and Keychain access group. The NSE passes the untrusted APNs payload and a
bounded execution window into Rust, then completes exactly once.

For Android, the FCM service schedules unique WorkManager work. The worker
constructs the Rust bridge, propagates cancellation, and maps only typed
dispositions to WorkManager results.

Use the supplied native packages instead of recreating deadline, queue, or
cancellation behavior. See [iOS background execution](integration/ios-background.md)
and [Android background execution](integration/android-background.md).

## 5. Register for wake delivery

Configure the APNs or FCM token, application and installation identifiers, and
secure wake-service endpoint. Process the durable registration outbox after:

- connection approval;
- push-token rotation;
- application foregrounding;
- connection revocation; and
- retryable registration failure.

Only acknowledge a registration after the server durably applies its revision.
See [Wake-service integration](integration/wake-server.md).

## 6. Deploy the wake service

The wake service is a separate project. It observes approved Nostr relays for
registered public connection identifiers and sends routing-only APNs or FCM
payloads. It must authenticate registration requests, enforce monotonic
connection revisions, and never receive connection secrets or decrypted NWC
content.

## Definition of done

Verify all of the following before enabling NWC by default:

- NWA approval displays the exact methods, budget, relays, and expiration that
  Rust validated.
- Revoked connections cannot be restored by stale registration or wake work.
- `pay_invoice` remains idempotent across timeout, cancellation, and process
  termination.
- Incoming and outgoing invoices become terminal through `lookup_invoice`.
- A duplicate wake never repeats a payment.
- A malformed, stale, unsigned, or unauthorized Nostr event never reaches the
  Lightning node.
- An iOS NSE wake succeeds with the main app terminated.
- An Android worker succeeds after process recreation.
- Expired background work is handed off or retried without losing durable
  state.
- Logs and notifications contain no wallet seed, secret key, NWC URI, invoice,
  payment details, push token, or remote error body.

Use the full [testing checklist](testing.md) for failure and physical-device
coverage.
