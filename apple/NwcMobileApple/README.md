# NwcMobileApple

`NwcMobileApple` is the thin iOS lifecycle layer for `nwc-mobile`. It owns
Notification Service Extension (NSE) callback and expiration mechanics while
the Rust engine owns validation, authorization, durable replay protection, and
payment policy.

The package supports iOS 15 and newer. Its macOS target exists so the package's
platform-neutral lifecycle behavior can be tested in CI.

Wallet applications can add `https://github.com/ntheile/nwc-mobile` in Xcode
and select the `NwcMobileApple` library product. Pin an audited commit revision
while the package is pre-1.0; do not follow a mutable branch in production.

## Responsibilities

The package:

- parses only the expected APNs routing fields;
- creates one cancellation bridge and one asynchronous attempt per request;
- cancels work and chooses an open-app fallback when the NSE is expiring;
- resolves the completion path exactly once;
- provides an atomic, cross-process file inbox for NSE-to-app handoff; and
- removes untrusted notification presentation fields before applying static,
  wallet-localized generic copy.

It does not validate Nostr identifiers, access secrets, contact relays, approve
methods, or decide whether a payment can be retried. Those decisions stay in
the Rust engine exposed through the generated `NwcMobile` module.

## APNs payload

The wake provider supplies these custom keys alongside the normal `aps`
dictionary:

| Key | Required | Meaning |
| --- | --- | --- |
| `nwc_relay` | yes | Candidate secure relay URL; Rust validates it |
| `nwc_event_id` | yes | Candidate request event id; Rust validates it |
| `nwc_wallet_service_pubkey` | yes | Candidate wallet service public key; Rust validates it |
| `nwc_event_json` | no | Embedded encrypted request event; Rust bounds and validates it |

Treat the entire dictionary as untrusted. Never include a client secret,
complete NWC URI, decrypted request, invoice, amount, counterparty, or wallet
error in a push payload, notification string, log, or analytics event.

## NSE wiring

Create one adapter per notification request. The wallet-provided executor is a
small bridge to generated UniFFI types: construct `MobileWakeEnvelope` with the
current receive timestamp, call `validateWakeEnvelope`, then call
`MobileNwcEngine.executeWake` with the supplied execution budget and
cancellation bridge. Map only its `MobileNotificationHint` to
`NwcWakePresentationHint`; do not surface Rust or remote error text.

Wallets that validate the full APNs dictionary through Rust before constructing
the adapter can call `didReceive(payload:content:contentHandler:)` directly. The
adapter replaces `userInfo` with `NwcWakePayload.normalizedUserInfo`. Use
`NwcNotificationPresenter` to build the same sanitized open-application fallback
when shared storage or the Rust executor is unavailable.

```swift
import NwcMobileApple
import UserNotifications

final class NotificationService: UNNotificationServiceExtension {
    private var adapter: NwcNotificationServiceAdapter?

    override func didReceive(
        _ request: UNNotificationRequest,
        withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
    ) {
        let adapter = makeNwcAdapter() // Wallet-owned NwcWakeExecutor and copy.
        self.adapter = adapter
        adapter.didReceive(request, contentHandler: contentHandler)
    }

    override func serviceExtensionTimeWillExpire() {
        adapter?.timeWillExpire()
    }
}
```

Choose an execution budget below the NSE window and retain enough time for Rust
to checkpoint and for the completion handler to run. The application and NSE
must open the same app-group ledger and use the same Keychain access group.

## Foreground and background maintenance

`NwcMaintenanceCoordinator` serializes one bounded payment-reconciliation pass
and one wake-registration outbox pass. The wallet supplies an
`NwcMaintenanceExecutor` that maps generated `MobileNwcEngine` reports into the
package's aggregate report types. Call `cancel()` when an iOS background task
expires or before suspension; the coordinator cancels the shared Rust scope,
ignores late completion races, and completes exactly once without surfacing
wallet or provider error text.

Run the package tests with:

```sh
swift test --package-path apple/NwcMobileApple
```
