# iOS background execution

The iOS integration uses a Notification Service Extension (NSE) to process an
NWC wake while the application is suspended or terminated. Swift owns Apple
lifecycle mechanics; Rust owns the Nostr and wallet behavior.

Use the [`NwcMobileApple`](../../apple/NwcMobileApple/README.md) package rather
than recreating NSE deadline, cancellation, queue, or completion logic.

## Required targets and capabilities

Configure the main application and NSE with:

- one shared App Group;
- one shared Keychain access group;
- the generated `nwc-mobile` Rust framework and bindings;
- the `NwcMobileApple` package;
- Push Notifications for the main application; and
- the correct APNs environment for each build configuration.

Both processes must resolve the same `nwc-mobile` data directory through the
App Group and the same wallet/Nostr secrets through the Keychain access group.

## NSE responsibilities

The wallet's `UNNotificationServiceExtension` subclass should only:

1. create an `NwcNotificationServiceAdapter` for the request;
2. pass the APNs dictionary through the shared payload adapter;
3. construct the wallet-specific Rust wake executor;
4. start work with a deadline below Apple's NSE limit;
5. forward `serviceExtensionTimeWillExpire()`; and
6. release the request after the completion handler runs.

The adapter guarantees one completion path and replaces untrusted notification
presentation fields with wallet-authored copy.

```swift
import NwcMobileApple
import UserNotifications

final class NotificationService: UNNotificationServiceExtension {
  private var adapter: NwcNotificationServiceAdapter?

  override func didReceive(
    _ request: UNNotificationRequest,
    withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
  ) {
    let adapter = makeWalletNwcAdapter()
    self.adapter = adapter
    adapter.didReceive(request, contentHandler: contentHandler)
  }

  override func serviceExtensionTimeWillExpire() {
    adapter?.timeWillExpire()
  }
}
```

Do not parse Nostr events, inspect NWC methods, authorize payments, or build
responses in Swift.

## APNs payload

Treat every field as untrusted routing input. The shared contract recognizes:

| Key | Required | Meaning |
| --- | --- | --- |
| `nwc_relay` | Yes | Candidate secure relay URL |
| `nwc_event_id` | Yes | Candidate Nostr request event id |
| `nwc_wallet_service_pubkey` | Yes | Candidate wallet-service public key |
| `nwc_event_json` | No | Optional bounded encrypted request event |
| `settlement_check` | No | Trusted targeted invoice-settlement intent |

Rust canonicalizes and validates the complete envelope. Push content must never
include a wallet seed, client or service secret, complete NWC URI, decrypted
request, invoice, amount, counterparty, or raw wallet error.

## App handoff and recovery

`NwcAppGroupWakeStore` and `NwcAppGroupWakeInbox` provide atomic cross-process
handoff. If the NSE cannot finish, enqueue the normalized request and let the
foreground application resubmit it through the same Rust engine. The shared
ledger, not the inbox, remains the replay authority.

On application launch and foregrounding:

- drain queued wake requests;
- reconcile unresolved payments;
- process wake-registration changes; and
- remove inbox entries only after the typed result permits it.

`NwcMaintenanceCoordinator` serializes reconciliation and registration passes
and propagates iOS background-task expiration into Rust cancellation.

## Notification presentation

Use wallet-authored localized strings selected from stable Rust outcome hints.
Never render remote error text or untrusted Nostr content. A completed wake does
not always require a visible notification; follow product policy while retaining
the system-required NSE completion behavior.

## Device testing

Simulator tests cannot validate APNs delivery, NSE launch, Keychain sharing, or
real suspension behavior. Test on a physical device with the application:

- foregrounded;
- backgrounded;
- force-terminated;
- locked; and
- restarted after an interrupted payment.

See [Testing an integration](../testing.md).
