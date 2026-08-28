# Rebel Wallet reference integration

[Rebel Wallet](https://github.com/ntheile/rebel-wallet/tree/nwc-wake) is the
current end-to-end reference for integrating `nwc-mobile` with a Bark Lightning
wallet and an iOS application.

Use it to understand file boundaries and lifecycle wiring. Do not copy
wallet-specific Bark behavior into another node implementation.

## Rust integration map

| Responsibility | Rebel Wallet file |
| --- | --- |
| `NwcMobile` composition, connection lifecycle, wake orchestration, and app-facing controller | [`nwc_mobile.rs`](https://github.com/ntheile/rebel-wallet/blob/nwc-wake/rebel-wallet-core/src/nwc/nwc_mobile.rs) |
| NWA application routing, approval selection, callback actions, and state updates | [`nwa.rs`](https://github.com/ntheile/rebel-wallet/blob/nwc-wake/rebel-wallet-core/src/nwc/nwa.rs) |
| Bark `NwcLightningNode`, wallet opening, payment recovery, and transaction conversion | [`nwc_bark.rs`](https://github.com/ntheile/rebel-wallet/blob/nwc-wake/rebel-wallet-core/src/nwc/nwc_bark.rs) |
| Small module exports | [`mod.rs`](https://github.com/ntheile/rebel-wallet/blob/nwc-wake/rebel-wallet-core/src/nwc/mod.rs) |

The Bark file's “movement” helpers are an example of wallet-specific adapter
code. Bark represents history as generic `Movement` records; the adapter maps
their direction, amount, fee, status, timestamps, payment hash, and preimage to
`WalletTransaction`. That conversion correctly remains in Rebel Wallet rather
than making `nwc-mobile` depend on Bark.

## iOS integration map

| Responsibility | Rebel Wallet file |
| --- | --- |
| Thin Swift state observation, typed action dispatch, and verified callback capability | [`NwcAppManager.swift`](https://github.com/ntheile/rebel-wallet/blob/nwc-wake/ios/Sources/NwcAppManager.swift) |
| Connection screens | [`NwcConnectionsView.swift`](https://github.com/ntheile/rebel-wallet/blob/nwc-wake/ios/Sources/Views/NwcConnectionsView.swift) |
| NWA approval screen | [`NwaWalletAuthApprovalView.swift`](https://github.com/ntheile/rebel-wallet/blob/nwc-wake/ios/Sources/Views/NwaWalletAuthApprovalView.swift) |
| Verified callback opening | [`NwaCallbackOpener.swift`](https://github.com/ntheile/rebel-wallet/blob/nwc-wake/ios/Sources/NwaCallbackOpener.swift) |
| NSE lifecycle adapter | [`NotificationService.swift`](https://github.com/ntheile/rebel-wallet/blob/nwc-wake/ios/NotificationService/NotificationService.swift) |
| Shared App Group wake inbox | [`NwcWakeInbox.swift`](https://github.com/ntheile/rebel-wallet/blob/nwc-wake/ios/Shared/NwcWakeInbox.swift) |
| Shared Keychain bridge | [`KeychainSecretStore.swift`](https://github.com/ntheile/rebel-wallet/blob/nwc-wake/ios/Shared/KeychainSecretStore.swift) |
| APNs registration and lifecycle | [`PushNotifications.swift`](https://github.com/ntheile/rebel-wallet/blob/nwc-wake/ios/Sources/PushNotifications.swift) |

The Swift manager does not parse Nostr or approve payments. It observes
Rust-owned state, dispatches typed actions, and performs bounded Apple
capabilities such as opening a verified URL.

## Wake service

The reference notification server is maintained separately under
[`ntheile/notification-server`](https://github.com/ntheile/notification-server/tree/nwc-wake).
The wallet uses the shared registration and settlement completion transports;
the service observes public connection identifiers and sends routing-only APNs
payloads.

## What to copy conceptually

- One Rust NWC application controller rather than NWC policy in UI code.
- One wallet-specific `NwcLightningNode` adapter.
- A cold-start provider that opens the same existing wallet in the NSE.
- Shared App Group ledger and Keychain namespaces.
- Rust-derived presentation models and typed application actions.
- A minimal NSE that delegates the entire wake to Rust.

## What not to copy

- Bark `Movement` conversion for a non-Bark wallet.
- Rebel-specific navigation, display strings, server choices, or wallet-open
  configuration.
- Generated Swift bindings; regenerate them from the pinned library revision.
- Test credentials, bundle identifiers, App Groups, or signing configuration.

When the reference and this documentation disagree, treat the pinned
`nwc-mobile` API and its tests as authoritative and open an issue to update the
stale guide.
