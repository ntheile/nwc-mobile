# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project intends to use [Semantic Versioning](https://semver.org/) after its
public API stabilizes.

## Unreleased

- Simplified `NwcNode` construction by making `NwcNodeConfig` own the
  application-supplied `LightningNode`.

- Added an LNI-style `LightningNode` contract and Tokio `NwcNode` facade that
  own engine assembly, execution bounds, and settlement-notification workers.
- Added reusable application coordinators for NWA callback retries and
  process-local wake-registration refresh, execution, and timer decisions.
- Fixed application revocation and Apple legacy cleanup so transient Keychain
  deletion failures remain observable and retryable.
- Added an application workflow that atomically generates, stores, persists,
  exports, approves, and revokes wallet connections behind a narrow secret-store
  capability.
- Added shared native connection-view builders for wallet-created and NWA-approved
  connections so hosts do not reconstruct the same display model.
- Added configurable Apple Keychain and App Group wake-store helpers so apps and
  notification extensions only provide identifiers and UI notifications.
- Added a reusable Tokio exponential-backoff helper and public core/native enum
  conversions for thin host adapters.
- Added application-level connection validation, relay normalization, fee
  policy, export URI construction, and non-sensitive presentations.
- Added shared native connection, NWA session, wake-envelope, and wake-history
  records so containing wallets do not need parallel domain models.
- Aligned the UniFFI runtime and binding generator on the reviewed 0.31.1 ABI.
- Added `NwcMobileService`, a batteries-included facade that owns NWA sessions,
  host connection validation, legacy migration, durable usage, revocation, and
  wake-registration refresh state.
- Extended `MobileNwcEngine` so Swift and Kotlin hosts can use the same facade
  for NWA review/approval, legacy migration, idempotent host revocation, usage,
  and registration refresh without recreating Rust state machines.
- Added an idempotent, revision-bound host connection revocation API.
- Added a bounded Nostr info-event publisher so host wallets no longer need to
  coordinate relay validation, signing, budgeting, and transport themselves.
- Renamed the wallet host contract to `NwcWalletBackend` and moved
  wallet-specific backend implementations into their containing applications.

### Added

- Durable NWC wake validation, replay protection, payment accounting, and
  reconciliation.
- Nostr Wallet Auth parsing and revision-bound connection lifecycle.
- UniFFI contracts with Swift NSE, Android WorkManager, and maintenance helpers.
- A foreground wake coordinator for process-local ownership, bounded retries,
  and consistent engine-disposition handling.
- Shared native wake-envelope parsing, cancellation, bounded background
  execution, and host-engine assembly helpers.
- Apple payload normalization and generic notification presentation helpers for
  Rust-validated NSE wake requests and fail-closed fallback content.
- Bounded Apple App Group wake diagnostics with fail-closed corrupt-log handling.
- Host-string connection parsing and direct NWA connection approval with
  request-bound client, expiration, relay, method, and budget validation.
- Locked and checksum-verified Rust and Android dependency controls.

### Changed

- The minimum supported Rust version is now 1.90.
