# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project intends to use [Semantic Versioning](https://semver.org/) after its
public API stabilizes.

## Unreleased

### Added

- Durable NWC wake validation, replay protection, payment accounting, and
  reconciliation.
- Nostr Wallet Auth parsing and revision-bound connection lifecycle.
- UniFFI contracts with Swift NSE, Android WorkManager, and maintenance helpers.
- An optional Bark wallet adapter implementing the complete `WalletBackend`
  contract.
- Locked and checksum-verified Rust and Android dependency controls.

### Changed

- The minimum supported Rust version is now 1.90, matching the pinned Bark
  wallet revision used by the optional adapter.
