import Foundation
// Compile together with generated NwcMobile.swift, linked to the SAME Rust
// framework used by the React Native module (or the standalone NSE target).

/// Supply a native opener backed by your wallet registry and secure storage.
/// Register an instance once, before starting RN, and independently in the NSE.
final class NativeWalletFactory: MobileWalletFactory, @unchecked Sendable {
    private let open: @Sendable (String) throws -> MobileWallet

    init(open: @escaping @Sendable (String) throws -> MobileWallet) {
        self.open = open
    }

    func openWallet(walletId: String) throws -> MobileWallet {
        // The supplied registry must reject unknown IDs; never treat this as a
        // path, auto-create a wallet, or recover credentials from JavaScript.
        try open(walletId)
    }
}

// In native app/NSE bootstrap:
// try registerMobileWalletFactory(factory: NativeWalletFactory(open: registry.openNwcWallet))
//
// In registry.openNwcWallet:
// let engine = try MobileNwcEngine.open(databasePath: sharedLedgerPath,
//     wallet: lightningBackend, relays: nativeRelays, secrets: serviceKeyProvider)
// return MobileWallet(engine: engine, config: MobileWalletConfig(
//     walletServicePublicKeyHex: servicePublicKey, relayUrls: relays, lud16: nil),
//     secrets: nativeClientKeyStore)
//
// In the NSE's NwcWakeExecutor implementation, access this same native engine:
// let engine = try openRegisteredMobileWallet(walletId: walletId).engine()
// Then call validateWakeEnvelope and engine.executeWake with the cancellation
// and bounded deadline supplied by NwcMobileApple. Never instantiate RN here.
