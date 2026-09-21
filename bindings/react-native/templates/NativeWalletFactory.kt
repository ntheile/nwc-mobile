package org.nwc.mobile.example

import org.nwc.mobile.MobileWallet
import org.nwc.mobile.MobileWalletFactory

/** Native registry adapter. Install before RN and on service cold starts. */
class NativeWalletFactory(
  private val open: (String) -> MobileWallet,
) : MobileWalletFactory {
  override fun openWallet(walletId: String): MobileWallet = open(walletId)
}

// In Application/service bootstrap:
// registerMobileWalletFactory(NativeWalletFactory(registry::openNwcWallet))
//
// The registry validates walletId and constructs MobileWallet from:
// - MobileNwcEngine.open(sharedLedgerPath, backend, nativeRelays, serviceKeys)
// - MobileWalletConfig(servicePublicKey, relayUrls, lightningAddress)
// - your native MobileClientSecretStore implementation
//
// In NwcWakeExecutor, use openRegisteredMobileWallet(walletId).engine(), then
// validateWakeEnvelope and executeWake with the worker cancellation/deadline.
// This must work before React Native has started. Load the SAME Rust .so from
// both Kotlin/JNA and JSI; duplicate copies have separate factory registries.
