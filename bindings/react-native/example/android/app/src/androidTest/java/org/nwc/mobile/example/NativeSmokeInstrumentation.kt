package org.nwc.mobile.example

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import java.io.File
import java.util.UUID
import kotlinx.coroutines.runBlocking
import org.nwc.mobile.*

/** Exercises the real Rust/JNA callbacks and Keystore without launching an Activity or Hermes. */
class NativeSmokeInstrumentation : Instrumentation() {
    override fun onCreate(arguments: Bundle?) { super.onCreate(arguments); start() }
    override fun onStart() {
        val result = Bundle()
        var stage = "native bootstrap"
        try {
            waitForIdleSync()
            runBlocking {
                val wallet = openRegisteredMobileWallet("primary")
                stage = "create connection"
                val created = wallet.createConnection(MobileConnectionOptions(
                    listOf(MobileNwcMethod.GET_INFO), 0u, MobileBudgetInterval.NEVER,
                    MobileNwcEncryption.NIP44_V2, null))
                try {
                    stage = "export connection"
                    check(wallet.listConnections().any { it.connectionId == created.connectionId })
                    check(wallet.exportConnectionUri(created.connectionId).startsWith("nostr+walletconnect://"))
                    val wake = validateWakeEnvelope(MobileWakeEnvelope("wss://relay.example",
                        "ab".repeat(32),
                        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                        null, (System.currentTimeMillis() / 1000).toULong(), false))
                    stage = "offline wake"
                    check(wallet.engine().executeWake(wake, 500u, MobileCancellation()) is MobileWakeDisposition.RetryAfter)
                } finally {
                    stage = "revoke connection"
                    check(wallet.revokeConnection(created.connectionId))
                }
                check(wallet.listConnections().none { it.connectionId == created.connectionId })
                val requestUri = "nostr+walletauth://687dd8ece211539364549b1f32c63eceec1e0661009ba65cf8ff2e73ba000746?relay=wss%3A%2F%2Frelay.example.com"
                stage = "NWA approval"
                // A revoked client identity must not be reauthorized by replaying
                // a fixture. Give each test run its own NWA ledger instead.
                val nwaDirectory = File(targetContext.cacheDir, "nwa-smoke-${UUID.randomUUID()}")
                check(nwaDirectory.mkdir())
                val host = ExampleHost(targetContext)
                val nwaEngine = MobileNwcEngine.open(File(nwaDirectory, "nwc.sqlite").path, host, host, host)
                val nwaWallet = MobileWallet(nwaEngine, MobileWalletConfig(
                    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                    listOf("wss://relay.example"), null), host)
                try {
                val request = nwaWallet.parseNwaRequest(requestUri)
                check(nwaWallet.pendingNwaRequest()?.requestIdHex == request.requestIdHex)
                nwaWallet.cancelNwaRequest()
                check(nwaWallet.pendingNwaRequest() == null)
                val reviewed = nwaWallet.parseNwaRequest(requestUri)
                val approved = nwaWallet.approveNwaRequest(reviewed.requestIdHex,
                    MobileConnectionOptions(listOf(MobileNwcMethod.GET_INFO), 0u,
                        MobileBudgetInterval.NEVER, MobileNwcEncryption.NIP44_V2, null))
                try {
                    check(approved.callbackUrl == null)
                    check(nwaWallet.listConnections().any { it.connectionId == approved.connection.connectionId })
                } finally {
                    check(nwaWallet.revokeConnection(approved.connection.connectionId))
                }
                } finally {
                    nwaWallet.close()
                    nwaEngine.close()
                    nwaDirectory.deleteRecursively()
                }
            }
            result.putString("stream", "Native factory, Keystore, connection lifecycle, NWA approval, and offline wake passed without Hermes\n")
            finish(Activity.RESULT_OK, result)
        } catch (failure: Throwable) {
            // Never log exception messages or URIs from native secret operations.
            result.putString("stream", "Native smoke failed at $stage: ${failure.javaClass.simpleName}\n")
            finish(Activity.RESULT_CANCELED, result)
        }
    }
}
