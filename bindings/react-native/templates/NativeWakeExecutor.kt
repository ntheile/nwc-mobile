package org.nwc.mobile.example

import java.util.concurrent.CancellationException
import org.nwc.mobile.*
import org.nwc.mobile.android.NwcWakeCancellation
import org.nwc.mobile.android.NwcWakeExecutor
import org.nwc.mobile.android.NwcWakePayload
import org.nwc.mobile.android.NwcWakeWorkerDisposition

class NativeWakeCancellation : NwcWakeCancellation {
  val native = MobileCancellation()
  override fun cancel() = native.cancel()
}

/** Supply the wallet id from the trusted registry, never from FCM data. */
class NativeWakeExecutor(private val walletId: String) : NwcWakeExecutor {
  override suspend fun execute(
    payload: NwcWakePayload,
    executionMilliseconds: Long,
    cancellation: NwcWakeCancellation,
  ): NwcWakeWorkerDisposition {
    if (cancellation !is NativeWakeCancellation || executionMilliseconds <= 0 || payload.receivedAtSeconds < 0) {
      return NwcWakeWorkerDisposition.OPEN_APPLICATION
    }
    try {
      val wake = validateWakeEnvelope(MobileWakeEnvelope(
        relayUrl = payload.relayUrl,
        eventIdHex = payload.eventIdHex,
        walletServicePublicKeyHex = payload.walletServicePublicKeyHex,
        embeddedEventJson = null,
        receivedAtSeconds = payload.receivedAtSeconds.toULong(),
        settlementCheck = false,
      ))
      wake.use {
        openRegisteredMobileWallet(walletId).use { wallet ->
          wallet.engine().use { engine ->
            return when (engine.executeWake(wake, executionMilliseconds.toULong(), cancellation.native)) {
              is MobileWakeDisposition.Completed, is MobileWakeDisposition.AlreadyProcessed -> NwcWakeWorkerDisposition.COMPLETED
              is MobileWakeDisposition.RetryAfter -> NwcWakeWorkerDisposition.RETRY
              is MobileWakeDisposition.QueuedForApplication -> NwcWakeWorkerDisposition.OPEN_APPLICATION
              is MobileWakeDisposition.Rejected -> NwcWakeWorkerDisposition.REJECTED
            }
          }
        }
      }
    } catch (cancelled: CancellationException) {
      cancellation.cancel()
      throw cancelled
    } catch (_: Exception) {
      return NwcWakeWorkerDisposition.OPEN_APPLICATION
    }
  }
}
