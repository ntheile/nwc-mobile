package org.nwc.mobile.android

/** Generic worker result with no invoice, amount, counterparty, or error text. */
enum class NwcWakeWorkerDisposition {
  COMPLETED,
  RETRY,
  OPEN_APPLICATION,
  REJECTED,
}

/** Request-scoped bridge to the generated Rust `MobileCancellation`. */
fun interface NwcWakeCancellation {
  fun cancel()
}

/**
 * Wallet-owned bridge to the generated `NwcMobile` Kotlin API.
 *
 * Implementations construct and validate `MobileWakeEnvelope`, invoke
 * `MobileNwcEngine.executeWake`, and map only the stable lifecycle result.
 */
fun interface NwcWakeExecutor {
  suspend fun execute(
    payload: NwcWakePayload,
    executionMilliseconds: Long,
    cancellation: NwcWakeCancellation,
  ): NwcWakeWorkerDisposition
}

internal enum class NwcPlatformWorkResult {
  SUCCESS,
  RETRY,
}

internal fun NwcWakeWorkerDisposition.platformResult(): NwcPlatformWorkResult =
  when (this) {
    NwcWakeWorkerDisposition.RETRY -> NwcPlatformWorkResult.RETRY
    NwcWakeWorkerDisposition.COMPLETED,
    NwcWakeWorkerDisposition.OPEN_APPLICATION,
    NwcWakeWorkerDisposition.REJECTED,
    -> NwcPlatformWorkResult.SUCCESS
  }
