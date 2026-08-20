package org.nwc.mobile.android

import androidx.work.Data
import java.security.MessageDigest
import java.util.Locale

/** Untrusted routing fields decoded from an FCM data message. */
@ConsistentCopyVisibility
data class NwcWakePayload internal constructor(
  val relayUrl: String,
  val eventIdHex: String,
  val walletServicePublicKeyHex: String,
  val receivedAtSeconds: Long,
)

/** Non-sensitive reason an FCM envelope could not be queued. */
enum class NwcWakePayloadError {
  MISSING_FIELD,
  INVALID_FIELD,
}

/** Result of bounded native decoding before Rust performs protocol validation. */
sealed interface NwcWakePayloadDecodeResult {
  data class Accepted(val payload: NwcWakePayload) : NwcWakePayloadDecodeResult

  data class Rejected(val error: NwcWakePayloadError) : NwcWakePayloadDecodeResult
}

object NwcWakePayloadKeys {
  const val RELAY_URL = "nwc_relay"
  const val EVENT_ID = "nwc_event_id"
  const val WALLET_SERVICE_PUBLIC_KEY = "nwc_wallet_service_pubkey"
  const val EMBEDDED_EVENT = "nwc_event_json"
}

internal const val NWC_WAKE_WORK_TAG = "nwc-mobile-wake"
internal const val NWC_WAKE_WORK_PREFIX = "nwc-mobile-wake:"
private const val MAX_RELAY_URL_BYTES = 2_048
private const val MAX_EMBEDDED_EVENT_BYTES = 64 * 1_024
private const val HEX_KEY_LENGTH = 64

/**
 * Performs only bounded transport decoding.
 *
 * The optional embedded event is intentionally not copied into WorkManager's
 * database. Android execution fetches the exact event from the Rust-approved
 * relay, avoiding WorkManager's small input-data limit and another ciphertext
 * persistence location.
 */
fun decodeNwcWakePayload(
  remoteData: Map<String, String>,
  receivedAtSeconds: Long = System.currentTimeMillis() / 1_000,
): NwcWakePayloadDecodeResult {
  fun required(key: String): String? = remoteData[key]?.takeIf(String::isNotEmpty)

  val relayUrl = required(NwcWakePayloadKeys.RELAY_URL)
    ?: return NwcWakePayloadDecodeResult.Rejected(NwcWakePayloadError.MISSING_FIELD)
  val eventId = required(NwcWakePayloadKeys.EVENT_ID)
    ?: return NwcWakePayloadDecodeResult.Rejected(NwcWakePayloadError.MISSING_FIELD)
  val walletKey = required(NwcWakePayloadKeys.WALLET_SERVICE_PUBLIC_KEY)
    ?: return NwcWakePayloadDecodeResult.Rejected(NwcWakePayloadError.MISSING_FIELD)
  val embeddedEvent = remoteData[NwcWakePayloadKeys.EMBEDDED_EVENT]

  if (
    receivedAtSeconds < 0 ||
      relayUrl.length > MAX_RELAY_URL_BYTES ||
      relayUrl.toByteArray(Charsets.UTF_8).size > MAX_RELAY_URL_BYTES ||
      embeddedEvent?.let {
        it.length > MAX_EMBEDDED_EVENT_BYTES ||
          it.toByteArray(Charsets.UTF_8).size > MAX_EMBEDDED_EVENT_BYTES
      } == true ||
      !eventId.isFixedHex() ||
      !walletKey.isFixedHex()
  ) {
    return NwcWakePayloadDecodeResult.Rejected(NwcWakePayloadError.INVALID_FIELD)
  }

  return NwcWakePayloadDecodeResult.Accepted(
    NwcWakePayload(
      relayUrl = relayUrl,
      eventIdHex = eventId.lowercase(Locale.ROOT),
      walletServicePublicKeyHex = walletKey.lowercase(Locale.ROOT),
      receivedAtSeconds = receivedAtSeconds,
    )
  )
}

internal fun NwcWakePayload.toWorkData(): Data =
  Data.Builder()
    .putString(NwcWakePayloadKeys.RELAY_URL, relayUrl)
    .putString(NwcWakePayloadKeys.EVENT_ID, eventIdHex)
    .putString(NwcWakePayloadKeys.WALLET_SERVICE_PUBLIC_KEY, walletServicePublicKeyHex)
    .putLong(RECEIVED_AT_SECONDS, receivedAtSeconds)
    .build()

internal fun decodeNwcWakeWorkData(data: Data): NwcWakePayloadDecodeResult {
  val remoteData = buildMap {
    data.getString(NwcWakePayloadKeys.RELAY_URL)?.let {
      put(NwcWakePayloadKeys.RELAY_URL, it)
    }
    data.getString(NwcWakePayloadKeys.EVENT_ID)?.let {
      put(NwcWakePayloadKeys.EVENT_ID, it)
    }
    data.getString(NwcWakePayloadKeys.WALLET_SERVICE_PUBLIC_KEY)?.let {
      put(NwcWakePayloadKeys.WALLET_SERVICE_PUBLIC_KEY, it)
    }
  }
  return decodeNwcWakePayload(
    remoteData = remoteData,
    receivedAtSeconds = data.getLong(RECEIVED_AT_SECONDS, -1),
  )
}

internal fun NwcWakePayload.uniqueWorkName(): String {
  val digest = MessageDigest.getInstance("SHA-256").digest(eventIdHex.toByteArray(Charsets.US_ASCII))
  return NWC_WAKE_WORK_PREFIX + digest.joinToString(separator = "") {
    "%02x".format(Locale.ROOT, it.toInt() and 0xff)
  }
}

private fun String.isFixedHex(): Boolean =
  length == HEX_KEY_LENGTH && all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

private const val RECEIVED_AT_SECONDS = "nwc_received_at_seconds"
