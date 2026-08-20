package org.nwc.mobile.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NwcWakePayloadTest {
  @Test
  fun decodesAndCanonicalizesBoundedRoutingFields() {
    val decoded = decodeNwcWakePayload(validData(), receivedAtSeconds = 123)

    assertTrue(decoded is NwcWakePayloadDecodeResult.Accepted)
    val payload = (decoded as NwcWakePayloadDecodeResult.Accepted).payload
    assertEquals("a".repeat(64), payload.eventIdHex)
    assertEquals("b".repeat(64), payload.walletServicePublicKeyHex)
    assertEquals(123, payload.receivedAtSeconds)
  }

  @Test
  fun rejectsMissingInvalidAndOversizedFields() {
    assertEquals(
      NwcWakePayloadDecodeResult.Rejected(NwcWakePayloadError.MISSING_FIELD),
      decodeNwcWakePayload(emptyMap(), receivedAtSeconds = 1),
    )
    assertEquals(
      NwcWakePayloadDecodeResult.Rejected(NwcWakePayloadError.INVALID_FIELD),
      decodeNwcWakePayload(
        validData().toMutableMap().apply { put(NwcWakePayloadKeys.EVENT_ID, "not-hex") },
        receivedAtSeconds = 1,
      ),
    )
    assertEquals(
      NwcWakePayloadDecodeResult.Rejected(NwcWakePayloadError.INVALID_FIELD),
      decodeNwcWakePayload(
        validData().toMutableMap().apply {
          put(NwcWakePayloadKeys.RELAY_URL, "wss://" + "x".repeat(2_048))
        },
        receivedAtSeconds = 1,
      ),
    )
    assertEquals(
      NwcWakePayloadDecodeResult.Rejected(NwcWakePayloadError.INVALID_FIELD),
      decodeNwcWakePayload(
        validData().toMutableMap().apply {
          put(NwcWakePayloadKeys.EMBEDDED_EVENT, "x".repeat(64 * 1_024 + 1))
        },
        receivedAtSeconds = 1,
      ),
    )
  }

  @Test
  fun workDataOmitsEmbeddedCiphertextAndRoundTripsRouting() {
    val decoded = decodeNwcWakePayload(validData(), receivedAtSeconds = 123)
      as NwcWakePayloadDecodeResult.Accepted
    val workData = decoded.payload.toWorkData()

    assertNull(workData.getString(NwcWakePayloadKeys.EMBEDDED_EVENT))
    assertEquals(decoded, decodeNwcWakeWorkData(workData))
  }

  @Test
  fun uniqueNameIsCanonicalAndDoesNotExposeRoutingMetadata() {
    val first = decodeNwcWakePayload(validData(), 1) as NwcWakePayloadDecodeResult.Accepted
    val second = decodeNwcWakePayload(
      validData().toMutableMap().apply {
        put(NwcWakePayloadKeys.EVENT_ID, "a".repeat(64))
      },
      1,
    ) as NwcWakePayloadDecodeResult.Accepted

    assertEquals(first.payload.uniqueWorkName(), second.payload.uniqueWorkName())
    assertTrue(first.payload.uniqueWorkName().startsWith(NWC_WAKE_WORK_PREFIX))
    assertFalse(first.payload.uniqueWorkName().contains(first.payload.eventIdHex))
    assertFalse(first.payload.uniqueWorkName().contains("relay.example"))
  }

  private fun validData(): Map<String, String> = mapOf(
    NwcWakePayloadKeys.RELAY_URL to "wss://relay.example",
    NwcWakePayloadKeys.EVENT_ID to "A".repeat(64),
    NwcWakePayloadKeys.WALLET_SERVICE_PUBLIC_KEY to "B".repeat(64),
    NwcWakePayloadKeys.EMBEDDED_EVENT to "encrypted event that must not be persisted",
  )
}
