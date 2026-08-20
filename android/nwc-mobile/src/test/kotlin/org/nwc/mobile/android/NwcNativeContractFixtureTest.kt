package org.nwc.mobile.android

import java.nio.file.Files
import java.nio.file.Path
import java.util.Properties
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NwcNativeContractFixtureTest {
  @Test
  fun sharedWakeFixtureDecodesAndOmitsEmbeddedEventFromWorkData() {
    val properties = Properties().apply {
      val fixture = Path.of(
        System.getProperty("user.dir"),
        "../../fixtures/mobile-wake-envelope.properties",
      ).normalize()
      Files.newInputStream(fixture).use(::load)
    }
    val decoded = decodeNwcWakePayload(
      remoteData = properties.stringPropertyNames().associateWith(properties::getProperty),
      receivedAtSeconds = 123,
    )

    assertTrue(decoded is NwcWakePayloadDecodeResult.Accepted)
    val payload = (decoded as NwcWakePayloadDecodeResult.Accepted).payload
    assertEquals("wss://relay.example/nwc", payload.relayUrl)
    assertEquals("a".repeat(64), payload.eventIdHex)
    assertEquals("b".repeat(64), payload.walletServicePublicKeyHex)
    assertNull(payload.toWorkData().getString(NwcWakePayloadKeys.EMBEDDED_EVENT))
  }
}
