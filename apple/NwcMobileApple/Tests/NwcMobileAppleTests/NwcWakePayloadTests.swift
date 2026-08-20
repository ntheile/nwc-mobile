import XCTest

@testable import NwcMobileApple

final class NwcWakePayloadTests: XCTestCase {
  func testDecodesExpectedFieldsWithoutInterpretingSecrets() throws {
    let payload = try NwcWakePayload.decode(userInfo: [
      NwcWakePayloadKey.relayURL: "wss://relay.example",
      NwcWakePayloadKey.eventID: "event-id",
      NwcWakePayloadKey.walletServicePublicKey: "wallet-key",
      NwcWakePayloadKey.embeddedEvent: "{encrypted}",
    ])

    XCTAssertEqual(payload.relayURL, "wss://relay.example")
    XCTAssertEqual(payload.eventIDHex, "event-id")
    XCTAssertEqual(payload.walletServicePublicKeyHex, "wallet-key")
    XCTAssertEqual(payload.embeddedEventJSON, "{encrypted}")
  }

  func testRejectsMissingAndNonStringFields() {
    XCTAssertThrowsError(try NwcWakePayload.decode(userInfo: [:]))
    XCTAssertThrowsError(
      try NwcWakePayload.decode(userInfo: [
        NwcWakePayloadKey.relayURL: 42,
        NwcWakePayloadKey.eventID: "event-id",
        NwcWakePayloadKey.walletServicePublicKey: "wallet-key",
      ]))
  }
}
