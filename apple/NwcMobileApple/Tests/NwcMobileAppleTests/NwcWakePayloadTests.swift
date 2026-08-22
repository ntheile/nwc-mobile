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
    XCTAssertEqual(payload.normalizedUserInfo.count, 4)
    XCTAssertEqual(
      payload.normalizedUserInfo[NwcWakePayloadKey.embeddedEvent] as? String,
      "{encrypted}"
    )
  }

  func testNormalizationDropsUnrecognizedNotificationFields() throws {
    let payload = try NwcWakePayload.decode(userInfo: [
      NwcWakePayloadKey.relayURL: "wss://relay.example",
      NwcWakePayloadKey.eventID: "event-id",
      NwcWakePayloadKey.walletServicePublicKey: "wallet-key",
      "title": "remote text",
      "category": "remote action",
    ])

    XCTAssertEqual(payload.normalizedUserInfo.count, 3)
    XCTAssertNil(payload.normalizedUserInfo["title"])
    XCTAssertNil(payload.normalizedUserInfo["category"])
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
