import XCTest

@testable import NwcMobileApple

final class NwcWakePayloadTests: XCTestCase {
  private let eventID = String(repeating: "A", count: 64)
  private let walletKey = String(repeating: "B", count: 64)

  func testDecodesExpectedFieldsWithoutInterpretingSecrets() throws {
    let payload = try NwcWakePayload.decode(userInfo: [
      NwcWakePayloadKey.relayURL: "wss://relay.example",
      NwcWakePayloadKey.eventID: eventID,
      NwcWakePayloadKey.walletServicePublicKey: walletKey,
      NwcWakePayloadKey.embeddedEvent: "{encrypted}",
    ])

    XCTAssertEqual(payload.relayURL, "wss://relay.example")
    XCTAssertEqual(payload.eventIDHex, eventID.lowercased())
    XCTAssertEqual(payload.walletServicePublicKeyHex, walletKey.lowercased())
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
      NwcWakePayloadKey.eventID: eventID,
      NwcWakePayloadKey.walletServicePublicKey: walletKey,
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
        NwcWakePayloadKey.eventID: eventID,
        NwcWakePayloadKey.walletServicePublicKey: walletKey,
      ]))
  }

  func testRejectsInvalidHexAndOversizedTransportFields() {
    XCTAssertThrowsError(
      try NwcWakePayload.decode(userInfo: [
        NwcWakePayloadKey.relayURL: "wss://relay.example",
        NwcWakePayloadKey.eventID: "not-hex",
        NwcWakePayloadKey.walletServicePublicKey: walletKey,
      ]))
    XCTAssertThrowsError(
      try NwcWakePayload.decode(userInfo: [
        NwcWakePayloadKey.relayURL: String(repeating: "x", count: 2_049),
        NwcWakePayloadKey.eventID: eventID,
        NwcWakePayloadKey.walletServicePublicKey: walletKey,
      ]))
    XCTAssertThrowsError(
      try NwcWakePayload.decode(userInfo: [
        NwcWakePayloadKey.relayURL: "wss://relay.example",
        NwcWakePayloadKey.eventID: eventID,
        NwcWakePayloadKey.walletServicePublicKey: walletKey,
        NwcWakePayloadKey.embeddedEvent: String(repeating: "x", count: 65_537),
      ]))
  }
}
