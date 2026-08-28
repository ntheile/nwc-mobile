import Foundation
import XCTest

@testable import NwcMobileApple

final class NwcNativeContractFixtureTests: XCTestCase {
  func testSharedWakeFixtureDecodesWithExpectedKeys() throws {
    let values = try loadFixture()
    let decoded = try NwcWakePayload.decode(userInfo: values)

    XCTAssertEqual(decoded.relayURL, "wss://relay.example/nwc")
    XCTAssertEqual(decoded.eventIDHex, String(repeating: "a", count: 64))
    XCTAssertEqual(decoded.walletServicePublicKeyHex, String(repeating: "b", count: 64))
    XCTAssertEqual(decoded.embeddedEventJSON, "synthetic-encrypted-event")
  }

  private func loadFixture() throws -> [AnyHashable: Any] {
    var root = URL(fileURLWithPath: #filePath)
    for _ in 0..<5 {
      root.deleteLastPathComponent()
    }
    let fixture = root.appendingPathComponent(
      "fixtures/mobile-wake-envelope.properties"
    )
    let contents = try String(contentsOf: fixture, encoding: .utf8)
    return Dictionary(
      uniqueKeysWithValues: contents.split(separator: "\n").map { line in
        let pair = line.split(separator: "=", maxSplits: 1)
        return (AnyHashable(String(pair[0])), String(pair[1]))
      }
    )
  }
}
