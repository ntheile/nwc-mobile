import Foundation
import XCTest

@testable import NwcMobileApple

final class NwcAppGroupWakeInboxTests: XCTestCase {
  private var temporaryDirectories: [URL] = []
  private var defaultsSuites: [String] = []

  override func tearDownWithError() throws {
    for directory in temporaryDirectories {
      try FileManager.default.removeItem(at: directory)
    }
    for suite in defaultsSuites {
      UserDefaults(suiteName: suite)?.removePersistentDomain(forName: suite)
    }
  }

  func testCreatesDataDirectoryAndDelegatesQueueOperations() throws {
    let root = makeTemporaryDirectory()
    let appInbox = NwcAppGroupWakeInbox(rootURL: root)
    let request = queuedRequest(eventID: "event", receivedAt: 5)

    let dataDirectory = try appInbox.dataDirectoryURL()
    try appInbox.enqueue(request)

    XCTAssertEqual(dataDirectory, root.appendingPathComponent("RustCore/ApplicationSupport"))
    XCTAssertTrue(FileManager.default.fileExists(atPath: dataDirectory.path))
    XCTAssertEqual(try appInbox.pendingRequests(), [request])
    XCTAssertTrue(try appInbox.remove(eventIDs: ["event"]))
    XCTAssertTrue(try appInbox.pendingRequests().isEmpty)
  }

  func testRejectsDataDirectoryTraversal() throws {
    let appInbox = NwcAppGroupWakeInbox(rootURL: makeTemporaryDirectory())

    XCTAssertThrowsError(try appInbox.dataDirectoryURL(pathComponents: ["..", "escape"]))
    XCTAssertThrowsError(try appInbox.dataDirectoryURL(pathComponents: ["nested/path"]))
  }

  func testMigratesLegacyFlatQueueIdempotently() throws {
    let appInbox = NwcAppGroupWakeInbox(rootURL: makeTemporaryDirectory())
    let defaults = makeUserDefaults()
    defaults.set(
      try JSONSerialization.data(withJSONObject: [
        [
          "relay": "wss://relay.example/path",
          "eventId": "event",
          "walletServicePubkey": "wallet",
          "eventJson": "{}",
          "receivedAt": 42,
        ]
      ]),
      forKey: "legacy"
    )

    XCTAssertTrue(try appInbox.migrateLegacyFlatQueue(from: defaults, key: "legacy"))
    XCTAssertNil(defaults.data(forKey: "legacy"))
    XCTAssertEqual(
      try appInbox.pendingRequests(),
      [
        NwcQueuedWakeRequest(
          payload: NwcWakePayload(
            relayURL: "wss://relay.example/path",
            eventIDHex: "event",
            walletServicePublicKeyHex: "wallet",
            embeddedEventJSON: "{}"
          ),
          receivedAtSeconds: 42
        )
      ]
    )
    XCTAssertFalse(try appInbox.migrateLegacyFlatQueue(from: defaults, key: "legacy"))
  }

  private func makeTemporaryDirectory() -> URL {
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try! FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    temporaryDirectories.append(directory)
    return directory
  }

  private func makeUserDefaults() -> UserDefaults {
    let suite = "NwcAppGroupWakeInboxTests.\(UUID().uuidString)"
    defaultsSuites.append(suite)
    return UserDefaults(suiteName: suite)!
  }

  private func queuedRequest(eventID: String, receivedAt: UInt64) -> NwcQueuedWakeRequest {
    NwcQueuedWakeRequest(
      payload: NwcWakePayload(
        relayURL: "wss://relay.example",
        eventIDHex: eventID,
        walletServicePublicKeyHex: "wallet-key"
      ),
      receivedAtSeconds: receivedAt
    )
  }
}
