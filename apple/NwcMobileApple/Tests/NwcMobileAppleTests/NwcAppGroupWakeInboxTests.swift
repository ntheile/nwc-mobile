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
    let recorder = AppGroupEvictionRecorder()
    let appInbox = NwcAppGroupWakeInbox(
      rootURL: root,
      maxPendingRequests: 1,
      onEviction: { recorder.record($0) }
    )
    let request = queuedRequest(eventID: "event", receivedAt: 5)

    let dataDirectory = try appInbox.dataDirectoryURL()
    try appInbox.enqueue(request)

    XCTAssertEqual(dataDirectory, root.appendingPathComponent("RustCore/ApplicationSupport"))
    XCTAssertTrue(FileManager.default.fileExists(atPath: dataDirectory.path))
    XCTAssertEqual(try appInbox.pendingRequests(), [request])
    try appInbox.enqueue(queuedRequest(eventID: "second", receivedAt: 6))
    XCTAssertEqual(recorder.count, 1)
    XCTAssertTrue(try appInbox.remove(eventIDs: [fixedGroupHex("second")]))
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
          "eventId": fixedGroupHex("event"),
          "walletServicePubkey": String(repeating: "b", count: 64),
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
            eventIDHex: fixedGroupHex("event"),
            walletServicePublicKeyHex: String(repeating: "b", count: 64),
            embeddedEventJSON: "{}"
          ),
          receivedAtSeconds: 42
        )
      ]
    )
    XCTAssertFalse(try appInbox.migrateLegacyFlatQueue(from: defaults, key: "legacy"))
  }

  func testRejectsInvalidOrOverCapacityLegacyQueueBeforeMigration() throws {
    let defaults = makeUserDefaults()
    let appInbox = NwcAppGroupWakeInbox(
      rootURL: makeTemporaryDirectory(),
      maxPendingRequests: 1
    )
    defaults.set(
      try JSONSerialization.data(withJSONObject: [
        legacyRequest(eventID: fixedGroupHex("one")),
        legacyRequest(eventID: fixedGroupHex("two")),
      ]),
      forKey: "over-capacity"
    )
    XCTAssertThrowsError(
      try appInbox.migrateLegacyFlatQueue(from: defaults, key: "over-capacity")
    )
    XCTAssertNotNil(defaults.data(forKey: "over-capacity"))

    defaults.set(
      try JSONSerialization.data(withJSONObject: [legacyRequest(eventID: "invalid")]),
      forKey: "invalid"
    )
    XCTAssertThrowsError(
      try appInbox.migrateLegacyFlatQueue(from: defaults, key: "invalid")
    )
    XCTAssertNotNil(defaults.data(forKey: "invalid"))
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
        eventIDHex: fixedGroupHex(eventID),
        walletServicePublicKeyHex: String(repeating: "b", count: 64)
      ),
      receivedAtSeconds: receivedAt
    )
  }

  private func legacyRequest(eventID: String) -> [String: Any] {
    [
      "relay": "wss://relay.example/path",
      "eventId": eventID,
      "walletServicePubkey": String(repeating: "b", count: 64),
      "receivedAt": 42,
    ]
  }
}

private func fixedGroupHex(_ value: String) -> String {
  let prefix = value.utf8.map { String(format: "%02x", $0) }.joined()
  return String((prefix + String(repeating: "0", count: 64)).prefix(64))
}

private final class AppGroupEvictionRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var recordedCount = 0

  var count: Int {
    lock.withLock { recordedCount }
  }

  func record(_ count: Int) {
    lock.withLock { recordedCount += count }
  }
}
