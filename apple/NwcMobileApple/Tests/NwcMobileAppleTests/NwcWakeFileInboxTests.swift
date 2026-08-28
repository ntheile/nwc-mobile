import Foundation
import XCTest

@testable import NwcMobileApple

final class NwcWakeFileInboxTests: XCTestCase {
  private var temporaryDirectories: [URL] = []

  override func tearDownWithError() throws {
    for directory in temporaryDirectories {
      try FileManager.default.removeItem(at: directory)
    }
    temporaryDirectories = []
  }

  func testDeduplicatesCapsAndAcknowledgesByEventID() throws {
    let inbox = makeInbox(maxPendingRequests: 2)
    try inbox.enqueue(request(eventID: "one", receivedAt: 1))
    try inbox.enqueue(request(eventID: "two", receivedAt: 2))
    try inbox.enqueue(request(eventID: "one", receivedAt: 3))

    XCTAssertEqual(
      try inbox.pendingRequests(),
      [request(eventID: "two", receivedAt: 2), request(eventID: "one", receivedAt: 3)]
    )

    try inbox.enqueue(request(eventID: "three", receivedAt: 4))
    XCTAssertEqual(
      try inbox.pendingRequests().map(\.eventIDHex),
      [fixedWakeHex("one"), fixedWakeHex("three")]
    )
    XCTAssertTrue(try inbox.remove(eventIDs: [fixedWakeHex("one").uppercased()]))
    XCTAssertEqual(try inbox.pendingRequests().map(\.eventIDHex), [fixedWakeHex("three")])
    XCTAssertFalse(try inbox.remove(eventIDs: ["missing"]))
  }

  func testSeparateInstancesDoNotLoseConcurrentEnqueues() throws {
    let directory = makeTemporaryDirectory()
    let failures = FailureRecorder()

    DispatchQueue.concurrentPerform(iterations: 40) { index in
      do {
        let inbox = NwcWakeFileInbox(
          directoryURL: directory,
          maxPendingRequests: 50
        )
        try inbox.enqueue(
          NwcQueuedWakeRequest(
            payload: NwcWakePayload(
              relayURL: "wss://relay.example",
              eventIDHex: fixedWakeHex("event-\(index)"),
              walletServicePublicKeyHex: String(repeating: "b", count: 64)
            ),
            receivedAtSeconds: UInt64(index)
          ))
      } catch {
        failures.record(error)
      }
    }

    XCTAssertTrue(failures.errors.isEmpty, "Unexpected errors: \(failures.errors)")
    let requests = try NwcWakeFileInbox(directoryURL: directory).pendingRequests()
    XCTAssertEqual(Set(requests.map(\.eventIDHex)).count, 40)
  }

  func testCorruptQueueIsNotSilentlyOverwritten() throws {
    let directory = makeTemporaryDirectory()
    let queueURL = directory.appendingPathComponent("pending.json")
    try Data("not-json".utf8).write(to: queueURL)
    let inbox = NwcWakeFileInbox(directoryURL: directory)

    XCTAssertThrowsError(try inbox.pendingRequests())
    XCTAssertThrowsError(try inbox.enqueue(request(eventID: "new", receivedAt: 1)))
    XCTAssertEqual(try Data(contentsOf: queueURL), Data("not-json".utf8))
  }

  func testBoundsEmbeddedCiphertextCanonicalizesIDsAndReportsEviction() throws {
    let directory = makeTemporaryDirectory()
    let recorder = EvictionRecorder()
    let inbox = NwcWakeFileInbox(
      directoryURL: directory,
      maxPendingRequests: 1,
      onEviction: { recorder.record($0) }
    )
    let firstID = String(repeating: "A", count: 64)
    try inbox.enqueue(
      NwcQueuedWakeRequest(
        payload: NwcWakePayload(
          relayURL: "wss://relay.example",
          eventIDHex: firstID,
          walletServicePublicKeyHex: String(repeating: "B", count: 64),
          embeddedEventJSON: "encrypted-remote-event"
        ),
        receivedAtSeconds: 1
      ))
    let pending = try inbox.pendingRequests()
    let first = try XCTUnwrap(pending.first)
    XCTAssertEqual(first.eventIDHex, firstID.lowercased())
    XCTAssertEqual(first.payload.embeddedEventJSON, "encrypted-remote-event")
    XCTAssertTrue(try inbox.remove(eventIDs: [firstID]))

    try inbox.enqueue(
      NwcQueuedWakeRequest(
        payload: NwcWakePayload(
          relayURL: "wss://relay.example",
          eventIDHex: firstID,
          walletServicePublicKeyHex: String(repeating: "B", count: 64),
          embeddedEventJSON: String(repeating: "x", count: 65_537)
        ),
        receivedAtSeconds: 2
      ))
    XCTAssertNil(try inbox.pendingRequests().first?.payload.embeddedEventJSON)

    try inbox.enqueue(request(eventID: "next", receivedAt: 3))
    XCTAssertEqual(recorder.count, 1)
  }

  func testLegacyQueueDefaultsToOrdinaryRequestIntent() throws {
    let eventID = fixedWakeHex("event")
    let walletKey = String(repeating: "b", count: 64)
    let legacy = """
      [{"payload":{"relayURL":"wss://relay.example","eventIDHex":"\(eventID)","walletServicePublicKeyHex":"\(walletKey)"},"receivedAtSeconds":1}]
      """
    let requests = try JSONDecoder().decode(
      [NwcQueuedWakeRequest].self,
      from: Data(legacy.utf8)
    )

    XCTAssertEqual(requests.count, 1)
    XCTAssertFalse(requests[0].settlementCheck)
  }

  func testRejectsOversizedInvalidAndOverCapacityPersistedQueues() throws {
    let oversizedDirectory = makeTemporaryDirectory()
    let oversizedURL = oversizedDirectory.appendingPathComponent("pending.json")
    try Data(repeating: 0x20, count: 8 * 1_024 * 1_024 + 1).write(to: oversizedURL)
    XCTAssertThrowsError(
      try NwcWakeFileInbox(directoryURL: oversizedDirectory).pendingRequests()
    )

    let invalidDirectory = makeTemporaryDirectory()
    let invalidURL = invalidDirectory.appendingPathComponent("pending.json")
    let invalid = """
      [{"payload":{"relayURL":"wss://relay.example","eventIDHex":"invalid","walletServicePublicKeyHex":"invalid"},"receivedAtSeconds":1}]
      """
    try Data(invalid.utf8).write(to: invalidURL)
    XCTAssertThrowsError(
      try NwcWakeFileInbox(directoryURL: invalidDirectory).pendingRequests()
    )

    let overCapacityDirectory = makeTemporaryDirectory()
    let overCapacityURL = overCapacityDirectory.appendingPathComponent("pending.json")
    try JSONEncoder().encode([
      request(eventID: "one", receivedAt: 1),
      request(eventID: "two", receivedAt: 2),
    ]).write(to: overCapacityURL)
    XCTAssertThrowsError(
      try NwcWakeFileInbox(
        directoryURL: overCapacityDirectory,
        maxPendingRequests: 1
      ).pendingRequests()
    )
  }

  private func makeInbox(maxPendingRequests: Int) -> NwcWakeFileInbox {
    NwcWakeFileInbox(
      directoryURL: makeTemporaryDirectory(),
      maxPendingRequests: maxPendingRequests
    )
  }

  private func makeTemporaryDirectory() -> URL {
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try! FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    temporaryDirectories.append(directory)
    return directory
  }

  private func request(eventID: String, receivedAt: UInt64) -> NwcQueuedWakeRequest {
    NwcQueuedWakeRequest(
      payload: NwcWakePayload(
        relayURL: "wss://relay.example",
        eventIDHex: fixedWakeHex(eventID),
        walletServicePublicKeyHex: String(repeating: "b", count: 64)
      ),
      receivedAtSeconds: receivedAt
    )
  }

}

private func fixedWakeHex(_ value: String) -> String {
  let prefix = value.utf8.map { String(format: "%02x", $0) }.joined()
  return String((prefix + String(repeating: "0", count: 64)).prefix(64))
}

private final class FailureRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var recordedErrors: [Error] = []

  var errors: [Error] {
    lock.withLock { recordedErrors }
  }

  func record(_ error: Error) {
    lock.withLock { recordedErrors.append(error) }
  }
}

private final class EvictionRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var recordedCount = 0

  var count: Int {
    lock.withLock { recordedCount }
  }

  func record(_ count: Int) {
    lock.withLock { recordedCount += count }
  }
}
