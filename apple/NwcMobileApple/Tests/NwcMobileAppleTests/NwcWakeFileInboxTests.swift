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
      ["one", "three"]
    )
    XCTAssertTrue(try inbox.remove(eventIDs: ["one"]))
    XCTAssertEqual(try inbox.pendingRequests().map(\.eventIDHex), ["three"])
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
              eventIDHex: "event-\(index)",
              walletServicePublicKeyHex: "wallet-key"
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
        eventIDHex: eventID,
        walletServicePublicKeyHex: "wallet-key"
      ),
      receivedAtSeconds: receivedAt
    )
  }
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
