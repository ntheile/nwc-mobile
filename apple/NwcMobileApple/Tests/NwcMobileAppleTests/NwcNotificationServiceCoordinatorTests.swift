import Foundation
import XCTest

@testable import NwcMobileApple

final class TestCancellation: NwcWakeCancellation, @unchecked Sendable {
  private let lock = NSLock()
  private(set) var isCancelled = false

  func cancel() {
    lock.withLock {
      isCancelled = true
    }
  }
}

private actor ControlledExecutor: NwcWakeExecutor {
  private var continuation: CheckedContinuation<NwcWakePresentationHint, Never>?

  func execute(
    payload _: NwcWakePayload,
    executionMilliseconds _: UInt64,
    cancellation _: any NwcWakeCancellation
  ) async -> NwcWakePresentationHint {
    await withCheckedContinuation { continuation = $0 }
  }

  func resolve(_ hint: NwcWakePresentationHint) {
    continuation?.resume(returning: hint)
    continuation = nil
  }
}

final class NwcNotificationServiceCoordinatorTests: XCTestCase {
  private let payload = NwcWakePayload(
    relayURL: "wss://relay.example",
    eventIDHex: "event",
    walletServicePublicKeyHex: "wallet"
  )

  func testCompletesSuccessfulAttemptExactlyOnce() async {
    let executor = ControlledExecutor()
    let cancellation = TestCancellation()
    let coordinator = NwcNotificationServiceCoordinator(
      executor: executor,
      cancellationFactory: { cancellation },
      executionMilliseconds: 25_000
    )
    let completed = expectation(description: "completion")
    completed.expectedFulfillmentCount = 1
    let result = LockedResult()

    XCTAssertTrue(
      coordinator.start(payload: payload) { hint in
        result.set(hint)
        completed.fulfill()
      })
    await Task.yield()
    await executor.resolve(.completed)
    await fulfillment(of: [completed], timeout: 1)
    coordinator.timeWillExpire()

    XCTAssertEqual(result.value, .completed)
    XCTAssertFalse(cancellation.isCancelled)
  }

  func testExpirationCancelsAndWinsRaceWithLateResult() async {
    let executor = ControlledExecutor()
    let cancellation = TestCancellation()
    let coordinator = NwcNotificationServiceCoordinator(
      executor: executor,
      cancellationFactory: { cancellation },
      executionMilliseconds: 25_000
    )
    let completed = expectation(description: "expiration completion")
    completed.expectedFulfillmentCount = 1
    let result = LockedResult()

    XCTAssertTrue(
      coordinator.start(payload: payload) { hint in
        result.set(hint)
        completed.fulfill()
      })
    await Task.yield()
    coordinator.timeWillExpire()
    await executor.resolve(.completed)
    await fulfillment(of: [completed], timeout: 1)

    XCTAssertEqual(result.value, .openApplication)
    XCTAssertTrue(cancellation.isCancelled)
  }

  func testRefusesASecondStart() {
    let executor = ControlledExecutor()
    let cancellation = TestCancellation()
    let coordinator = NwcNotificationServiceCoordinator(
      executor: executor,
      cancellationFactory: { cancellation },
      executionMilliseconds: 1
    )

    XCTAssertTrue(coordinator.start(payload: payload) { _ in })
    XCTAssertFalse(coordinator.start(payload: payload) { _ in })
    coordinator.timeWillExpire()
  }

  func testExpirationBeforeStartPermanentlyRefusesWork() {
    let executor = ControlledExecutor()
    let cancellation = TestCancellation()
    let coordinator = NwcNotificationServiceCoordinator(
      executor: executor,
      cancellationFactory: { cancellation },
      executionMilliseconds: 1
    )

    coordinator.timeWillExpire()

    XCTAssertFalse(coordinator.start(payload: payload) { _ in })
  }
}

private final class LockedResult: @unchecked Sendable {
  private let lock = NSLock()
  private var stored: NwcWakePresentationHint?

  var value: NwcWakePresentationHint? {
    lock.withLock { stored }
  }

  func set(_ value: NwcWakePresentationHint) {
    lock.withLock {
      stored = value
    }
  }
}
