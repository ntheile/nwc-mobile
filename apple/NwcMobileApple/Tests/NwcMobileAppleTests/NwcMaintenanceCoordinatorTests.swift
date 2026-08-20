import Foundation
import XCTest

@testable import NwcMobileApple

private enum MaintenanceTestError: Error {
  case unavailable
}

private actor ControlledMaintenanceExecutor: NwcMaintenanceExecutor {
  private var paymentContinuation: CheckedContinuation<NwcPaymentMaintenanceReport, any Error>?
  private var registrationContinuation:
    CheckedContinuation<NwcRegistrationMaintenanceReport, any Error>?
  private(set) var registrationCallCount = 0

  func reconcilePayments(
    maximumAttempts _: UInt16,
    executionMilliseconds _: UInt64,
    cancellation _: any NwcWakeCancellation
  ) async throws -> NwcPaymentMaintenanceReport {
    try await withCheckedThrowingContinuation { paymentContinuation = $0 }
  }

  func processWakeRegistrations(
    maximumChanges _: UInt16,
    executionMilliseconds _: UInt64,
    cancellation _: any NwcWakeCancellation
  ) async throws -> NwcRegistrationMaintenanceReport {
    registrationCallCount += 1
    return try await withCheckedThrowingContinuation { registrationContinuation = $0 }
  }

  func resolvePayments(_ report: NwcPaymentMaintenanceReport) {
    paymentContinuation?.resume(returning: report)
    paymentContinuation = nil
  }

  func failPayments() {
    paymentContinuation?.resume(throwing: MaintenanceTestError.unavailable)
    paymentContinuation = nil
  }

  func resolveRegistrations(_ report: NwcRegistrationMaintenanceReport) {
    registrationContinuation?.resume(returning: report)
    registrationContinuation = nil
  }
}

final class NwcMaintenanceCoordinatorTests: XCTestCase {
  private let paymentReport = NwcPaymentMaintenanceReport(
    examined: 2,
    succeeded: 1,
    failed: 0,
    unresolved: 1,
    deferred: 0,
    interrupted: false,
    needsRetry: true
  )
  private let registrationReport = NwcRegistrationMaintenanceReport(
    examined: 1,
    applied: 1,
    deferred: 0,
    superseded: 0,
    interrupted: false,
    needsRetry: false
  )

  func testRunsBothPassesAndAggregatesRetryState() async {
    let executor = ControlledMaintenanceExecutor()
    let cancellation = TestCancellation()
    let coordinator = makeCoordinator(executor: executor, cancellation: cancellation)
    let completed = expectation(description: "maintenance completion")
    let result = LockedMaintenanceResult()

    XCTAssertTrue(
      coordinator.start { disposition in
        result.set(disposition)
        completed.fulfill()
      })
    await Task.yield()
    await executor.resolvePayments(paymentReport)
    await Task.yield()
    await executor.resolveRegistrations(registrationReport)
    await fulfillment(of: [completed], timeout: 1)

    XCTAssertEqual(
      result.value,
      .completed(payments: paymentReport, registrations: registrationReport)
    )
    XCTAssertEqual(result.value?.needsRetry, true)
    XCTAssertFalse(cancellation.isCancelled)
  }

  func testFailureRequestsRetryWithoutStartingRegistration() async {
    let executor = ControlledMaintenanceExecutor()
    let coordinator = makeCoordinator(executor: executor, cancellation: TestCancellation())
    let completed = expectation(description: "retry completion")
    let result = LockedMaintenanceResult()

    XCTAssertTrue(
      coordinator.start { disposition in
        result.set(disposition)
        completed.fulfill()
      })
    await Task.yield()
    await executor.failPayments()
    await fulfillment(of: [completed], timeout: 1)

    XCTAssertEqual(result.value, .retry)
    let registrationCallCount = await executor.registrationCallCount
    XCTAssertEqual(registrationCallCount, 0)
  }

  func testCancellationWinsRaceWithLateResult() async {
    let executor = ControlledMaintenanceExecutor()
    let cancellation = TestCancellation()
    let coordinator = makeCoordinator(executor: executor, cancellation: cancellation)
    let completed = expectation(description: "cancelled completion")
    completed.expectedFulfillmentCount = 1
    let result = LockedMaintenanceResult()

    XCTAssertTrue(
      coordinator.start { disposition in
        result.set(disposition)
        completed.fulfill()
      })
    await Task.yield()
    coordinator.cancel()
    await executor.resolvePayments(paymentReport)
    await fulfillment(of: [completed], timeout: 1)

    XCTAssertEqual(result.value, .cancelled)
    XCTAssertEqual(result.value?.needsRetry, true)
    XCTAssertTrue(cancellation.isCancelled)
  }

  func testRefusesOverlappingOrPostCancellationRuns() {
    let coordinator = makeCoordinator(
      executor: ControlledMaintenanceExecutor(),
      cancellation: TestCancellation()
    )

    XCTAssertTrue(coordinator.start { _ in })
    XCTAssertFalse(coordinator.start { _ in })
    coordinator.cancel()
    XCTAssertFalse(coordinator.start { _ in })
  }

  private func makeCoordinator(
    executor: ControlledMaintenanceExecutor,
    cancellation: TestCancellation
  ) -> NwcMaintenanceCoordinator {
    NwcMaintenanceCoordinator(
      executor: executor,
      cancellationFactory: { cancellation },
      paymentExecutionMilliseconds: 10_000,
      registrationExecutionMilliseconds: 5_000
    )
  }
}

private final class LockedMaintenanceResult: @unchecked Sendable {
  private let lock = NSLock()
  private var stored: NwcMaintenanceDisposition?

  var value: NwcMaintenanceDisposition? {
    lock.withLock { stored }
  }

  func set(_ value: NwcMaintenanceDisposition) {
    lock.withLock {
      stored = value
    }
  }
}
