import UserNotifications
import XCTest

@testable import NwcMobileApple

private struct ImmediateExecutor: NwcWakeExecutor {
  let hint: NwcWakePresentationHint

  func execute(
    payload _: NwcWakePayload,
    executionMilliseconds _: UInt64,
    cancellation _: any NwcWakeCancellation
  ) async -> NwcWakePresentationHint {
    hint
  }
}

final class NwcNotificationServiceAdapterTests: XCTestCase {
  func testReplacesAndSanitizesUntrustedPresentationFields() async throws {
    let adapter = NwcNotificationServiceAdapter(
      executor: ImmediateExecutor(hint: .completed),
      cancellationFactory: { TestCancellation() },
      executionMilliseconds: 1_000,
      copy: copy()
    )
    let original = UNMutableNotificationContent()
    original.title = "remote payment title"
    original.subtitle = "remote counterparty"
    original.body = "remote wallet error"
    original.categoryIdentifier = "REMOTE_ACTIONS"
    original.threadIdentifier = "remote-payment-id"
    original.badge = 9_999
    original.sound = .defaultCritical
    original.interruptionLevel = .critical
    original.relevanceScore = 1
    original.targetContentIdentifier = "remote-target"
    original.summaryArgument = "remote summary"
    original.summaryArgumentCount = 3
    #if os(iOS)
      original.filterCriteria = "remote-focus-filter"
      original.launchImageName = "remote-image"
    #endif
    original.userInfo = payload()
    let request = UNNotificationRequest(
      identifier: "test",
      content: original,
      trigger: nil
    )
    let completed = expectation(description: "notification completion")
    let result = LockedNotificationContent()

    adapter.didReceive(request) { content in
      result.set(content)
      completed.fulfill()
    }
    await fulfillment(of: [completed], timeout: 1)

    let content = try XCTUnwrap(result.value)
    XCTAssertEqual(content.title, "Request handled")
    XCTAssertEqual(content.body, "Open the wallet for details.")
    XCTAssertEqual(content.subtitle, "")
    XCTAssertEqual(content.categoryIdentifier, "")
    XCTAssertEqual(content.threadIdentifier, "nwc")
    XCTAssertNil(content.badge)
    XCTAssertNil(content.sound)
    XCTAssertEqual(content.interruptionLevel, .active)
    XCTAssertEqual(content.relevanceScore, 0)
    XCTAssertNil(content.targetContentIdentifier)
    XCTAssertEqual(content.summaryArgument, "")
    XCTAssertEqual(content.summaryArgumentCount, 0)
    #if os(iOS)
      XCTAssertNil(content.filterCriteria)
      XCTAssertEqual(content.launchImageName, "")
    #endif
    XCTAssertTrue(content.attachments.isEmpty)
  }

  func testMalformedPayloadFailsClosedWithoutRemoteText() {
    let adapter = NwcNotificationServiceAdapter(
      executor: ImmediateExecutor(hint: .completed),
      cancellationFactory: { TestCancellation() },
      executionMilliseconds: 1_000,
      copy: copy()
    )
    let original = UNMutableNotificationContent()
    original.title = "remote title"
    original.body = "remote body"
    let request = UNNotificationRequest(
      identifier: "invalid",
      content: original,
      trigger: nil
    )
    let completed = expectation(description: "fallback completion")
    let result = LockedNotificationContent()

    adapter.didReceive(request) { content in
      result.set(content)
      completed.fulfill()
    }
    wait(for: [completed], timeout: 1)

    XCTAssertEqual(result.value?.title, "Open wallet")
    XCTAssertEqual(result.value?.body, "Open the wallet to continue safely.")
  }

  private func payload() -> [AnyHashable: Any] {
    [
      NwcWakePayloadKey.relayURL: "wss://relay.example",
      NwcWakePayloadKey.eventID: "event-id",
      NwcWakePayloadKey.walletServicePublicKey: "wallet-key",
    ]
  }

  private func copy() -> NwcNotificationCopy {
    NwcNotificationCopy(
      processingTitle: "Processing request",
      processingBody: "Open the wallet for details.",
      completedTitle: "Request handled",
      completedBody: "Open the wallet for details.",
      openApplicationTitle: "Open wallet",
      openApplicationBody: "Open the wallet to continue safely."
    )
  }
}

private final class LockedNotificationContent: @unchecked Sendable {
  private let lock = NSLock()
  private var stored: UNNotificationContent?

  var value: UNNotificationContent? {
    lock.withLock { stored }
  }

  func set(_ value: UNNotificationContent) {
    lock.withLock {
      stored = value
    }
  }
}
