@preconcurrency import UserNotifications

/// Wallet-localized generic notification copy.
///
/// Values must be static application resources and must not be derived from a
/// decrypted request, wallet response, relay response, or error string.
public struct NwcNotificationCopy: Sendable, Equatable {
  public let processingTitle: String
  public let processingBody: String
  public let completedTitle: String
  public let completedBody: String
  public let openApplicationTitle: String
  public let openApplicationBody: String

  public init(
    processingTitle: String,
    processingBody: String,
    completedTitle: String,
    completedBody: String,
    openApplicationTitle: String,
    openApplicationBody: String
  ) {
    self.processingTitle = processingTitle
    self.processingBody = processingBody
    self.completedTitle = completedTitle
    self.completedBody = completedBody
    self.openApplicationTitle = openApplicationTitle
    self.openApplicationBody = openApplicationBody
  }
}

/// Thin `UNNotificationServiceExtension` adapter around the lifecycle coordinator.
public final class NwcNotificationServiceAdapter: @unchecked Sendable {
  private let coordinator: NwcNotificationServiceCoordinator
  private let copy: NwcNotificationCopy

  public init(
    executor: any NwcWakeExecutor,
    cancellationFactory: @escaping NwcWakeCancellationFactory,
    executionMilliseconds: UInt64,
    copy: NwcNotificationCopy
  ) {
    coordinator = NwcNotificationServiceCoordinator(
      executor: executor,
      cancellationFactory: cancellationFactory,
      executionMilliseconds: executionMilliseconds
    )
    self.copy = copy
  }

  /// Decodes the APNs envelope, runs Rust-owned policy, and completes once.
  public func didReceive(
    _ request: UNNotificationRequest,
    contentHandler: @escaping (UNNotificationContent) -> Void
  ) {
    let contentHandler = NwcContentHandler(contentHandler)
    let mutableContent =
      (request.content.mutableCopy() as? UNMutableNotificationContent)
      ?? UNMutableNotificationContent()
    let payload: NwcWakePayload
    do {
      payload = try NwcWakePayload.decode(userInfo: request.content.userInfo)
    } catch {
      apply(.openApplication, to: mutableContent)
      contentHandler.call(mutableContent)
      return
    }

    let started = coordinator.start(payload: payload) { [copy] hint in
      Self.apply(hint, copy: copy, to: mutableContent)
      contentHandler.call(mutableContent)
    }
    if !started {
      apply(.openApplication, to: mutableContent)
      contentHandler.call(mutableContent)
    }
  }

  /// Forwards the NSE expiration callback to cancellation and completion.
  public func timeWillExpire() {
    coordinator.timeWillExpire()
  }

  private func apply(
    _ hint: NwcWakePresentationHint,
    to content: UNMutableNotificationContent
  ) {
    Self.apply(hint, copy: copy, to: content)
  }

  private static func apply(
    _ hint: NwcWakePresentationHint,
    copy: NwcNotificationCopy,
    to content: UNMutableNotificationContent
  ) {
    content.subtitle = ""
    content.attachments = []
    content.categoryIdentifier = ""
    content.threadIdentifier = "nwc"
    content.badge = nil
    content.sound = nil
    content.interruptionLevel = .active
    content.relevanceScore = 0
    content.targetContentIdentifier = nil
    content.summaryArgument = ""
    content.summaryArgumentCount = 0
    #if os(iOS)
      if #available(iOS 16.0, *) {
        content.filterCriteria = nil
      }
      content.launchImageName = ""
    #endif

    switch hint {
    case .processing:
      content.title = copy.processingTitle
      content.body = copy.processingBody
    case .completed:
      content.title = copy.completedTitle
      content.body = copy.completedBody
    case .openApplication:
      content.title = copy.openApplicationTitle
      content.body = copy.openApplicationBody
    }
  }
}

private final class NwcContentHandler: @unchecked Sendable {
  private let handler: (UNNotificationContent) -> Void

  init(_ handler: @escaping (UNNotificationContent) -> Void) {
    self.handler = handler
  }

  func call(_ content: UNNotificationContent) {
    handler(content)
  }
}
