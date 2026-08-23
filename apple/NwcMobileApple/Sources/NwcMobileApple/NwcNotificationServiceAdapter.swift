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
  public let getInfoBody: String
  public let getBalanceBody: String
  public let payInvoiceBody: String
  public let makeInvoiceBody: String
  public let lookupInvoiceBody: String
  public let listTransactionsBody: String
  public let openApplicationTitle: String
  public let openApplicationBody: String

  public init(
    processingTitle: String,
    processingBody: String,
    completedTitle: String,
    completedBody: String,
    getInfoBody: String,
    getBalanceBody: String,
    payInvoiceBody: String,
    makeInvoiceBody: String,
    lookupInvoiceBody: String,
    listTransactionsBody: String,
    openApplicationTitle: String,
    openApplicationBody: String
  ) {
    self.processingTitle = processingTitle
    self.processingBody = processingBody
    self.completedTitle = completedTitle
    self.completedBody = completedBody
    self.getInfoBody = getInfoBody
    self.getBalanceBody = getBalanceBody
    self.payInvoiceBody = payInvoiceBody
    self.makeInvoiceBody = makeInvoiceBody
    self.lookupInvoiceBody = lookupInvoiceBody
    self.listTransactionsBody = listTransactionsBody
    self.openApplicationTitle = openApplicationTitle
    self.openApplicationBody = openApplicationBody
  }
}

/// Applies static wallet-owned copy and strips untrusted presentation fields.
public struct NwcNotificationPresenter: Sendable {
  private let copy: NwcNotificationCopy

  public init(copy: NwcNotificationCopy) {
    self.copy = copy
  }

  /// Returns sanitized content for a Rust-owned presentation hint.
  public func content(
    applying hint: NwcWakePresentationHint,
    to content: UNNotificationContent,
    userInfo: [AnyHashable: Any]? = nil
  ) -> UNNotificationContent {
    let mutableContent =
      (content.mutableCopy() as? UNMutableNotificationContent)
      ?? UNMutableNotificationContent()
    if let userInfo {
      mutableContent.userInfo = userInfo
    }
    apply(hint, to: mutableContent)
    return mutableContent
  }

  fileprivate func apply(
    _ hint: NwcWakePresentationHint,
    to content: UNMutableNotificationContent
  ) {
    content.subtitle = ""
    content.attachments = []
    content.categoryIdentifier = ""
    content.threadIdentifier = "nwc"
    content.badge = nil
    content.sound = nil
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
      content.interruptionLevel = .active
      content.title = copy.processingTitle
      content.body = copy.processingBody
    case .completed:
      // A successful background request requires no attention. Keep the alert
      // passive so it is grouped quietly in Notification Center without a
      // banner, sound, or interruption.
      content.interruptionLevel = .passive
      content.title = copy.completedTitle
      content.body = copy.completedBody
    case .request(let action):
      content.interruptionLevel = .passive
      content.title = copy.completedTitle
      content.body = requestBody(for: action)
    case .openApplication:
      content.interruptionLevel = .active
      content.title = copy.openApplicationTitle
      content.body = copy.openApplicationBody
    }
  }

  private func requestBody(for action: NwcWakeRequestAction) -> String {
    switch action {
    case .getInfo:
      copy.getInfoBody
    case .getBalance:
      copy.getBalanceBody
    case .payInvoice:
      copy.payInvoiceBody
    case .makeInvoice:
      copy.makeInvoiceBody
    case .lookupInvoice:
      copy.lookupInvoiceBody
    case .listTransactions:
      copy.listTransactionsBody
    }
  }
}

/// Thin `UNNotificationServiceExtension` adapter around the lifecycle coordinator.
public final class NwcNotificationServiceAdapter: @unchecked Sendable {
  private let coordinator: NwcNotificationServiceCoordinator
  private let presenter: NwcNotificationPresenter

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
    presenter = NwcNotificationPresenter(copy: copy)
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
      mutableContent.userInfo = [:]
      presenter.apply(.openApplication, to: mutableContent)
      contentHandler.call(mutableContent)
      return
    }

    didReceive(
      payload: payload,
      content: mutableContent,
      contentHandler: contentHandler.call
    )
  }

  /// Runs a payload already validated and normalized by the containing wallet.
  public func didReceive(
    payload: NwcWakePayload,
    content: UNNotificationContent,
    contentHandler: @escaping (UNNotificationContent) -> Void
  ) {
    let contentHandler = NwcContentHandler(contentHandler)
    let mutableContent =
      (content.mutableCopy() as? UNMutableNotificationContent)
      ?? UNMutableNotificationContent()
    mutableContent.userInfo = payload.normalizedUserInfo

    let started = coordinator.start(payload: payload) { [presenter] hint in
      presenter.apply(hint, to: mutableContent)
      contentHandler.call(mutableContent)
    }
    if !started {
      presenter.apply(.openApplication, to: mutableContent)
      contentHandler.call(mutableContent)
    }
  }

  /// Forwards the NSE expiration callback to cancellation and completion.
  public func timeWillExpire() {
    coordinator.timeWillExpire()
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
