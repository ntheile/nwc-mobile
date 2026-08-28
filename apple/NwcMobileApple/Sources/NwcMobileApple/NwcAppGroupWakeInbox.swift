import Foundation

private let maximumLegacyQueueBytes = 8 * 1_024 * 1_024

/// App Group-backed paths and durable foreground handoff for an NWC wake.
///
/// The application and its notification service extension must create this
/// value with the same App Group identifier. Queue mutations retain the
/// cross-process locking and atomic replacement guarantees of
/// `NwcWakeFileInbox`.
public struct NwcAppGroupWakeInbox: Sendable {
  private struct LegacyFlatWakeRequest: Decodable {
    let payload: NwcWakePayload
    let receivedAt: UInt64

    private enum CodingKeys: String, CodingKey {
      case relay
      case eventId
      case walletServicePubkey
      case eventJson
      case receivedAt
    }

    init(from decoder: any Decoder) throws {
      let container = try decoder.container(keyedBy: CodingKeys.self)
      payload = try NwcWakePayload.validated(
        relayURL: container.decode(String.self, forKey: .relay),
        eventIDHex: container.decode(String.self, forKey: .eventId),
        walletServicePublicKeyHex: container.decode(String.self, forKey: .walletServicePubkey),
        embeddedEventJSON: container.decodeIfPresent(String.self, forKey: .eventJson)
      )
      receivedAt = try container.decode(UInt64.self, forKey: .receivedAt)
    }

    var queuedRequest: NwcQueuedWakeRequest {
      NwcQueuedWakeRequest(
        payload: payload,
        receivedAtSeconds: receivedAt
      )
    }
  }

  private let rootURL: URL
  private let inbox: NwcWakeFileInbox
  private let maxPendingRequests: Int

  /// Resolves an App Group container and returns `nil` when it is unavailable.
  public init?(
    appGroupIdentifier: String,
    queueDirectoryName: String = "NwcWakeInbox",
    maxPendingRequests: Int = 100,
    onEviction: (@Sendable (Int) -> Void)? = nil
  ) {
    guard
      !appGroupIdentifier.isEmpty,
      let rootURL = FileManager.default.containerURL(
        forSecurityApplicationGroupIdentifier: appGroupIdentifier
      )
    else {
      return nil
    }
    self.init(
      rootURL: rootURL,
      queueDirectoryName: queueDirectoryName,
      maxPendingRequests: maxPendingRequests,
      onEviction: onEviction
    )
  }

  /// Creates an inbox rooted at an already-authorized application container.
  ///
  /// This initializer is also useful to hosts that provide their own container
  /// resolution and to tests that use a temporary directory.
  public init(
    rootURL: URL,
    queueDirectoryName: String = "NwcWakeInbox",
    maxPendingRequests: Int = 100,
    onEviction: (@Sendable (Int) -> Void)? = nil
  ) {
    self.rootURL = rootURL
    self.maxPendingRequests = max(1, maxPendingRequests)
    inbox = NwcWakeFileInbox(
      directoryURL: rootURL.appendingPathComponent(queueDirectoryName, isDirectory: true),
      maxPendingRequests: self.maxPendingRequests,
      onEviction: onEviction
    )
  }

  /// Creates and returns an application-owned data directory below the App Group root.
  public func dataDirectoryURL(
    pathComponents: [String] = ["RustCore", "ApplicationSupport"]
  ) throws -> URL {
    guard
      !pathComponents.isEmpty,
      pathComponents.allSatisfy({ component in
        !component.isEmpty && component != "." && component != ".."
          && !component.contains("/") && !component.contains("\\")
      })
    else {
      throw CocoaError(.fileWriteInvalidFileName)
    }
    let directory = pathComponents.reduce(rootURL) { partial, component in
      partial.appendingPathComponent(component, isDirectory: true)
    }
    try FileManager.default.createDirectory(
      at: directory,
      withIntermediateDirectories: true
    )
    return directory
  }

  public func enqueue(_ request: NwcQueuedWakeRequest) throws {
    try inbox.enqueue(request)
  }

  public func pendingRequests() throws -> [NwcQueuedWakeRequest] {
    try inbox.pendingRequests()
  }

  @discardableResult
  public func remove(eventIDs: Set<String>) throws -> Bool {
    try inbox.remove(eventIDs: eventIDs)
  }

  /// Migrates the original flat JSON queue used by early wallet integrations.
  ///
  /// Enqueue is idempotent by event id, so interruption before the defaults key
  /// is removed remains safe to retry on the next process launch.
  @discardableResult
  public func migrateLegacyFlatQueue(
    from defaults: UserDefaults,
    key: String
  ) throws -> Bool {
    guard let data = defaults.data(forKey: key) else { return false }
    guard data.count <= maximumLegacyQueueBytes else {
      throw CocoaError(.fileReadTooLarge)
    }
    let requests = try JSONDecoder().decode([LegacyFlatWakeRequest].self, from: data)
    guard requests.count <= maxPendingRequests else {
      throw CocoaError(.fileReadCorruptFile)
    }
    for request in requests {
      try inbox.enqueue(request.queuedRequest)
    }
    defaults.removeObject(forKey: key)
    return true
  }
}
