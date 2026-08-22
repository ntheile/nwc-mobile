import Foundation

/// Batteries-included App Group queue and diagnostic storage used by an app and its NSE.
///
/// Host applications remain responsible for emitting their own UI notifications after a
/// mutation; this type owns only cross-process persistence and bounded migration behavior.
public struct NwcAppGroupWakeStore: @unchecked Sendable {
  private let inbox: NwcAppGroupWakeInbox
  private let defaults: UserDefaults
  private let debugLog: NwcWakeDebugLog

  public init?(
    appGroupIdentifier: String,
    debugLogKey: String = "nwcWakeDebugLog",
    maximumDebugEntries: Int = 30
  ) {
    guard
      let defaults = UserDefaults(suiteName: appGroupIdentifier),
      let inbox = NwcAppGroupWakeInbox(appGroupIdentifier: appGroupIdentifier)
    else {
      return nil
    }
    self.init(
      inbox: inbox,
      defaults: defaults,
      debugLogKey: debugLogKey,
      maximumDebugEntries: maximumDebugEntries
    )
  }

  /// Creates a store over host-resolved components. This is also useful in tests.
  public init(
    inbox: NwcAppGroupWakeInbox,
    defaults: UserDefaults,
    debugLogKey: String = "nwcWakeDebugLog",
    maximumDebugEntries: Int = 30
  ) {
    self.inbox = inbox
    self.defaults = defaults
    debugLog = NwcWakeDebugLog(
      defaults: defaults,
      key: debugLogKey,
      maximumEntries: maximumDebugEntries
    )
  }

  /// Migrates the original flat queue and enqueues the new request idempotently.
  @discardableResult
  public func enqueue(
    _ request: NwcQueuedWakeRequest,
    legacyQueueKey: String? = nil
  ) throws -> Bool {
    if let legacyQueueKey {
      try inbox.migrateLegacyFlatQueue(from: defaults, key: legacyQueueKey)
    }
    try inbox.enqueue(request)
    return true
  }

  /// Migrates the original flat queue before returning pending requests.
  public func pendingRequests(legacyQueueKey: String? = nil) throws -> [NwcQueuedWakeRequest] {
    if let legacyQueueKey {
      try inbox.migrateLegacyFlatQueue(from: defaults, key: legacyQueueKey)
    }
    return try inbox.pendingRequests()
  }

  @discardableResult
  public func remove(eventIDs: Set<String>) throws -> Bool {
    try inbox.remove(eventIDs: eventIDs)
  }

  public func dataDirectoryURL(
    pathComponents: [String] = ["RustCore", "ApplicationSupport"]
  ) throws -> URL {
    try inbox.dataDirectoryURL(pathComponents: pathComponents)
  }

  public func appendDebug(source: String, message: String) throws {
    try debugLog.append(source: source, message: message)
  }

  public func debugEntries() throws -> [NwcWakeDebugEntry] {
    try debugLog.entries()
  }

  public func clearDebugEntries() {
    debugLog.clear()
  }

  /// Removes obsolete defaults and Keychain state from pre-file-inbox integrations.
  public func removeLegacyState(
    defaultsKeys: [String],
    keychainEntries: [(vault: NwcKeychainVault, key: String)] = []
  ) {
    defaultsKeys.forEach(defaults.removeObject(forKey:))
    keychainEntries.forEach { entry in
      entry.vault.deleteValue(forKey: entry.key)
    }
  }
}
