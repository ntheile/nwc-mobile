import Foundation

/// One wallet-authored, non-sensitive wake diagnostic.
public struct NwcWakeDebugEntry: Codable, Hashable, Identifiable, Sendable {
  public let id: String
  public let timestamp: UInt64
  public let source: String
  public let message: String

  public init(
    id: String = UUID().uuidString,
    source: String,
    message: String,
    timestamp: UInt64 = UInt64(Date().timeIntervalSince1970)
  ) {
    self.id = id
    self.timestamp = timestamp
    self.source = source
    self.message = message
  }

  public var timestampText: String {
    Date(timeIntervalSince1970: TimeInterval(timestamp)).formatted(
      date: .omitted,
      time: .standard
    )
  }
}

public enum NwcWakeDebugLogError: Error, Sendable, Equatable {
  case invalidEntry
  case invalidStoredLog
}

/// Bounded `UserDefaults` storage for wallet-authored wake diagnostics.
///
/// Callers must use static local messages and must never include request,
/// invoice, relay, secret, counterparty, or remote error text.
public struct NwcWakeDebugLog: @unchecked Sendable {
  private static let maximumEncodedBytes = 64 * 1024
  private static let maximumSourceBytes = 64
  private static let maximumMessageBytes = 512

  private let defaults: UserDefaults
  private let key: String
  private let maximumEntries: Int

  public init(
    defaults: UserDefaults,
    key: String = "nwcWakeDebugLog",
    maximumEntries: Int = 30
  ) {
    precondition(!key.isEmpty)
    precondition(maximumEntries > 0)
    self.defaults = defaults
    self.key = key
    self.maximumEntries = maximumEntries
  }

  public func entries() throws -> [NwcWakeDebugEntry] {
    guard let data = defaults.data(forKey: key) else {
      return []
    }
    guard data.count <= Self.maximumEncodedBytes else {
      throw NwcWakeDebugLogError.invalidStoredLog
    }
    let entries = try JSONDecoder().decode([NwcWakeDebugEntry].self, from: data)
    guard
      entries.count <= maximumEntries,
      entries.allSatisfy(Self.isValid)
    else {
      throw NwcWakeDebugLogError.invalidStoredLog
    }
    return entries
  }

  public func append(
    source: String,
    message: String,
    timestamp: UInt64 = UInt64(Date().timeIntervalSince1970)
  ) throws {
    let entry = NwcWakeDebugEntry(
      source: source,
      message: message,
      timestamp: timestamp
    )
    guard Self.isValid(entry) else {
      throw NwcWakeDebugLogError.invalidEntry
    }

    var entries = try entries()
    entries.append(entry)
    if entries.count > maximumEntries {
      entries.removeFirst(entries.count - maximumEntries)
    }
    let data = try JSONEncoder().encode(entries)
    guard data.count <= Self.maximumEncodedBytes else {
      throw NwcWakeDebugLogError.invalidEntry
    }
    defaults.set(data, forKey: key)
  }

  public func clear() {
    defaults.removeObject(forKey: key)
  }

  private static func isValid(_ entry: NwcWakeDebugEntry) -> Bool {
    !entry.id.isEmpty && entry.id.utf8.count <= 64
      && !entry.source.isEmpty && entry.source.utf8.count <= maximumSourceBytes
      && !entry.message.isEmpty && entry.message.utf8.count <= maximumMessageBytes
  }
}
