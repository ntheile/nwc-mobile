import Darwin
import Foundation

/// A durable foreground handoff for a wake request that could not finish in an NSE.
public struct NwcQueuedWakeRequest: Sendable, Equatable, Codable {
  public let payload: NwcWakePayload
  public let receivedAtSeconds: UInt64
  public let settlementCheck: Bool

  public init(
    payload: NwcWakePayload,
    receivedAtSeconds: UInt64,
    settlementCheck: Bool = false
  ) {
    self.payload = payload
    self.receivedAtSeconds = receivedAtSeconds
    self.settlementCheck = settlementCheck
  }

  public var eventIDHex: String {
    payload.eventIDHex
  }

  private enum CodingKeys: String, CodingKey {
    case payload
    case receivedAtSeconds
    case settlementCheck
  }

  public init(from decoder: any Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    payload = try container.decode(NwcWakePayload.self, forKey: .payload)
    receivedAtSeconds = try container.decode(UInt64.self, forKey: .receivedAtSeconds)
    settlementCheck = try container.decodeIfPresent(Bool.self, forKey: .settlementCheck) ?? false
  }
}

/// An atomic, cross-process queue shared by an application and its NSE.
///
/// Each mutation holds an advisory lock on a stable sibling file and replaces
/// the JSON queue atomically. Callers should remove an entry only after the
/// Rust engine reports a terminal result; replay protection makes re-delivery
/// safe when an application exits between acceptance and acknowledgement.
public struct NwcWakeFileInbox: Sendable {
  private let queueURL: URL
  private let lockURL: URL
  private let maxPendingRequests: Int

  public init(
    directoryURL: URL,
    fileName: String = "pending.json",
    maxPendingRequests: Int = 100
  ) {
    queueURL = directoryURL.appendingPathComponent(fileName)
    lockURL = directoryURL.appendingPathComponent(".\(fileName).lock")
    self.maxPendingRequests = max(1, maxPendingRequests)
  }

  public func enqueue(_ request: NwcQueuedWakeRequest) throws {
    try withLock {
      var requests = try loadLocked()
      requests.removeAll { $0.eventIDHex == request.eventIDHex }
      requests.append(request)
      if requests.count > maxPendingRequests {
        requests.removeFirst(requests.count - maxPendingRequests)
      }
      try saveLocked(requests)
    }
  }

  public func pendingRequests() throws -> [NwcQueuedWakeRequest] {
    try withLock {
      try loadLocked()
    }
  }

  @discardableResult
  public func remove(eventIDs: Set<String>) throws -> Bool {
    guard !eventIDs.isEmpty else { return false }
    return try withLock {
      var requests = try loadLocked()
      let previousCount = requests.count
      requests.removeAll { eventIDs.contains($0.eventIDHex) }
      guard requests.count != previousCount else { return false }
      try saveLocked(requests)
      return true
    }
  }

  private func withLock<T>(_ operation: () throws -> T) throws -> T {
    try FileManager.default.createDirectory(
      at: queueURL.deletingLastPathComponent(),
      withIntermediateDirectories: true
    )
    let descriptor = Darwin.open(
      lockURL.path,
      O_CREAT | O_RDWR,
      mode_t(S_IRUSR | S_IWUSR)
    )
    guard descriptor >= 0 else { throw currentPOSIXError() }
    defer { _ = Darwin.close(descriptor) }
    guard flock(descriptor, LOCK_EX) == 0 else {
      throw currentPOSIXError()
    }
    defer { _ = flock(descriptor, LOCK_UN) }
    return try operation()
  }

  private func loadLocked() throws -> [NwcQueuedWakeRequest] {
    guard FileManager.default.fileExists(atPath: queueURL.path) else { return [] }
    let data = try Data(contentsOf: queueURL)
    return try JSONDecoder().decode([NwcQueuedWakeRequest].self, from: data)
  }

  private func saveLocked(_ requests: [NwcQueuedWakeRequest]) throws {
    if requests.isEmpty {
      if FileManager.default.fileExists(atPath: queueURL.path) {
        try FileManager.default.removeItem(at: queueURL)
      }
      return
    }

    let data = try JSONEncoder().encode(requests)
    var options: Data.WritingOptions = [.atomic]
    #if os(iOS)
      options.insert(.completeFileProtectionUntilFirstUserAuthentication)
    #endif
    try data.write(to: queueURL, options: options)
  }

  private func currentPOSIXError() -> POSIXError {
    POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
  }
}
