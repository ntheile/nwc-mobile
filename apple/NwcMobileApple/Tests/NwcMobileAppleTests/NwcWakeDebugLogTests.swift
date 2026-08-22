import Foundation
import XCTest

@testable import NwcMobileApple

final class NwcWakeDebugLogTests: XCTestCase {
  func testAppendsBoundsAndClearsDiagnostics() throws {
    let suite = "NwcWakeDebugLogTests.\(UUID().uuidString)"
    let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let log = NwcWakeDebugLog(defaults: defaults, maximumEntries: 2)

    try log.append(source: "NSE", message: "first", timestamp: 1)
    try log.append(source: "App", message: "second", timestamp: 2)
    try log.append(source: "NSE", message: "third", timestamp: 3)

    let entries = try log.entries()
    XCTAssertEqual(entries.map(\.message), ["second", "third"])
    XCTAssertEqual(entries.map(\.timestamp), [2, 3])

    log.clear()
    XCTAssertTrue(try log.entries().isEmpty)
  }

  func testRejectsOversizedOrCorruptDiagnosticsWithoutOverwrite() throws {
    let suite = "NwcWakeDebugLogTests.\(UUID().uuidString)"
    let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let key = "debug"
    let log = NwcWakeDebugLog(defaults: defaults, key: key)

    XCTAssertThrowsError(
      try log.append(source: "NSE", message: String(repeating: "x", count: 513))
    )

    let corrupt = Data("not-json".utf8)
    defaults.set(corrupt, forKey: key)
    XCTAssertThrowsError(try log.entries())
    XCTAssertThrowsError(try log.append(source: "NSE", message: "safe"))
    XCTAssertEqual(defaults.data(forKey: key), corrupt)
  }
}
