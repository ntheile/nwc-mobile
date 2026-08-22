import Foundation
import Testing

@testable import NwcMobileApple

@Suite("NwcAppGroupWakeStore")
struct NwcAppGroupWakeStoreTests {
  @Test("coordinates queue and bounded debug storage")
  func coordinatesQueueAndDebugStorage() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let suite = "NwcAppGroupWakeStoreTests.\(UUID().uuidString)"
    let defaults = try #require(UserDefaults(suiteName: suite))
    defer {
      defaults.removePersistentDomain(forName: suite)
      try? FileManager.default.removeItem(at: root)
    }
    let store = NwcAppGroupWakeStore(
      inbox: NwcAppGroupWakeInbox(rootURL: root),
      defaults: defaults
    )
    let request = NwcQueuedWakeRequest(
      payload: NwcWakePayload(
        relayURL: "wss://relay.example",
        eventIDHex: String(repeating: "a", count: 64),
        walletServicePublicKeyHex: String(repeating: "b", count: 64),
        embeddedEventJSON: nil
      ),
      receivedAtSeconds: 42
    )

    try store.enqueue(request)
    #expect(try store.pendingRequests() == [request])
    #expect(try store.remove(eventIDs: [request.payload.eventIDHex]))
    #expect(try store.pendingRequests().isEmpty)

    try store.appendDebug(source: "NSE", message: "Started bounded processing")
    #expect(try store.debugEntries().map(\.message) == ["Started bounded processing"])
    store.clearDebugEntries()
    #expect(try store.debugEntries().isEmpty)
  }
}
