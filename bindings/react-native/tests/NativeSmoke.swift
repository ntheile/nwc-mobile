import Foundation

/// Test-only store; not part of the application or production templates.
final class MemorySecrets: MobileClientSecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: String] = [:]
    func load(key: String) throws -> String? {
        lock.lock(); defer { lock.unlock() }; return values[key]
    }
    func store(key: String, secret: String) throws {
        lock.lock(); defer { lock.unlock() }; values[key] = secret
    }
    func delete(key: String) throws {
        lock.lock(); defer { lock.unlock() }; values.removeValue(forKey: key)
    }
}

@main
struct NativeSmoke {
    static func main() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("nwc-native-smoke-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let host = try ExampleHost(directory: directory)
        let engine = try MobileNwcEngine.open(databasePath: directory.appendingPathComponent("test.sqlite").path,
            wallet: host, relays: host, secrets: host)
        let wallet = MobileWallet(engine: engine, config: MobileWalletConfig(
            walletServicePublicKeyHex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            relayUrls: ["wss://relay.example"], lud16: nil), secrets: MemorySecrets())
        try registerMobileWalletFactory(factory: NativeWalletFactory(open: { id in
            guard id == "primary" else { throw MobileEngineError.NotFound }
            return wallet
        }))
        let opened = try openRegisteredMobileWallet(walletId: "primary")
        let created = try opened.createConnection(options: MobileConnectionOptions(
            methods: [.getInfo], budgetLimitSat: 0, budgetInterval: .never,
            encryption: .nip44V2, expiresAt: nil))
        let initialConnections = try opened.listConnections()
        precondition(initialConnections.count == 1)
        let uri = try opened.exportConnectionUri(connectionId: created.connectionId)
        precondition(uri.hasPrefix("nostr+walletconnect://"))

        // Exercise the async native relay callback on the Rust runtime, with no
        // Hermes/React Native initialized. Offline relay means a stable retry.
        let wake = try validateWakeEnvelope(envelope: MobileWakeEnvelope(
            relayUrl: "wss://relay.example", eventIdHex: String(repeating: "ab", count: 32),
            walletServicePublicKeyHex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            embeddedEventJson: nil, receivedAtSeconds: UInt64(Date().timeIntervalSince1970), settlementCheck: false))
        let result = try await opened.engine().executeWake(wake: wake, executionMilliseconds: 500,
            cancellation: MobileCancellation())
        guard case .retryAfter = result else { fatalError("Offline native relay should request retry") }
        let deleted = try opened.revokeConnection(connectionId: created.connectionId)
        precondition(deleted)
        let remainingConnections = try opened.listConnections()
        precondition(remainingConnections.isEmpty)

        // Public client-created request fixture: no callback or secret delivery.
        // Parsing and cancellation must not create connection authority.
        let requestUri = "nostr+walletauth://687dd8ece211539364549b1f32c63eceec1e0661009ba65cf8ff2e73ba000746?relay=wss%3A%2F%2Frelay.example.com"
        let request = try opened.parseNwaRequest(uri: requestUri)
        let pending = try opened.pendingNwaRequest()
        precondition(pending?.requestIdHex == request.requestIdHex)
        let beforeApproval = try opened.listConnections()
        precondition(beforeApproval.isEmpty)
        try opened.cancelNwaRequest()
        let cancelled = try opened.pendingNwaRequest()
        precondition(cancelled == nil)
        let reviewed = try opened.parseNwaRequest(uri: requestUri)
        let approved = try opened.approveNwaRequest(requestId: reviewed.requestIdHex,
            options: MobileConnectionOptions(methods: [.getInfo], budgetLimitSat: 0,
                budgetInterval: .never, encryption: .nip44V2, expiresAt: nil))
        precondition(approved.callbackUrl == nil)
        let authorized = try opened.listConnections()
        precondition(authorized.count == 1)
        precondition(authorized[0].connectionId == approved.connection.connectionId)
        _ = try opened.revokeConnection(connectionId: approved.connection.connectionId)
        print("Native bootstrap, secure-store callbacks, NWA approval, and async wake smoke passed without JavaScript")
    }
}
