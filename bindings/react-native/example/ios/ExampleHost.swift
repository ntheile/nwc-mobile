import Foundation
import Security

/// Offline, read-only demonstration. Never connect this public test identity
/// to a real relay or substitute it for a production wallet adapter.
final class ExampleHost: MobileWalletFactory, MobileWalletBackend, MobileRelayTransport,
                         MobileSecretProvider, MobileClientSecretStore, @unchecked Sendable {
    private let databasePath: String
    private let service = "org.nwc.mobile.example.clients"
    private let publicKey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

    init(directory: URL) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        databasePath = directory.appendingPathComponent("nwc.sqlite").path
    }

    func openWallet(walletId: String) throws -> MobileWallet {
        guard walletId == "primary" else { throw MobileEngineError.NotFound }
        let engine = try MobileNwcEngine.open(databasePath: databasePath, wallet: self, relays: self, secrets: self)
        return MobileWallet(engine: engine, config: MobileWalletConfig(
            walletServicePublicKeyHex: publicKey, relayUrls: ["wss://relay.example"], lud16: nil), secrets: self)
    }

    func getInfo(timeoutMilliseconds: UInt64, cancellation: MobileCancellation) async throws -> MobileWalletInfo {
        MobileWalletInfo(publicKeyHex: publicKey, methods: [.getInfo, .getBalance], notifications: [])
    }
    func getBalance(timeoutMilliseconds: UInt64, cancellation: MobileCancellation) async throws -> UInt64 { 0 }
    func makeInvoice(request: MobileMakeInvoiceRequest, timeoutMilliseconds: UInt64, cancellation: MobileCancellation) async throws -> MobileCreatedInvoice { throw MobileHostError.Rejected }
    func quotePayment(invoice: String, amountMsat: UInt64?, timeoutMilliseconds: UInt64, cancellation: MobileCancellation) async throws -> MobilePaymentQuote { throw MobileHostError.Rejected }
    func paymentStatus(paymentHashHex: String, timeoutMilliseconds: UInt64, cancellation: MobileCancellation) async throws -> MobilePaymentStatus { throw MobileHostError.NotFound }
    func startPayment(request: MobilePayInvoiceRequest, timeoutMilliseconds: UInt64, cancellation: MobileCancellation) async throws -> MobilePaymentStatus { throw MobileHostError.Rejected }
    func lookupInvoice(request: MobileInvoiceLookup, timeoutMilliseconds: UInt64, cancellation: MobileCancellation) async throws -> MobileWalletTransaction? { nil }
    func listTransactions(request: MobileListTransactionsRequest, timeoutMilliseconds: UInt64, cancellation: MobileCancellation) async throws -> [MobileWalletTransaction] { [] }
    func fetchEvent(relayUrl: String, eventIdHex: String, maximumEventBytes: UInt64, timeoutMilliseconds: UInt64, cancellation: MobileCancellation) async throws -> String? { nil }
    func publishEvent(relayUrl: String, eventJson: String, timeoutMilliseconds: UInt64, cancellation: MobileCancellation) async throws { throw MobileHostError.Unavailable }
    func loadNwcSecret(connectionId: String) throws -> Data {
        // Public fixture scalar 1; there is deliberately no network transport.
        Data(Array(repeating: UInt8(0), count: 31) + [1])
    }

    private func query(_ key: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: key]
    }
    func load(key: String) throws -> String? {
        var parameters = query(key)
        parameters[kSecReturnData as String] = true
        parameters[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(parameters as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data,
              let value = String(data: data, encoding: .utf8) else { throw MobileEngineError.DatabaseUnavailable }
        return value
    }
    func store(key: String, secret: String) throws {
        var parameters = query(key)
        parameters[kSecValueData as String] = Data(secret.utf8)
        parameters[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        guard SecItemAdd(parameters as CFDictionary, nil) == errSecSuccess else {
            throw MobileEngineError.DatabaseUnavailable
        }
    }
    func delete(key: String) throws {
        let status = SecItemDelete(query(key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw MobileEngineError.DatabaseUnavailable
        }
    }
}
