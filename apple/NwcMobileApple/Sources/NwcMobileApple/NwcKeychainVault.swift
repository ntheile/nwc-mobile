import Foundation
import Security

/// Configurable device-only Keychain storage for native NWC secret adapters.
///
/// Values never leave the caller-requested operation and are never logged.
public struct NwcKeychainVault: Sendable {
  private let service: String
  private let accessGroup: String?

  public init(service: String, accessGroup: String? = nil) {
    precondition(!service.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
    self.service = service
    let trimmedAccessGroup = accessGroup?.trimmingCharacters(in: .whitespacesAndNewlines)
    self.accessGroup = trimmedAccessGroup?.isEmpty == false ? trimmedAccessGroup : nil
  }

  public func string(forKey key: String) -> String? {
    var query = baseQuery(key: key)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess, let data = result as? Data else {
      return nil
    }
    return String(data: data, encoding: .utf8)
  }

  @discardableResult
  public func setString(_ value: String, forKey key: String) -> Bool {
    let data = Data(value.utf8)
    var query = baseQuery(key: key)
    let update: [String: Any] = [kSecValueData as String: data]
    if SecItemUpdate(query as CFDictionary, update as CFDictionary) == errSecSuccess {
      return true
    }

    query[kSecValueData as String] = data
    query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
  }

  /// Deletes a value idempotently.
  @discardableResult
  public func deleteValue(forKey key: String) -> Bool {
    let status = SecItemDelete(baseQuery(key: key) as CFDictionary)
    return status == errSecSuccess || status == errSecItemNotFound
  }

  private func baseQuery(key: String) -> [String: Any] {
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: key,
    ]
    if let accessGroup {
      query[kSecAttrAccessGroup as String] = accessGroup
    }
    return query
  }
}
