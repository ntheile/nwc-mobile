import Foundation

/// Bounded, transport-validated NWC routing fields extracted from APNs.
///
/// Rust still performs all protocol and authorization validation. These values
/// must never be logged by the native adapter.
public struct NwcWakePayload: Sendable, Equatable, Codable {
  public let relayURL: String
  public let eventIDHex: String
  public let walletServicePublicKeyHex: String
  public let embeddedEventJSON: String?

  public init(
    relayURL: String,
    eventIDHex: String,
    walletServicePublicKeyHex: String,
    embeddedEventJSON: String? = nil
  ) {
    self.relayURL = relayURL
    self.eventIDHex = eventIDHex
    self.walletServicePublicKeyHex = walletServicePublicKeyHex
    self.embeddedEventJSON = embeddedEventJSON
  }

  private enum CodingKeys: String, CodingKey {
    case relayURL
    case eventIDHex
    case walletServicePublicKeyHex
    case embeddedEventJSON
  }

  public init(from decoder: any Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    self = try Self.validated(
      relayURL: container.decode(String.self, forKey: .relayURL),
      eventIDHex: container.decode(String.self, forKey: .eventIDHex),
      walletServicePublicKeyHex: container.decode(
        String.self,
        forKey: .walletServicePublicKeyHex
      ),
      embeddedEventJSON: container.decodeIfPresent(String.self, forKey: .embeddedEventJSON)
    )
  }
}

/// Stable APNs keys understood by the NSE helper.
public enum NwcWakePayloadKey {
  public static let relayURL = "nwc_relay"
  public static let eventID = "nwc_event_id"
  public static let walletServicePublicKey = "nwc_wallet_service_pubkey"
  public static let embeddedEvent = "nwc_event_json"
}

/// Non-sensitive payload decoding failure.
public enum NwcWakePayloadError: Error, Sendable, Equatable {
  case missingRequiredField
  case invalidFieldType
  case invalidFieldValue
}

private let maximumRelayURLBytes = 2_048
private let maximumEmbeddedEventBytes = 64 * 1_024
private let fixedHexLength = 64

extension NwcWakePayload {
  static func validated(
    relayURL: String,
    eventIDHex: String,
    walletServicePublicKeyHex: String,
    embeddedEventJSON: String?
  ) throws -> NwcWakePayload {
    guard
      !relayURL.isEmpty,
      relayURL.count <= maximumRelayURLBytes,
      relayURL.utf8.count <= maximumRelayURLBytes,
      eventIDHex.isFixedHex,
      walletServicePublicKeyHex.isFixedHex,
      embeddedEventJSON.map({
        $0.count <= maximumEmbeddedEventBytes
          && $0.utf8.count <= maximumEmbeddedEventBytes
      }) ?? true
    else {
      throw NwcWakePayloadError.invalidFieldValue
    }
    return NwcWakePayload(
      relayURL: relayURL,
      eventIDHex: eventIDHex.lowercased(),
      walletServicePublicKeyHex: walletServicePublicKeyHex.lowercased(),
      embeddedEventJSON: embeddedEventJSON
    )
  }

  /// Encodes only the stable APNs routing keys understood by the NSE helper.
  ///
  /// This deliberately drops every unrecognized notification field so callers
  /// cannot accidentally retain remote presentation text or actions.
  public var normalizedUserInfo: [AnyHashable: Any] {
    var userInfo: [AnyHashable: Any] = [
      NwcWakePayloadKey.relayURL: relayURL,
      NwcWakePayloadKey.eventID: eventIDHex,
      NwcWakePayloadKey.walletServicePublicKey: walletServicePublicKeyHex,
    ]
    if let embeddedEventJSON {
      userInfo[NwcWakePayloadKey.embeddedEvent] = embeddedEventJSON
    }
    return userInfo
  }

  /// Decodes only bounded APNs routing fields and canonicalizes fixed hex values.
  public static func decode(
    userInfo: [AnyHashable: Any]
  ) throws -> NwcWakePayload {
    func requiredString(_ key: String) throws -> String {
      guard let value = userInfo[key] else {
        throw NwcWakePayloadError.missingRequiredField
      }
      guard let value = value as? String else {
        throw NwcWakePayloadError.invalidFieldType
      }
      return value
    }

    let embeddedEvent: String?
    if let value = userInfo[NwcWakePayloadKey.embeddedEvent] {
      guard let value = value as? String else {
        throw NwcWakePayloadError.invalidFieldType
      }
      embeddedEvent = value
    } else {
      embeddedEvent = nil
    }

    let relayURL = try requiredString(NwcWakePayloadKey.relayURL)
    let eventID = try requiredString(NwcWakePayloadKey.eventID)
    let walletServicePublicKey = try requiredString(
      NwcWakePayloadKey.walletServicePublicKey
    )
    return try validated(
      relayURL: relayURL,
      eventIDHex: eventID,
      walletServicePublicKeyHex: walletServicePublicKey,
      embeddedEventJSON: embeddedEvent
    )
  }
}

extension String {
  fileprivate var isFixedHex: Bool {
    count == fixedHexLength
      && unicodeScalars.allSatisfy {
        switch $0.value {
        case 48...57, 65...70, 97...102:
          return true
        default:
          return false
        }
      }
  }
}
