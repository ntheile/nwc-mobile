import Foundation

/// Untrusted NWC routing fields extracted from an APNs user-info dictionary.
///
/// The values remain unvalidated until the generated Rust API creates a
/// `MobileWakeEnvelope`. They must never be logged by the native adapter.
public struct NwcWakePayload: Sendable, Equatable {
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
}

extension NwcWakePayload {
  /// Decodes only the expected APNs fields without interpreting their values.
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

    return NwcWakePayload(
      relayURL: try requiredString(NwcWakePayloadKey.relayURL),
      eventIDHex: try requiredString(NwcWakePayloadKey.eventID),
      walletServicePublicKeyHex: try requiredString(
        NwcWakePayloadKey.walletServicePublicKey
      ),
      embeddedEventJSON: embeddedEvent
    )
  }
}
