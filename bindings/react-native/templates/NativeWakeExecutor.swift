import Foundation
import NwcMobileApple
// Compile alongside the generated NwcMobile.swift in both the app and NSE.

final class NativeWakeCancellation: NwcWakeCancellation, @unchecked Sendable {
    let native = MobileCancellation()
    func cancel() { native.cancel() }
}

struct NativeWakeExecutor: NwcWakeExecutor {
    /// Chosen by the trusted native wallet registry, never by push userInfo.
    let walletId: String

    func execute(payload: NwcWakePayload, executionMilliseconds: UInt64,
                 cancellation: any NwcWakeCancellation) async -> NwcWakePresentationHint {
        guard let cancellation = cancellation as? NativeWakeCancellation else {
            return .openApplication
        }
        do {
            let wake = try validateWakeEnvelope(envelope: MobileWakeEnvelope(
                relayUrl: payload.relayURL,
                eventIdHex: payload.eventIDHex,
                walletServicePublicKeyHex: payload.walletServicePublicKeyHex,
                embeddedEventJson: payload.embeddedEventJSON,
                receivedAtSeconds: UInt64(max(0, Date().timeIntervalSince1970)),
                settlementCheck: false))
            let engine = try openRegisteredMobileWallet(walletId: walletId).engine()
            let result = try await engine.executeWake(wake: wake,
                executionMilliseconds: executionMilliseconds, cancellation: cancellation.native)
            let hint: MobileNotificationHint
            switch result {
            case .completed(let notification), .alreadyProcessed(let notification): hint = notification
            case .queuedForApplication(_, let notification), .rejected(_, let notification): hint = notification
            case .retryAfter(_, _, let notification): hint = notification
            }
            switch hint {
            case .processing: return .processing
            case .completed: return .completed
            case .openApplication: return .openApplication
            case .request(let method):
                switch method {
                case .getInfo: return .request(.getInfo)
                case .getBalance: return .request(.getBalance)
                case .makeInvoice: return .request(.makeInvoice)
                case .payInvoice: return .request(.payInvoice)
                case .lookupInvoice: return .request(.lookupInvoice)
                case .listTransactions: return .request(.listTransactions)
                }
            }
        } catch {
            // No remote error text, invoice, URI, or identity in presentation.
            return .openApplication
        }
    }
}
