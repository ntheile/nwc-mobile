import Foundation
import React
import NwcMobile

/// Compile in the containing app, alongside its generated native Swift bindings.
/// The app owns consent UI; JavaScript must be trusted to request approval.
final class ReactNativeWalletHost: NSObject, NwcMobileHost {
    func dispatchWallet(_ walletId: String, request: String,
                        resolve: @escaping RCTPromiseResolveBlock,
                        reject: @escaping RCTPromiseRejectBlock) {
        Task {
            do { resolve(try await dispatchMobileWalletJson(walletId: walletId, requestJson: request)) }
            catch { reject("NwcRequestFailed", "Native NWC request failed", nil) }
        }
    }
}
// Native app bootstrap, after registering MobileWalletFactory:
// precondition(NwcMobileHostRegistry.registerHost(ReactNativeWalletHost()))
// Do not register this RN adapter in the notification extension.
