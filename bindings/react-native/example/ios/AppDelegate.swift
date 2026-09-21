import UIKit
import React
import React_RCTAppDelegate
import ReactAppDependencyProvider

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    var reactNativeDelegate: ExampleReactDelegate?
    var reactNativeFactory: RCTReactNativeFactory?

    func application(_ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        do {
            let directory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("NwcDemo")
            try registerMobileWalletFactory(factory: ExampleHost(directory: directory))
        } catch {
            // Keep the UI available; opening the unregistered wallet fails closed.
            // Never log native errors which could contain sensitive host details.
        }
        let delegate = ExampleReactDelegate()
        delegate.dependencyProvider = RCTAppDependencyProvider()
        let factory = RCTReactNativeFactory(delegate: delegate)
        reactNativeDelegate = delegate
        reactNativeFactory = factory
        window = UIWindow(frame: UIScreen.main.bounds)
        factory.startReactNative(withModuleName: "NwcMobileExample", in: window, launchOptions: launchOptions)
        return true
    }
}

class ExampleReactDelegate: RCTDefaultReactNativeFactoryDelegate {
    override func sourceURL(for bridge: RCTBridge) -> URL? { bundleURL() }
    override func bundleURL() -> URL? {
#if DEBUG
        RCTBundleURLProvider.sharedSettings().jsBundleURL(forBundleRoot: "index")
#else
        Bundle.main.url(forResource: "main", withExtension: "jsbundle")
#endif
    }
}
