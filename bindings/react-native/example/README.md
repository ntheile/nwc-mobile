# Example UI and native host

`App.tsx` demonstrates the public facade with no Lightning SDK in JavaScript:
open a native wallet, list/create/revoke read-only connections, review an NWA
request, and explicitly approve a read-only subset. It deliberately does not
grant payment authority or automatically open callback URLs.

Standalone iOS and Android project scaffolding lives in `ios/` and `android/`.
The iOS host implements an offline native wallet and stores generated client
secrets in Keychain. Its simulator flow supports opening the wallet and
creating, listing, and revoking read-only connections. The Android host registers
the same offline interface before React Native starts and encrypts demo client
secrets with an Android Keystore key. Its native instrumentation test passes on
an API 35 arm64 emulator, including NWA approval and offline wake execution.

This is an offline demonstration, not a Lightning wallet. Its fixed public test
identity must never be connected to a real relay or used with funds. No payments
or APNs/FCM delivery are exercised by the demo.

## Running the iOS example

From `bindings/react-native`, install the approved locked dependencies with
`npm ci`, then run `npm run generate`, `npm run generate:native`,
`npm run build:ios`, and `npm run codegen`. Generated bindings are intentionally
not committed. The framework build
refuses to overwrite an existing framework; move it aside before rebuilding.
With XcodeGen and CocoaPods installed, run `xcodegen generate` and `pod install`
from `example/ios`, then open `NwcMobileExample.xcworkspace` in Xcode. Start Metro
from `example` with `npm start` and run the app on an Apple Silicon simulator.
Use normal simulator ad-hoc signing: disabling signing prevents the native
Keychain store from working. A physical device requires your signing team.

`npm run test:native:ios` separately exercises the Swift factory, Rust connection
workflow, and offline wake execution without React Native or Hermes running.
It does not prove killed-app push delivery; test that with the production host's
entitlements, push provider, native wallet, and extension/worker.

Before adapting it to a real wallet, register `MobileWalletFactory` from native bootstrap and
provide a wallet named `primary`. Use the templates in `../templates`:

- `NativeWalletFactory.swift` / `.kt` adapt your native wallet registry.
- `NativeWakeExecutor.swift` / `.kt` call Rust directly from the platform wake
  helpers without loading React Native.

Generate the host bindings with `npm run generate:native`. Compile the Swift
bindings and templates into the host/NSE targets against the same Rust
framework. Compile the Kotlin bindings and templates into the native host with
the UniFFI-required JNA and coroutine runtime dependencies; load the same Rust
shared library as the JSI wrapper. Keep native dependencies pinned in the host.

The factory composes `MobileNwcEngine`, `MobileWalletConfig`, and a
`MobileClientSecretStore`. Resolve database locations and credentials natively.
Use OS-protected secure storage and the same shared ledger across app/wake
processes. Never implement those callbacks in JavaScript.

The Swift executor plugs into `NwcNotificationServiceAdapter` with a fresh
`NativeWakeCancellation` for every request. The Kotlin executor plugs into the
existing `NwcWakeWorker` factory, also with a fresh cancellation per attempt.
Use existing native maintenance helpers to drain registration/reconciliation
work at startup/resume. The example UI's registration refresh only queues work;
it does not deliver push registrations itself.

For a real wallet, add verified native NWA callback delivery, QR/share UI,
push-provider registration, and the platform entitlements/manifests. Obtain
notification permission in the UI, not from the extension or worker.

## Android native smoke test

Generate the bindings and platform glue, build the Android Rust library, and
start an arm64 emulator. From `example/android`, build the app and test APKs:

```sh
./gradlew :app:assembleDebug :app:assembleDebugAndroidTest
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb shell am instrument -w -r org.nwc.mobile.example.test/org.nwc.mobile.example.NativeSmokeInstrumentation
```

Require the `passed without Hermes` message and `INSTRUMENTATION_CODE: -1`;
an adb exit code alone does not prove success. The test opens the native registry,
creates/exports/revokes a read-only connection with real Keystore storage, and
executes an offline wake through Kotlin callbacks without starting an Activity.
It does not exercise FCM delivery or make any payments.
