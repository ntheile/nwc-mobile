# React Native

The React Native integration is under development in `bindings/react-native`.
It uses `uniffi-bindgen-react-native` to call the existing Rust engine through
JSI. It does not implement NIP-47 or payment policy in JavaScript.

## The integration boundary

React Native owns connection screens and explicit NWA approval. Rust owns
authorization, durable request processing, budgets, replay protection, payment
reconciliation, and connection persistence. The wallet supplies its Lightning
backend and native secure storage. Native code handles push delivery and OS
execution deadlines.

Use a native `MobileWalletFactory` to open an existing wallet's
`MobileWallet`, which wraps a `MobileNwcEngine`, native defaults, and a
`MobileClientSecretStore`. Register it before starting React Native. The public JS
facade selects an opaque wallet identifier, not a database path or credentials.
The factory must resolve that identifier against the host's own registry and
reject unknown wallets. It must not implicitly create or restore a wallet.

Register independently in the application and background process. An iOS NSE
cannot use a JavaScript object, a Rust pointer, or a factory registration from
the containing application process. Both processes must reconstruct their
native backend and open the same App Group ledger and Keychain access group.
On Android, bootstrap the factory from application/service initialization even
when React Native has never started.

The native defaults contain the service public key, relays, and optional
Lightning address. The UI passes `MobileConnectionOptions`: approved methods,
budget, renewal interval, encryption, and expiry. Rust generates and securely
stores client keys through the existing application workflow. The normal
creation result contains no secret. Export a URI only for an explicit user
QR/share interaction, and never persist that URI in application state storage.

Registration is one-time per process. Duplicate registration is an error, not
a hot-swap operation. Opened engines keep their native dependencies alive.
Do not register a TypeScript callback factory for a background-capable wallet.
The generated callback interface is internal. This package removes automatic
JS callback registration during generation because UniFFI's vtables are
process-global: JS registration would overwrite the Swift/Kotlin implementation.
The transformation checks the exact callback inventory and keeps all ABI
version/checksum validation. Do not initialize an unmodified generated JS
module alongside the native bindings.

## Wallet-specific code

Implement `MobileWalletBackend` in Swift/Kotlin, or compose the Rust engine with
your own native backend. A Rust `NwcLightningNode` adapter can remain in your
wallet's Rust crate. Neither a Lexe nor an LNI dependency is required by this
package.

The current UniFFI engine constructor also takes `MobileRelayTransport` and
`MobileSecretProvider`. Keep these native and reuse them in your factory;
do not pass NWC secrets through JS for background execution. A JS-only Lightning
adapter would require a separate foreground-only integration; this package
intentionally does not register JavaScript callback implementations.

When linking a wallet-specific Rust composition crate, use a single copy of
the nwc-mobile UniFFI symbols in each process. Do not link a second static copy
of the same engine into the React Native module. On Android, the generated
Kotlin bridge and JSI wrapper must load the same Rust shared library so they
see the same factory registry. All generated bindings and native libraries
must come from the same source revision.

## Background integration

Use [the Apple helpers](../../apple/NwcMobileApple/README.md) for NSE expiration,
sanitized presentation, completion, and shared inbox handling. Use
[the Android helpers](../../android/nwc-mobile/README.md) for bounded wake work
and maintenance scheduling. The app still supplies its APNs/FCM configuration,
push provider registration, signing, entitlements, and native wallet factory.

Never start a React Native bridge inside the NSE. Parse and validate the push
through Rust, execute the native engine with an OS-bounded deadline and
cancellation, and finish via the platform helper. Push delivery and completion
within the execution window are not guaranteed by either mobile OS.

## Approval and secrets

Parsing an NWA link is not approval. Display the requesting identity as
unverified unless the native host has independently verified it; show the
methods, budget, expiry, and callback destination. Persist only an explicit
approval of the exact retained request. Callback delivery belongs to native
code. Do not use a generic browser-opening operation for secret-bearing
callbacks or log callback URLs, connection URIs, payment preimages, or secrets.

Generated 64-bit integer fields use `bigint`, including satoshi limits,
revisions, and timestamps. Do not silently convert them to JavaScript `number`.

## Verification status

The local example has been built for both iOS and Android. The iOS simulator
flow has exercised opening the native wallet, creating/listing/revoking a
read-only connection, and Keychain storage. Native Swift and Android API 35
arm64 smoke tests exercise connection export, NWA review/cancellation/approval,
revocation, and offline wake execution without starting JavaScript. Android's
test uses the real Keystore and can be repeated without reauthorizing a revoked
fixture identity. TypeScript tests additionally check bigint preservation,
explicit approval, and native callback-table ownership with ABI checks enabled.

Generated sources are deliberately excluded from Git. CI regenerates them;
the package's prepack check requires generated bindings and native libraries.
The distribution file allowlist excludes Android build caches. See the
[example instructions](../../bindings/react-native/example/README.md) to rerun
the native tests. These checks use an offline, read-only wallet, not real funds.

## Host acceptance checks before shipping

- Generate TS/C++ and Swift/Kotlin from the same Rust artifact and verify checksums.
- Compile the package and consuming native example on iOS and Android.
- Verify connection creation, explicit NWA approval, revocation, and UI refresh.
- With the React Native app terminated, deliver a real push and verify that
  the native backend processes it without starting JavaScript.
- Deliver duplicate requests concurrently to foreground/background processes;
  verify a payment is submitted once and its response can be replayed.
- Exercise extension expiration, cancellation, locked secure storage, network
  failure, ambiguous payment outcomes, and resume-time reconciliation.

TypeScript unit tests do not prove NSE or Android background execution works.
Use a native development build; this package cannot run inside Expo Go.
