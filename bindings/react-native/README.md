# React Native bindings for nwc-mobile

Work in progress. This package is private until native integration and
background execution have been verified. Do not publish or ship it yet.

The generated TypeScript/C++ bindings call the existing Rust UniFFI engine.
`NwcMobile` is a small UI-facing facade. Payment processing stays native,
including when the React Native application is not running.

```ts
import { NwcMobile } from '@nwc-mobile/react-native';

// Register the native wallet factory during native app startup first.
const nwc = await NwcMobile.open({ walletId: 'primary' });
const connections = await nwc.listConnections();
await nwc.revokeConnection(connections[0].connectionId);
```

`createConnection` accepts approved permissions, budget, encryption, and expiry.
The native `MobileWallet` configuration supplies the wallet service public key
and relays; Rust generates the client secret and stores it through the native
secure store. Export a secret-bearing URI only through an explicit
`exportConnectionUri` call for a user-requested QR/share interaction.

Parsing an NWA request never approves it; call `approveNwaRequest` only after
explicit review. No method automatically opens a callback URL.

This package intentionally disables generated **JavaScript callback
registration**. UniFFI callback tables are process-global; letting JavaScript
register the same traits would replace Swift/Kotlin callbacks. Native bootstrap
owns those callbacks for the lifetime of the process. ABI checks remain enabled.
Do not use generated callback interfaces to implement a backend in JavaScript.

See [the integration guide](../../docs/integration/react-native.md) for the
native factory, wallet adapter, background execution, and security boundary.

## Development

Use Node 22.13+ and the protected package managers in PATH. From this directory:

```sh
npm ci
npm run generate
npm run generate:native
npm run codegen
npm test
npm run build:ios
```

Generated TypeScript, C++, Swift, Kotlin, and React Native platform glue are
build artifacts, not committed source. Run the generation commands above after
a fresh checkout. CI regenerates them before checking the facade and callback
ownership. Keep the pinned generators, lockfiles, handwritten adapters, and
tests in Git; include generated bindings and native binaries only in a built
distribution package. Build caches and installed dependencies are ignored too.

The generator's npm distribution does not include a Cargo lockfile. We keep
its separately resolved build-tool lockfile in `scripts/ubrn.Cargo.lock` and
restore it before invoking Cargo with `--locked`. The project Cargo.lock is
independent. Do not run upstream's unlocked CLI wrapper or bypass dependency
security checks to regenerate bindings.

Swift/Kotlin ABI checks remain at the repository root:

```sh
./scripts/check-generated-bindings.sh
```

React Native New Architecture and Hermes are required. A native development
build is required; Expo Go is unsupported. The iOS framework build currently
targets Apple Silicon devices and simulators.

For Android, install the Rust `aarch64-linux-android` target, set
`ANDROID_NDK_HOME` to your pinned NDK, and run `npm run build:android`. The
initial Android artifact is arm64-v8a/API 24+, with 16 KB page alignment.
The standalone Android example includes native wallet bootstrap and a
Keystore-backed demo secret store. Its native smoke test passes on an API 35
arm64 emulator without Hermes. Real push delivery and physical-device background
verification remain pending on both platforms. See [the example](example/README.md)
for the tested iOS simulator flow and both native smoke tests.
