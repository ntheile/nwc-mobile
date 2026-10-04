# React Native bindings for nwc-mobile

Work in progress. This package is private until native integration and
background execution have been verified. Do not publish or ship it yet.

React Native sends bounded JSON commands through a string-only TurboModule.
Rust validates an explicit command allowlist before opening the native wallet.
Native Swift/Kotlin UniFFI bindings remain available for background execution;
no Rust pointers, allocation functions, engine constructors or callback vtables
are installed in the JavaScript runtime.

```ts
import { NwcMobile } from '@nwc-mobile/react-native';

// Register the native wallet factory during native app startup first.
const nwc = await NwcMobile.open({ walletId: 'primary' });
const connections = await nwc.listConnections();
await nwc.revokeConnection(connections[0].connectionId);
```

Connection creation and secret-bearing URI export are native-only. JavaScript
can review and approve a retained NWA request, list/revoke connections, manage
foreground payment handoff and queue push registrations. Its approval UI remains
trusted: this interface does not prove native user presence or protect consent
from compromised JavaScript. A host requiring that property must enforce a native
confirmation gate before approval.

Register the native wallet factory and a native message adapter during app
bootstrap. See `templates/ReactNativeWalletHost.swift` and `.kt`. The adapter calls
`dispatchMobileWalletJson`; it must not implement arbitrary method lookup or
return native object handles. Register only the factory in background processes.

Integers cross the message boundary as decimal strings, preserving `bigint`
precision and rejecting negatives/overflow. Unknown operations, extra fields,
invalid enums and oversized messages fail closed in Rust, even when callers
bypass the TypeScript facade. `resumePayment` now resolves without returning the
internal wake disposition; native callers can still inspect the full result.

See [the integration guide](../../docs/integration/react-native.md) for the
native factory, wallet adapter, background execution, and security boundary.

## Development

Use Node 22.13+ and the protected package managers in PATH. From this directory:

```sh
pnpm install --frozen-lockfile
pnpm generate
pnpm generate:native
pnpm codegen
pnpm test
pnpm build:ios
```

Swift/Kotlin bindings and React Native platform glue are generated artifacts.
The TypeScript data contract and command facade are authored source. The build
cleans `lib/` before compiling, preventing stale raw/web exports from shipping.
The React Native build never invokes the upstream raw JSI generator.

Swift/Kotlin ABI checks remain at the repository root:

```sh
./scripts/check-generated-bindings.sh
```

React Native New Architecture and Hermes are required. A native development
build is required; Expo Go is unsupported. The iOS framework build currently
targets Apple Silicon devices and simulators.

For Android, install the Rust `aarch64-linux-android` target, set
`ANDROID_NDK_HOME` to your pinned NDK, and run `pnpm build:android`. The
initial Android artifact is arm64-v8a/API 24+, with 16 KB page alignment.
The standalone Android example includes native wallet bootstrap and a
Keystore-backed demo secret store. Its native smoke test passes on an API 35
arm64 emulator without Hermes. Real push delivery and physical-device background
verification remain pending on both platforms. See [the example](example/README.md)
for the tested iOS simulator flow and both native smoke tests.
