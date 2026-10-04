import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

// Use the wallet project's pinned NDK. Never download a toolchain implicitly.
const ndk = process.env.ANDROID_NDK_HOME;
if (!ndk) throw new Error('Set ANDROID_NDK_HOME to your pinned Android NDK');
const host = process.platform === 'darwin' ? 'darwin-x86_64' : 'linux-x86_64';
const bin = join(ndk, 'toolchains/llvm/prebuilt', host, 'bin');
const linker = join(bin, 'aarch64-linux-android24-clang');
if (!existsSync(linker)) throw new Error('NDK arm64 compiler not found');
const result = spawnSync('cargo', ['build', '--locked', '--manifest-path', '../../Cargo.toml',
  '-p', 'nwc-mobile-uniffi', '--release', '--target', 'aarch64-linux-android'], {
  stdio: 'inherit',
  env: { ...process.env,
    CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER: linker,
    CC_aarch64_linux_android: linker,
    AR_aarch64_linux_android: join(bin, 'llvm-ar'),
    CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS: '-C link-arg=-Wl,-z,max-page-size=16384',
  },
});
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);
const destination = resolve('android/src/main/jniLibs/arm64-v8a');
mkdirSync(destination, { recursive: true });
copyFileSync(resolve('../../target/aarch64-linux-android/release/libnwc_mobile_uniffi.so'),
  join(destination, 'libnwc_mobile_uniffi.so'));
