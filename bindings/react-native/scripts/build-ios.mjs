import { spawnSync } from 'node:child_process';
import { mkdtempSync, copyFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { stdio: 'inherit', ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
if (process.platform !== 'darwin') throw new Error('The iOS build requires macOS and Xcode');
const output = resolve('NwcMobileFramework.xcframework');
if (existsSync(output)) throw new Error('Move the existing NwcMobileFramework.xcframework aside before rebuilding');
const staging = mkdtempSync(join(tmpdir(), 'nwc-rn-ios-'));
const headers = join(staging, 'headers');
for (const target of ['aarch64-apple-ios', 'aarch64-apple-ios-sim']) {
  run('cargo', ['build', '--locked', '--manifest-path', '../../Cargo.toml', '-p', 'nwc-mobile-uniffi', '--release', '--target', target], {
    env: { ...process.env, IPHONEOS_DEPLOYMENT_TARGET: '15.1' },
  });
}
run('cargo', ['run', '--locked', '--manifest-path', '../../Cargo.toml', '-p', 'nwc-mobile-uniffi-bindgen', '--',
  'generate', '--library', '../../target/aarch64-apple-ios/release/libnwc_mobile_uniffi.a',
  '--language', 'swift', '--out-dir', headers, '--no-format']);
copyFileSync(join(headers, 'NwcMobileFFI.modulemap'), join(headers, 'module.modulemap'));
run('xcodebuild', ['-create-xcframework',
  '-library', resolve('../../target/aarch64-apple-ios/release/libnwc_mobile_uniffi.a'), '-headers', headers,
  '-library', resolve('../../target/aarch64-apple-ios-sim/release/libnwc_mobile_uniffi.a'), '-headers', headers,
  '-output', output]);
console.log(`Native Swift bootstrap bindings: ${join(headers, 'NwcMobile.swift')}`);
console.log('Compile those bindings into the host and NSE against this same framework; do not link a second Rust engine.');
