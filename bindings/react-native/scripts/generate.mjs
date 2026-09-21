import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { readFileSync, writeFileSync } from 'node:fs';
import { retainNativeCallbacks } from './native-callbacks.mjs';

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { stdio: 'inherit', ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

const extension = process.platform === 'darwin' ? 'dylib' : 'so';
run('cargo', ['build', '--locked', '--manifest-path', '../../Cargo.toml', '-p', 'nwc-mobile-uniffi']);
run(process.execPath, [resolve('scripts/ubrn.mjs'), 'generate', 'jsi', 'bindings',
  '--library', resolve(`../../target/debug/libnwc_mobile_uniffi.${extension}`),
  '--ts-dir', resolve('src/generated'), '--cpp-dir', resolve('cpp/generated'), '--no-format'], { cwd: resolve('../..') });
// Native module scaffolding is maintained separately, not regenerated over
// platform fixes each time the Rust API changes.
const generated = resolve('src/generated/nwc_mobile_uniffi.ts');
writeFileSync(generated, retainNativeCallbacks(readFileSync(generated, 'utf8')));
