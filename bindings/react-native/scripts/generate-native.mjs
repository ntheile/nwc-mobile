import { spawnSync } from 'node:child_process';

function cargo(args) {
  const result = spawnSync('cargo', args, { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
const extension = process.platform === 'darwin' ? 'dylib' : 'so';
cargo(['build', '--locked', '--manifest-path', '../../Cargo.toml', '-p', 'nwc-mobile-uniffi']);
for (const language of ['swift', 'kotlin']) {
  cargo(['run', '--locked', '--manifest-path', '../../Cargo.toml', '-p', 'nwc-mobile-uniffi-bindgen', '--',
    'generate', '--library', `../../target/debug/libnwc_mobile_uniffi.${extension}`,
    '--language', language, '--out-dir', `native/${language}`, '--no-format']);
}
