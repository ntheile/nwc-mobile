import { spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
function run(command, args) {
  const result = spawnSync(command, args, { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
if (process.platform !== 'darwin') throw new Error('Swift native smoke requires macOS');
run(process.execPath, ['scripts/generate-native.mjs']);
const binary = join(mkdtempSync(join(tmpdir(), 'nwc-native-test-')), 'smoke');
run('swiftc', ['-parse-as-library', '-I', 'native/swift', '-Xcc',
  '-fmodule-map-file=native/swift/NwcMobileFFI.modulemap',
  'native/swift/NwcMobile.swift', 'example/ios/ExampleHost.swift',
  'templates/NativeWalletFactory.swift', 'tests/NativeSmoke.swift',
  '-L', resolve('../../target/debug'), '-lnwc_mobile_uniffi',
  '-Xlinker', '-rpath', '-Xlinker', resolve('../../target/debug'), '-o', binary]);
run(binary, []);
