// Generate native host bindings only, never a Rust-pointer JS host object.
import { spawnSync } from 'node:child_process';
for (const script of ['scripts/generate-native.mjs', 'scripts/codegen.mjs']) {
  const result = spawnSync(process.execPath, [script], { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
