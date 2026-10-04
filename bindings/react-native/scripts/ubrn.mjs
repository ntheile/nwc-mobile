// Use PATH's protected cargo and the generator's existing lockfile.
// The upstream npm CLI currently omits --locked.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { copyFileSync } from 'node:fs';

const manifest = fileURLToPath(new URL('../node_modules/uniffi-bindgen-react-native/crates/ubrn_cli/Cargo.toml', import.meta.url));
copyFileSync(new URL('./ubrn.Cargo.lock', import.meta.url), new URL('../node_modules/uniffi-bindgen-react-native/Cargo.lock', import.meta.url));
const result = spawnSync('cargo', ['run', '--locked', '--manifest-path', manifest, '--', ...process.argv.slice(2)], { stdio: 'inherit' });
if (result.error) throw result.error;
process.exit(result.status ?? 1);
