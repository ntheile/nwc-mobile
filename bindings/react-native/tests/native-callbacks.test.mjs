import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { retainNativeCallbacks } from '../scripts/native-callbacks.mjs';

test('generator transformation refuses unreviewed callback inventories', () => {
  assert.throws(() => retainNativeCallbacks('uniffiCallbackInterfaceNewThing.register();'), /inventory changed/);
});

test('generated initialization retains ABI checks without registering JS callbacks', () => {
  const source = readFileSync(new URL('../src/generated/nwc_mobile_uniffi.ts', import.meta.url), 'utf8');
  const initialization = source.slice(source.indexOf('function uniffiEnsureInitialized'));
  assert.match(initialization, /ContractVersionMismatch/);
  assert.match(initialization, /ApiChecksumMismatch/);
  assert.doesNotMatch(initialization, /\.register\(\)/);
  assert.equal((initialization.match(/callback table is owned by native bootstrap/g) ?? []).length, 6);
});

test('actual generated initializer checks ABI but never replaces native vtables', () => {
  const source = readFileSync(new URL('../src/generated/nwc_mobile_uniffi.ts', import.meta.url), 'utf8');
  const checksums = new Map([...source.matchAll(/nativeModule\(\)\.(\w+)\(\) !== (\d+)/g)]
    .map(match => [match[1], Number(match[2])]));
  const contract = Number(source.match(/const bindingsContractVersion = (\d+)/)[1]);
  let registrations = 0;
  globalThis.NativeNwcMobileUniffi = new Proxy({}, {
    get(_target, name) {
      if (String(name).includes('init_callback_vtable')) return () => { registrations++; };
      if (String(name).endsWith('uniffi_contract_version')) return () => contract;
      if (checksums.has(name)) return () => checksums.get(name);
      throw new Error(`Unexpected native call: ${String(name)}`);
    },
  });
  const require = createRequire(import.meta.url);
  const generated = require('../lib/generated/nwc_mobile_uniffi.js');
  try {
    generated.default.initialize();
    assert.ok(checksums.size > 30);
    assert.equal(registrations, 0);
    const first = checksums.keys().next().value;
    checksums.set(first, -1);
    assert.throws(() => generated.default.initialize());
  } finally {
    delete globalThis.NativeNwcMobileUniffi;
  }
});
