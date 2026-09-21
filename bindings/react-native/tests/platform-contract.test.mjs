import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const source = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('iOS installer and cleanup return booleans to match the TurboModule spec', () => {
  const adapter = source('ios/NwcMobile.mm');
  for (const operation of ['installRustCrate', 'cleanupRustCrate']) {
    const body = adapter.match(new RegExp(`__hostFunction_NwcMobile_${operation}\\([^]*?\\n    }`))?.[0];
    assert.ok(body, `${operation} host function exists`);
    assert.match(body, /return facebook::jsi::Value\(result != 0\);/);
  }
});

test('iOS adapter explicitly rejects legacy architecture', () => {
  const header = source('ios/NwcMobile.h');
  assert.match(header, /#if !defined\(RCT_NEW_ARCH_ENABLED\) \|\| !RCT_NEW_ARCH_ENABLED\s+#error/);
  assert.doesNotMatch(header, /RCTBridgeModule/);
  assert.match(source('ios/NwcMobile.mm'), /#if defined\(RCT_NEW_ARCH_ENABLED\) && RCT_NEW_ARCH_ENABLED/);
});

test('native entrypoint keeps generated namespace private', () => {
  const entrypoint = source('src/native.ts');
  assert.doesNotMatch(entrypoint, /export default|export \*/);
  assert.match(entrypoint, /nwc_mobile_uniffi\.default\.initialize\(\)/);
});

test('native project declarations include their platform prerequisites', () => {
  assert.match(source('android/CMakeLists.txt'), /cmake_minimum_required\(VERSION 3\.20\)/);
  assert.match(source('example/ios/project.yml'), /path: PrivacyInfo\.xcprivacy\s+buildPhase: resources/);
});
