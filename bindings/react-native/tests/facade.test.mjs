import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { NwcMobile } from '../lib/NwcMobile.js';
import { encodeRequest, decodeResponse } from '../lib/protocol.js';
import { MobileNwcMethod, MobileBudgetInterval } from '../lib/types.js';

test('public JS has no native handles, authority creation or secret export', () => {
  for (const name of ['createConnection', 'exportConnectionUri', 'engine']) assert.equal(NwcMobile.prototype[name], undefined);
  assert.equal(NwcMobile.fromNativeWallet, undefined);
  const spec = readFileSync(new URL('../src/NativeNwcMobile.ts', import.meta.url), 'utf8');
  assert.doesNotMatch(spec, /installRustCrate|cleanupRustCrate/);
  assert.match(spec, /dispatch\(walletId: string, request: string\): Promise<string>/);
});
test('unsigned values fail closed rather than wrapping', () => {
  for (const value of [-1n, 1n << 64n]) assert.throws(() => encodeRequest({ amountMsat: value }), RangeError);
  assert.equal(JSON.parse(encodeRequest({ amountMsat: (1n << 64n) - 1n })).amountMsat, '18446744073709551615');
  assert.equal(decodeResponse('{"amountMsat":{"$nwcU64":"18446744073709551615"}}').amountMsat, (1n << 64n) - 1n);
  for (const digits of ['-1', '18446744073709551616', '01', '1e3']) assert.throws(() => decodeResponse(JSON.stringify({ $nwcU64: digits })));
});
test('enums, nullable records and digit-looking strings preserve API semantics', () => {
  const command = JSON.parse(encodeRequest({ options: { methods: [MobileNwcMethod.GetInfo], budgetInterval: MobileBudgetInterval.Monthly } }));
  assert.deepEqual(command.options, { methods: ['GetInfo'], budgetInterval: 'Monthly' });
  const record = decodeResponse('{"methods":["PayInvoice"],"budgetInterval":"Monthly","expiresAt":null,"connectionId":"123"}');
  assert.equal(record.methods[0], MobileNwcMethod.PayInvoice);
  assert.equal(MobileNwcMethod[record.methods[0]], 'PayInvoice');
  assert.equal(record.expiresAt, undefined);
  assert.equal(record.connectionId, '123');
  for (const methods of [['pay_invoice'], [-1], [1000]]) assert.throws(() => encodeRequest({ methods }));
});
test('both platforms exclude generated JSI from their build', () => {
  const read = name => readFileSync(new URL('../' + name, import.meta.url), 'utf8');
  assert.doesNotMatch(read('NwcMobile.podspec'), /cpp\/|uniffi-bindgen-react-native/);
  assert.doesNotMatch(read('android/build.gradle'), /externalNativeBuild/);
  assert.doesNotMatch(read('ios/NwcMobile.mm'), /installRustCrate|NativeNwcMobileUniffi/);
  assert.doesNotMatch(read('android/src/main/java/com/nwcmobile/reactnative/NwcMobileModule.kt'), /external fun|runtimePointer|javaScriptContextHolder/);
});

test('closed native errors retain the tag used by pending-NWA recovery', () => {
  assert.throws(() => decodeResponse('{"$nwcError":"NwaAlreadyPending"}'), error => error.tag === 'NwaAlreadyPending');
  assert.throws(() => decodeResponse('{"$nwcError":"secret-bearing host exception"}'), TypeError);
});
