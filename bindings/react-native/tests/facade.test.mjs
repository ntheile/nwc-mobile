import assert from 'node:assert/strict';
import { test } from 'node:test';
import { NwcMobile } from '../lib/NwcMobile.js';

test('connection operations preserve bigint precision and use native authority', async () => {
  const approval = { budgetLimitSat: 9007199254740993n };
  const calls = [];
  const nwc = NwcMobile.fromNativeWallet({
    createConnection(value) { calls.push(value); return { connectionId: 'one' }; },
    listConnections() { return [approval]; },
    revokeConnection(id) { calls.push(id); },
  });
  assert.deepEqual(await nwc.createConnection(approval), { connectionId: 'one' });
  assert.equal((await nwc.listConnections())[0].budgetLimitSat, 9007199254740993n);
  await nwc.revokeConnection('one');
  assert.deepEqual(calls, [approval, 'one']);
});

test('NWA parsing never approves implicitly; approval carries the reviewed id', async () => {
  const calls = [];
  const nwc = NwcMobile.fromNativeWallet({
    parseNwaRequest(uri) { calls.push(['parse', uri]); return { requestIdHex: 'reviewed' }; },
    approveNwaRequest(...args) { calls.push(['approve', ...args]); return { callbackUrl: undefined }; },
    cancelNwaRequest() { calls.push(['clear']); },
  });
  const request = await nwc.parseNwaRequest('nostr+walletauth://example');
  assert.equal(calls.length, 1);
  const approval = { methods: [] };
  await nwc.approveNwaRequest(request.requestIdHex, approval);
  await nwc.cancelNwaRequest();
  assert.deepEqual(calls[1], ['approve', 'reviewed', approval]);
  assert.deepEqual(calls[2], ['clear']);
});

test('native rejection is propagated without retrying or approving', async () => {
  let attempts = 0;
  const rejection = new Error('native rejection');
  const nwc = NwcMobile.fromNativeWallet({
    createConnection() { attempts++; throw rejection; },
  });
  await assert.rejects(nwc.createConnection({}), (error) => error === rejection);
  assert.equal(attempts, 1);
});

test('push refresh only forwards the requested native registration state', async () => {
  const states = [];
  const nwc = NwcMobile.fromNativeWallet({
    refreshWakeRegistrations(enabled) { states.push(enabled); return 2n; },
  });
  assert.equal(await nwc.refreshWakeRegistrations(false), 2n);
  assert.deepEqual(states, [false]);
});
