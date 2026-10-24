import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { createReadRecallProcessor } = require('../lark-message-recall.cjs');

test('recall waits for the exact requester and never touches other messages', async () => {
  let rows = [{ id: 'request', larkUserId: 'ou_requester', sensitiveMessages: [{ messageId: 'om_password' }] }];
  let reader = 'ou_admin';
  let clock = 0;
  const deleted = [];
  const tick = createReadRecallProcessor({ read: async () => structuredClone(rows), write: async (r) => { rows = r; }, hasRead: async (id, user) => reader === user, recall: async (id) => deleted.push(id), now: () => clock });
  await tick();
  assert.deepEqual(deleted, []);
  reader = 'ou_requester';
  await tick();
  assert.ok(rows[0].sensitiveMessages[0].readAt);
  clock = 59999;
  await tick();
  assert.deepEqual(deleted, []);
  clock = 60000;
  await tick();
  assert.deepEqual(deleted, ['om_password']);
  assert.ok(rows[0].sensitiveMessages[0].recalledAt);
});

test('failed recall stays pending and can be retried without recording false success', async () => {
  let rows = [{ id: 'request', larkUserId: 'ou_requester', sensitiveMessages: [{ messageId: 'om_pin', readAt: new Date(0).toISOString() }] }];
  let fail = true;
  const tick = createReadRecallProcessor({ read: async () => structuredClone(rows), write: async (r) => { rows = r; }, hasRead: async () => true, recall: async () => { if (fail) throw new Error('permission denied'); }, now: () => 60000 });
  await tick();
  assert.equal(rows[0].sensitiveMessages[0].recalledAt, undefined);
  fail = false;
  await tick();
  assert.ok(rows[0].sensitiveMessages[0].recalledAt);
});
