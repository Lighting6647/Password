import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { createAutoApprovalProcessor, scheduleAutoApproval } = require('../lark-auto-approval.cjs');

test('new requests wait three minutes and record Agent as the actor', async () => {
  const start = Date.parse('2026-10-21T00:00:00Z');
  let clock = start;
  let requests = [{ id: 'r1', source: 'Lark', status: 'pending', requestVaultItemId: 'wifi-2', ...scheduleAutoApproval(start) }];
  const sent = [];
  const tick = createAutoApprovalProcessor({
    read: async () => structuredClone(requests),
    write: async (value) => { requests = structuredClone(value); },
    deliver: async (request) => { sent.push(request.requestVaultItemId); },
    now: () => clock,
  });
  clock = start + 179999;
  await tick();
  assert.deepEqual(sent, []);
  clock += 1;
  await tick();
  await tick();
  assert.deepEqual(sent, ['wifi-2']);
  assert.equal(requests[0].status, 'delivered');
  assert.equal(requests[0].approvedBy.type, 'agent');
  assert.equal(requests[0].approvalMethod, 'automatic-after-3-minutes');
  assert.equal(requests[0].approvedBy.openId, undefined);
});

test('rejected, already approved, unscheduled and non-exact requests are never auto-delivered', async () => {
  const due = scheduleAutoApproval(0);
  let requests = [
    { id: 'rejected', source: 'Lark', status: 'rejected', requestVaultItemId: 'a', ...due },
    { id: 'done', source: 'Lark', status: 'delivered', requestVaultItemId: 'b', ...due },
    { id: 'old', source: 'Lark', status: 'pending', requestVaultItemId: 'c' },
    { id: 'ambiguous', source: 'Lark', status: 'pending', ...due },
  ];
  const sent = [];
  const tick = createAutoApprovalProcessor({ read: async () => requests, write: async (r) => { requests = r; }, deliver: async (r) => sent.push(r.id), now: () => 180000 });
  await tick();
  assert.deepEqual(sent, []);
});

test('parallel scans cannot send twice and a delivery error is not retried automatically', async () => {
  let requests = [{ id: 'r1', source: 'Lark', status: 'pending', requestVaultItemId: 'a', ...scheduleAutoApproval(0) }];
  let attempts = 0;
  const tick = createAutoApprovalProcessor({
    read: async () => structuredClone(requests),
    write: async (r) => { requests = structuredClone(r); },
    deliver: async () => { attempts++; throw new Error('delivery failed'); },
    now: () => 180000,
  });
  await Promise.all([tick(), tick()]);
  await tick();
  assert.equal(attempts, 1);
  assert.equal(requests[0].status, 'pending');
  assert.equal(requests[0].autoApprovalError, 'delivery_failed');
});
