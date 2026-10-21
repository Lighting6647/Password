const AUTO_APPROVAL_DELAY_MS = 30 * 1000;

function scheduleAutoApproval(now = Date.now()) {
  return { autoApproveAt: new Date(now + AUTO_APPROVAL_DELAY_MS).toISOString() };
}

function createAutoApprovalProcessor({ read, write, deliver, now = Date.now, locks = new Set() }) {
  let running = false;
  return async function processDueRequests() {
    if (running) return;
    running = true;
    try {
      const candidates = await read();
      for (const candidate of candidates) {
        if (locks.has(candidate.id)) continue;
        locks.add(candidate.id);
        try {
          const current = await read();
          const item = current.find((request) => request.id === candidate.id);
          if (!item || item.source !== 'Lark' || item.status !== 'pending'
            || !item.requestVaultItemId || !item.autoApproveAt || item.autoApprovalError
            || !Number.isFinite(Date.parse(item.autoApproveAt))
            || Date.parse(item.autoApproveAt) > now()) continue;

          // Persist a claim before any external send. A restart must not blindly resend it.
          item.status = 'auto_approving';
          item.approvedBy = { type: 'agent', name: 'Passly Agent' };
          item.approvalMethod = 'automatic-after-30-seconds';
          item.approvedAt = new Date(now()).toISOString();
          await write(current);
          let delivered = false;
          let deliveryResult;
          try {
            deliveryResult = await deliver(item);
            delivered = true;
          } catch {
            // The remote send may have succeeded despite a network error. Require human retry.
          }
          const latest = await read();
          const saved = latest.find((request) => request.id === item.id);
          if (saved && saved.status === 'auto_approving') {
            saved.status = delivered ? 'delivered' : 'pending';
            if (delivered) {
              saved.deliveryMethod = 'lark-agent-auto-approval';
              if (deliveryResult?.sensitiveMessages) saved.sensitiveMessages = deliveryResult.sensitiveMessages;
            }
            else saved.autoApprovalError = 'delivery_failed';
            await write(latest);
          }
        } finally {
          locks.delete(candidate.id);
        }
      }
    } finally {
      running = false;
    }
  };
}

module.exports = { scheduleAutoApproval, createAutoApprovalProcessor };
