function createReadRecallProcessor({ read, write, hasRead, recall, now = Date.now, locks = new Set(), onError = () => {} }) {
  let running = false;
  return async function recallReadMessages() {
    if (running) return;
    running = true;
    try {
      for (const request of await read()) {
        if (!request.larkUserId || locks.has(request.id)) continue;
        locks.add(request.id);
        try {
          for (const message of request.sensitiveMessages || []) {
            if (!message.messageId || message.recalledAt) continue;
            try {
              if (!await hasRead(message.messageId, request.larkUserId)) continue;
              await recall(message.messageId);
              const latest = await read();
              const saved = latest.find((item) => item.id === request.id)
                ?.sensitiveMessages?.find((item) => item.messageId === message.messageId);
              if (saved) {
                saved.recalledAt = new Date(now()).toISOString();
                await write(latest);
              }
            } catch {
              onError();
            }
          }
        } finally {
          locks.delete(request.id);
        }
      }
    } finally {
      running = false;
    }
  };
}

module.exports = { createReadRecallProcessor };
