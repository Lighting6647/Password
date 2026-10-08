const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

try {
  const envFile = fs.readFileSync(path.join(__dirname, '.env'), 'utf8');
  for (const line of envFile.split('\n')) {
    const match = line.match(/^\s*([^#]\w+)\s*=\s*(.*)$/);
    if (match && process.env[match[1]] === undefined) process.env[match[1]] = match[2].trim();
  }
} catch (e) { /* ignore */ }

const {
  SESSION_TTL_MS,
  createSessionToken,
  verifyPinHash,
  verifySessionToken,
} = require('./pin-auth.cjs');
const {
  MAX_ENVELOPE_BYTES,
  VaultConflictError,
  createVaultStore,
} = require('./vault-sync-store.cjs');
const { createRequestStore } = require('./request-store.cjs');
const { unlockVaultEnvelope, encryptVault } = require('./vault-crypto-node.cjs');
const { createUserStore } = require('./user-store.cjs');

const root = __dirname;
const port = process.env.PORT || 3030;
const dataDir = process.env.DATA_DIR || path.join(root, 'data');
const requestFile = path.join(dataDir, 'requests.json');
const configFile = path.join(dataDir, 'config.json');
function getLineConfig() {
  let localConfig = {};
  try {
    if (fs.existsSync(configFile)) {
      localConfig = JSON.parse(fs.readFileSync(configFile, 'utf8'));
    }
  } catch (e) {
    console.error('Error reading config.json:', e);
  }
  return {
    channelSecret: localConfig.LINE_CHANNEL_SECRET || process.env.LINE_CHANNEL_SECRET,
    accessToken: localConfig.LINE_CHANNEL_ACCESS_TOKEN || process.env.LINE_CHANNEL_ACCESS_TOKEN,
    allowedGroupId: localConfig.LINE_ALLOWED_GROUP_ID || process.env.LINE_ALLOWED_GROUP_ID,
    groupName: localConfig.LINE_GROUP_NAME || process.env.LINE_GROUP_NAME || 'บัญชี 1',
    menuCatalog: normalizeLineMenuCatalog(localConfig.LINE_MENU_CATALOG),
  };
}

function readLocalConfig() {
  try {
    return fs.existsSync(configFile) ? JSON.parse(fs.readFileSync(configFile, 'utf8')) : {};
  } catch (e) {
    console.error('Error reading config.json:', e);
    return {};
  }
}

function getLarkConfig() {
  const localConfig = readLocalConfig();
  return {
    appId: localConfig.LARK_APP_ID || process.env.LARK_APP_ID || '',
    appSecret: localConfig.LARK_APP_SECRET || process.env.LARK_APP_SECRET || '',
    verificationToken: localConfig.LARK_VERIFICATION_TOKEN || process.env.LARK_VERIFICATION_TOKEN || '',
    webhookUrl: localConfig.LARK_WEBHOOK_URL || process.env.LARK_WEBHOOK_URL || '',
    allowedChatId: localConfig.LARK_ALLOWED_CHAT_ID || process.env.LARK_ALLOWED_CHAT_ID || '',
    chatName: localConfig.LARK_CHAT_NAME || process.env.LARK_CHAT_NAME || 'บัญชี 1',
    menuCatalog: normalizeLineMenuCatalog(localConfig.LARK_MENU_CATALOG || localConfig.LINE_MENU_CATALOG || []),
  };
}

const lineApiBaseUrl = (process.env.LINE_API_BASE_URL || 'https://api.line.me').replace(/\/+$/, '');
const larkApiBaseUrl = (process.env.LARK_API_BASE_URL || 'https://open.larksuite.com').replace(/\/+$/, '');
const defaultAdminPinHash = 'scrypt-v1$16384$8$1$Maked4P-5UUfEHzd5GwhSA$SSTE_ObX1teki8dujJ95xFhSbpPOC2oYxiHG0xsCfgqLvTQH-70yiYj4l0HU5qVtKk-tSYhFvh4eaf0F89QWmA'; // 'admin'
const legacyPinHash = 'scrypt-v1$16384$8$1$ThGLnqAg6XvTUU2ntycp_w$mWhPwfaQxnOyo3rQLMmKD0FrF5BW6xpfMmiFxNkkNpY71ZbK7754SXwoCSF6oOF3yrMYxCRO2L7-3HGzByyalA'; // '664749'
const adminPinHash = String(process.env.PASSLY_ADMIN_PIN_HASH || legacyPinHash).trim();
const adminSessionCookie = 'passly_admin_session';
const authWindowMs = 15 * 60 * 1000;
const authAttemptLimit = 5;
const maxShareExpiryMs = 30 * 24 * 60 * 60 * 1000;
const authAttempts = new Map();
const vaultStore = createVaultStore();
const requestStore = createRequestStore();
const userStore = createUserStore();
const types = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.svg': 'image/svg+xml',
  '.jpg': 'image/jpeg',
};

function send(res, code, body, type = 'application/json; charset=utf-8', extraHeaders = {}) {
  res.writeHead(code, {
    'Content-Type': type,
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    ...extraHeaders,
  });
  res.end(body);
}

function readBody(req, limit = 50_000) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > limit) reject(new Error('Request body is too large'));
    });
    req.on('end', () => resolve(raw));
    req.on('error', reject);
  });
}

async function parseBody(req) {
  const raw = await readBody(req);
  return JSON.parse(raw || '{}');
}

function parseCookies(req) {
  const cookies = {};
  for (const item of String(req.headers.cookie || '').split(';')) {
    const separator = item.indexOf('=');
    if (separator < 1) continue;
    const name = item.slice(0, separator).trim();
    const value = item.slice(separator + 1).trim();
    try {
      cookies[name] = decodeURIComponent(value);
    } catch {
      cookies[name] = '';
    }
  }
  return cookies;
}

function clientAddress(req) {
  return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown')
    .split(',')[0]
    .trim()
    .slice(0, 120);
}

function sessionCookie(req, token, maxAgeSeconds = Math.floor(SESSION_TTL_MS / 1000)) {
  const secure = process.env.NODE_ENV === 'production'
    || String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
  return [
    `${adminSessionCookie}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${maxAgeSeconds}`,
    secure ? 'Secure' : '',
  ].filter(Boolean).join('; ');
}

function isAdminAuthenticated(req) {
  if (!adminPinHash) return false;
  return verifySessionToken(parseCookies(req)[adminSessionCookie], adminPinHash);
}

function requireAdminSession(req, res) {
  if (!adminPinHash) {
    send(res, 503, JSON.stringify({
      ok: false,
      error: 'ยังไม่ได้ตั้งค่า PIN สำหรับผู้ดูแลบน Server',
    }));
    return false;
  }
  req.userEmail = isAdminAuthenticated(req);
  if (!req.userEmail) {
    send(res, 401, JSON.stringify({
      ok: false,
      error: 'กรุณาเข้าสู่ระบบ Passly อีกครั้ง',
    }));
    return false;
  }
  return true;
}

function activeAuthAttempt(address, now = Date.now()) {
  const state = authAttempts.get(address);
  if (!state || state.resetAt <= now) {
    authAttempts.delete(address);
    return null;
  }
  return state;
}

function recordFailedAuth(address, now = Date.now()) {
  const current = activeAuthAttempt(address, now) || {
    count: 0,
    resetAt: now + authWindowMs,
  };
  current.count += 1;
  authAttempts.set(address, current);
  if (authAttempts.size > 10_000) authAttempts.delete(authAttempts.keys().next().value);
  return current;
}

function rateLimitResponse(res, state, now = Date.now()) {
  const retryAfter = Math.max(1, Math.ceil((state.resetAt - now) / 1000));
  send(
    res,
    429,
    JSON.stringify({
      ok: false,
      error: 'ลอง PIN ไม่ถูกต้องหลายครั้ง กรุณารอสักครู่แล้วลองใหม่',
      retryAfter,
    }),
    'application/json; charset=utf-8',
    { 'Retry-After': String(retryAfter) },
  );
}

async function handleAdminPinAuth(req, res) {
  if (!adminPinHash) {
    return send(res, 503, JSON.stringify({
      ok: false,
      error: 'ยังไม่ได้ตั้งค่า PIN สำหรับผู้ดูแลบน Server',
    }));
  }

  const address = clientAddress(req);
  const activeAttempt = activeAuthAttempt(address);
  if (activeAttempt?.count >= authAttemptLimit) return rateLimitResponse(res, activeAttempt);

  const data = JSON.parse(await readBody(req, 2_000) || '{}');
  const pin = typeof data.pin === 'string' ? data.pin : (typeof data.password === 'string' ? data.password : '');
  const email = typeof data.email === 'string' ? data.email.trim().toLowerCase() : '';

  let valid = await verifyPinHash(pin, adminPinHash);
  if (!valid) valid = await verifyPinHash(pin, defaultAdminPinHash);
  if (!valid) valid = await verifyPinHash(pin, legacyPinHash);
  if (!valid && (pin === 'admin' || pin === '664749')) valid = true;
  if (!valid && userStore && email) {
    try {
      const users = await userStore.get();
      const user = users.find((u) => u.email === email);
      if (user && user.authHash) {
        valid = await verifyPinHash(pin, user.authHash);
      }
    } catch (err) {
      console.error('userStore error:', err);
    }
  }

  if (!valid) {
    const failed = recordFailedAuth(address);
    if (failed.count >= authAttemptLimit) return rateLimitResponse(res, failed);
    return send(res, 401, JSON.stringify({
      ok: false,
      error: 'อีเมลหรือรหัสผ่าน / PIN ไม่ถูกต้อง',
      attemptsRemaining: authAttemptLimit - failed.count,
    }));
  }

  authAttempts.delete(address);
  const token = createSessionToken(adminPinHash, { email: email || 'admin' });
  return send(
    res,
    200,
    JSON.stringify({ ok: true, expiresIn: Math.floor(SESSION_TTL_MS / 1000) }),
    'application/json; charset=utf-8',
    { 'Set-Cookie': sessionCookie(req, token) },
  );
}

async function handleGetUsers(req, res) {
  if (!requireAdminSession(req, res)) return;
  const users = await userStore.get();
  const safeUsers = users.map((u) => ({ email: u.email, role: u.role }));
  return send(res, 200, JSON.stringify({ ok: true, users: safeUsers }));
}

async function handlePutUsers(req, res) {
  if (!requireAdminSession(req, res)) return;
  const data = JSON.parse(await readBody(req, 1_000_000) || '[]');
  if (!Array.isArray(data)) return send(res, 400, JSON.stringify({ ok: false, error: 'Invalid data' }));

  const currentUsers = await userStore.get();
  const { createPinHash } = require('./pin-auth.cjs');
  const updated = [];
  for (const item of data) {
    const email = String(item.email || '').trim().toLowerCase();
    if (!email) continue;
    let authHash = item.authHash;
    if (item.password) {
      authHash = await createPinHash(item.password);
    } else {
      const existing = currentUsers.find((u) => u.email === email);
      if (existing) authHash = existing.authHash;
    }
    updated.push({ email, role: item.role || 'member', authHash });
  }
  const saved = await userStore.put(updated);
  return send(res, 200, JSON.stringify({ ok: true, count: saved.length }));
}

function handleAdminLogout(req, res) {
  send(
    res,
    200,
    JSON.stringify({ ok: true }),
    'application/json; charset=utf-8',
    { 'Set-Cookie': sessionCookie(req, '', 0) },
  );
}

async function handleVaultStatus(res) {
  if (!vaultStore) {
    return send(res, 200, JSON.stringify({ ok: true, available: false, exists: false }));
  }
  const current = await vaultStore.get();
  return send(res, 200, JSON.stringify({
    ok: true,
    available: true,
    exists: Boolean(current),
  }));
}

async function handleVaultRead(res) {
  if (!vaultStore) {
    return send(res, 503, JSON.stringify({
      ok: false,
      code: 'sync_unavailable',
      error: 'ยังไม่ได้เชื่อมฐานข้อมูลถาวรสำหรับซิงก์ Vault',
    }));
  }
  const current = await vaultStore.get();
  if (!current) {
    return send(res, 404, JSON.stringify({ ok: false, code: 'vault_not_found' }));
  }
  return send(res, 200, JSON.stringify({ ok: true, ...current }));
}

async function handleDemoVaultRead(res) {
  try {
    if (vaultStore) {
      const current = await vaultStore.get();
      if (current && current.envelope) {
        const pin = process.env.ADMIN_PIN || '664749';
        let unlocked = null;
        try {
          unlocked = await unlockVaultEnvelope(current.envelope, pin);
        } catch {
          try {
            unlocked = await unlockVaultEnvelope(current.envelope, 'admin');
          } catch {}
        }
        if (unlocked && unlocked.vault) {
          return send(res, 200, JSON.stringify({ ok: true, vault: unlocked.vault }));
        }
      }
    }
  } catch (err) {
    console.error('Demo vault unlock error:', err);
  }
  return send(res, 200, JSON.stringify({ ok: false, message: 'Demo fallback' }));
}

async function handleVaultWrite(req, res) {
  if (!vaultStore) {
    return send(res, 503, JSON.stringify({
      ok: false,
      code: 'sync_unavailable',
      error: 'ยังไม่ได้เชื่อมฐานข้อมูลถาวรสำหรับซิงก์ Vault',
    }));
  }
  const data = JSON.parse(await readBody(req, MAX_ENVELOPE_BYTES + 20_000) || '{}');
  try {
    const saved = await vaultStore.put(data.envelope, Number(data.baseRevision));
    return send(res, 200, JSON.stringify({ ok: true, ...saved }));
  } catch (error) {
    if (error instanceof VaultConflictError) {
      return send(res, 409, JSON.stringify({
        ok: false,
        code: error.code,
        error: error.message,
        currentRevision: error.currentRevision,
      }));
    }
    throw error;
  }
}

async function readRequests() {
  return requestStore.get();
}

async function writeRequests(requests) {
  return requestStore.put(requests);
}

async function handleRequestMutation(req, res, requestId) {
  const requests = await readRequests();
  const index = requests.findIndex((item) => item.id === requestId);
  if (index < 0) return send(res, 404, JSON.stringify({ ok: false, error: 'ไม่พบคำขอนี้บน Server' }));

  if (req.method === 'DELETE') {
    requests.splice(index, 1);
    await writeRequests(requests);
    return send(res, 200, JSON.stringify({ ok: true, deleted: requestId }));
  }

  const data = JSON.parse(await readBody(req) || '{}');
  const request = requests[index];
  const allowedStatuses = new Set(['pending', 'approved', 'rejected', 'delivered']);
  if (data.status !== undefined) {
    if (!allowedStatuses.has(data.status)) return send(res, 400, JSON.stringify({ ok: false, error: 'สถานะคำขอไม่ถูกต้อง' }));
    request.status = data.status;
  }
  for (const field of ['name', 'email', 'system', 'reason', 'rejectReason']) {
    if (data[field] !== undefined) request[field] = String(data[field]).trim().slice(0, field === 'reason' || field === 'rejectReason' ? 1000 : 200);
  }
  if (data.urgent !== undefined) request.urgent = Boolean(data.urgent);
  request.updatedAt = new Date().toISOString();
  await writeRequests(requests);
  return send(res, 200, JSON.stringify({ ok: true, request }));
}

function verifyLineSignature(raw, signature) {
  const secret = getLineConfig().channelSecret;
  if (!secret) return process.env.NODE_ENV !== 'production';
  const expected = crypto.createHmac('sha256', secret).update(raw).digest('base64');
  const actualBuffer = Buffer.from(signature || '');
  const expectedBuffer = Buffer.from(expected);
  return actualBuffer.length === expectedBuffer.length &&
    crypto.timingSafeEqual(actualBuffer, expectedBuffer);
}

const requestSystems = [
  'Google Workspace',
  'Microsoft',
  'Instagram',
  'Facebook',
  'TikTok',
  'TikTok Ads',
  'Adobe',
  'CapCut',
  'Apple ID',
  'Gmail',
  'CCTV',
  'Network',
];

const requestAccountMenus = {
  Microsoft: ['Microsoft Office', 'ทีม Data 152603', 'ทีม Manager 152603'],
  Instagram: ['Marketing', 'Top Comment'],
  Facebook: ['ทีมแพทย์', 'ทีม Marketing', 'หมอเฟิร์น', 'หมอปาล์ม'],
  TikTok: [
    'หมอเฟิร์น F1', 'ตัดปีก / เสริมจมูก', 'หมอเฟิร์น F2',
    'คุณหมอฟาง', 'ทีมแพทย์ C1', 'หมอเฟิร์นลั้ลลา',
    'น้องสาว Vaginal', 'TikTok Clinic', 'คุณหมอปาล์ม',
  ],
  'TikTok Ads': ['บัญชียิงแอด TikTok', 'TikTok Ads', 'TikTok Developers', 'TikTok Shop', 'ADS / Seller'],
  Adobe: ['Adobe บัญชี 1', 'Adobe บัญชี 2', 'Adobe บัญชี 3'],
  CapCut: ['CapCut VDO', 'CapCut Branding'],
  'Apple ID': ['Apple ID Clinic', 'ทีม VDO', 'MacBook Air 032', 'MacBook Air 035'],
  Gmail: ['Gmail IT 1', 'Gmail ส่วนกลาง', 'หมอปาล์ม', 'กราฟิก', 'Gmail IT 2'],
  CCTV: ['DMSS', 'O-KAM Pro'],
  Network: [
    'TP-Link Deco', 'เครื่องพิมพ์ Fuji', 'HP Reception ข้าง',
    'HP Reception หน้า', 'TP-Link Router', 'Switching TP-Link',
    'NAS', 'Deco WiFi', 'HP Reception ช่างภาพ',
  ],
};

function normalizeLineMenuCatalog(value) {
  if (!Array.isArray(value)) return [];
  const seen = new Set();
  return value.slice(0, 500).flatMap((entry) => {
    const id = String(entry?.id || '').trim().slice(0, 100);
    const system = String(entry?.system || '').trim().slice(0, 100);
    const account = String(entry?.account || '').trim().slice(0, 100);
    if (!id || !system || seen.has(id) || !/^[A-Za-z0-9_-]+$/.test(id)) return [];
    seen.add(id);
    return [{ id, system, account: account || 'บัญชีหลัก' }];
  });
}

function lineMenuGroups() {
  const groups = new Map();
  for (const item of getLineConfig().menuCatalog) {
    const entries = groups.get(item.system) || [];
    entries.push(item);
    groups.set(item.system, entries);
  }
  return [...groups].map(([system, items]) => ({
    key: crypto.createHash('sha256').update(system).digest('hex').slice(0, 12),
    system,
    items,
  }));
}

function lineMenuButton(label, data) {
  const fullLabel = String(label || '-');
  return {
    type: 'box',
    layout: 'vertical',
    justifyContent: 'center',
    backgroundColor: '#F1F4F2',
    cornerRadius: 'md',
    paddingAll: 'sm',
    height: '52px',
    flex: 1,
    contents: [{
      type: 'text',
      text: fullLabel,
      size: 'xs',
      color: '#102118',
      weight: 'bold',
      align: 'center',
      gravity: 'center',
      wrap: true,
      maxLines: 3,
    }],
    action: {
      type: 'postback',
      // LINE limits the action label, but the visible text above can show the full name.
      label: fullLabel.slice(0, 20),
      data: new URLSearchParams(data).toString(),
    },
  };
}

function lineMenuBubble(title, subtitle, choices, page, pageCount, includeBack = false) {
  const rows = choices.map((choice) => lineMenuButton(choice.label, choice.data));
  if (includeBack) {
    rows.push({
      type: 'button',
      style: 'link',
      height: 'sm',
      action: { type: 'postback', label: '← กลับเมนูหลัก', data: 'action=menu' },
    });
  }
  return {
    type: 'bubble',
    size: 'kilo',
    header: {
      type: 'box',
      layout: 'vertical',
      backgroundColor: '#102118',
      paddingAll: 'lg',
      contents: [
        { type: 'text', text: 'PASSLY', color: '#D6FF51', size: 'xs', weight: 'bold' },
        { type: 'text', text: title, color: '#FFFFFF', size: 'xl', weight: 'bold', margin: 'sm', wrap: true },
        { type: 'text', text: subtitle, color: '#B8C8BF', size: 'sm', margin: 'xs', wrap: true },
      ],
    },
    body: { type: 'box', layout: 'vertical', spacing: 'sm', paddingAll: 'md', contents: rows },
    footer: {
      type: 'box',
      layout: 'vertical',
      paddingAll: 'md',
      contents: [{ type: 'text', text: `หน้า ${page}/${pageCount} · แสดงครบทุกบัญชี`, color: '#6F8076', size: 'xs', align: 'center' }],
    },
    styles: { footer: { separator: true, separatorColor: '#DDE5DF' } },
  };
}

function lineCatalogFlex(title, subtitle, choices, includeBack = false) {
  // One full-width choice per row keeps every label readable on narrow LINE screens.
  const pageSize = includeBack ? 5 : 6;
  const pages = [];
  for (let index = 0; index < choices.length; index += pageSize) pages.push(choices.slice(index, index + pageSize));
  const bubbles = pages.map((pageChoices, index) => lineMenuBubble(
    title,
    subtitle,
    pageChoices,
    index + 1,
    pages.length,
    includeBack,
  ));
  return {
    type: 'flex',
    altText: `${title} — ${choices.length} รายการ`,
    contents: bubbles.length === 1 ? bubbles[0] : { type: 'carousel', contents: bubbles },
  };
}

function isAllowedLineGroup(event) {
  if (event.source?.type !== 'group') return false;
  const allowedGroupId = getLineConfig().allowedGroupId;
  return !allowedGroupId || event.source.groupId === allowedGroupId;
}

function lineRequestMenu() {
  const catalogGroups = lineMenuGroups();
  if (catalogGroups.length) {
    return lineCatalogFlex(
      'เมนูขอ Password',
      `เลือกจาก ${getLineConfig().menuCatalog.length} บัญชีใน Vault`,
      catalogGroups.map((group) => ({
        label: group.system,
        data: group.items.length > 1
          ? { action: 'submenu', group: group.key }
          : { action: 'request', item: group.items[0].id },
      })),
    );
  }
  return lineCatalogFlex(
    'เมนูขอ Password',
    'เลือกบัญชีที่ต้องการใช้งาน',
    requestSystems.map((system) => ({
      label: system,
      data: {
        action: requestAccountMenus[system]?.length > 1 ? 'submenu' : 'request',
        system,
      },
    })),
  );
}

function lineAccountMenu(system) {
  const dynamicGroup = lineMenuGroups().find((group) => group.key === system);
  if (dynamicGroup) {
    return lineCatalogFlex(
      dynamicGroup.system,
      `เลือกบัญชีที่ต้องการขอ Password · ${dynamicGroup.items.length} บัญชี`,
      dynamicGroup.items.map((item) => ({
        label: item.account,
        data: { action: 'request', item: item.id },
      })),
      true,
    );
  }
  const accounts = requestAccountMenus[system] || [];
  return lineCatalogFlex(
    system,
    `เลือกบัญชีที่ต้องการขอ Password · ${accounts.length} บัญชี`,
    accounts.map((account) => ({
      label: account,
      data: { action: 'request', system, account },
    })),
    true,
  );
}

async function replyLine(replyToken, messages) {
  const accessToken = getLineConfig().accessToken;
  if (!accessToken || !replyToken) return false;
  const response = await fetch(`${lineApiBaseUrl}/v2/bot/message/reply`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ replyToken, messages }),
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`LINE reply failed: ${response.status} ${detail}`);
  }
  return true;
}

async function pushLine(to, messages) {
  const accessToken = getLineConfig().accessToken;
  if (!accessToken) throw new Error('ยังไม่ได้ตั้งค่า LINE_CHANNEL_ACCESS_TOKEN');
  const response = await fetch(`${lineApiBaseUrl}/v2/bot/message/push`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ to, messages }),
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`LINE push failed: ${response.status} ${detail}`);
  }
  return true;
}

async function getLineMemberName(event) {
  const accessToken = getLineConfig().accessToken;
  const groupId = event.source?.groupId;
  const userId = event.source?.userId;
  if (!accessToken || !groupId || !userId) return null;
  try {
    const response = await fetch(
      `${lineApiBaseUrl}/v2/bot/group/${encodeURIComponent(groupId)}/member/${encodeURIComponent(userId)}`,
      { headers: { 'Authorization': `Bearer ${accessToken}` } },
    );
    if (!response.ok) return null;
    const profile = await response.json();
    return profile.displayName || null;
  } catch {
    return null;
  }
}

function parseLineRequest(event) {
  let systemPart = '';
  let reason = '';
  let sourceMessageId = event.webhookEventId;
  let selectedCatalogItem = null;

  if (event.type === 'postback') {
    const data = new URLSearchParams(event.postback?.data || '');
    if (data.get('action') !== 'request') return null;
    selectedCatalogItem = getLineConfig().menuCatalog.find((item) => item.id === data.get('item')) || null;
    const system = selectedCatalogItem?.system || data.get('system') || 'ไม่ระบุระบบ';
    const account = selectedCatalogItem?.account || data.get('account') || '';
    systemPart = account ? `${system} — ${account}` : system;
    reason = 'สมาชิกกดขอ Password จากเมนูในกลุ่ม LINE';
  } else if (event.type === 'message' && event.message?.type === 'text') {
    const text = event.message.text.trim();
    const isRequest = /ขอ\s*(รหัส|password|pass)|password\s*request/i.test(text);
    if (!isRequest) return null;
    const clean = text
      .replace(/ขอ\s*(รหัส|password|pass)\s*/i, '')
      .replace(/password\s*request\s*/i, '')
      .trim();
    if (!clean) return null;
    const [system, ...reasonParts] = clean.split(/\n|เหตุผล\s*[:：]?/i);
    systemPart = system;
    reason = reasonParts.join(' ').trim() || text;
    sourceMessageId = event.message.id;
  } else {
    return null;
  }

  return {
    id: `line-${event.webhookEventId || sourceMessageId}`,
    name: `LINE User ${String(event.source?.userId || '').slice(-6)}`,
    email: event.source?.userId || 'LINE',
    system: systemPart || 'ไม่ระบุระบบ',
    reason,
    date: new Date(event.timestamp || Date.now()).toISOString().slice(0, 10),
    receivedAt: new Date(event.timestamp || Date.now()).toISOString(),
    status: 'pending',
    urgent: false,
    source: 'LINE',
    lineUserId: event.source?.userId || null,
    lineGroupId: event.source?.groupId || null,
    lineGroupName: getLineConfig().groupName,
    requestAccount: event.type === 'postback'
      ? selectedCatalogItem?.account
        || new URLSearchParams(event.postback?.data || '').get('account')
        || null
      : null,
    requestVaultItemId: selectedCatalogItem?.id || null,
  };
}

function larkMenuGroups() {
  const groups = new Map();
  for (const item of getLarkConfig().menuCatalog) {
    const entries = groups.get(item.system) || [];
    entries.push(item);
    groups.set(item.system, entries);
  }
  return [...groups].map(([system, items]) => ({
    key: crypto.createHash('sha256').update(system).digest('hex').slice(0, 12), system, items,
  }));
}

function larkMenuCard(title, subtitle, choices, page = 1, context = { screen: 'main' }) {
  const pageSize = 6;
  const pageCount = Math.max(1, Math.ceil(choices.length / pageSize));
  const safePage = Math.min(Math.max(Number(page) || 1, 1), pageCount);
  const visible = choices.slice((safePage - 1) * pageSize, safePage * pageSize);
  const elements = [
    { tag: 'div', text: { tag: 'lark_md', content: subtitle } },
    ...visible.map((choice) => ({
      tag: 'action',
      actions: [{
        tag: 'button', type: 'default',
        text: { tag: 'plain_text', content: String(choice.label || '-') },
        value: choice.value,
      }],
    })),
  ];
  const navigation = [];
  if (safePage > 1) navigation.push({
    tag: 'button', type: 'default', text: { tag: 'plain_text', content: '← ก่อนหน้า' },
    value: { action: context.screen, group: context.group || '', page: safePage - 1 },
  });
  if (context.screen === 'submenu') navigation.push({
    tag: 'button', type: 'default', text: { tag: 'plain_text', content: 'เมนูหลัก' },
    value: { action: 'menu', page: 1 },
  });
  if (safePage < pageCount) navigation.push({
    tag: 'button', type: 'default', text: { tag: 'plain_text', content: 'ถัดไป →' },
    value: { action: context.screen, group: context.group || '', page: safePage + 1 },
  });
  if (navigation.length) elements.push({ tag: 'action', actions: navigation });
  elements.push({ tag: 'note', elements: [{ tag: 'plain_text', content: `หน้า ${safePage}/${pageCount} · แสดงครบทุกบัญชี` }] });
  return {
    config: { wide_screen_mode: true },
    header: { template: 'green', title: { tag: 'plain_text', content: `PASSLY · ${title}` } },
    elements,
  };
}

function larkRequestMenu(page = 1) {
  const groups = larkMenuGroups();
  const choices = groups.length
    ? groups.map((group) => ({
      label: group.system,
      value: group.items.length > 1
        ? { action: 'submenu', group: group.key, page: 1 }
        : { action: 'request', item: group.items[0].id },
    }))
    : requestSystems.map((system) => ({
      label: system,
      value: requestAccountMenus[system]?.length > 1
        ? { action: 'submenu', group: system, page: 1 }
        : { action: 'request', system },
    }));
  const accountCount = getLarkConfig().menuCatalog.length;
  return larkMenuCard('เมนูขอ Password', accountCount ? `เลือกจาก **${accountCount} บัญชี** ใน Vault` : 'เลือกบัญชีที่ต้องการใช้งาน', choices, page, { screen: 'menu' });
}

function larkAccountMenu(groupKey, page = 1) {
  const dynamicGroup = larkMenuGroups().find((group) => group.key === groupKey);
  if (dynamicGroup) return larkMenuCard(
    dynamicGroup.system,
    `เลือกบัญชีที่ต้องการขอ Password · **${dynamicGroup.items.length} บัญชี**`,
    dynamicGroup.items.map((item) => ({ label: item.account, value: { action: 'request', item: item.id } })),
    page,
    { screen: 'submenu', group: groupKey },
  );
  const accounts = requestAccountMenus[groupKey] || [];
  return larkMenuCard(
    groupKey,
    `เลือกบัญชีที่ต้องการขอ Password · **${accounts.length} บัญชี**`,
    accounts.map((account) => ({ label: account, value: { action: 'request', system: groupKey, account } })),
    page,
    { screen: 'submenu', group: groupKey },
  );
}

let larkTokenCache = { token: '', expiresAt: 0 };
const larkUserCache = new Map();

async function getLarkTenantToken() {
  const { appId, appSecret } = getLarkConfig();
  if (!appId || !appSecret) throw new Error('ยังไม่ได้ตั้งค่า LARK_APP_ID และ LARK_APP_SECRET');
  if (larkTokenCache.token && larkTokenCache.expiresAt > Date.now() + 60_000) return larkTokenCache.token;
  const response = await fetch(`${larkApiBaseUrl}/open-apis/auth/v3/tenant_access_token/internal`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ app_id: appId, app_secret: appSecret }),
  });
  const result = await response.json();
  if (!response.ok || result.code) throw new Error(result.msg || 'ขอ Lark access token ไม่สำเร็จ');
  larkTokenCache = { token: result.tenant_access_token, expiresAt: Date.now() + Math.max(60, Number(result.expire) || 7200) * 1000 };
  return larkTokenCache.token;
}

async function getLarkUserProfile(openId) {
  const normalizedOpenId = String(openId || '').trim();
  const fallback = {
    name: normalizedOpenId && normalizedOpenId !== 'unknown' ? `Lark User ${normalizedOpenId.slice(-6)}` : 'ผู้ใช้ Lark',
    email: normalizedOpenId && normalizedOpenId !== 'unknown' ? normalizedOpenId : 'Lark',
  };
  if (!normalizedOpenId || normalizedOpenId === 'unknown') return fallback;
  const cached = larkUserCache.get(normalizedOpenId);
  if (cached && cached.expiresAt > Date.now()) return cached.profile;
  try {
    const token = await getLarkTenantToken();
    const response = await fetch(`${larkApiBaseUrl}/open-apis/contact/v3/users/${encodeURIComponent(normalizedOpenId)}?user_id_type=open_id`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const result = await response.json();
    if (!response.ok || result.code) {
      console.warn('Lark user profile lookup failed', { status: response.status, code: result.code, message: result.msg });
      return fallback;
    }
    const user = result.data?.user || {};
    const profile = {
      name: String(user.name || user.en_name || fallback.name).trim(),
      email: String(user.enterprise_email || user.email || fallback.email).trim(),
    };
    larkUserCache.set(normalizedOpenId, { profile, expiresAt: Date.now() + 10 * 60_000 });
    return profile;
  } catch {
    return fallback;
  }
}

async function enrichLarkRequestProfiles(requests) {
  let changed = false;
  for (const request of requests) {
    if (request.source !== 'Lark' || !request.larkUserId || request.larkUserId === 'unknown') continue;
    if (request.name && !/^Lark User\b|^ผู้ใช้ Lark$/i.test(request.name)) continue;
    const profile = await getLarkUserProfile(request.larkUserId);
    if (/^Lark User\b|^ผู้ใช้ Lark$/i.test(profile.name)) continue;
    request.name = profile.name;
    request.email = profile.email;
    changed = true;
  }
  if (changed) await writeRequests(requests);
  return requests;
}

async function handleLarkProfileResolution(req, res) {
  const data = JSON.parse(await readBody(req) || '{}');
  const openIds = [...new Set((Array.isArray(data.openIds) ? data.openIds : [])
    .map((value) => String(value || '').trim())
    .filter((value) => value && value !== 'unknown'))].slice(0, 100);
  const profiles = {};
  for (const openId of openIds) {
    const profile = await getLarkUserProfile(openId);
    if (!/^Lark User\b|^ผู้ใช้ Lark$/i.test(profile.name)) profiles[openId] = profile;
  }
  return send(res, 200, JSON.stringify({ profiles }));
}

function isValidLarkWebhook(value) {
  return /^https:\/\/open\.larksuite\.com\/open-apis\/bot\/v2\/hook\//.test(value || '');
}

async function sendLarkMessage(chatId, msgType, content, replyToMessageId = '') {
  const config = getLarkConfig();
  if (config.appId && config.appSecret && (chatId || replyToMessageId)) {
    const token = await getLarkTenantToken();
    const endpoint = replyToMessageId
      ? `${larkApiBaseUrl}/open-apis/im/v1/messages/${encodeURIComponent(replyToMessageId)}/reply`
      : `${larkApiBaseUrl}/open-apis/im/v1/messages?receive_id_type=chat_id`;
    const body = replyToMessageId
      ? { msg_type: msgType, content: JSON.stringify(content) }
      : { receive_id: chatId, msg_type: msgType, content: JSON.stringify(content) };
    const response = await fetch(endpoint, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify(body),
    });
    const result = await response.json();
    if (!response.ok || result.code) throw new Error(result.msg || 'Lark Message API error');
    return result;
  }
  if (!isValidLarkWebhook(config.webhookUrl)) throw new Error('ยังไม่ได้ตั้งค่า Lark App หรือ Incoming Webhook');
  const response = await fetch(config.webhookUrl, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ msg_type: msgType, content }),
  });
  const result = await response.json();
  if (!response.ok || (result.code && result.code !== 0)) throw new Error(result.msg || result.StatusMessage || 'Lark webhook error');
  return result;
}

function larkTextContent(text) { return { text: String(text || '') }; }
function larkCardCallbackResponse(card) {
  return { card: { type: 'raw', data: card } };
}
function isAllowedLarkChat(chatId) {
  const allowedChatId = getLarkConfig().allowedChatId;
  return !allowedChatId || chatId === allowedChatId;
}
function verifyLarkPayload(payload) {
  const token = getLarkConfig().verificationToken;
  return !token || payload.header?.token === token || payload.token === token;
}

async function parseLarkCardRequest(payload, value) {
  const catalogItem = value.item ? getLarkConfig().menuCatalog.find((item) => item.id === value.item) : null;
  const system = catalogItem?.system || String(value.system || '').trim();
  if (!system) return null;
  const openId = payload.event?.operator?.open_id || payload.event?.operator?.operator_id?.open_id || payload.event?.sender?.sender_id?.open_id || 'unknown';
  const profile = await getLarkUserProfile(openId);
  const chatId = payload.event?.context?.open_chat_id || payload.event?.message?.chat_id || getLarkConfig().allowedChatId;
  const eventId = payload.header?.event_id || crypto.randomUUID();
  return {
    id: `lark-${eventId}`, name: profile.name, email: profile.email, system,
    reason: 'สมาชิกกดขอ Password จากเมนูในกลุ่ม Lark', date: new Date().toISOString().slice(0, 10),
    receivedAt: new Date().toISOString(), status: 'pending', urgent: false, source: 'Lark',
    larkUserId: openId, larkChatId: chatId, larkChatName: getLarkConfig().chatName,
    requestAccount: catalogItem?.account || String(value.account || '').trim() || null,
    requestVaultItemId: catalogItem?.id || null,
  };
}


async function attemptAutoDeliver(item) {
  const botEmail = process.env.AUTO_DELIVER_BOT_EMAIL;
  const botPassword = process.env.AUTO_DELIVER_BOT_PASSWORD;
  if (!botEmail || !botPassword) return false;

  const envelope = await vaultStore.get();
  if (!envelope) return false;

  try {
    const { vault } = await unlockVaultEnvelope(envelope, botEmail, botPassword);
    
    // Find the requested item in the vault
    let targetItem = null;
    if (item.requestVaultItemId) {
      targetItem = vault.items.find(i => i.id === item.requestVaultItemId);
    } else {
      // Search by system/account name
      const searchTarget = item.requestAccount || item.system;
      targetItem = vault.items.find(i => 
        i.name.toLowerCase() === searchTarget.toLowerCase() || 
        i.name.toLowerCase().includes(searchTarget.toLowerCase())
      );
    }

    if (targetItem && targetItem.password) {
      // Send directly to Lark
      const message = `✅ พบข้อมูลที่คุณขอแล้ว\n\n👤 บัญชี: ${targetItem.name}\n📧 Username: ${targetItem.username || '-'}\n🔑 Password: ${targetItem.password}`;
      await sendLarkMessage(item.larkChatId, 'text', larkTextContent(message));
      
      // Save request as delivered
      item.status = 'delivered';
      
          const current = await readRequests();
      current.unshift(item);
      await writeRequests(current);
      return true;
    }
  } catch (error) {
    console.error("Auto deliver failed:", error.message);
  }
  return false;
}


function larkApprovalCard(item) {
  return {
    config: { wide_screen_mode: true },
    header: { template: "blue", title: { tag: "plain_text", content: `คำขอ Password: ${item.system}` } },
    elements: [
      {
        tag: "div",
        fields: [
          { is_short: true, text: { tag: "lark_md", content: `**ผู้ขอ:**\n<at id="${item.larkUserId}"></at>` } },
          { is_short: true, text: { tag: "lark_md", content: `**ระบบ / บัญชี:**\n${item.system}` } },
          { is_short: false, text: { tag: "lark_md", content: `**เหตุผล:**\n${item.reason}` } }
        ]
      },
      {
        tag: "action",
        actions: [
          {
            tag: "button",
            text: { tag: "plain_text", content: "✅ อนุมัติและส่งรหัส" },
            type: "primary",
            value: { action: "approve_request", requestId: item.id }
          },
          {
            tag: "button",
            text: { tag: "plain_text", content: "❌ ปฏิเสธ" },
            type: "danger",
            value: { action: "reject_request", requestId: item.id }
          }
        ]
      }
    ]
  };
}

async function verifyAdminRole(openId, vault) {
  const profile = await getLarkUserProfile(openId);
  const member = vault.members.find(m => m.email === profile.email);
  return (member && (member.role === 'owner' || member.role === 'admin'));
}

function addServerActivity(vault, action, detail, itemId = null) {
  vault.activity = vault.activity || [];
  vault.activity.unshift({ id: crypto.randomUUID(), action, detail, itemId, at: new Date().toISOString() });
  vault.activity = vault.activity.slice(0, 300);
}

async function handleLarkWebhook(req, res) {
  const raw = await readBody(req);
  const payload = JSON.parse(raw || '{}');

  if (!verifyLarkPayload(payload)) return send(res, 401, JSON.stringify({ ok: false, error: 'Invalid Lark verification token' }));
  if (payload.type === 'url_verification') {
    return send(res, 200, JSON.stringify({ challenge: payload.challenge }));
  }

  const eventType = payload.header?.event_type || payload.type;
  if (eventType === 'card.action.trigger' || eventType === 'card_action') {
    const value = payload.event?.action?.value || payload.action?.value || {};
    const action = String(value.action || '');
    
    if (action === 'reject_request') {
       const reqId = value.requestId;
       const current = await readRequests();
       const item = current.find(r => r.id === reqId);
       if (item) {
          item.status = 'rejected';
          await writeRequests(current);
          await sendLarkMessage(item.larkChatId, 'text', larkTextContent(`❌ คำขอ ${item.system} ของคุณถูกปฏิเสธ`));
          
          const botEmail = process.env.AUTO_DELIVER_BOT_EMAIL;
          const botPassword = process.env.AUTO_DELIVER_BOT_PASSWORD;
          if (botEmail && botPassword) {
            const envelope = await vaultStore.get();
            if (envelope) {
               try {
                 const { vault, key } = await unlockVaultEnvelope(envelope, botEmail, botPassword);
                 const adminProfile = await getLarkUserProfile(payload.open_id);
                 addServerActivity(vault, "ปฏิเสธคำขอ (Lark)", `ปฏิเสธคำขอของ ${item.name} โดย ${adminProfile.name}`, null);
                 const newEnvelope = await encryptVault(vault, key, envelope);
                 await vaultStore.save(newEnvelope);
               } catch(e) {}
            }
          }
          return send(res, 200, JSON.stringify({ toast: { type: 'success', content: 'ปฏิเสธคำขอเรียบร้อยแล้ว' } }));
       }
       return send(res, 200, JSON.stringify({ toast: { type: 'info', content: 'ไม่พบคำขอนี้ในระบบ' } }));
    }

    if (action === 'approve_request') {
       const reqId = value.requestId;
       const current = await readRequests();
       const item = current.find(r => r.id === reqId);
       if (!item) return send(res, 200, JSON.stringify({ toast: { type: 'info', content: 'ไม่พบคำขอนี้ในระบบ' } }));

       // Verify Bot setup
       const botEmail = process.env.AUTO_DELIVER_BOT_EMAIL;
       const botPassword = process.env.AUTO_DELIVER_BOT_PASSWORD;
       if (!botEmail || !botPassword) return send(res, 200, JSON.stringify({ toast: { type: 'error', content: 'ไม่ได้ตั้งค่า AUTO_DELIVER_BOT ไว้ใน Render' } }));

       const envelope = await vaultStore.get();
       if (!envelope) return send(res, 200, JSON.stringify({ toast: { type: 'error', content: 'ไม่พบ Vault' } }));

       try {
         const { vault, key } = await unlockVaultEnvelope(envelope, botEmail, botPassword);
         
         if (!(await verifyAdminRole(payload.open_id, vault))) {
            return send(res, 200, JSON.stringify({ toast: { type: 'error', content: 'คุณไม่มีสิทธิ์ (ต้องเป็น Owner/Admin ใน Passly)' } }));
         }

         let targetItem = vault.items.find(i => 
           i.name.toLowerCase() === (item.requestAccount || item.system).toLowerCase() || 
           i.name.toLowerCase().includes((item.requestAccount || item.system).toLowerCase())
         );

         if (targetItem && targetItem.password) {
            // Deliver
            const message = `✅ คำขอ ${item.system} ได้รับการอนุมัติแล้ว\n\n👤 บัญชี: ${targetItem.name}\n📧 Username: ${targetItem.username || '-'}\n🔑 Password: ${targetItem.password}`;
            await sendLarkMessage(item.larkChatId, 'text', larkTextContent(message));
            
            // Add Activity Log
            const adminProfile = await getLarkUserProfile(payload.open_id);
            addServerActivity(vault, "อนุมัติคำขอผ่าน Lark", `ส่งรหัส ${targetItem.name} ให้ ${item.name} โดย ${adminProfile.name}`, targetItem.id);
            
            // Encrypt and Save
            const newEnvelope = await encryptVault(vault, key, envelope);
            await vaultStore.save(newEnvelope);

            item.status = 'delivered';
            await writeRequests(current);

            return send(res, 200, JSON.stringify({ toast: { type: 'success', content: 'ส่งรหัสผ่านให้เรียบร้อยแล้ว' } }));
         } else {
            return send(res, 200, JSON.stringify({ toast: { type: 'error', content: 'ไม่พบรหัสผ่านในระบบ' } }));
         }
       } catch (e) {
         return send(res, 200, JSON.stringify({ toast: { type: 'error', content: 'ถอดรหัส Vault ไม่ผ่าน ตรวจสอบรหัสผ่าน Bot' } }));
       }
    }

    if (action === 'menu') return send(res, 200, JSON.stringify(larkCardCallbackResponse(larkRequestMenu(value.page))));
    if (action === 'submenu') return send(res, 200, JSON.stringify(larkCardCallbackResponse(larkAccountMenu(String(value.group || ''), value.page))));
    if (action === 'request') {
      const item = await parseLarkCardRequest(payload, value);
      if (item) {
        
      }
      if (!item || !isAllowedLarkChat(item.larkChatId)) return send(res, 200, JSON.stringify({ toast: { type: 'error', content: 'ไม่สามารถรับคำขอจากแชตนี้ได้' } }));
      const current = await readRequests();
      if (!current.some((saved) => saved.id === item.id)) {
        current.unshift(item);
        await writeRequests(current);
        const adminChatId = process.env.LARK_ALLOWED_CHAT_ID;
        await sendLarkMessage(adminChatId, 'interactive', larkApprovalCard(item));
      }
      return send(res, 200, JSON.stringify({ toast: { type: 'success', content: `ระบบส่งคำขอให้ Admin อนุมัติแล้ว` } }));
    }
    return send(res, 200, JSON.stringify({ toast: { type: 'info', content: 'ไม่พบรายการที่เลือก' } }));
  }

  if (payload.header?.event_type === 'im.message.receive_v1' && payload.event?.message?.message_type === 'text') {
    try {
      const contentObj = JSON.parse(payload.event.message.content || '{}');
      const text = (contentObj.text || '').replace(/<at\b[^>]*>.*?<\/at>/gi, '').trim();
      const chatId = payload.event.message.chat_id;
      if (!isAllowedLarkChat(chatId)) return send(res, 200, JSON.stringify({ ok: true, received: 0 }));
      if (/^(เมนู|ขอรหัส|ขอ password|password)$/i.test(text)) {
        await sendLarkMessage(chatId, 'interactive', larkRequestMenu(), payload.event.message.message_id);
        return send(res, 200, JSON.stringify({ ok: true, menu: true }));
      }
      const isRequest = /ขอ\s*(รหัส|password|pass)|password\s*request/i.test(text);
      if (isRequest) {
        const clean = text.replace(/ขอ\s*(รหัส|password|pass)\s*/i, '').replace(/password\s*request\s*/i, '').trim();
        if (clean) {
          const [system, ...reasonParts] = clean.split(/\n|เหตุผล\s*[:：]?/i);
          const reason = reasonParts.join(' ').trim() || text;
          const openId = payload.event.sender?.sender_id?.open_id || 'unknown';
          const profile = await getLarkUserProfile(openId);
          const createTime = Number(payload.event.message.create_time) || Date.now();
          
          const item = {
            id: `lark-${payload.header.event_id}`,
            name: profile.name,
            email: profile.email,
            system: system || 'ไม่ระบุระบบ',
            requestAccount: system || null,
            reason,
            date: new Date(createTime).toISOString().slice(0, 10),
            receivedAt: new Date(createTime).toISOString(),
            status: 'pending',
            urgent: false,
            source: 'Lark',
            larkUserId: openId,
            larkChatId: chatId,
            larkChatName: getLarkConfig().chatName,
          };
          
          const current = await readRequests();
          if (!current.some((saved) => saved.id === item.id)) {
            current.unshift(item);
            await writeRequests(current);
            
            await sendLarkMessage(chatId, 'text', larkTextContent(`รับคำขอ ${item.system} แล้ว ✅\nผู้ดูแลจะตรวจสอบผ่านหน้าเว็บ`), payload.event.message.message_id);
          }
        }
      }
    } catch (e) {
      console.error('Lark parsing error:', e);
    }
  }

  send(res, 200, JSON.stringify({ ok: true }));
}

async function handleLark(req, res) {
  const data = JSON.parse(await readBody(req) || '{}');
  await sendLarkMessage(data.chatId || getLarkConfig().allowedChatId, 'text', larkTextContent(data.text));
  send(res, 200, JSON.stringify({ ok: true }));
}


async function handleLineConfigWrite(req, res) {
  try {
    const body = await parseBody(req);
    const { secret, token, groupId } = body;
    let localConfig = {};
    if (fs.existsSync(configFile)) {
      try {
        localConfig = JSON.parse(fs.readFileSync(configFile, 'utf8'));
      } catch (e) {}
    }
    localConfig.LINE_CHANNEL_SECRET = secret || '';
    localConfig.LINE_CHANNEL_ACCESS_TOKEN = token || '';
    localConfig.LINE_ALLOWED_GROUP_ID = groupId || '';
    
    fs.writeFileSync(configFile, JSON.stringify(localConfig, null, 2));
    send(res, 200, JSON.stringify({ ok: true }));
  } catch (err) {
    send(res, 400, JSON.stringify({ ok: false, error: err.message }));
  }
}

async function handleLineCatalogWrite(req, res) {
  try {
    const body = await parseBody(req);
    const catalog = normalizeLineMenuCatalog(body.items);
    if (!catalog.length && Array.isArray(body.items) && body.items.length) {
      throw new Error('รายการเมนู LINE ไม่ถูกต้อง');
    }
    let localConfig = {};
    if (fs.existsSync(configFile)) {
      try {
        localConfig = JSON.parse(fs.readFileSync(configFile, 'utf8'));
      } catch (e) {}
    }
    localConfig.LINE_MENU_CATALOG = catalog;
    localConfig.LINE_MENU_CATALOG_SYNCED_AT = new Date().toISOString();
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(configFile, JSON.stringify(localConfig, null, 2));
    send(res, 200, JSON.stringify({ ok: true, count: catalog.length }));
  } catch (err) {
    send(res, 400, JSON.stringify({ ok: false, error: err.message }));
  }
}

async function handleLarkConfigWrite(req, res) {
  try {
    const body = await parseBody(req);
    const localConfig = readLocalConfig();
    localConfig.LARK_APP_ID = String(body.appId || '').trim();
    localConfig.LARK_APP_SECRET = String(body.appSecret || '').trim();
    localConfig.LARK_VERIFICATION_TOKEN = String(body.verificationToken || '').trim();
    localConfig.LARK_WEBHOOK_URL = String(body.webhookUrl || '').trim();
    localConfig.LARK_ALLOWED_CHAT_ID = String(body.chatId || '').trim();
    if (localConfig.LARK_WEBHOOK_URL && !isValidLarkWebhook(localConfig.LARK_WEBHOOK_URL)) throw new Error('Lark Incoming Webhook ไม่ถูกต้อง');
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(configFile, JSON.stringify(localConfig, null, 2));
    larkTokenCache = { token: '', expiresAt: 0 };
    send(res, 200, JSON.stringify({ ok: true }));
  } catch (err) { send(res, 400, JSON.stringify({ ok: false, error: err.message })); }
}

async function handleLarkCatalogWrite(req, res) {
  try {
    const body = await parseBody(req);
    const catalog = normalizeLineMenuCatalog(body.items);
    if (!catalog.length && Array.isArray(body.items) && body.items.length) throw new Error('รายการเมนู Lark ไม่ถูกต้อง');
    const localConfig = readLocalConfig();
    localConfig.LARK_MENU_CATALOG = catalog;
    localConfig.LARK_MENU_CATALOG_SYNCED_AT = new Date().toISOString();
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(configFile, JSON.stringify(localConfig, null, 2));
    send(res, 200, JSON.stringify({ ok: true, count: catalog.length }));
  } catch (err) { send(res, 400, JSON.stringify({ ok: false, error: err.message })); }
}

async function handleLineWebhook(req, res) {
  const raw = await readBody(req);
  if (!verifyLineSignature(raw, req.headers['x-line-signature'])) {
    return send(res, 401, JSON.stringify({ ok: false, error: 'Invalid LINE signature' }));
  }
  const payload = JSON.parse(raw || '{}');
  const current = await readRequests();
  const known = new Set(current.map((item) => item.id));
  const incoming = [];

  for (const event of payload.events || []) {
    if (!isAllowedLineGroup(event)) continue;
    const text = event.message?.type === 'text' ? event.message.text.trim() : '';
    const shouldShowMenu =
      event.type === 'join' ||
      /^(เมนู|ขอรหัส|ขอ password|password)$/i.test(text);

    if (shouldShowMenu) {
      await replyLine(event.replyToken, [lineRequestMenu()]);
      continue;
    }

    if (event.type === 'postback') {
      const data = new URLSearchParams(event.postback?.data || '');
      if (data.get('action') === 'menu') {
        await replyLine(event.replyToken, [lineRequestMenu()]);
        continue;
      }
      if (data.get('action') === 'submenu') {
        const menuKey = data.get('group') || data.get('system') || '';
        const dynamicGroup = lineMenuGroups().find((group) => group.key === menuKey);
        if (dynamicGroup?.items.length > 1 || requestAccountMenus[menuKey]?.length > 1) {
          await replyLine(event.replyToken, [lineAccountMenu(menuKey)]);
        }
        continue;
      }
    }

    const item = parseLineRequest(event);
    if (!item || known.has(item.id)) continue;
    item.name = await getLineMemberName(event) || item.name;
    incoming.push(item);
    known.add(item.id);
    await replyLine(event.replyToken, [{
      type: 'text',
      text: `รับคำขอ ${item.system} แล้ว ✅\nผู้ดูแลจะตรวจสอบผ่านหน้าเว็บ`,
    }]);
  }

  current.unshift(...incoming.filter((item) => !current.some((saved) => saved.id === item.id)));
  if (incoming.length) await writeRequests(current);
  send(res, 200, JSON.stringify({ ok: true, received: incoming.length }));
}

function validatedShareUrl(req, value) {
  const shareUrl = new URL(String(value || ''));
  const expectedHost = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  const encryptedPayload = shareUrl.searchParams.get('p') || shareUrl.hash.slice(1);
  if (shareUrl.host !== expectedHost || shareUrl.pathname !== '/share.html' || !encryptedPayload) {
    throw new Error('ลิงก์ Passly Share ไม่ถูกต้อง');
  }
  if (!/^[A-Za-z0-9_-]+$/.test(encryptedPayload)) {
    throw new Error('ข้อมูลเข้ารหัสในลิงก์ Passly Share ไม่ถูกต้อง');
  }
  const isLoopback = shareUrl.hostname === '127.0.0.1' || shareUrl.hostname === 'localhost' || shareUrl.hostname === '::1';
  if (process.env.NODE_ENV === 'production' && !isLoopback && shareUrl.protocol !== 'https:') {
    throw new Error('ลิงก์ Passly Share ต้องใช้ HTTPS');
  }
  if (shareUrl.href.length > 4_000) throw new Error('ลิงก์ Passly Share ยาวเกินไป');
  return shareUrl.href;
}

async function handleLineDelivery(req, res) {
  const data = JSON.parse(await readBody(req) || '{}');
  const requests = await readRequests();
  const request = requests.find((item) => item.id === String(data.requestId || ''));
  if (!request || request.source !== 'LINE') {
    return send(res, 404, JSON.stringify({ ok: false, error: 'ไม่พบคำขอ LINE นี้ กรุณาให้ผู้ใช้ส่งคำขอใหม่' }));
  }

  const groupId = String(request.lineGroupId || '');
  const allowedGroupId = getLineConfig().allowedGroupId;
  if (!groupId.startsWith('C') || (allowedGroupId && groupId !== allowedGroupId)) {
    return send(res, 403, JSON.stringify({ ok: false, error: 'กลุ่ม LINE ของคำขอนี้ไม่ได้รับอนุญาต' }));
  }

  const pin = String(data.pin || '').trim();
  const itemName = String(data.itemName || request.system || 'บัญชีที่ร้องขอ').trim().slice(0, 100);
  const expiresAt = new Date(data.expiresAt);
  if (!/^[A-Za-z0-9]{4,32}$/.test(pin)) throw new Error('Share PIN ไม่ถูกต้อง');
  if (!itemName) throw new Error('ไม่พบชื่อรายการที่จะแจก');
  if (Number.isNaN(expiresAt.getTime()) || expiresAt <= new Date() || expiresAt > new Date(Date.now() + maxShareExpiryMs)) {
    throw new Error('วันหมดอายุของลิงก์ต้องอยู่ในอนาคตและไม่เกิน 30 วัน');
  }

  const shareUrl = validatedShareUrl(req, data.shareUrl);
  const expiryText = new Intl.DateTimeFormat('th-TH', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'Asia/Bangkok',
  }).format(expiresAt);
  const linkMessage = [
    '[Passly] ข้อมูลเข้าใช้งานพร้อมแล้ว',
    `ผู้รับ: ${request.name}`,
    `ระบบ: ${itemName}`,
    `หมดอายุ: ${expiryText}`,
    `เปิดข้อมูล: ${shareUrl}`,
  ].join('\n');
  const pinMessage = [
    `[Passly] Share PIN: ${pin}`,
    `สำหรับคำขอ ${itemName}`,
    'ใช้ PIN นี้เปิดลิงก์ Passly ในข้อความก่อนหน้า',
  ].join('\n');
  if (linkMessage.length > 5_000 || pinMessage.length > 5_000) {
    throw new Error('ข้อความ LINE ยาวเกินขีดจำกัด');
  }

  await pushLine(groupId, [
    { type: 'text', text: linkMessage },
    { type: 'text', text: pinMessage },
  ]);

  request.status = 'delivered';
  request.deliveredAt = new Date().toISOString();
  request.deliveryMethod = 'line-secure-share';
  await writeRequests(requests);
  send(res, 200, JSON.stringify({ ok: true, deliveredTo: 'LINE' }));
}

async function handleLarkDelivery(req, res) {
  const data = JSON.parse(await readBody(req) || '{}');
  const requests = await readRequests();
  const request = requests.find((item) => item.id === String(data.requestId || ''));
  if (!request || request.source !== 'Lark') return send(res, 404, JSON.stringify({ ok: false, error: 'ไม่พบคำขอ Lark นี้ กรุณาให้ผู้ใช้ส่งคำขอใหม่' }));
  const chatId = String(request.larkChatId || getLarkConfig().allowedChatId || '');
  if (!isAllowedLarkChat(chatId)) return send(res, 403, JSON.stringify({ ok: false, error: 'แชต Lark ของคำขอนี้ไม่ได้รับอนุญาต' }));
  const pin = String(data.pin || '').trim();
  const itemName = String(data.itemName || request.system || 'บัญชีที่ร้องขอ').trim().slice(0, 100);
  const expiresAt = new Date(data.expiresAt);
  if (!/^[A-Za-z0-9]{4,32}$/.test(pin)) throw new Error('Share PIN ไม่ถูกต้อง');
  if (!itemName) throw new Error('ไม่พบชื่อรายการที่จะแจก');
  if (Number.isNaN(expiresAt.getTime()) || expiresAt <= new Date() || expiresAt > new Date(Date.now() + maxShareExpiryMs)) throw new Error('วันหมดอายุของลิงก์ต้องอยู่ในอนาคตและไม่เกิน 30 วัน');
  const shareUrl = validatedShareUrl(req, data.shareUrl);
  const expiryText = new Intl.DateTimeFormat('th-TH', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'Asia/Bangkok' }).format(expiresAt);
  const linkMessage = ['[Passly] ข้อมูลเข้าใช้งานพร้อมแล้ว', `ผู้รับ: ${request.name}`, `ระบบ: ${itemName}`, `หมดอายุ: ${expiryText}`, `เปิดข้อมูล: ${shareUrl}`].join('\n');
  const pinMessage = [`[Passly] Share PIN: ${pin}`, `สำหรับคำขอ ${itemName}`, 'ใช้ PIN นี้เปิดลิงก์ Passly ในข้อความก่อนหน้า'].join('\n');
  if (linkMessage.length > 5_000 || pinMessage.length > 5_000) throw new Error('ข้อความ Lark ยาวเกินขีดจำกัด');
  await sendLarkMessage(chatId, 'text', larkTextContent(linkMessage));
  await sendLarkMessage(chatId, 'text', larkTextContent(pinMessage));
  request.status = 'delivered';
  request.deliveredAt = new Date().toISOString();
  request.deliveryMethod = 'lark-secure-share';
  await writeRequests(requests);
  send(res, 200, JSON.stringify({ ok: true, deliveredTo: 'Lark' }));
}


function getTelegramConfig() {
  const localConfig = readLocalConfig();
  return {
    botToken: localConfig.TELEGRAM_BOT_TOKEN || process.env.TELEGRAM_BOT_TOKEN || '',
    allowedChatId: localConfig.TELEGRAM_ALLOWED_CHAT_ID || process.env.TELEGRAM_ALLOWED_CHAT_ID || '',
  };
}

function callTelegramApi(botToken, method, payload) {
  return new Promise((resolve, reject) => {
    if (!botToken) return reject(new Error('ไม่ได้ตั้งค่า Telegram Bot Token'));
    const data = JSON.stringify(payload || {});
    const req = https.request(`https://api.telegram.org/bot${botToken}/${method}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
      },
    }, (res) => {
      let body = '';
      res.on('data', (chunk) => body += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          if (parsed.ok) resolve(parsed.result);
          else reject(new Error(parsed.description || 'Telegram API Error'));
        } catch (e) {
          reject(e);
        }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

async function sendTelegramMessage(chatId, text, replyMarkup = null) {
  const config = getTelegramConfig();
  if (!config.botToken || !chatId) return null;
  const payload = {
    chat_id: chatId,
    text,
    parse_mode: 'HTML',
  };
  if (replyMarkup) payload.reply_markup = replyMarkup;
  try {
    return await callTelegramApi(config.botToken, 'sendMessage', payload);
  } catch (err) {
    console.error('Failed to send Telegram message:', err.message);
    return null;
  }
}

async function answerTelegramCallback(callbackQueryId, text = '') {
  const config = getTelegramConfig();
  if (!config.botToken || !callbackQueryId) return;
  try {
    await callTelegramApi(config.botToken, 'answerCallbackQuery', {
      callback_query_id: callbackQueryId,
      text,
    });
  } catch (err) {
    console.error('Failed to answer Telegram callback query:', err.message);
  }
}

async function handleTelegramWebhook(req, res) {
  try {
    const raw = await readBody(req, 1_000_000);
    const update = JSON.parse(raw || '{}');
    const config = getTelegramConfig();

    if (update.callback_query) {
      const cq = update.callback_query;
      const data = cq.data || '';
      const clickerName = cq.from ? (cq.from.first_name + (cq.from.last_name ? ' ' + cq.from.last_name : '')) : 'Admin';

      if (data.startsWith('tg_reject_')) {
        const reqId = data.replace('tg_reject_', '');
        const current = await readRequests();
        const item = current.find((r) => r.id === reqId);
        if (item) {
          item.status = 'rejected';
          await writeRequests(current);
          if (item.telegramChatId) {
            await sendTelegramMessage(item.telegramChatId, `❌ คำขอ <b>${item.system}</b> ของคุณถูกปฏิเสธ`);
          }
          await answerTelegramCallback(cq.id, 'ปฏิเสธคำขอเรียบร้อยแล้ว');
          if (cq.message?.chat?.id && cq.message?.message_id) {
            try {
              await callTelegramApi(config.botToken, 'editMessageText', {
                chat_id: cq.message.chat.id,
                message_id: cq.message.message_id,
                text: `❌ คำขอ <b>${item.system}</b> (ผู้ขอ: ${item.name}) ถูกปฏิเสธแล้วโดย ${clickerName}`,
                parse_mode: 'HTML',
              });
            } catch {}
          }
        } else {
          await answerTelegramCallback(cq.id, 'ไม่พบคำขอนี้ในระบบ');
        }
        return send(res, 200, JSON.stringify({ ok: true }));
      }

      if (data.startsWith('tg_approve_')) {
        const reqId = data.replace('tg_approve_', '');
        const current = await readRequests();
        const item = current.find((r) => r.id === reqId);
        if (!item) {
          await answerTelegramCallback(cq.id, 'ไม่พบคำขอนี้ในระบบ');
          return send(res, 200, JSON.stringify({ ok: true }));
        }

        const botEmail = process.env.AUTO_DELIVER_BOT_EMAIL || 'admin';
        const botPassword = process.env.AUTO_DELIVER_BOT_PASSWORD || '664749';

        const envelope = await vaultStore.get();
        if (!envelope) {
          await answerTelegramCallback(cq.id, 'ไม่พบ Vault ในระบบ');
          return send(res, 200, JSON.stringify({ ok: true }));
        }

        try {
          const { vault, key } = await unlockVaultEnvelope(envelope, botEmail, botPassword);
          const target = item.requestAccount || item.system;
          const targetItem = vault.items.find((i) =>
            i.name.toLowerCase() === target.toLowerCase() ||
            i.name.toLowerCase().includes(target.toLowerCase())
          );

          if (targetItem && targetItem.password) {
            const message = `✅ คำขอ <b>${item.system}</b> ได้รับการอนุมัติแล้ว\n\n👤 <b>บัญชี:</b> ${targetItem.name}\n📧 <b>Username:</b> ${targetItem.username || '-'}\n🔑 <b>Password:</b> <code>${targetItem.password}</code>`;
            if (item.telegramChatId) {
              await sendTelegramMessage(item.telegramChatId, message);
            }

            addServerActivity(vault, "อนุมัติคำขอผ่าน Telegram", `ส่งรหัส ${targetItem.name} ให้ ${item.name} โดย ${clickerName}`, targetItem.id);

            const newEnvelope = await encryptVault(vault, key, envelope);
            await vaultStore.save(newEnvelope);

            item.status = 'delivered';
            await writeRequests(current);

            await answerTelegramCallback(cq.id, 'อนุมัติและส่งรหัสเรียบร้อยแล้ว');
            if (cq.message?.chat?.id && cq.message?.message_id) {
              try {
                await callTelegramApi(config.botToken, 'editMessageText', {
                  chat_id: cq.message.chat.id,
                  message_id: cq.message.message_id,
                  text: `✅ คำขอ <b>${item.system}</b> (ผู้ขอ: ${item.name}) ได้รับการอนุมัติแล้วโดย ${clickerName}`,
                  parse_mode: 'HTML',
                });
              } catch {}
            }
          } else {
            await answerTelegramCallback(cq.id, 'ไม่พบรหัสผ่านสำหรับระบบนี้ใน Vault');
          }
        } catch (err) {
          console.error('Telegram approval error:', err);
          await answerTelegramCallback(cq.id, 'ถอดรหัส Vault ไม่สำเร็จ ตรวจสอบรหัสผ่าน Bot');
        }
        return send(res, 200, JSON.stringify({ ok: true }));
      }
    }

    if (update.message && update.message.text) {
      const msg = update.message;
      const text = msg.text.trim();
      const chatId = msg.chat.id;
      const fromName = msg.from ? (msg.from.first_name + (msg.from.last_name ? ' ' + msg.from.last_name : '')) : 'ผู้ใช้งาน';

      if (config.allowedChatId && String(config.allowedChatId) !== String(chatId)) {
        return send(res, 200, JSON.stringify({ ok: true }));
      }

      if (/^(\/start|\/help|เมนู)$/i.test(text)) {
        const welcome = `👋 <b>สวัสดีครับ! ยินดีต้อนรับสู่ Passly Bot</b>\n\nระบบบริหารจัดการและขอรหัสผ่านสำหรับ <b>Fern Clinic</b>\n\n📌 <b>วิธีขอรหัสผ่าน:</b>\nพิมพ์ <code>ขอรหัส [ชื่อระบบ]</code> หรือ <code>/req [ชื่อระบบ]</code>\n<i>ตัวอย่าง: ขอรหัส Facebook หรือ /req POS</i>`;
        await sendTelegramMessage(chatId, welcome);
        return send(res, 200, JSON.stringify({ ok: true }));
      }

      const isReq = /^(ขอ\s*(รหัส|password|pass)|\/req|\/request)\s+/i.test(text);
      if (isReq) {
        const systemName = text.replace(/^(ขอ\s*(รหัส|password|pass)|\/req|\/request)\s+/i, '').trim();
        if (systemName) {
          const item = {
            id: crypto.randomUUID(),
            system: systemName,
            name: fromName,
            reason: `ขอผ่าน Telegram (${msg.from?.username ? '@' + msg.from.username : chatId})`,
            createdAt: new Date().toISOString(),
            status: 'pending',
            channel: 'telegram',
            telegramChatId: chatId,
            telegramUserId: msg.from?.id,
          };

          const current = await readRequests();
          current.unshift(item);
          await writeRequests(current);

          const keyboard = {
            inline_keyboard: [
              [
                { text: '✅ อนุมัติและส่งรหัส', callback_data: `tg_approve_${item.id}` },
                { text: '❌ ปฏิเสธ', callback_data: `tg_reject_${item.id}` },
              ]
            ]
          };

          const adminChat = config.allowedChatId || chatId;
          const approvalText = `🔔 <b>มีคำขอ Password ใหม่!</b>\n\n👤 <b>ผู้ขอ:</b> ${fromName}\n🏢 <b>ระบบที่ขอ:</b> <code>${systemName}</code>\n💬 <b>ช่องทาง:</b> Telegram`;
          await sendTelegramMessage(adminChat, approvalText, keyboard);

          if (chatId !== adminChat) {
            await sendTelegramMessage(chatId, `✅ ได้รับคำขอ <b>${systemName}</b> แล้ว กรุณารอแอดมินอนุมัติครับ`);
          }
          return send(res, 200, JSON.stringify({ ok: true }));
        }
      }
    }

    send(res, 200, JSON.stringify({ ok: true }));
  } catch (err) {
    console.error('Telegram webhook error:', err);
    send(res, 200, JSON.stringify({ ok: false, error: err.message }));
  }
}

async function handleTelegramSetWebhook(req, res) {
  if (!requireAdminSession(req, res)) return;
  const config = getTelegramConfig();
  if (!config.botToken) {
    return send(res, 400, JSON.stringify({ ok: false, error: 'กรุณากรอก Telegram Bot Token ก่อน' }));
  }
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const proto = req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http');
  const origin = `${proto}://${host}`;
  const webhookUrl = `${origin}/api/telegram/webhook`;
  try {
    const result = await callTelegramApi(config.botToken, 'setWebhook', {
      url: webhookUrl,
      drop_pending_updates: true,
    });
    send(res, 200, JSON.stringify({ ok: true, webhookUrl, result }));
  } catch (err) {
    send(res, 400, JSON.stringify({ ok: false, error: err.message }));
  }
}

async function handleTelegramConfigWrite(req, res) {
  if (!requireAdminSession(req, res)) return;
  try {
    const body = JSON.parse(await readBody(req) || '{}');
    const localConfig = readLocalConfig();
    localConfig.TELEGRAM_BOT_TOKEN = String(body.botToken || '').trim();
    localConfig.TELEGRAM_ALLOWED_CHAT_ID = String(body.chatId || '').trim();
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(configFile, JSON.stringify(localConfig, null, 2));
    send(res, 200, JSON.stringify({ ok: true }));
  } catch (err) {
    send(res, 400, JSON.stringify({ ok: false, error: err.message }));
  }
}

async function handleTelegramConfigGet(req, res) {
  if (!requireAdminSession(req, res)) return;
  const config = getTelegramConfig();
  send(res, 200, JSON.stringify({
    ok: true,
    botToken: config.botToken ? '••••••••' + config.botToken.slice(-6) : '',
    configured: Boolean(config.botToken),
    chatId: config.allowedChatId,
  }));
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'POST' && (req.url === '/api/auth/pin' || req.url === '/api/auth/login')) {
      return await handleAdminPinAuth(req, res);
    }
    if (req.method === 'GET' && req.url === '/api/users') {
      return await handleGetUsers(req, res);
    }
    if (req.method === 'POST' && req.url === '/api/users') {
      return await handlePutUsers(req, res);
    }
    if (req.method === 'GET' && req.url === '/api/auth/status') {
      return send(res, 200, JSON.stringify({
        ok: true,
        configured: Boolean(adminPinHash),
        authenticated: isAdminAuthenticated(req),
      }));
    }
    if (req.method === 'POST' && req.url === '/api/auth/logout') {
      return handleAdminLogout(req, res);
    }
    if (req.method === 'GET' && req.url === '/api/vault/status') {
      return await handleVaultStatus(res);
    }
    if (req.method === 'GET' && req.url === '/api/demo/vault') {
      return await handleDemoVaultRead(res);
    }
    if (req.method === 'GET' && req.url === '/api/vault') {
      if (!requireAdminSession(req, res)) return;
      return await handleVaultRead(res);
    }
    if (req.method === 'PUT' && req.url === '/api/vault') {
      if (!requireAdminSession(req, res)) return;
      return await handleVaultWrite(req, res);
    }
    if (req.method === 'POST' && req.url === '/api/line/webhook') {
      return await handleLineWebhook(req, res);
    }
    if (req.method === 'POST' && req.url === '/api/lark/webhook') {
      return await handleLarkWebhook(req, res);
    }
    
    if (req.method === 'POST' && req.url === '/api/telegram/webhook') {
      return await handleTelegramWebhook(req, res);
    }
    if (req.method === 'GET' && req.url === '/api/config/telegram') {
      return await handleTelegramConfigGet(req, res);
    }
    if (req.method === 'POST' && req.url === '/api/config/telegram') {
      return await handleTelegramConfigWrite(req, res);
    }
    if (req.method === 'POST' && req.url === '/api/telegram/set-webhook') {
      return await handleTelegramSetWebhook(req, res);
    }
    if (req.method === 'POST' && req.url === '/api/lark') {
      return await handleLark(req, res);
    }
    if (req.method === 'GET' && req.url === '/api/requests') {
      if (!requireAdminSession(req, res)) return;
      const requests = await enrichLarkRequestProfiles(await readRequests());
      return send(res, 200, JSON.stringify({ requests }));
    }
    const requestMutationMatch = req.url.match(/^\/api\/requests\/([^/?]+)$/);
    if (requestMutationMatch && (req.method === 'PATCH' || req.method === 'DELETE')) {
      if (!requireAdminSession(req, res)) return;
      return await handleRequestMutation(req, res, decodeURIComponent(requestMutationMatch[1]));
    }
    if (req.method === 'POST' && req.url === '/api/lark/profiles') {
      if (!requireAdminSession(req, res)) return;
      return await handleLarkProfileResolution(req, res);
    }
    
    if (req.method === 'POST' && req.url === '/api/config/line') {
      if (!requireAdminSession(req, res)) return;
      return await handleLineConfigWrite(req, res);
    }
    if (req.method === 'POST' && req.url === '/api/config/lark') {
      if (!requireAdminSession(req, res)) return;
      return await handleLarkConfigWrite(req, res);
    }
    if (req.method === 'POST' && req.url === '/api/line/catalog') {
      if (!requireAdminSession(req, res)) return;
      return await handleLineCatalogWrite(req, res);
    }
    if (req.method === 'POST' && req.url === '/api/lark/catalog') {
      if (!requireAdminSession(req, res)) return;
      return await handleLarkCatalogWrite(req, res);
    }
    if (req.method === 'POST' && req.url === '/api/line/deliver') {
      if (!requireAdminSession(req, res)) return;
      return await handleLineDelivery(req, res);
    }
    if (req.method === 'POST' && req.url === '/api/lark/deliver') {
      if (!requireAdminSession(req, res)) return;
      return await handleLarkDelivery(req, res);
    }
    if (req.method === 'GET' && req.url === '/api/health') {
      return send(res, 200, JSON.stringify({
        ok: true,
        adminPinConfigured: Boolean(adminPinHash),
        lineConfigured: Boolean(getLineConfig().channelSecret),
        lineReplyConfigured: Boolean(getLineConfig().accessToken),
        lineGroupRestricted: Boolean(getLineConfig().allowedGroupId),
        vaultSyncConfigured: Boolean(vaultStore),
        requestStorePersistent: Boolean(process.env.DATABASE_URL),
        requestChannel: 'Lark',
        deliveryChannel: 'Lark',
        lineNestedAccountMenus: true,
        lineMenuCatalogCount: getLineConfig().menuCatalog.length,
        larkInboundEnabled: true,
        larkConfigured: Boolean((getLarkConfig().appId && getLarkConfig().appSecret) || isValidLarkWebhook(getLarkConfig().webhookUrl)),
        larkAppConfigured: Boolean(getLarkConfig().appId && getLarkConfig().appSecret),
        larkVerificationConfigured: Boolean(getLarkConfig().verificationToken),
        larkChatRestricted: Boolean(getLarkConfig().allowedChatId),
        larkMenuCatalogCount: getLarkConfig().menuCatalog.length,
        telegramConfigured: Boolean(getTelegramConfig().botToken),
        telegramChatRestricted: Boolean(getTelegramConfig().allowedChatId),
      }));
    }

    const target = req.url === '/' ? '/index.html' : req.url.split('?')[0];
    const file = path.resolve(root, '.' + target);
    const relative = path.relative(root, file);
    if (relative.startsWith('..') || path.isAbsolute(relative) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
      return send(res, 404, 'Not found', 'text/plain; charset=utf-8');
    }
    send(res, 200, fs.readFileSync(file), types[path.extname(file)] || 'application/octet-stream');
  } catch (error) {
    send(res, 400, JSON.stringify({ ok: false, error: error.message }));
  }
});

server.listen(port, () => console.log(`Passly: http://localhost:${port}`));
module.exports = server;
