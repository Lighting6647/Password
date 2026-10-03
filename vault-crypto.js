const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const VAULT_STORAGE_KEY = "passly-encrypted-vault-v1";
export const VAULT_VERSION = 3;
export const KDF_ITERATIONS = 600_000;
export const SHARE_KDF_ITERATIONS = 250_000;
export const MAX_SHARE_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000;
export const MASTER_PASSWORD_NORMALIZATION = "NFKC";
export const VAULT_SECRET_CANONICALIZATION = "PASSLY-V2";
export const VAULT_SECRET_ENCODING = "SHA-512-64-BYTE";

function thaiDigitsToAscii(value) {
  return value.replace(/[๐-๙]/g, (digit) => String("๐๑๒๓๔๕๖๗๘๙".indexOf(digit)));
}

export function normalizeVaultSecret(value) {
  const normalized = String(value).normalize(MASTER_PASSWORD_NORMALIZATION).trim();
  if (/^[0-9๐-๙\s-]+$/.test(normalized)) {
    return thaiDigitsToAscii(normalized).replace(/[\s-]/g, "");
  }
  return normalized;
}

export function toLocalDatetimeValue(date) {
  const value = date instanceof Date ? date : new Date(date);
  if (Number.isNaN(value.getTime())) return "";
  const pad = (part) => String(part).padStart(2, "0");
  return [
    `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}`,
    `${pad(value.getHours())}:${pad(value.getMinutes())}`,
  ].join("T");
}

export function resolveShareExpiry(expiryValue, customValue, nowMs = Date.now()) {
  let expiresAt;
  if (expiryValue === "custom") {
    if (!customValue) throw new Error("กรุณากำหนดวันและเวลาหมดอายุ");
    expiresAt = new Date(customValue);
  } else {
    const hours = Number(expiryValue);
    if (!Number.isFinite(hours) || hours <= 0) throw new Error("ระยะเวลาหมดอายุไม่ถูกต้อง");
    expiresAt = new Date(nowMs + hours * 3_600_000);
  }
  if (Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() <= nowMs) {
    throw new Error("วันและเวลาหมดอายุต้องอยู่ในอนาคต");
  }
  if (expiresAt.getTime() > nowMs + MAX_SHARE_EXPIRY_MS) {
    throw new Error("ลิงก์ Passly กำหนดอายุได้สูงสุด 30 วัน");
  }
  return expiresAt.toISOString();
}

export function bytesToBase64(bytes) {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary);
}

export function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export function base64UrlToBytes(value) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return base64ToBytes(padded);
}

export function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

export async function deriveVaultKey(
  masterPassword,
  salt,
  iterations = KDF_ITERATIONS,
  secretEncoding = null,
) {
  let secretBytes = encoder.encode(masterPassword);
  if (secretEncoding === VAULT_SECRET_ENCODING) {
    secretBytes = new Uint8Array(await crypto.subtle.digest("SHA-512", secretBytes));
  }
  const material = await crypto.subtle.importKey(
    "raw",
    secretBytes,
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}


export async function addKeyring(masterKey, email, password) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const userKey = await deriveVaultKey(
    normalizeVaultSecret(password),
    salt,
    KDF_ITERATIONS,
    VAULT_SECRET_ENCODING
  );
  const rawMasterKey = await crypto.subtle.exportKey("raw", masterKey);
  const encryptedKey = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, userKey, rawMasterKey);
  return {
    email: email.toLowerCase().trim(),
    kdf: "PBKDF2-SHA256",
    iterations: KDF_ITERATIONS,
    salt: bytesToBase64(salt),
    passwordNormalization: MASTER_PASSWORD_NORMALIZATION,
    secretCanonicalization: VAULT_SECRET_CANONICALIZATION,
    secretEncoding: VAULT_SECRET_ENCODING,
    keyrings: envelope.keyrings || [],
    iv: bytesToBase64(iv),
    encryptedKey: bytesToBase64(new Uint8Array(encryptedKey))
  };
}

export async function encryptVault(vault, key, envelope = {}) {
  const iv = randomBytes(12);
  const payload = encoder.encode(JSON.stringify(vault));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, payload);
  return {
    version: VAULT_VERSION,
    algorithm: "AES-GCM-256",
    kdf: "PBKDF2-SHA256",
    iterations: envelope.iterations ?? KDF_ITERATIONS,
    salt: envelope.salt,
    passwordNormalization: envelope.passwordNormalization,
    secretCanonicalization: envelope.secretCanonicalization,
    secretEncoding: envelope.secretEncoding,
    iv: bytesToBase64(iv),
    data: bytesToBase64(new Uint8Array(encrypted)),
    updatedAt: new Date().toISOString(),
  };
}

export async function decryptVault(envelope, key) {
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(envelope.iv) },
    key,
    base64ToBytes(envelope.data),
  );
  return JSON.parse(decoder.decode(decrypted));
}

export async function createVaultEnvelope(vault, masterPassword) {
  const salt = randomBytes(16);
  const key = await deriveVaultKey(
    normalizeVaultSecret(masterPassword),
    salt,
    KDF_ITERATIONS,
    VAULT_SECRET_ENCODING,
  );
  const envelope = await encryptVault(vault, key, {
    salt: bytesToBase64(salt),
    iterations: KDF_ITERATIONS,
    passwordNormalization: MASTER_PASSWORD_NORMALIZATION,
    secretCanonicalization: VAULT_SECRET_CANONICALIZATION,
    secretEncoding: VAULT_SECRET_ENCODING,
  });
  return { key, envelope };
}

export async function unlockVaultEnvelope(envelope, email, password) {
  if (password === undefined) {
    password = email;
    email = null;
  }

  const normalizedPassword = envelope.secretCanonicalization === VAULT_SECRET_CANONICALIZATION
    ? normalizeVaultSecret(password)
    : envelope.passwordNormalization
      ? password.normalize(envelope.passwordNormalization)
      : password;

  let key = null;

  if (email && Array.isArray(envelope.keyrings) && envelope.keyrings.length > 0) {
    const targetEmail = String(email).trim().toLowerCase();
    const keyring = envelope.keyrings.find((k) => k.email && k.email.trim().toLowerCase() === targetEmail);
    if (keyring && keyring.encryptedKey && keyring.iv && keyring.salt) {
      try {
        const userKey = await deriveVaultKey(
          normalizedPassword,
          base64ToBytes(keyring.salt),
          keyring.iterations ?? KDF_ITERATIONS,
          keyring.secretEncoding || VAULT_SECRET_ENCODING,
        );
        const subtle = crypto.subtle;
        const rawMasterKey = await subtle.decrypt(
          { name: "AES-GCM", iv: base64ToBytes(keyring.iv) },
          userKey,
          base64ToBytes(keyring.encryptedKey),
        );
        key = await subtle.importKey(
          "raw",
          rawMasterKey,
          { name: "AES-GCM" },
          true,
          ["encrypt", "decrypt"],
        );
      } catch (err) {
        console.warn("Keyring unlock failed, falling back to root:", err.message);
      }
    }
  }

  if (!key) {
    key = await deriveVaultKey(
      normalizedPassword,
      base64ToBytes(envelope.salt),
      envelope.iterations ?? KDF_ITERATIONS,
      envelope.secretEncoding,
    );
  }

  const vault = await decryptVault(envelope, key);
  return { key, vault };
}

function secureRandomIndex(max) {
  if (max <= 0) throw new Error("Invalid random range");
  const limit = Math.floor(0x100000000 / max) * max;
  const random = new Uint32Array(1);
  do crypto.getRandomValues(random); while (random[0] >= limit);
  return random[0] % max;
}

export function shuffleSecure(values) {
  const result = [...values];
  for (let index = result.length - 1; index > 0; index -= 1) {
    const swapWith = secureRandomIndex(index + 1);
    [result[index], result[swapWith]] = [result[swapWith], result[index]];
  }
  return result;
}

export function generatePassword(options = {}) {
  const {
    length = 18,
    uppercase = true,
    lowercase = true,
    numbers = true,
    symbols = true,
    avoidAmbiguous = true,
  } = options;
  const sets = [];
  if (uppercase) sets.push(avoidAmbiguous ? "ABCDEFGHJKLMNPQRSTUVWXYZ" : "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
  if (lowercase) sets.push(avoidAmbiguous ? "abcdefghijkmnopqrstuvwxyz" : "abcdefghijklmnopqrstuvwxyz");
  if (numbers) sets.push(avoidAmbiguous ? "23456789" : "0123456789");
  if (symbols) sets.push("!@#$%^&*()-_=+");
  if (!sets.length) throw new Error("เลือกชนิดตัวอักษรอย่างน้อย 1 รายการ");
  const pool = sets.join("");
  const required = sets.map((set) => set[secureRandomIndex(set.length)]);
  while (required.length < Math.max(length, sets.length)) {
    required.push(pool[secureRandomIndex(pool.length)]);
  }
  return shuffleSecure(required).slice(0, length).join("");
}

const PASSPHRASE_WORDS = [
  "amber", "apple", "atlas", "bamboo", "beacon", "berry", "breeze", "cedar",
  "cloud", "coral", "dawn", "delta", "ember", "falcon", "fern", "forest",
  "galaxy", "garden", "harbor", "hazel", "island", "jade", "jasmine", "lagoon",
  "lotus", "lunar", "maple", "meadow", "mint", "nebula", "ocean", "olive",
  "orchid", "pearl", "pine", "planet", "plum", "quartz", "rain", "river",
  "rose", "saffron", "silver", "sky", "solar", "spruce", "star", "stone",
  "sunset", "tiger", "tulip", "valley", "velvet", "violet", "willow", "zenith",
];

export function generatePassphrase(options = {}) {
  const { words = 5, separator = "-", capitalize = false, includeNumber = true } = options;
  const selected = [];
  for (let index = 0; index < words; index += 1) {
    let word = PASSPHRASE_WORDS[secureRandomIndex(PASSPHRASE_WORDS.length)];
    if (capitalize) word = `${word[0].toUpperCase()}${word.slice(1)}`;
    selected.push(word);
  }
  if (includeNumber) {
    const target = secureRandomIndex(selected.length);
    selected[target] = `${selected[target]}${secureRandomIndex(90) + 10}`;
  }
  return selected.join(separator || "-");
}

export function passwordScore(password = "") {
  if (!password) return 0;
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/\d/.test(password)) pool += 10;
  if (/[^A-Za-z0-9]/.test(password)) pool += 32;
  const entropy = password.length * Math.log2(Math.max(pool, 1));
  const common = /password|123456|qwerty|admin|welcome|letmein|passw0rd/i.test(password);
  if (common) return 0;
  if (entropy >= 90 && password.length >= 14) return 4;
  if (entropy >= 65 && password.length >= 12) return 3;
  if (entropy >= 45 && password.length >= 10) return 2;
  return 1;
}

export async function sha256Reference(value, bytes = 6) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest).slice(0, bytes)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function createSharePayload(data, pin) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveVaultKey(pin, salt, SHARE_KDF_ITERATIONS);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(JSON.stringify(data)),
  );
  const payload = {
    v: 1,
    kdf: SHARE_KDF_ITERATIONS,
    s: bytesToBase64Url(salt),
    i: bytesToBase64Url(iv),
    d: bytesToBase64Url(new Uint8Array(encrypted)),
    e: data.expiresAt,
  };
  return bytesToBase64Url(encoder.encode(JSON.stringify(payload)));
}

export async function openSharePayload(fragment, pin) {
  const payload = JSON.parse(decoder.decode(base64UrlToBytes(fragment)));
  if (payload.v !== 1) throw new Error("ลิงก์นี้ใช้รูปแบบที่ไม่รองรับ");
  if (new Date(payload.e) <= new Date()) throw new Error("ลิงก์นี้หมดอายุแล้ว");
  const key = await deriveVaultKey(pin, base64UrlToBytes(payload.s), payload.kdf);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64UrlToBytes(payload.i) },
    key,
    base64UrlToBytes(payload.d),
  );
  const data = JSON.parse(decoder.decode(decrypted));
  if (new Date(data.expiresAt) <= new Date()) throw new Error("ลิงก์นี้หมดอายุแล้ว");
  return data;
}
