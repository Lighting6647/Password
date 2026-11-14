import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const appSource = fs.readFileSync(path.join(projectRoot, "app.js"), "utf8");
const pageSource = fs.readFileSync(path.join(projectRoot, "index.html"), "utf8");

test("login stays active without an inactivity or sleep auto-lock timer", () => {
  assert.doesNotMatch(
    appSource,
    /\b(lockTimeout|lockDeadline|lockTimer|countdownTimer|resetLockTimer|armLockTimer|resumeVaultSession)\b/,
  );
  assert.doesNotMatch(pageSource, /id="lockTimeout"/);
  assert.match(pageSource, /ระบบจะไม่ล็อกอัตโนมัติ/);
  assert.match(pageSource, /ออกจากระบบ/);
});

test("manual logout remains available", () => {
  assert.match(pageSource, /id="lockVaultBtn"/);
  assert.match(
    appSource,
    /\$\("#lockVaultBtn"\)\.addEventListener\("click", \(\) => lockVault\("ผู้ดูแลกดออกจากระบบ"\)\)/,
  );
});

test("privacy shield hides an unlocked vault when capture-related focus is lost", () => {
  assert.match(pageSource, /id="privacyShield"/);
  assert.match(appSource, /function hasSensitiveScreenContent/);
  assert.match(appSource, /input\[type="password"\]/);
  assert.match(appSource, /function activatePrivacyShield/);
  assert.match(appSource, /window\.addEventListener\("blur", \(\) => activatePrivacyShield\(\)\)/);
  assert.match(appSource, /document\.addEventListener\("visibilitychange"/);
  assert.match(appSource, /event\.key !== "PrintScreen"/);
  assert.match(appSource, /window\.addEventListener\("beforeprint"/);
  assert.match(appSource, /deactivatePrivacyShield\(true\)/);
  assert.match(appSource, /if \(document\.hidden \|\| !document\.hasFocus\(\)\) activatePrivacyShield\(\)/);
});

test("login targets the submit button and allows simultaneous active tabs", () => {
  assert.match(
    appSource,
    /const form = event\.currentTarget;/,
  );
  assert.match(appSource, /form\.querySelector\('button\[type="submit"\]'\)/);
  assert.match(appSource, /form\.reset\(\);/);
  assert.doesNotMatch(appSource, /event\.currentTarget\.reset\(\);/);
  assert.doesNotMatch(appSource, /navigator\.locks\.request/);
  assert.doesNotMatch(appSource, /Passly เปิดใช้งานอยู่ในแท็บอื่น/);
  assert.match(pageSource, /id="resetFromLock"/);
  assert.match(pageSource, /id="resetVaultModal"/);
  assert.match(pageSource, /id="resetVaultForm"/);
  assert.match(pageSource, /id="restoreArchivedFromLock"/);
  assert.match(pageSource, /id="restoreFromLock"/);
  assert.match(pageSource, /เก็บ Vault เดิมและสร้างใหม่/);
  assert.match(appSource, /readVaultArchive\(localStorage\)/);
  assert.match(appSource, /openResetVaultConfirmation/);
  const resetConfirmationStart = appSource.indexOf("function openResetVaultConfirmation()");
  const resetConfirmationEnd = appSource.indexOf(
    '$("#resetVaultForm").addEventListener',
    resetConfirmationStart,
  );
  const resetConfirmationSource = appSource.slice(resetConfirmationStart, resetConfirmationEnd);
  assert.doesNotMatch(resetConfirmationSource, /\bprompt\(/);
});

test("vault creation snapshots one PIN before asynchronous server verification", () => {
  const setupStart = appSource.indexOf('$("#setupForm").addEventListener("submit"');
  const unlockStart = appSource.indexOf('$("#unlockForm").addEventListener("submit"');
  const setupSource = appSource.slice(setupStart, unlockStart);

  assert.match(setupSource, /const enteredSecret = form\.elements\.password\.value/);
  assert.match(setupSource, /await authenticateServerPin\(enteredSecret\)/);
  assert.match(setupSource, /createVaultEnvelope\(vault, enteredSecret\)/);
  assert.doesNotMatch(
    setupSource,
    /createVaultEnvelope\(vault, form\.elements\.password\.value\)/,
  );
  assert.match(setupSource, /input\.disabled = true/);
  assert.match(appSource, /let vaultEnvelope = null/);
  assert.match(appSource, /const envelopeForSave = structuredClone\(vaultEnvelope\)/);
  assert.doesNotMatch(
    appSource.slice(
      appSource.indexOf("async function persistVault()"),
      appSource.indexOf("function addActivity"),
    ),
    /getStoredEnvelope\(\)/,
  );
});

test("PIN rotation snapshots current and new values before asynchronous work", () => {
  const changeStart = appSource.indexOf('$("#changeMasterForm").addEventListener("submit"');
  const clickStart = appSource.indexOf('document.addEventListener("click"', changeStart);
  const changeSource = appSource.slice(changeStart, clickStart);

  assert.match(changeSource, /const currentSecret = form\.elements\.currentPassword\.value/);
  assert.match(changeSource, /const newSecret = form\.elements\.newPassword\.value/);
  assert.match(changeSource, /unlockStoredVault\(localStorage, currentSecret\)/);
  assert.match(changeSource, /authenticateServerPin\(newSecret\)/);
  assert.match(changeSource, /createVaultEnvelope\(vault, newSecret\)/);
});
