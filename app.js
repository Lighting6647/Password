import {
  MAX_SHARE_EXPIRY_MS,
  VAULT_STORAGE_KEY,
  VAULT_SECRET_ENCODING,
  createSharePayload,
  createVaultEnvelope,
  generatePassphrase,
  generatePassword,
  normalizeVaultSecret,
  passwordScore,
  resolveShareExpiry,
  sha256Reference,
  toLocalDatetimeValue,
} from "./vault-crypto.js";
import {
  VAULT_BACKUP_STORAGE_KEY,
  archiveAndResetStoredVault,
  commitVaultEnvelope,
  createVaultArchive,
  isVaultArchive,
  isVaultEnvelope,
  queueVaultSave,
  readVaultArchive,
  readVaultEnvelope,
  restoreVaultArchive,
  unlockStoredVault,
  vaultEnvelopeIdentity,
} from "./vault-storage.js";
import { readCredentialFile } from "./xlsx-reader.js";
import { createPortableShareUrl } from "./share-link.js";
import { requestItemMatchScore } from "./request-matching.js";
import { gsap } from "./node_modules/gsap/index.js";

const REQUEST_STORAGE_KEY = "passly-password-requests-v2";
const THEME_KEY = "passly-theme";
const VAULT_SYNC_REVISION_KEY = "passly-vault-sync-revision-v1";
const VAULT_SYNC_CONFLICT_KEY = "passly-vault-sync-conflict-v1";
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const nowIso = () => new Date().toISOString();
const todayIso = () => nowIso().slice(0, 10);
const typeMeta = {
  login: { label: "Login", icon: "⌁" },
  note: { label: "Secure Note", icon: "▤" },
  card: { label: "Card", icon: "▰" },
  identity: { label: "Identity", icon: "◎" },
};
const requestLabels = {
  pending: "รออนุมัติ",
  approved: "อนุมัติแล้ว",
  delivered: "แจกสำเร็จ",
  rejected: "ปฏิเสธ",
};
const pageTitles = {
  dashboard: "ภาพรวม",
  vault: "Vault",
  requests: "คำขอ Password",
  generator: "ตัวสร้างรหัส",
  security: "รายงานความเสี่ยง",
  collections: "Collections",
  members: "สมาชิกและกลุ่ม",
  activity: "Activity Log",
  settings: "ตั้งค่า",
};

let vault = null;
let vaultKey = null;
let vaultEnvelope = null;
let saveQueue = Promise.resolve();
let activeView = "dashboard";
let vaultFilter = "all";
let vaultSearch = "";
let generatorType = "password";
let generatedValue = "";
let detailItemId = null;
let shareResult = null;
let lineInterval = null;
let linePollReady = false;
let lineReconnectBusy = false;
let lockInProgress = false;
let requests = loadRequests();
let remoteVaultRevision = null;
let remoteSyncAvailable = false;
let remoteSyncConflict = false;
let pendingRemoteUpload = false;
let remoteSyncQueue = Promise.resolve();
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

function animateViewEntrance(view = activeView) {
  if (reducedMotion.matches) return;
  const section = $(`#view-${view}`);
  if (!section || section.hidden) return;
  const targets = [...section.children];
  gsap.killTweensOf(targets);
  gsap.fromTo(targets,
    { autoAlpha: 0, y: 18, scale: 0.992 },
    { autoAlpha: 1, y: 0, scale: 1, duration: 0.55, stagger: 0.055, ease: "power3.out", clearProps: "transform,opacity,visibility" });
}

function initializeLiquidGlassMotion() {
  const ambient = document.createElement("div");
  ambient.className = "liquid-ambient";
  ambient.setAttribute("aria-hidden", "true");
  ambient.innerHTML = '<i class="liquid-orb liquid-orb-a"></i><i class="liquid-orb liquid-orb-b"></i><i class="liquid-orb liquid-orb-c"></i>';
  document.body.prepend(ambient);
  if (reducedMotion.matches) return;
  gsap.to(".liquid-orb-a", { x: 90, y: 55, scale: 1.16, duration: 14, repeat: -1, yoyo: true, ease: "sine.inOut" });
  gsap.to(".liquid-orb-b", { x: -70, y: 100, scale: 0.9, duration: 17, repeat: -1, yoyo: true, ease: "sine.inOut" });
  gsap.to(".liquid-orb-c", { x: 65, y: -60, scale: 1.12, duration: 19, repeat: -1, yoyo: true, ease: "sine.inOut" });
  gsap.fromTo(".lock-intro > *, .unlock-card", { autoAlpha: 0, y: 24 }, { autoAlpha: 1, y: 0, duration: 0.75, stagger: 0.08, ease: "power3.out", delay: 0.08 });
}

function escapeHtml(value = "") {
  const element = document.createElement("div");
  element.textContent = String(value);
  return element.innerHTML;
}

function initials(name = "") {
  return name.trim().split(/\s+/).slice(0, 2).map((part) => part[0] || "").join("").toUpperCase() || "U";
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value.length === 10 ? `${value}T00:00:00` : value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("th-TH", { day: "numeric", month: "short", year: "2-digit" }).format(date);
}

function formatDateTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("th-TH", {
    day: "numeric",
    month: "short",
    year: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function toast(title, message) {
  $("#toastTitle").textContent = title;
  $("#toastMessage").textContent = message;
  $("#toast").classList.add("show");
  if (!reducedMotion.matches) {
    gsap.fromTo("#toast", { autoAlpha: 0, y: 18, scale: 0.97 }, { autoAlpha: 1, y: 0, scale: 1, duration: 0.38, ease: "back.out(1.7)", clearProps: "transform,opacity,visibility" });
  }
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => $("#toast").classList.remove("show"), 2800);
}

function openModal(id) {
  const backdrop = $(`#${id}`);
  backdrop.hidden = false;
  document.body.style.overflow = "hidden";
  if (!reducedMotion.matches) {
    const modal = $(".modal", backdrop);
    gsap.fromTo(backdrop, { autoAlpha: 0 }, { autoAlpha: 1, duration: 0.22, ease: "power2.out", clearProps: "opacity,visibility" });
    gsap.fromTo(modal, { autoAlpha: 0, y: 24, scale: 0.965 }, { autoAlpha: 1, y: 0, scale: 1, duration: 0.46, ease: "back.out(1.35)", clearProps: "transform,opacity,visibility" });
  }
}

function closeModal(id) {
  $(`#${id}`).hidden = true;
  if (!$$(".modal-backdrop").some((modal) => !modal.hidden)) document.body.style.overflow = "";
}

let privacyShieldTimer = null;

function hasSensitiveScreenContent() {
  if (vault && vaultKey) return true;
  return $$('input[type="password"]').some((input) => input.value.length > 0);
}

function activatePrivacyShield(reason = "Passly ปิดทับข้อมูลเมื่อหน้าต่างไม่อยู่ด้านหน้า เพื่อช่วยป้องกันการแคปหน้าจอ") {
  if (!hasSensitiveScreenContent() || lockInProgress) return;
  clearTimeout(privacyShieldTimer);
  $("#privacyShieldReason").textContent = reason;
  $("#privacyShield").hidden = false;
  $("#privacyShield").setAttribute("aria-hidden", "false");
  document.body.classList.add("privacy-shield-active");
}

function deactivatePrivacyShield(force = false) {
  if (!force && (document.hidden || !document.hasFocus())) return;
  clearTimeout(privacyShieldTimer);
  $("#privacyShield").hidden = true;
  $("#privacyShield").setAttribute("aria-hidden", "true");
  document.body.classList.remove("privacy-shield-active");
}

function downloadFile(name, content, type = "application/json") {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([content], { type }));
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

let currentUserEmail = '';
async function authenticateServerLogin(email, password) {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || result.ok === false) {
    const error = new Error(result.error || "Server ปฏิเสธการเข้าสู่ระบบ");
    error.code = response.status;
    throw error;
  }
  currentUserEmail = email;
  return result;
}

function activeItems() {
  return vault?.items.filter((item) => !item.trashedAt) ?? [];
}

function loginItems() {
  return activeItems().filter((item) => item.type === "login");
}

function itemLabel(item) {
  if (item.type === "login") return item.username || item.uri || "ไม่มี Username";
  if (item.type === "note") return "Secure Note";
  if (item.type === "card") return item.cardNumber ? `•••• ${item.cardNumber.replace(/\s/g, "").slice(-4)}` : "Card";
  return item.identityEmail || item.fullName || "Identity";
}

function strengthLabel(score) {
  return ["เสี่ยงมาก", "อ่อน", "พอใช้", "แข็งแรง", "แข็งแรงมาก"][score] || "—";
}

function getSecurityReport() {
  const logins = loginItems();
  const passwordGroups = new Map();
  logins.forEach((item) => {
    if (!item.password) return;
    const list = passwordGroups.get(item.password) || [];
    list.push(item.id);
    passwordGroups.set(item.password, list);
  });
  const findings = [];
  const counts = { weak: 0, reused: 0, old: 0, incomplete: 0 };
  for (const item of logins) {
    const score = passwordScore(item.password);
    if (score <= 1) {
      counts.weak += 1;
      findings.push({ item, type: "รหัสอ่อน", detail: "ควรเปลี่ยนเป็นรหัสสุ่มอย่างน้อย 14 ตัวอักษร", level: "high", weight: 4 });
    }
    if (item.password && (passwordGroups.get(item.password)?.length || 0) > 1) {
      counts.reused += 1;
      findings.push({ item, type: "รหัสซ้ำ", detail: "รหัสเดียวกันถูกใช้มากกว่าหนึ่งบัญชี", level: "high", weight: 4 });
    }
    const updated = new Date(item.passwordUpdatedAt || item.updatedAt || item.createdAt);
    const ageDays = Number.isNaN(updated.getTime()) ? 0 : (Date.now() - updated.getTime()) / 86_400_000;
    if (ageDays > 90) {
      counts.old += 1;
      findings.push({ item, type: "รหัสเก่า", detail: `ไม่ได้เปลี่ยนรหัสประมาณ ${Math.floor(ageDays)} วัน`, level: "medium", weight: 2 });
    }
    if (!item.username || !item.uri) {
      counts.incomplete += 1;
      findings.push({ item, type: "ข้อมูลไม่ครบ", detail: "ควรเพิ่ม Username และเว็บไซต์เพื่อค้นหาและตรวจสอบง่ายขึ้น", level: "medium", weight: 1 });
    }
  }
  findings.sort((a, b) => b.weight - a.weight);
  const penalty = counts.weak * 14 + counts.reused * 11 + counts.old * 5 + counts.incomplete * 3;
  return { counts, findings, score: Math.max(0, 100 - Math.min(100, penalty)) };
}

function setLockScreenMode(remoteExists = false) {
  const exists = Boolean(
    getStoredEnvelope()
    || readVaultEnvelope(localStorage, VAULT_BACKUP_STORAGE_KEY)
    || remoteExists
  );
  $("#setupPanel").hidden = exists;
  $("#unlockPanel").hidden = !exists;
  $("#lockScreen").hidden = false;
  $("#mainApp").hidden = true;
  document.body.classList.remove("vault-open");
  deactivatePrivacyShield(true);
  $("#unlockForm").elements.password.type = "password";
  $("#toggleUnlockPassword").textContent = "ดูรหัส";
  $("#restoreArchivedFromLock").hidden = !readVaultArchive(localStorage);
  setTimeout(() => $(`#${exists ? "unlockForm" : "setupForm"} [name=password]`)?.focus(), 80);
}

async function refreshLockScreenMode() {
  let remoteExists = false;
  try {
    const response = await fetch("/api/vault/status", { cache: "no-store" });
    const status = await response.json();
    remoteExists = Boolean(response.ok && status.available && status.exists);
  } catch {
    // Offline startup still supports the encrypted local copy.
  }
  setLockScreenMode(remoteExists);
}

async function lockVault(reason = "ออกจากระบบแล้ว", { save = true } = {}) {
  if (lockInProgress) return;
  lockInProgress = true;
  clearInterval(lineInterval);
  lineInterval = null;

  try {
    if (save && vault && vaultKey) await persistVault();
  } catch (error) {
    console.error("Unable to finish the final vault save before locking.", error);
  } finally {
    await logoutServerSession();
    vault = null;
    vaultKey = null;
    vaultEnvelope = null;
    detailItemId = null;
    shareResult = null;
    $$(".modal-backdrop").forEach((modal) => { modal.hidden = true; });
    document.body.style.overflow = "";
    setLockScreenMode();
    $("#unlockError").hidden = true;
    lockInProgress = false;
    if (reason) toast("ออกจากระบบ Passly", reason);
  }
}

function afterUnlock() {
  lockInProgress = false;
  $("#lockScreen").hidden = true;
  $("#mainApp").hidden = false;
  document.body.classList.add("vault-open");
  if (document.hidden || !document.hasFocus()) activatePrivacyShield();
  renderAll();
  showView(activeView);
  syncLarkMenuCatalog();
  pullLineRequests();
  clearInterval(lineInterval);
  lineInterval = setInterval(pullLineRequests, 5000);
  checkServerConfiguration();
  if (pendingRemoteUpload) queueRemoteEnvelopeSync(vaultEnvelope);
}

function showView(view) {
  activeView = pageTitles[view] ? view : "dashboard";
  $$(".view").forEach((section) => { section.hidden = section.id !== `view-${activeView}`; });
  $$(".nav-item[data-view]").forEach((button) => button.classList.toggle("active", button.dataset.view === activeView));
  $("#currentPageTitle").textContent = pageTitles[activeView];
  $(".sidebar").classList.remove("open");
  if (activeView === "security") renderSecurity();
  if (activeView === "generator") renderGeneratorHistory();
  history.replaceState(null, "", `#${activeView}`);
  window.scrollTo({ top: 0, behavior: reducedMotion.matches ? "auto" : "smooth" });
  const activeNav = $(`.nav-item[data-view="${activeView}"]`);
  if (activeNav && !reducedMotion.matches) {
    gsap.fromTo(activeNav, { x: -7 }, { x: 0, duration: 0.42, ease: "back.out(2)", clearProps: "transform" });
  }
  requestAnimationFrame(() => {
    animateViewEntrance(activeView);
  });
}

function renderAll() {
  if (!vault) return;
  renderSelectOptions();
  renderDashboard();
  renderVault();
  renderRequests();
  renderCollections();
  renderMembers();
  renderActivity();
  renderGeneratorHistory();
  renderSecurity();
}

function renderDashboard() {
  const items = activeItems();
  const logins = loginItems();
  const report = getSecurityReport();
  $("#dashboardItemCount").textContent = items.length;
  $("#dashboardLoginCount").textContent = `${logins.length} logins`;
  $("#dashboardHealthScore").textContent = report.score;
  $("#dashboardRiskCount").textContent = report.findings.length;
  $("#dashboardPendingCount").textContent = requests.filter((request) => request.status === "pending").length;
  $("#navVaultCount").textContent = items.length;
  $("#navRequestCount").textContent = requests.filter((request) => request.status === "pending").length;
  $("#navRiskDot").hidden = report.findings.length === 0;

  const recent = [...items].sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt)).slice(0, 5);
  $("#recentVaultItems").innerHTML = recent.length ? recent.map((item) => `
    <article class="recent-item">
      <span class="vault-item-icon ${item.type}">${typeMeta[item.type]?.icon || "▣"}</span>
      <div><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(itemLabel(item))} · ${typeMeta[item.type]?.label}</small></div>
      <button data-item-view="${item.id}">เปิด →</button>
    </article>
  `).join("") : `<div class="empty-state compact"><div>▣</div><h3>Vault ยังว่าง</h3><p>เพิ่มรายการแรกหรือนำเข้า Excel</p></div>`;

  const risks = [
    { label: "รหัสอ่อน", value: report.counts.weak, color: "#c74e4e" },
    { label: "รหัสซ้ำ", value: report.counts.reused, color: "#d77935" },
    { label: "รหัสเกิน 90 วัน", value: report.counts.old, color: "#735dc1" },
    { label: "ข้อมูลไม่ครบ", value: report.counts.incomplete, color: "#3e6fe0" },
  ];
  $("#securitySummary").innerHTML = risks.map((risk) => `
    <div class="summary-row"><span style="background:${risk.color}"></span><strong>${risk.label}</strong><small>${risk.value} รายการ</small></div>
  `).join("");

  const latestRequests = [...requests].slice(0, 3);
  $("#requestPreview").innerHTML = latestRequests.length ? latestRequests.map((request) => `
    <article class="request-preview-item">
      <span class="avatar">${escapeHtml(initials(request.name))}</span>
      <div><strong>${escapeHtml(request.name)}</strong><small>${escapeHtml(request.system)} · ${requestLabels[request.status] || request.status}</small></div>
    </article>
  `).join("") : `<div class="empty-state compact"><div>◇</div><h3>ยังไม่มีคำขอ</h3></div>`;
}

function filteredVaultItems() {
  const folderId = $("#folderFilter").value;
  const collectionId = $("#collectionFilter").value;
  const sort = $("#vaultSort").value;
  let items = vault.items.filter((item) => vaultFilter === "trash" ? Boolean(item.trashedAt) : !item.trashedAt);
  if (vaultFilter === "favorite") items = items.filter((item) => item.favorite);
  else if (["login", "note", "card", "identity"].includes(vaultFilter)) items = items.filter((item) => item.type === vaultFilter);
  if (folderId !== "all") items = items.filter((item) => item.folderId === folderId);
  if (collectionId !== "all") items = items.filter((item) => item.collectionId === collectionId);
  if (vaultSearch) {
    const term = vaultSearch.toLowerCase();
    items = items.filter((item) => `${item.name} ${item.username || ""} ${item.uri || ""} ${item.owner || ""} ${item.notes || ""}`.toLowerCase().includes(term));
  }
  if (sort === "name") items.sort((a, b) => a.name.localeCompare(b.name, "th"));
  else if (sort === "strength") items.sort((a, b) => passwordScore(a.password) - passwordScore(b.password));
  else items.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
  return items;
}

function renderVault() {
  const items = filteredVaultItems();
  $("#filterAllCount").textContent = activeItems().length;
  $("#vaultList").innerHTML = items.map((item) => {
    const score = item.type === "login" ? passwordScore(item.password) : 4;
    const folder = vault.folders.find((entry) => entry.id === item.folderId)?.name || "ไม่มี Folder";
    const collection = vault.collections.find((entry) => entry.id === item.collectionId)?.name || "My Vault";
    return `
      <article class="vault-row">
        <div class="vault-main">
          <span class="vault-item-icon ${item.type}">${typeMeta[item.type]?.icon || "▣"}</span>
          <div><strong>${escapeHtml(item.name)}${item.favorite ? '<span class="favorite-star">★</span>' : ""}</strong><small>${escapeHtml(itemLabel(item))}</small></div>
        </div>
        <div class="vault-meta"><strong>${escapeHtml(item.owner || collection)}</strong><small>${escapeHtml(folder)} · ${escapeHtml(collection)}</small></div>
        <span class="strength-badge strength-${score}">${item.type === "login" ? strengthLabel(score) : typeMeta[item.type]?.label}</span>
        <span class="vault-updated">${formatDate(item.updatedAt)}</span>
        <div class="row-actions">
          ${item.trashedAt ? `<button data-item-restore="${item.id}">กู้คืน</button><button data-item-delete-forever="${item.id}">ลบถาวร</button>` : `<button data-item-favorite="${item.id}" title="Favorite">${item.favorite ? "★" : "☆"}</button><button data-item-view="${item.id}">เปิด</button><button data-item-edit="${item.id}">แก้ไข</button>`}
        </div>
      </article>
    `;
  }).join("");
  $("#vaultEmpty").hidden = items.length > 0;
  $("#vaultList").hidden = items.length === 0;
}

function renderSelectOptions() {
  const folderOptions = vault.folders.map((folder) => `<option value="${folder.id}">${escapeHtml(folder.name)}</option>`).join("");
  const collectionOptions = vault.collections.map((collection) => `<option value="${collection.id}">${escapeHtml(collection.name)}</option>`).join("");
  const currentFolderFilter = $("#folderFilter").value || "all";
  const currentCollectionFilter = $("#collectionFilter").value || "all";
  $("#folderFilter").innerHTML = `<option value="all">ทุก Folder</option>${folderOptions}`;
  $("#collectionFilter").innerHTML = `<option value="all">ทุก Collection</option>${collectionOptions}`;
  $("#itemFolderSelect").innerHTML = `<option value="">ไม่มี Folder</option>${folderOptions}`;
  $("#itemCollectionSelect").innerHTML = `<option value="">My Vault</option>${collectionOptions}`;
  $("#groupCollectionSelect").innerHTML = `<option value="">ยังไม่กำหนด</option>${collectionOptions}`;
  $("#folderFilter").value = currentFolderFilter;
  $("#collectionFilter").value = currentCollectionFilter;
  $("#vaultSystemList").innerHTML = loginItems().map((item) => `<option value="${escapeHtml(item.name)}"></option>`).join("");
}

function renderRequests() {
  const term = $("#requestSearch").value.trim().toLowerCase();
  const status = $("#requestStatusFilter").value;
  const filtered = requests.filter((request) => {
    const matchesTerm = !term || `${request.name} ${request.email} ${request.system} ${request.requestAccount || ""} ${request.reason}`.toLowerCase().includes(term);
    return matchesTerm && (status === "all" || request.status === status);
  });
  $("#requestTableBody").innerHTML = filtered.map((request) => `
    <tr>
      <td><div class="user-cell"><span class="avatar">${escapeHtml(initials(request.name))}</span><div><strong>${escapeHtml(request.name)}${request.urgent ? '<em class="urgent-dot">ด่วน</em>' : ""}</strong><small>${escapeHtml(request.email)}</small></div></div></td>
      <td><strong>${escapeHtml(request.system)}</strong><small class="vault-updated">${request.source === "Lark" ? `บัญชีที่ขอ: ${escapeHtml(request.requestAccount || "ยังไม่ระบุ")} · จาก Lark` : `บัญชีที่ขอ: ${escapeHtml(request.requestAccount || "ยังไม่ระบุ")} · จาก ${escapeHtml(request.source || "รายการเดิม")}`}</small></td>
      <td class="reason-cell">${escapeHtml(request.reason)}</td>
      <td>${formatDate(request.date)}</td>
      <td><span class="status ${request.status}">${requestLabels[request.status] || request.status}</span></td>
      <td><div class="row-actions">
        ${request.status === "pending" ? `<button class="action-approve" data-request-approve="${request.id}">อนุมัติ</button><button data-request-reject="${request.id}">ปฏิเสธ</button>` : ""}
        ${request.status === "approved" ? `<button class="action-share" data-request-share="${request.id}">แจกจาก Vault</button>` : ""}
        <button data-request-edit="${request.id}">แก้ไข</button><button data-request-delete="${request.id}">ลบ</button>
      </div></td>
    </tr>
  `).join("");
  $("#requestEmpty").hidden = filtered.length > 0;
  $("#requestTableBody").closest("table").hidden = filtered.length === 0;
  $("#navRequestCount").textContent = requests.filter((request) => request.status === "pending").length;
}

function renderGeneratorHistory() {
  if (!vault) return;
  $("#generatorHistory").innerHTML = vault.generatorHistory.length ? vault.generatorHistory.map((entry) => `
    <div class="history-row"><div><strong>${escapeHtml(entry.value)}</strong><small>${entry.type === "passphrase" ? "Passphrase" : "Password"} · ${formatDateTime(entry.at)}</small></div><button data-history-copy="${entry.id}">คัดลอก</button></div>
  `).join("") : `<div class="empty-state compact"><div>✦</div><h3>ยังไม่มีประวัติ</h3><p>รหัสที่สร้างจะปรากฏที่นี่</p></div>`;
}

function renderSecurity() {
  if (!vault) return;
  const report = getSecurityReport();
  $("#healthScore").textContent = report.score;
  $("#healthRing").style.strokeDashoffset = String(314 - 314 * report.score / 100);
  const health = report.score >= 85 ? ["ยอดเยี่ยม", "Vault มีสุขภาพดี"] : report.score >= 60 ? ["ควรปรับปรุง", "มีบางรายการที่ควรแก้ไข"] : ["ความเสี่ยงสูง", "ควรแก้ไขรายการสำคัญทันที"];
  $("#healthLabel").textContent = health[0];
  $("#healthDescription").textContent = report.findings.length ? `${health[1]} พบ ${report.findings.length} ประเด็น` : "ยังไม่พบรายการที่ต้องแก้ไข";
  const cards = [
    ["รหัสอ่อน", report.counts.weak, "ควรใช้ Generator"],
    ["รหัสซ้ำ", report.counts.reused, "ควรใช้รหัสไม่ซ้ำกัน"],
    ["รหัสเก่า", report.counts.old, "เกิน 90 วัน"],
    ["ข้อมูลไม่ครบ", report.counts.incomplete, "ไม่มี Username หรือ URL"],
  ];
  $("#riskCards").innerHTML = cards.map(([label, value, note]) => `<article class="risk-card"><span>${label}</span><strong>${value}</strong><small>${note}</small></article>`).join("");
  $("#securityFindings").innerHTML = report.findings.length ? report.findings.map((finding) => `
    <div class="finding-row"><span class="finding-level ${finding.level === "high" ? "high" : ""}"></span><div><strong>${escapeHtml(finding.item.name)} · ${finding.type}</strong><small>${escapeHtml(finding.detail)}</small></div><button data-item-edit="${finding.item.id}">แก้ไข →</button></div>
  `).join("") : `<div class="empty-state compact"><div>✓</div><h3>ยังไม่พบความเสี่ยง</h3><p>เพิ่ม Login แล้ว Passly จะตรวจสอบให้อัตโนมัติ</p></div>`;
  $("#navRiskDot").hidden = report.findings.length === 0;
}

function renderCollections() {
  $("#collectionGrid").innerHTML = vault.collections.length ? vault.collections.map((collection) => {
    const count = activeItems().filter((item) => item.collectionId === collection.id).length;
    const permission = { view: "ดูข้อมูล", edit: "ดูและแก้ไข", manage: "จัดการ Collection" }[collection.permission] || collection.permission;
    return `
      <article class="collection-card">
        <span class="collection-accent" style="background:${collection.color}"></span>
        <div class="collection-top"><span class="collection-icon" style="background:${collection.color}">⊞</span><div><strong>${escapeHtml(collection.name)}</strong><small>${count} รายการ</small></div></div>
        <p>${escapeHtml(collection.description || "ยังไม่มีคำอธิบาย")}</p>
        <div class="collection-meta"><span>${escapeHtml(collection.members || "ยังไม่ระบุกลุ่ม")}</span><span>${escapeHtml(permission)}</span></div>
        <div class="collection-actions"><button data-collection-edit="${collection.id}">แก้ไข</button><button data-collection-open="${collection.id}">เปิดรายการ</button><button data-collection-delete="${collection.id}">ลบ</button></div>
      </article>
    `;
  }).join("") : `<div class="empty-state"><div>⊞</div><h3>ยังไม่มี Collection</h3></div>`;
  $("#folderList").innerHTML = vault.folders.length ? vault.folders.map((folder) => {
    const count = activeItems().filter((item) => item.folderId === folder.id).length;
    return `<span class="folder-pill">▱ ${escapeHtml(folder.name)} <small>${count}</small><button data-folder-rename="${folder.id}">✎</button><button data-folder-delete="${folder.id}">×</button></span>`;
  }).join("") : `<span class="vault-updated">ยังไม่มี Folder</span>`;
}

function renderMembers() {
  const members = vault.members || [];
  const groups = vault.groups || [];
  $("#memberCount").textContent = members.length;
  $("#confirmedMemberCount").textContent = members.filter((member) => member.status === "confirmed").length;
  $("#invitedMemberCount").textContent = members.filter((member) => member.status === "invited").length;
  $("#groupCount").textContent = groups.length;
  $("#memberTableBody").innerHTML = members.map((member) => {
    const collections = (member.collectionIds || []).map((id) => vault.collections.find((collection) => collection.id === id)?.name).filter(Boolean);
    const statusLabel = { invited: "Invited", confirmed: "Confirmed", revoked: "Revoked" }[member.status] || member.status;
    const statusClass = member.status === "confirmed" ? "approved" : member.status === "invited" ? "pending" : "rejected";
    return `
      <tr>
        <td><div class="user-cell"><span class="avatar">${escapeHtml(initials(member.name))}</span><div><strong>${escapeHtml(member.name)}</strong><small>${escapeHtml(member.email)}</small></div></div></td>
        <td>${escapeHtml(member.role)}</td>
        <td>${escapeHtml(collections.join(", ") || "ยังไม่กำหนด")}</td>
        <td><span class="status ${statusClass}">${statusLabel}</span></td>
        <td><div class="row-actions"><button data-member-edit="${member.id}">แก้ไข</button><button data-member-toggle="${member.id}">${member.status === "revoked" ? "คืนสิทธิ์" : "ระงับ"}</button><button data-member-delete="${member.id}">ลบ</button></div></td>
      </tr>
    `;
  }).join("");
  $("#memberEmpty").hidden = members.length > 0;
  $("#memberTableBody").closest("table").hidden = members.length === 0;
  $("#groupGrid").innerHTML = groups.length ? groups.map((group) => {
    const collection = vault.collections.find((entry) => entry.id === group.collectionId);
    const permission = { view: "ดูข้อมูล", edit: "ดูและแก้ไข", manage: "จัดการ Collection" }[group.permission] || group.permission;
    return `
      <article class="group-card">
        <div><span class="collection-icon">◎</span><div><h3>${escapeHtml(group.name)}</h3><small>${escapeHtml(collection?.name || "ยังไม่กำหนด Collection")}</small></div></div>
        <p>${escapeHtml(group.members || "ยังไม่ระบุสมาชิก")}</p>
        <small>สิทธิ์: ${escapeHtml(permission)}</small>
        <div class="collection-actions"><button data-group-edit="${group.id}">แก้ไข</button><button data-group-delete="${group.id}">ลบ</button></div>
      </article>
    `;
  }).join("") : `<div class="empty-state compact"><div>◎</div><h3>ยังไม่มีกลุ่ม</h3></div>`;
}

function renderActivity() {
  $("#activityList").innerHTML = vault.activity.length ? vault.activity.map((entry) => `
    <div class="activity-row"><span class="activity-icon">↻</span><div><strong>${escapeHtml(entry.action)}</strong><small>${escapeHtml(entry.detail)}</small></div><time>${formatDateTime(entry.at)}</time></div>
  `).join("") : `<div class="empty-state compact"><div>↻</div><h3>ยังไม่มีกิจกรรม</h3></div>`;
}

function updateItemFields(type) {
  $$("[data-item-fields]").forEach((section) => { section.hidden = section.dataset.itemFields !== type; });
}

function openItemEditor(itemId = null, preset = {}) {
  const form = $("#itemForm");
  form.reset();
  form.elements.id.value = itemId || "";
  const item = itemId ? vault.items.find((entry) => entry.id === itemId) : null;
  const data = { type: "login", ...preset, ...(item || {}) };
  form.elements.type.value = data.type;
  updateItemFields(data.type);
  const fields = [
    "name", "username", "password", "uri", "purpose", "passwordUpdatedAt", "previousPassword",
    "secureNote", "cardholder", "brand", "cardNumber", "cardExpiry", "cardCvv",
    "fullName", "identityEmail", "phone", "idNumber", "address", "folderId",
    "collectionId", "owner", "notes",
  ];
  fields.forEach((field) => {
    if (form.elements[field]) form.elements[field].value = data[field] || "";
  });
  form.elements.favorite.checked = Boolean(data.favorite);
  form.elements.reprompt.checked = Boolean(data.reprompt);
  $("#itemModalTitle").textContent = item ? "แก้ไขรายการใน Vault" : "เพิ่มรายการใน Vault";
  form.elements.password.type = "password";
  $("#toggleItemPassword").textContent = "ดู";
  openModal("itemModal");
  setTimeout(() => form.elements.name.focus(), 60);
}

async function verifyMasterPassword(message = "ยืนยันรหัสผ่านเพื่อเปิดข้อมูลนี้") {
  const password = prompt(message);
  if (password === null) return false;
  try {
    await unlockStoredVault(localStorage, password);
    return true;
  } catch {
    toast("ยืนยันไม่สำเร็จ", "รหัสผ่านหรือ PIN ไม่ถูกต้อง");
    return false;
  }
}

async function openItemDetail(itemId) {
  const item = vault.items.find((entry) => entry.id === itemId);
  if (!item || item.trashedAt) return;
  if (item.reprompt && !await verifyMasterPassword()) return;
  detailItemId = itemId;
  addActivity("เปิดดูรายการ", item.name, item.id);
  persistVault();
  const meta = typeMeta[item.type] || typeMeta.login;
  let fields = "";
  if (item.type === "login") {
    fields = `
      <div class="detail-field"><span>Username</span><strong>${escapeHtml(item.username || "—")}</strong><div><button data-detail-copy="username">คัดลอก</button></div></div>
      <div class="detail-field"><span>Password</span><strong id="detailPassword">••••••••••••</strong><div><button data-detail-toggle-password>แสดง</button><button data-detail-copy="password">คัดลอก</button></div></div>
      <div class="detail-field"><span>Website / URI</span><strong>${escapeHtml(item.uri || "—")}</strong><div>${item.uri ? '<button data-detail-launch>เปิดเว็บ</button>' : ""}</div></div>
      <div class="detail-field"><span>อัปเดตรหัสล่าสุด</span><strong>${formatDate(item.passwordUpdatedAt || item.updatedAt)}</strong></div>
    `;
  } else if (item.type === "note") {
    fields = `<div class="detail-notes">${escapeHtml(item.secureNote || item.notes || "—")}</div>`;
  } else if (item.type === "card") {
    fields = `
      <div class="detail-field"><span>ชื่อบนบัตร</span><strong>${escapeHtml(item.cardholder || "—")}</strong></div>
      <div class="detail-field"><span>หมายเลขบัตร</span><strong id="detailCard">•••• •••• •••• ${escapeHtml((item.cardNumber || "").replace(/\s/g, "").slice(-4))}</strong><div><button data-detail-toggle-card>แสดง</button><button data-detail-copy="cardNumber">คัดลอก</button></div></div>
      <div class="field-row"><div class="detail-field"><span>วันหมดอายุ</span><strong>${escapeHtml(item.cardExpiry || "—")}</strong></div><div class="detail-field"><span>CVV</span><strong>•••</strong><div><button data-detail-copy="cardCvv">คัดลอก</button></div></div></div>
    `;
  } else {
    fields = `
      <div class="detail-field"><span>ชื่อ-นามสกุล</span><strong>${escapeHtml(item.fullName || "—")}</strong></div>
      <div class="detail-field"><span>อีเมล</span><strong>${escapeHtml(item.identityEmail || "—")}</strong><div><button data-detail-copy="identityEmail">คัดลอก</button></div></div>
      <div class="detail-field"><span>โทรศัพท์</span><strong>${escapeHtml(item.phone || "—")}</strong></div>
      <div class="detail-field"><span>เลขประจำตัว</span><strong>${escapeHtml(item.idNumber || "—")}</strong></div>
      <div class="detail-notes">${escapeHtml(item.address || "—")}</div>
    `;
  }
  $("#itemDetailContent").innerHTML = `
    <div class="detail-heading"><span class="vault-item-icon ${item.type}">${meta.icon}</span><div><p class="eyebrow">${meta.label}</p><h2>${escapeHtml(item.name)}</h2><small>${escapeHtml(item.owner || "Fern Clinic")} · แก้ไข ${formatDateTime(item.updatedAt)}</small></div><button class="icon-action" data-item-favorite="${item.id}">${item.favorite ? "★" : "☆"}</button></div>
    ${fields}
    ${item.notes && item.type !== "note" ? `<div class="detail-notes">${escapeHtml(item.notes)}</div>` : ""}
    <div class="detail-actions">${item.type === "login" ? '<button class="primary-btn" data-detail-share>สร้าง Secure Share</button>' : ""}<button class="secondary-btn" data-item-edit="${item.id}">แก้ไข</button><button class="danger-btn" data-item-trash="${item.id}">ย้ายไป Trash</button></div>
  `;
  openModal("itemDetailModal");
}

function openRequestEditor(requestId = null) {
  if (!requestId) {
    toast("รับคำขอผ่าน Lark เท่านั้น", "ให้สมาชิกพิมพ์ “เมนู” แล้วเลือกบัญชีในกลุ่ม Lark");
    return;
  }
  const form = $("#requestForm");
  form.reset();
  const request = requestId ? requests.find((entry) => entry.id === requestId) : null;
  if (!request) return;
  form.elements.id.value = request?.id || "";
  ["name", "email", "system", "reason", "status"].forEach((field) => {
    if (request) form.elements[field].value = request[field] || "";
  });
  form.elements.status.value = request?.status || "pending";
  form.elements.urgent.checked = Boolean(request?.urgent);
  $("#requestModalTitle").textContent = "แก้ไขคำขอจาก Lark";
  openModal("requestModal");
}

function generateSharePin() {
  return generatePassword({ length: 8, uppercase: true, lowercase: true, numbers: true, symbols: false, avoidAmbiguous: true });
}

function updateDeliverySubmitButton() {
  const form = $("#deliverForm");
  const button = form.querySelector('button[type="submit"]');
  button.innerHTML = form.elements.channel.value === "lark"
    ? 'ส่งเข้า Lark <span>→</span>'
    : 'คัดลอกข้อความ <span>→</span>';
}

function syncCustomExpiryControl(resetValue = false) {
  const form = $("#deliverForm");
  const input = form.elements.customExpiryAt;
  const custom = form.elements.expiry.value === "custom";
  const now = new Date();
  const earliest = new Date(now.getTime() + 60_000);
  const latest = new Date(now.getTime() + MAX_SHARE_EXPIRY_MS);
  $("#customExpiryField").hidden = !custom;
  input.required = custom;
  input.min = toLocalDatetimeValue(earliest);
  input.max = toLocalDatetimeValue(latest);
  if (resetValue || (custom && !input.value)) {
    const suggested = new Date(now.getTime() + 3_600_000);
    suggested.setSeconds(0, 0);
    input.value = toLocalDatetimeValue(suggested);
  }
}

async function openDeliverForRequest(requestId, presetItemId = null) {
  const request = requests.find((entry) => entry.id === requestId);
  const items = loginItems();
  if (!request) return;
  if (!items.length) {
    toast("ยังไม่มี Login ใน Vault", "เพิ่มหรือนำเข้ารายการก่อนแจกข้อมูล");
    showView("vault");
    return;
  }
  const form = $("#deliverForm");
  form.reset();
  form.elements.requestId.value = request.id;
  const rankedItems = items
    .map((item) => ({ item, score: requestItemMatchScore(request, item) }))
    .sort((a, b) => b.score - a.score || a.item.name.localeCompare(b.item.name, "th"));
  const suggested = rankedItems.filter((entry) => entry.score > 0);
  const others = rankedItems.filter((entry) => entry.score === 0);
  const optionMarkup = (entries) => entries.map(({ item }) => (
    `<option value="${item.id}">${escapeHtml(item.name)} — ${escapeHtml(item.username || "ไม่มี Username")}</option>`
  )).join("");
  $("#deliverItemSelect").innerHTML = [
    suggested.length ? `<optgroup label="ตรงกับคำขอ">${optionMarkup(suggested)}</optgroup>` : "",
    others.length ? `<optgroup label="รายการอื่นใน Vault">${optionMarkup(others)}</optgroup>` : "",
  ].join("");
  const explicitMatch = presetItemId || request.requestVaultItemId;
  const match = items.some((item) => item.id === explicitMatch)
    ? explicitMatch
    : rankedItems[0]?.score > 0
      ? rankedItems[0].item.id
      : null;
  if (match) form.elements.itemId.value = match;
  const matchedItem = items.find((item) => item.id === match);
  $("#deliverSummary").textContent = matchedItem
    ? `ผู้รับ: ${request.name} · คำขอ: ${request.system} · ระบบแนะนำ: ${matchedItem.name} — ${matchedItem.username || "ไม่มี Username"}`
    : `ผู้รับ: ${request.name} · ระบบ: ${request.system} · กรุณาเลือกบัญชีเพื่อตรวจสอบ`;
  form.elements.pin.value = generateSharePin();
  syncCustomExpiryControl(true);
  updateDeliverySubmitButton();
  openModal("deliverModal");
}

function updateGenerator() {
  try {
    if (generatorType === "password") {
      generatedValue = generatePassword({
        length: Number($("#passwordLength").value),
        uppercase: $("#genUpper").checked,
        lowercase: $("#genLower").checked,
        numbers: $("#genNumbers").checked,
        symbols: $("#genSymbols").checked,
        avoidAmbiguous: $("#genAmbiguous").checked,
      });
    } else {
      generatedValue = generatePassphrase({
        words: Number($("#wordCount").value),
        separator: $("#wordSeparator").value || "-",
        capitalize: $("#wordCapitalize").checked,
        includeNumber: $("#wordNumber").checked,
      });
    }
    $("#generatedValue").textContent = generatedValue;
    const score = passwordScore(generatedValue);
    $("#generatorStrengthLabel").textContent = strengthLabel(score);
    $("#generatorStrengthBar").style.width = `${Math.max(20, score * 25)}%`;
    $("#generatorStrengthBar").style.background = ["#c74e4e", "#c74e4e", "#d77935", "#3e6fe0", "#168457"][score];
  } catch (error) {
    toast("สร้างรหัสไม่ได้", error.message);
  }
}

async function saveGeneratedHistory() {
  vault.generatorHistory.unshift({ id: crypto.randomUUID(), type: generatorType, value: generatedValue, at: nowIso() });
  vault.generatorHistory = vault.generatorHistory.slice(0, 20);
  addActivity("สร้างรหัสใหม่", generatorType === "password" ? "Password" : "Passphrase");
  await persistVault();
  renderGeneratorHistory();
}

function openCollectionEditor(id = null) {
  const form = $("#collectionForm");
  form.reset();
  const collection = id ? vault.collections.find((entry) => entry.id === id) : null;
  form.elements.id.value = collection?.id || "";
  ["name", "description", "members", "permission", "color"].forEach((field) => {
    form.elements[field].value = collection?.[field] || (field === "color" ? "#5b73e8" : "");
  });
  $("#collectionModalTitle").textContent = collection ? "แก้ไข Collection" : "สร้าง Collection";
  openModal("collectionModal");
}

function openMemberEditor(id = null) {
  const form = $("#memberForm");
  form.reset();
  const member = id ? vault.members.find((entry) => entry.id === id) : null;
  form.elements.id.value = member?.id || "";
  form.elements.name.value = member?.name || "";
  form.elements.email.value = member?.email || "";
  form.elements.role.value = member?.role || "member";
  form.elements.status.value = member?.status || "invited";
  const selected = new Set(member?.collectionIds || []);
  $("#memberCollectionChecks").innerHTML = vault.collections.length ? vault.collections.map((collection) => `
    <label><input type="checkbox" name="collectionIds" value="${collection.id}" ${selected.has(collection.id) ? "checked" : ""} /> ${escapeHtml(collection.name)}</label>
  `).join("") : `<span class="vault-updated">สร้าง Collection ก่อนกำหนดสิทธิ์</span>`;
  $("#memberModalTitle").textContent = member ? "แก้ไขสมาชิก" : "เพิ่มสมาชิก";
  openModal("memberModal");
}

function openGroupEditor(id = null) {
  const form = $("#groupForm");
  form.reset();
  const group = id ? vault.groups.find((entry) => entry.id === id) : null;
  form.elements.id.value = group?.id || "";
  form.elements.name.value = group?.name || "";
  form.elements.members.value = group?.members || "";
  form.elements.collectionId.value = group?.collectionId || "";
  form.elements.permission.value = group?.permission || "view";
  $("#groupModalTitle").textContent = group ? "แก้ไขกลุ่ม" : "สร้างกลุ่ม";
  openModal("groupModal");
}

async function sendLarkDelivery({ requestId, itemName, expiresAt, shareUrl, pin }) {
  const response = await fetch("/api/lark/deliver", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ requestId, itemName, expiresAt, shareUrl, pin }),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || result.ok === false) throw new Error(result.error || "Lark ส่งข้อมูลไม่สำเร็จ");
  return result;
}

async function syncLarkMenuCatalog() {
  if (!vault) return false;
  const items = loginItems().map((item) => ({
    id: item.id,
    system: item.name,
    account: item.username || item.owner || item.purpose || "บัญชีหลัก",
  }));
  try {
    const response = await fetch("/api/lark/catalog", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ items }),
    });
    if (!response.ok) return false;
    const result = await response.json();
    $("#lineConfigStatus").dataset.catalogCount = String(result.count || 0);
    return true;
  } catch {
    return false;
  }
}

async function checkServerConfiguration() {
  try {
    const result = await fetch("/api/health", { cache: "no-store" }).then((response) => response.json());
    $("#serverPinStatus").textContent = result.adminPinConfigured
      ? "PIN ผู้ดูแลถูกเก็บเป็นค่า Hash บน Server และพร้อมใช้งาน"
      : "ยังไม่ได้ตั้งค่า PASSLY_ADMIN_PIN_HASH บน Server";
    $("#lineConfigStatus").textContent = result.larkConfigured
      ? `พร้อมใช้งาน${result.larkAppConfigured ? " · Lark App" : " · Incoming Webhook"}${result.larkChatRestricted ? " · จำกัดเฉพาะแชตที่กำหนด" : ""}`
      : "ยังตั้งค่า Lark App หรือ Incoming Webhook บน Server ไม่ครบ";
  } catch {
    $("#serverPinStatus").textContent = "ตรวจสอบระบบ PIN บน Server ไม่สำเร็จ";
    $("#lineConfigStatus").textContent = "ตรวจสอบ Server ไม่สำเร็จ";
  }
}

async function pullLineRequests() {
  if (!vault) return false;
  try {
    const response = await fetch("/api/requests", { cache: "no-store" });
    if (!response.ok) {
      const result = await response.json().catch(() => ({}));
      const error = new Error(
        response.status === 401
          ? "เซสชัน Server หมดอายุ · กดเชื่อมต่อใหม่"
          : result.error || "เชื่อมต่อ Server ไม่สำเร็จ",
      );
      error.code = response.status;
      throw error;
    }
    const payload = await response.json();
    const unresolvedOpenIds = [...new Set(requests
      .filter((request) => request.source === "Lark" && request.larkUserId && request.larkUserId !== "unknown" && (/^Lark User\b/i.test(request.name || "") || request.name === "ผู้ใช้ Lark"))
      .map((request) => request.larkUserId))];
    let resolvedProfiles = {};
    if (unresolvedOpenIds.length) {
      const profileResponse = await fetch("/api/lark/profiles", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ openIds: unresolvedOpenIds }),
      });
      if (profileResponse.ok) resolvedProfiles = (await profileResponse.json()).profiles || {};
    }
    if (Object.keys(resolvedProfiles).length) {
      requests = requests.map((request) => {
        const profile = resolvedProfiles[request.larkUserId];
        return profile ? { ...request, name: profile.name, email: profile.email } : request;
      });
    }
    const known = new Set(requests.map((request) => request.id));
    const serverRequests = payload.requests || [];
    const incoming = serverRequests.filter((request) => !known.has(request.id));
    const serverById = new Map(serverRequests.map((request) => [request.id, request]));
    const syncedRequests = requests.map((request) => serverById.has(request.id) ? { ...request, ...serverById.get(request.id) } : request);
    const hasUpdates = Object.keys(resolvedProfiles).length > 0 || syncedRequests.some((request, index) => JSON.stringify(request) !== JSON.stringify(requests[index]));
    if (incoming.length || hasUpdates) {
      requests = [...incoming, ...syncedRequests];
      saveRequests();
      renderRequests();
      renderDashboard();
      if (linePollReady && incoming.length) {
        const latest = incoming[0];
        toast("มีคำขอใหม่จาก Lark", `${latest.name} · ${latest.system} · ${latest.requestAccount || "ไม่ระบุบัญชี"}`);
        if ("Notification" in window && Notification.permission === "granted") new Notification("Passly: คำขอ Password ใหม่", { body: `${latest.name} — ${latest.system} — ${latest.requestAccount || "ไม่ระบุบัญชี"}`, tag: latest.id });
      }
    }
    linePollReady = true;
    $("#lineStatus").textContent = `เชื่อมต่อแล้ว · อัปเดต ${new Date().toLocaleTimeString("th-TH", { hour: "2-digit", minute: "2-digit" })}`;
    $("#lineAlert").classList.remove("offline");
    $("#lineReconnectBtn").hidden = true;
    return true;
  } catch (error) {
    $("#lineStatus").textContent = error.message;
    $("#lineAlert").classList.add("offline");
    $("#lineReconnectBtn").hidden = error.code !== 401;
    return false;
  }
}

async function reconnectLineRequests() {
  if (!vault || lineReconnectBusy) return;
  const pin = prompt("กรอก PIN เพื่อเชื่อมต่อรายการคำขอ Lark อีกครั้ง");
  if (pin === null) return;
  const button = $("#lineReconnectBtn");
  lineReconnectBusy = true;
  button.disabled = true;
  button.textContent = "กำลังเชื่อมต่อ…";
  try {
    const email = unlockForm.elements.email.value.trim().toLowerCase();
    await authenticateServerLogin(email, pin);
    await syncLarkMenuCatalog();
    linePollReady = false;
    if (!await pullLineRequests()) throw new Error("โหลดรายการคำขอจาก Server ไม่สำเร็จ");
    toast("เชื่อมต่อ Lark แล้ว", "โหลดรายการคำขอล่าสุดเรียบร้อย");
  } catch (error) {
    toast("เชื่อมต่อไม่สำเร็จ", error.message || "กรุณาตรวจสอบ PIN แล้วลองใหม่");
  } finally {
    lineReconnectBusy = false;
    button.disabled = false;
    button.textContent = "เชื่อมต่อใหม่";
  }
}

async function importCredentialFile(file) {
  const imported = await readCredentialFile(file);
  let importedCollection = vault.collections.find((collection) => collection.name === "Imported Excel");
  if (!importedCollection) {
    importedCollection = { id: crypto.randomUUID(), name: "Imported Excel", description: "ข้อมูลที่นำเข้าจากไฟล์รายการรหัสเดิม", members: "IT Admin", permission: "manage", color: "#735dc1" };
    vault.collections.push(importedCollection);
  }
  let importedFolder = vault.folders.find((folder) => folder.name === "Imported");
  if (!importedFolder) {
    importedFolder = { id: crypto.randomUUID(), name: "Imported" };
    vault.folders.push(importedFolder);
  }
  const existing = new Set(activeItems().map((item) => `${item.name}|${item.username || ""}|${item.uri || ""}`.toLowerCase()));
  let added = 0;
  let skipped = 0;
  for (const record of imported) {
    const key = `${record.name || ""}|${record.username || ""}|${record.uri || ""}`.toLowerCase();
    if (existing.has(key)) {
      skipped += 1;
      continue;
    }
    const timestamp = nowIso();
    vault.items.push({
      id: crypto.randomUUID(),
      type: ["login", "note", "card", "identity"].includes(record.type) ? record.type : "login",
      name: record.name || record.username || "Imported Login",
      username: record.username || "",
      password: record.password || "",
      previousPassword: record.previousPassword || "",
      uri: /^https?:\/\//i.test(record.uri || "") ? record.uri : "",
      purpose: record.purpose || "",
      owner: record.owner || "",
      notes: record.notes || "",
      passwordUpdatedAt: record.passwordUpdatedAt || todayIso(),
      folderId: importedFolder.id,
      collectionId: importedCollection.id,
      favorite: false,
      reprompt: false,
      history: record.previousPassword ? [{ password: record.previousPassword, at: timestamp }] : [],
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    existing.add(key);
    added += 1;
  }
  addActivity("นำเข้าข้อมูล", `${file.name}: เพิ่ม ${added} รายการ ข้ามรายการซ้ำ ${skipped}`);
  await persistVault();
  renderAll();
  showView("vault");
  toast("นำเข้าสำเร็จ", `เพิ่ม ${added} รายการ · ข้ามรายการซ้ำ ${skipped}`);
}

$("#setupForm").addEventListener("input", (event) => {
  if (event.target.name !== "password") return;
  const score = passwordScore(event.target.value);
  $("#masterMeter").style.width = `${score * 25}%`;
  $("#masterMeter").style.background = ["#c74e4e", "#c74e4e", "#d77935", "#3e6fe0", "#168457"][score];
});

$("#setupForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const enteredSecret = form.elements.password.value;
  const confirmedSecret = form.elements.confirmPassword.value;
  if (
    normalizeVaultSecret(enteredSecret)
    !== normalizeVaultSecret(confirmedSecret)
  ) return toast("รหัสไม่ตรงกัน", "กรุณายืนยันรหัสผ่านหรือ PIN อีกครั้ง");
  if (lockInProgress) return;
  lockInProgress = true;
  const button = form.querySelector("button[type=submit]");
  const secretInputs = [...form.querySelectorAll('input[type="password"]')];
  secretInputs.forEach((input) => { input.disabled = true; });
  button.disabled = true;
  button.textContent = "กำลังตรวจ PIN กับ Server…";
  try {
    const email = 'admin'; // Setup uses default admin
    await authenticateServerLogin(email, enteredSecret);
    button.textContent = "กำลังตรวจสอบ Vault กลาง…";
    await prepareRemoteVaultForUnlock();
    if (getStoredEnvelope()) {
      button.textContent = "กำลังถอดรหัส…";
      const stored = await unlockStoredVault(localStorage, email, enteredSecret);
      vault = migrateVaultData(stored.vault);
      vaultKey = stored.key;
      vaultEnvelope = stored.envelope;
      form.reset();
      afterUnlock();
      toast("โหลด Vault จาก Server แล้ว", "ข้อมูล Password พร้อมใช้งานบนอุปกรณ์นี้");
      return;
    }
    button.textContent = "กำลังสร้างกุญแจเข้ารหัส…";
    vault = createEmptyVault();
    const finalEmail = form.elements.email ? form.elements.email.value.trim().toLowerCase() : 'admin';
    const result = await createVaultEnvelope(vault, finalEmail, enteredSecret);
    vaultKey = result.key;
    vaultEnvelope = result.envelope;
    commitVaultEnvelope(localStorage, result.envelope, {
      preserveCurrentAsBackup: false,
      clearBackup: true,
    });
    pendingRemoteUpload = true;
    localStorage.removeItem("passly-lark");
    form.reset();
    afterUnlock();
    toast("สร้าง Passly Vault แล้ว", "ข้อมูลพร้อมบันทึกแบบเข้ารหัส");
  } catch (error) {
    vault = null;
    vaultKey = null;
    vaultEnvelope = null;
    toast("สร้าง Vault ไม่สำเร็จ", error.message);
  } finally {
    lockInProgress = false;
    secretInputs.forEach((input) => { input.disabled = false; });
    button.disabled = false;
    button.innerHTML = 'สร้าง Vault ที่เข้ารหัส <span>→</span>';
  }
});

$("#unlockForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (lockInProgress) return;
  lockInProgress = true;
  const form = event.currentTarget;
  const button = form.querySelector('button[type="submit"]');
  const secretInput = form.elements.password;
  const enteredSecret = secretInput.value;
  let serverPinVerified = false;
  secretInput.disabled = true;
  button.disabled = true;
  button.textContent = "กำลังตรวจ PIN กับ Server…";
  $("#unlockError").hidden = true;
  try {
    await authenticateServerPin(enteredSecret);
    serverPinVerified = true;
    button.textContent = "กำลังโหลด Vault กลาง…";
    await prepareRemoteVaultForUnlock();
    button.textContent = "กำลังถอดรหัส…";
    const result = await unlockStoredVault(
      localStorage,
      enteredSecret,
    );
    vault = migrateVaultData(result.vault);
    let securityUpgraded = false;
    if (result.envelope.secretEncoding === VAULT_SECRET_ENCODING) {
      vaultKey = result.key;
      vaultEnvelope = result.envelope;
    } else {
      const upgraded = await createVaultEnvelope(vault, email, enteredSecret);
      vaultKey = upgraded.key;
      vaultEnvelope = upgraded.envelope;
      commitVaultEnvelope(localStorage, upgraded.envelope);
      securityUpgraded = true;
    }
    form.reset();
    afterUnlock();
    if (result.repairError) {
      toast(
        "เปิด Vault ได้ แต่สำเนาสำรองยังไม่สมบูรณ์",
        "กรุณาส่งออก Backup หลังเข้าสู่ระบบ ระบบจะพยายามบันทึกสำเนาใหม่อีกครั้ง",
      );
    } else if (result.recoverySource === "recovery") {
      toast(
        "กู้คืน Vault จาก Recovery Snapshot สำเร็จ",
        "ระบบซ่อม Vault ที่ถูกแท็บเก่าเขียนทับ และเปิดข้อมูลล่าสุดให้แล้ว",
      );
    } else if (result.recoverySource === "archive") {
      toast(
        "กู้คืน Vault จาก Archive สำเร็จ",
        "ระบบเปิด Vault รุ่นที่ใช้ PIN ปัจจุบันได้ และเก็บ Vault ที่เปิดไม่ได้ไว้เป็น Archive แทนแล้ว",
      );
    } else if (result.recovered) {
      toast(
        "กู้คืน Vault สำเร็จ",
        "ระบบใช้ Snapshot สำรองก่อน Sleep และซ่อมข้อมูลที่บันทึกล่าสุดให้แล้ว",
      );
    } else if (securityUpgraded) {
      toast(
        "อัปเกรดระบบล็อกแล้ว",
        "Vault ใช้ SHA-512 ขนาด 64 ไบต์ร่วมกับ AES-256 แล้ว",
      );
    }
  } catch (error) {
    console.error("Vault unlock failed after server PIN verification.", error);
    $("#unlockError").textContent = serverPinVerified
      ? "PIN ถูกต้องสำหรับ Server แต่ Vault นี้อาจสร้างด้วย PIN เดิม กรุณากู้คืน Backup หรือเก็บ Vault เดิมก่อนสร้างใหม่"
      : error.message || "PIN ไม่ถูกต้อง";
    $("#unlockError").hidden = false;
  } finally {
    lockInProgress = false;
    secretInput.disabled = false;
    button.disabled = false;
    button.innerHTML = 'เข้าสู่ระบบ <span>→</span>';
  }
});

$("#itemForm").addEventListener("change", (event) => {
  if (event.target.name === "type") updateItemFields(event.target.value);
});

$("#itemForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const id = form.elements.id.value;
  const existing = id ? vault.items.find((item) => item.id === id) : null;
  const timestamp = nowIso();
  const item = existing || { id: crypto.randomUUID(), createdAt: timestamp, history: [] };
  if (existing?.type === "login" && existing.password && existing.password !== form.elements.password.value) {
    item.history = [{ password: existing.password, at: timestamp }, ...(existing.history || [])].slice(0, 10);
  }
  Object.assign(item, {
    type: form.elements.type.value,
    name: form.elements.name.value.trim(),
    username: form.elements.username.value.trim(),
    password: form.elements.password.value,
    uri: form.elements.uri.value.trim(),
    purpose: form.elements.purpose.value.trim(),
    passwordUpdatedAt: form.elements.passwordUpdatedAt.value || todayIso(),
    previousPassword: form.elements.previousPassword.value,
    secureNote: form.elements.secureNote.value,
    cardholder: form.elements.cardholder.value.trim(),
    brand: form.elements.brand.value.trim(),
    cardNumber: form.elements.cardNumber.value.trim(),
    cardExpiry: form.elements.cardExpiry.value.trim(),
    cardCvv: form.elements.cardCvv.value,
    fullName: form.elements.fullName.value.trim(),
    identityEmail: form.elements.identityEmail.value.trim(),
    phone: form.elements.phone.value.trim(),
    idNumber: form.elements.idNumber.value.trim(),
    address: form.elements.address.value.trim(),
    folderId: form.elements.folderId.value,
    collectionId: form.elements.collectionId.value,
    owner: form.elements.owner.value.trim(),
    notes: form.elements.notes.value.trim(),
    favorite: form.elements.favorite.checked,
    reprompt: form.elements.reprompt.checked,
    trashedAt: null,
    updatedAt: timestamp,
  });
  if (!existing) vault.items.push(item);
  addActivity(existing ? "แก้ไขรายการ" : "เพิ่มรายการ", item.name, item.id);
  await persistVault();
  closeModal("itemModal");
  form.reset();
  renderAll();
  toast("บันทึกแบบเข้ารหัสแล้ว", item.name);
});

$("#requestForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const existing = requests.find((request) => request.id === form.elements.id.value);
  if (!existing) {
    toast("เพิ่มคำขอจากหน้าเว็บไม่ได้", "คำขอใหม่ต้องมาจากเมนูในกลุ่ม Lark เท่านั้น");
    return;
  }
  const data = {
    name: form.elements.name.value.trim(),
    email: form.elements.email.value.trim(),
    system: form.elements.system.value.trim(),
    reason: form.elements.reason.value.trim(),
    status: form.elements.status.value,
    urgent: form.elements.urgent.checked,
  };
  try {
    await mutateServerRequest(existing.id, "PATCH", data);
    Object.assign(existing, data);
    saveRequests();
    closeModal("requestModal");
    renderRequests();
    renderDashboard();
    toast("บันทึกคำขอแล้ว", data.system);
  } catch (error) {
    toast("บันทึกคำขอไม่สำเร็จ", error.message);
  }
});

$("#deliverForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const submitButton = form.querySelector('button[type="submit"]');
  const request = requests.find((entry) => entry.id === form.elements.requestId.value);
  const item = vault.items.find((entry) => entry.id === form.elements.itemId.value);
  if (!request || !item) return;
  if (item.reprompt && !await verifyMasterPassword("ยืนยันรหัสผ่านก่อนสร้างลิงก์แจกข้อมูล")) return;
  const channel = form.elements.channel.value;
  submitButton.disabled = true;
  submitButton.textContent = channel === "lark" ? "กำลังส่งเข้า Lark…" : "กำลังคัดลอก…";
  try {
    const expiresAt = resolveShareExpiry(
      form.elements.expiry.value,
      form.elements.customExpiryAt.value,
    );
    const pin = form.elements.pin.value;
    const encryptedFragment = await createSharePayload({
      title: item.name,
      username: item.username,
      password: item.password,
      note: item.purpose || "",
      recipient: request.name,
      expiresAt,
    }, pin);
    const shareUrl = createPortableShareUrl(location.href, encryptedFragment);
    const prefix = vault.settings.sharePrefix || "[Passly] ข้อมูลเข้าใช้งาน";
    const message = `${prefix}\nผู้รับ: ${request.name}\nระบบ: ${item.name}\nหมดอายุ: ${formatDateTime(expiresAt)}\nลิงก์: ${shareUrl.href}`;

    if (channel === "lark") {
      await sendLarkDelivery({
        requestId: request.id,
        itemName: item.name,
        expiresAt,
        shareUrl: shareUrl.href,
        pin,
      });
    } else {
      await navigator.clipboard.writeText(message);
    }

    const reference = await sha256Reference(shareUrl.href);
    request.status = "delivered";
    request.deliveredAt = nowIso();
    request.deliveryMethod = channel === "lark" ? "lark-secure-share" : "manual-copy";
    request.deliveryAudit = { itemId: item.id, channel, expiresAt, reference };
    saveRequests();
    addActivity("แจกข้อมูลจาก Vault", `${item.name} ให้ ${request.name} · ${channel === "lark" ? "Lark" : "คัดลอก"} · ref ${reference}`, item.id);
    await persistVault();
    shareResult = { message, pin };
    $("#shareMessage").value = message;
    $("#sharePinResult").textContent = pin;
    $("#shareResultEyebrow").textContent = channel === "lark" ? "Sent to Lark" : "Share ready";
    $("#shareResultTitle").textContent = channel === "lark" ? "ส่งข้อมูลเข้า Lark แล้ว" : "คัดลอกข้อความแล้ว";
    $("#shareResultCopy").textContent = channel === "lark"
      ? "ผู้รับจะได้รับลิงก์ Passly และ Share PIN เป็น 2 ข้อความในแชตต้นทาง"
      : "นำข้อความไปส่งให้ผู้รับ และกดคัดลอก Share PIN เพื่อส่งแยกอีกครั้ง";
    closeModal("deliverModal");
    openModal("shareResultModal");
    renderAll();
    toast(
      channel === "lark" ? "ส่งเข้า Lark แล้ว" : "คัดลอกข้อความแล้ว",
      channel === "lark" ? "ลิงก์เข้ารหัสและ Share PIN ถูกส่งเป็น 2 ข้อความ" : "อย่าลืมส่ง Share PIN ให้ผู้รับ",
    );
  } catch (error) {
    toast(channel === "lark" ? "ส่งเข้า Lark ไม่สำเร็จ" : "คัดลอกไม่สำเร็จ", error.message);
  } finally {
    submitButton.disabled = false;
    updateDeliverySubmitButton();
  }
});

$("#collectionForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const existing = vault.collections.find((collection) => collection.id === form.elements.id.value);
  const data = {
    name: form.elements.name.value.trim(),
    description: form.elements.description.value.trim(),
    members: form.elements.members.value.trim(),
    permission: form.elements.permission.value,
    color: form.elements.color.value,
  };
  if (existing) Object.assign(existing, data);
  else vault.collections.push({ id: crypto.randomUUID(), ...data });
  addActivity(existing ? "แก้ไข Collection" : "สร้าง Collection", data.name);
  await persistVault();
  closeModal("collectionModal");
  renderAll();
  toast("บันทึก Collection แล้ว", data.name);
});

$("#memberForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const existing = vault.members.find((member) => member.id === form.elements.id.value);
  const data = {
    name: form.elements.name.value.trim(),
    email: form.elements.email.value.trim(),
    role: form.elements.role.value,
    status: form.elements.status.value,
    collectionIds: $$('input[name="collectionIds"]:checked', form).map((input) => input.value),
  };
  if (existing) Object.assign(existing, data);
  else vault.members.push({ id: crypto.randomUUID(), ...data });
  addActivity(existing ? "แก้ไขสมาชิก" : "เพิ่มสมาชิก", `${data.name} · ${data.role} · ${data.status}`);
  await persistVault();
  closeModal("memberModal");
  renderAll();
  toast("บันทึกสมาชิกแล้ว", data.name);
});

$("#groupForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const existing = vault.groups.find((group) => group.id === form.elements.id.value);
  const data = {
    name: form.elements.name.value.trim(),
    members: form.elements.members.value.trim(),
    collectionId: form.elements.collectionId.value,
    permission: form.elements.permission.value,
  };
  if (existing) Object.assign(existing, data);
  else vault.groups.push({ id: crypto.randomUUID(), ...data });
  addActivity(existing ? "แก้ไขกลุ่ม" : "สร้างกลุ่ม", `${data.name} · ${data.permission}`);
  await persistVault();
  closeModal("groupModal");
  renderAll();
  toast("บันทึกกลุ่มแล้ว", data.name);
});

$("#changeMasterForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const currentSecret = form.elements.currentPassword.value;
  const newSecret = form.elements.newPassword.value;
  const confirmedSecret = form.elements.confirmPassword.value;
  if (
    normalizeVaultSecret(newSecret)
    !== normalizeVaultSecret(confirmedSecret)
  ) return toast("รหัสใหม่ไม่ตรงกัน", "กรุณายืนยันอีกครั้ง");
  if (lockInProgress) return;
  lockInProgress = true;
  let currentPinVerified = false;
  const button = form.querySelector("button");
  const secretInputs = [...form.querySelectorAll('input[type="password"]')];
  secretInputs.forEach((input) => { input.disabled = true; });
  button.disabled = true;
  button.textContent = "กำลังเข้ารหัสใหม่…";
  try {
    await unlockStoredVault(localStorage, currentSecret);
    currentPinVerified = true;
    button.textContent = "กำลังตรวจ PIN ใหม่กับ Server…";
    await authenticateServerPin(newSecret);
    await persistVault();
    addActivity("เปลี่ยนรหัสผ่าน", "Vault ถูกเข้ารหัสใหม่ด้วยกุญแจชุดใหม่");
    const result = await createVaultEnvelope(vault, newSecret);
    vaultKey = result.key;
    vaultEnvelope = result.envelope;
    commitVaultEnvelope(localStorage, result.envelope, {
      preserveCurrentAsBackup: false,
      clearBackup: true,
    });
    form.reset();
    closeModal("changeMasterModal");
    toast("เปลี่ยนรหัสผ่านแล้ว", "รหัสใหม่พร้อมใช้เข้าสู่ระบบครั้งต่อไป");
  } catch (error) {
    toast(
      "เปลี่ยนไม่สำเร็จ",
      currentPinVerified ? error.message : "รหัสผ่านหรือ PIN ปัจจุบันไม่ถูกต้อง",
    );
  } finally {
    lockInProgress = false;
    secretInputs.forEach((input) => { input.disabled = false; });
    button.disabled = false;
    button.textContent = "บันทึกรหัสใหม่";
  }
});

document.addEventListener("click", async (event) => {
  const nav = event.target.closest("[data-view]");
  if (nav) showView(nav.dataset.view);
  const go = event.target.closest("[data-go-view]");
  if (go) showView(go.dataset.goView);
  if (event.target.closest("[data-open-item]")) openItemEditor();

  const close = event.target.closest("[data-close-modal]");
  if (close) closeModal(close.dataset.closeModal);

  const viewItem = event.target.closest("[data-item-view]");
  if (viewItem) await openItemDetail(viewItem.dataset.itemView);
  const editItem = event.target.closest("[data-item-edit]");
  if (editItem) {
    closeModal("itemDetailModal");
    openItemEditor(editItem.dataset.itemEdit);
  }
  const favoriteItem = event.target.closest("[data-item-favorite]");
  if (favoriteItem) {
    const item = vault.items.find((entry) => entry.id === favoriteItem.dataset.itemFavorite);
    if (item) {
      item.favorite = !item.favorite;
      item.updatedAt = nowIso();
      addActivity(item.favorite ? "เพิ่ม Favorite" : "นำออกจาก Favorite", item.name, item.id);
      await persistVault();
      renderAll();
      if (!$("#itemDetailModal").hidden) await openItemDetail(item.id);
    }
  }
  const trashItem = event.target.closest("[data-item-trash]");
  if (trashItem) {
    const item = vault.items.find((entry) => entry.id === trashItem.dataset.itemTrash);
    if (item && confirm(`ย้าย “${item.name}” ไป Trash ใช่หรือไม่?`)) {
      item.trashedAt = nowIso();
      item.updatedAt = nowIso();
      addActivity("ย้ายไป Trash", item.name, item.id);
      await persistVault();
      closeModal("itemDetailModal");
      renderAll();
    }
  }
  const restoreItem = event.target.closest("[data-item-restore]");
  if (restoreItem) {
    const item = vault.items.find((entry) => entry.id === restoreItem.dataset.itemRestore);
    item.trashedAt = null;
    item.updatedAt = nowIso();
    addActivity("กู้คืนจาก Trash", item.name, item.id);
    await persistVault();
    renderAll();
  }
  const deleteForever = event.target.closest("[data-item-delete-forever]");
  if (deleteForever) {
    const item = vault.items.find((entry) => entry.id === deleteForever.dataset.itemDeleteForever);
    if (item && confirm(`ลบ “${item.name}” ถาวรใช่หรือไม่?`)) {
      vault.items = vault.items.filter((entry) => entry.id !== item.id);
      addActivity("ลบรายการถาวร", item.name);
      await persistVault();
      renderAll();
    }
  }

  const approveRequest = event.target.closest("[data-request-approve]");
  if (approveRequest) {
    const request = requests.find((entry) => entry.id === approveRequest.dataset.requestApprove);
    try {
      await mutateServerRequest(request.id, "PATCH", { status: "approved" });
      request.status = "approved";
      saveRequests();
      renderAll();
      toast("อนุมัติคำขอแล้ว", "พร้อมเลือกข้อมูลจาก Vault");
    } catch (error) {
      toast("อนุมัติคำขอไม่สำเร็จ", error.message);
    }
  }
  const rejectRequest = event.target.closest("[data-request-reject]");
  if (rejectRequest) {
    const reason = prompt("เหตุผลที่ปฏิเสธคำขอ:");
    if (reason === null) return;
    const request = requests.find((entry) => entry.id === rejectRequest.dataset.requestReject);
    try {
      await mutateServerRequest(request.id, "PATCH", { status: "rejected", rejectReason: reason });
      request.status = "rejected";
      request.rejectReason = reason;
      saveRequests();
      renderAll();
      toast("ปฏิเสธคำขอแล้ว", request.system);
    } catch (error) {
      toast("ปฏิเสธคำขอไม่สำเร็จ", error.message);
    }
  }
  const shareRequest = event.target.closest("[data-request-share]");
  if (shareRequest) await openDeliverForRequest(shareRequest.dataset.requestShare);
  const editRequest = event.target.closest("[data-request-edit]");
  if (editRequest) openRequestEditor(editRequest.dataset.requestEdit);
  const deleteRequest = event.target.closest("[data-request-delete]");
  if (deleteRequest && confirm("ลบคำขอนี้ใช่หรือไม่?")) {
    try {
      await mutateServerRequest(deleteRequest.dataset.requestDelete, "DELETE");
      requests = requests.filter((entry) => entry.id !== deleteRequest.dataset.requestDelete);
      saveRequests();
      renderAll();
      toast("ลบคำขอแล้ว", "รายการถูกนำออกจาก Server เรียบร้อย");
    } catch (error) {
      toast("ลบคำขอไม่สำเร็จ", error.message);
    }
  }

  const historyCopy = event.target.closest("[data-history-copy]");
  if (historyCopy) {
    const entry = vault.generatorHistory.find((item) => item.id === historyCopy.dataset.historyCopy);
    if (entry) await copyText(entry.value);
  }

  const collectionEdit = event.target.closest("[data-collection-edit]");
  if (collectionEdit) openCollectionEditor(collectionEdit.dataset.collectionEdit);
  const collectionOpen = event.target.closest("[data-collection-open]");
  if (collectionOpen) {
    showView("vault");
    $("#collectionFilter").value = collectionOpen.dataset.collectionOpen;
    renderVault();
  }
  const collectionDelete = event.target.closest("[data-collection-delete]");
  if (collectionDelete) {
    const collection = vault.collections.find((entry) => entry.id === collectionDelete.dataset.collectionDelete);
    if (collection && confirm(`ลบ Collection “${collection.name}” ใช่หรือไม่? รายการจะย้ายกลับ My Vault`)) {
      vault.items.forEach((item) => { if (item.collectionId === collection.id) item.collectionId = ""; });
      vault.collections = vault.collections.filter((entry) => entry.id !== collection.id);
      addActivity("ลบ Collection", collection.name);
      await persistVault();
      renderAll();
    }
  }
  const folderRename = event.target.closest("[data-folder-rename]");
  if (folderRename) {
    const folder = vault.folders.find((entry) => entry.id === folderRename.dataset.folderRename);
    const name = prompt("ชื่อ Folder ใหม่:", folder.name);
    if (name?.trim()) {
      folder.name = name.trim();
      addActivity("เปลี่ยนชื่อ Folder", folder.name);
      await persistVault();
      renderAll();
    }
  }
  const folderDelete = event.target.closest("[data-folder-delete]");
  if (folderDelete) {
    const folder = vault.folders.find((entry) => entry.id === folderDelete.dataset.folderDelete);
    if (folder && confirm(`ลบ Folder “${folder.name}” ใช่หรือไม่?`)) {
      vault.items.forEach((item) => { if (item.folderId === folder.id) item.folderId = ""; });
      vault.folders = vault.folders.filter((entry) => entry.id !== folder.id);
      addActivity("ลบ Folder", folder.name);
      await persistVault();
      renderAll();
    }
  }
  const memberEdit = event.target.closest("[data-member-edit]");
  if (memberEdit) openMemberEditor(memberEdit.dataset.memberEdit);
  const memberToggle = event.target.closest("[data-member-toggle]");
  if (memberToggle) {
    const member = vault.members.find((entry) => entry.id === memberToggle.dataset.memberToggle);
    if (member) {
      member.status = member.status === "revoked" ? "confirmed" : "revoked";
      addActivity(member.status === "revoked" ? "ระงับสมาชิก" : "คืนสิทธิ์สมาชิก", member.name);
      await persistVault();
      renderAll();
    }
  }
  const memberDelete = event.target.closest("[data-member-delete]");
  if (memberDelete) {
    const member = vault.members.find((entry) => entry.id === memberDelete.dataset.memberDelete);
    const ownerCount = vault.members.filter((entry) => entry.role === "owner").length;
    if (member?.role === "owner" && ownerCount <= 1) return toast("ลบ Owner คนสุดท้ายไม่ได้", "เปลี่ยนบทบาทหรือเพิ่ม Owner อีกคนก่อน");
    if (member && confirm(`ลบสมาชิก “${member.name}” ใช่หรือไม่?`)) {
      vault.members = vault.members.filter((entry) => entry.id !== member.id);
      addActivity("ลบสมาชิก", member.name);
      await persistVault();
      renderAll();
    }
  }
  const groupEdit = event.target.closest("[data-group-edit]");
  if (groupEdit) openGroupEditor(groupEdit.dataset.groupEdit);
  const groupDelete = event.target.closest("[data-group-delete]");
  if (groupDelete) {
    const group = vault.groups.find((entry) => entry.id === groupDelete.dataset.groupDelete);
    if (group && confirm(`ลบกลุ่ม “${group.name}” ใช่หรือไม่?`)) {
      vault.groups = vault.groups.filter((entry) => entry.id !== group.id);
      addActivity("ลบกลุ่ม", group.name);
      await persistVault();
      renderAll();
    }
  }

  const detailCopy = event.target.closest("[data-detail-copy]");
  if (detailCopy && detailItemId) {
    const item = vault.items.find((entry) => entry.id === detailItemId);
    if (item.reprompt && !await verifyMasterPassword()) return;
    const value = item[detailCopy.dataset.detailCopy];
    if (value) {
      await copyText(value);
      addActivity("คัดลอกข้อมูล", `${item.name} · ${detailCopy.dataset.detailCopy}`, item.id);
      persistVault();
    }
  }
  if (event.target.closest("[data-detail-toggle-password]") && detailItemId) {
    const item = vault.items.find((entry) => entry.id === detailItemId);
    const target = $("#detailPassword");
    const hidden = target.textContent.includes("•");
    target.textContent = hidden ? item.password : "••••••••••••";
    event.target.textContent = hidden ? "ซ่อน" : "แสดง";
  }
  if (event.target.closest("[data-detail-toggle-card]") && detailItemId) {
    const item = vault.items.find((entry) => entry.id === detailItemId);
    const target = $("#detailCard");
    const hidden = target.textContent.includes("•");
    target.textContent = hidden ? item.cardNumber : `•••• •••• •••• ${(item.cardNumber || "").replace(/\s/g, "").slice(-4)}`;
    event.target.textContent = hidden ? "ซ่อน" : "แสดง";
  }
  if (event.target.closest("[data-detail-launch]") && detailItemId) {
    const item = vault.items.find((entry) => entry.id === detailItemId);
    if (item.uri) window.open(item.uri, "_blank", "noopener,noreferrer");
  }
  if (event.target.closest("[data-detail-share]") && detailItemId) {
    closeModal("itemDetailModal");
    const item = vault.items.find((entry) => entry.id === detailItemId);
    showView("requests");
    toast("เลือกคำขอที่อนุมัติแล้ว", `เพื่อแจก ${item.name} จาก Vault`);
  }
});

$("#newItemBtn").addEventListener("click", () => openItemEditor());
$("#menuBtn").addEventListener("click", () => $(".sidebar").classList.toggle("open"));
$("#lockVaultBtn").addEventListener("click", () => lockVault("ผู้ดูแลกดออกจากระบบ"));
$("#themeBtn").addEventListener("click", () => {
  document.body.classList.toggle("dark");
  localStorage.setItem(THEME_KEY, document.body.classList.contains("dark") ? "dark" : "light");
});

$("#globalSearch").addEventListener("input", (event) => {
  vaultSearch = event.target.value.trim();
  if (vaultSearch && activeView !== "vault") showView("vault");
  renderVault();
});
document.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    $("#globalSearch").focus();
  }
  if (event.key === "Escape") {
    $$(".modal-backdrop").forEach((modal) => { modal.hidden = true; });
    document.body.style.overflow = "";
  }
});

$("#vaultFilters").addEventListener("click", (event) => {
  const button = event.target.closest("[data-vault-filter]");
  if (!button) return;
  vaultFilter = button.dataset.vaultFilter;
  $$("[data-vault-filter]").forEach((entry) => entry.classList.toggle("active", entry === button));
  renderVault();
});
["folderFilter", "collectionFilter", "vaultSort"].forEach((id) => $(`#${id}`).addEventListener("change", renderVault));
$("#requestSearch").addEventListener("input", renderRequests);
$("#requestStatusFilter").addEventListener("change", renderRequests);

$("#toggleUnlockPassword").addEventListener("click", () => {
  const input = $("#unlockForm").elements.password;
  input.type = input.type === "password" ? "text" : "password";
  $("#toggleUnlockPassword").textContent = input.type === "password" ? "ดูรหัส" : "ซ่อนรหัส";
});
$("#toggleItemPassword").addEventListener("click", () => {
  const input = $("#itemForm").elements.password;
  input.type = input.type === "password" ? "text" : "password";
  $("#toggleItemPassword").textContent = input.type === "password" ? "ดู" : "ซ่อน";
});
$("#generateItemPassword").addEventListener("click", () => {
  const input = $("#itemForm").elements.password;
  input.value = generatePassword({ length: 18 });
  input.type = "text";
  $("#toggleItemPassword").textContent = "ซ่อน";
});

$$("[data-generator-type]").forEach((button) => button.addEventListener("click", () => {
  generatorType = button.dataset.generatorType;
  $$("[data-generator-type]").forEach((entry) => entry.classList.toggle("active", entry === button));
  $("#passwordOptions").hidden = generatorType !== "password";
  $("#passphraseOptions").hidden = generatorType !== "passphrase";
  updateGenerator();
}));
$("#passwordLength").addEventListener("input", () => { $("#lengthValue").textContent = $("#passwordLength").value; updateGenerator(); });
$("#wordCount").addEventListener("input", () => { $("#wordCountValue").textContent = $("#wordCount").value; updateGenerator(); });
["genUpper", "genLower", "genNumbers", "genSymbols", "genAmbiguous", "wordSeparator", "wordCapitalize", "wordNumber"].forEach((id) => $(`#${id}`).addEventListener("input", updateGenerator));
$("#regenerate").addEventListener("click", updateGenerator);
$("#copyGenerated").addEventListener("click", async () => { await copyText(generatedValue); await saveGeneratedHistory(); });
$("#copyGeneratedPrimary").addEventListener("click", async () => { await copyText(generatedValue); await saveGeneratedHistory(); });
$("#saveGenerated").addEventListener("click", async () => { await saveGeneratedHistory(); openItemEditor(null, { password: generatedValue, passwordUpdatedAt: todayIso() }); });
$("#clearGeneratorHistory").addEventListener("click", async () => {
  if (!confirm("ล้างประวัติรหัสที่สร้างทั้งหมดใช่หรือไม่?")) return;
  vault.generatorHistory = [];
  addActivity("ล้างประวัติ Generator", "ลบประวัติรหัสที่สร้าง");
  await persistVault();
  renderGeneratorHistory();
});

$("#newCollectionBtn").addEventListener("click", () => openCollectionEditor());
$("#newMemberBtn").addEventListener("click", () => openMemberEditor());
$("#newGroupBtn").addEventListener("click", () => openGroupEditor());
$("#newFolderBtn").addEventListener("click", async () => {
  const name = prompt("ชื่อ Folder ใหม่:");
  if (!name?.trim()) return;
  vault.folders.push({ id: crypto.randomUUID(), name: name.trim() });
  addActivity("สร้าง Folder", name.trim());
  await persistVault();
  renderAll();
});

$("#importBtn").addEventListener("click", () => $("#credentialFileInput").click());
$("#importQuickBtn").addEventListener("click", () => $("#credentialFileInput").click());
$("#credentialFileInput").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  event.target.value = "";
  if (!file) return;
  try {
    toast("กำลังนำเข้า", "ไฟล์ถูกอ่านในเบราว์เซอร์และจะเข้ารหัสก่อนบันทึก");
    await importCredentialFile(file);
  } catch (error) {
    toast("นำเข้าไม่สำเร็จ", error.message);
  }
});

$("#exportVaultBtn").addEventListener("click", async () => {
  await saveQueue;
  const envelope = getStoredEnvelope();
  downloadFile(`passly-encrypted-backup-${todayIso()}.json`, JSON.stringify(envelope, null, 2));
  addActivity("Export Backup", "ดาวน์โหลดไฟล์สำรองที่เข้ารหัส");
  persistVault();
  toast("ดาวน์โหลด Backup แล้ว", "ไฟล์ยังคงเข้ารหัสด้วยรหัสผ่านหรือ PIN");
});
$("#importBackupBtn").addEventListener("click", () => $("#backupFileInput").click());
$("#restoreFromLock").addEventListener("click", () => $("#backupFileInput").click());
$("#restoreArchivedFromLock").addEventListener("click", () => {
  const archive = readVaultArchive(localStorage);
  if (!archive) return toast("ไม่พบ Vault เดิม", "เลือกกู้คืนจากไฟล์ Backup แทน");
  if (!confirm("กู้คืน Vault เดิมที่เก็บไว้ในเบราว์เซอร์และแทนที่ Vault ปัจจุบันใช่หรือไม่?")) return;
  restoreVaultArchive(localStorage, archive);
  location.reload();
});
$("#backupFileInput").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  event.target.value = "";
  if (!file) return;
  try {
    const backupData = JSON.parse(await file.text());
    if (!isVaultEnvelope(backupData) && !isVaultArchive(backupData)) {
      throw new Error("ไม่ใช่ Passly encrypted backup");
    }
    if (!confirm("กู้คืน Backup นี้และแทนที่ Vault ปัจจุบันใช่หรือไม่?")) return;
    if (isVaultArchive(backupData)) restoreVaultArchive(localStorage, backupData);
    else commitVaultEnvelope(localStorage, backupData);
    lockVault("กรอกรหัสผ่านหรือ PIN ของ Backup เพื่อเปิด Vault", { save: false });
  } catch (error) {
    toast("กู้คืนไม่สำเร็จ", error.message);
  }
});

$("#exportActivityBtn").addEventListener("click", () => {
  const rows = [["Date", "Action", "Detail"], ...vault.activity.map((entry) => [entry.at, entry.action, entry.detail])];
  const csv = rows.map((row) => row.map((value) => `"${String(value).replaceAll('"', '""')}"`).join(",")).join("\r\n");
  downloadFile(`passly-activity-${todayIso()}.csv`, `\uFEFF${csv}`, "text/csv;charset=utf-8");
});

$("#changeMasterBtn").addEventListener("click", () => openModal("changeMasterModal"));

$("#larkConfigForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const appId = $("#larkAppId").value.trim();
  const appSecret = $("#larkAppSecret").value.trim();
  const verificationToken = $("#larkVerificationToken").value.trim();
  const webhookUrl = $("#larkWebhookUrl").value.trim();
  const chatId = $("#larkChatId").value.trim();
  const btn = e.target.querySelector('button');
  const originalText = btn.textContent;
  btn.textContent = "กำลังบันทึก...";
  btn.disabled = true;

  try {
    const response = await fetch('/api/config/lark', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ appId, appSecret, verificationToken, webhookUrl, chatId })
    });
    const result = await response.json();
    if (!result.ok) throw new Error(result.error || "เกิดข้อผิดพลาด");
    
    toast("บันทึกสำเร็จ", "ตั้งค่า Lark เรียบร้อยแล้ว");
    $("#larkAppSecret").value = "";
    $("#larkVerificationToken").value = "";
    await fetchServerHealth();
  } catch (err) {
    toast("ข้อผิดพลาด", err.message);
  } finally {
    btn.textContent = originalText;
    btn.disabled = false;
  }
});


async function resetVaultStorage() {
  if (vault && vaultKey) await persistVault();
  const archive = createVaultArchive(localStorage);
  downloadFile(
    `passly-vault-archive-${todayIso()}.json`,
    JSON.stringify(archive, null, 2),
  );
  archiveAndResetStoredVault(localStorage);
  vault = null;
  vaultKey = null;
  vaultEnvelope = null;
  location.reload();
}

function openResetVaultConfirmation() {
  const form = $("#resetVaultForm");
  form.reset();
  $("#resetVaultError").hidden = true;
  openModal("resetVaultModal");
  setTimeout(() => form.elements.confirmation.focus(), 80);
}

$("#resetVaultForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const confirmation = form.elements.confirmation.value.trim().toUpperCase();
  const error = $("#resetVaultError");
  if (confirmation !== "RESET") {
    error.textContent = "กรุณาพิมพ์ RESET ให้ถูกต้อง";
    error.hidden = false;
    return;
  }
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  button.textContent = "กำลังเก็บ Backup เข้ารหัส…";
  error.hidden = true;
  try {
    await resetVaultStorage();
  } catch (resetError) {
    error.textContent = resetError.message;
    error.hidden = false;
    button.disabled = false;
    button.textContent = "เก็บ Backup และสร้าง Vault ใหม่";
  }
});
$("#resetVaultBtn").addEventListener("click", openResetVaultConfirmation);
$("#resetFromLock").addEventListener("click", openResetVaultConfirmation);

$("#regenerateSharePin").addEventListener("click", () => { $("#deliverForm").elements.pin.value = generateSharePin(); });
$("#deliveryChannel").addEventListener("change", updateDeliverySubmitButton);
$("#deliveryExpiry").addEventListener("change", () => syncCustomExpiryControl());
$("#copyShareMessage").addEventListener("click", () => shareResult && copyText(shareResult.message, "คัดลอกข้อความแล้ว"));
$("#copySharePin").addEventListener("click", () => shareResult && copyText(shareResult.pin, "คัดลอก PIN แล้ว"));
$("#refreshSecurity").addEventListener("click", () => { renderSecurity(); toast("สแกน Vault แล้ว", "การตรวจสอบทำบนอุปกรณ์นี้"); });

$("#enableNotifications").addEventListener("click", async () => {
  if (!("Notification" in window)) return toast("ไม่รองรับ", "เบราว์เซอร์นี้ไม่รองรับ Desktop Notification");
  const permission = await Notification.requestPermission();
  toast(permission === "granted" ? "เปิดแจ้งเตือนแล้ว" : "ยังไม่ได้รับอนุญาต", permission === "granted" ? "คำขอใหม่จะแจ้งบนหน้าจอ" : "เปิดได้ภายหลังจากการตั้งค่าเบราว์เซอร์");
});
$("#lineReconnectBtn").addEventListener("click", reconnectLineRequests);

function persistBeforeSuspension() {
  if (!vault || !vaultKey || lockInProgress) return;
  persistVault().catch((error) => {
    console.error("Unable to save the vault before suspension.", error);
  });
}

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden") {
    activatePrivacyShield();
    persistBeforeSuspension();
    return;
  }
  privacyShieldTimer = setTimeout(() => deactivatePrivacyShield(), 180);
});
document.addEventListener("freeze", () => {
  activatePrivacyShield();
  persistBeforeSuspension();
});
window.addEventListener("blur", () => activatePrivacyShield());
window.addEventListener("focus", () => {
  privacyShieldTimer = setTimeout(() => deactivatePrivacyShield(), 180);
});
window.addEventListener("beforeprint", () => {
  activatePrivacyShield("Passly ไม่อนุญาตให้พิมพ์หรือบันทึกหน้าที่มีข้อมูลสำคัญ");
});
window.addEventListener("afterprint", () => deactivatePrivacyShield());
window.addEventListener("keydown", (event) => {
  if (event.key !== "PrintScreen") return;
  activatePrivacyShield("ตรวจพบคำสั่งจับภาพหน้าจอ จึงซ่อนข้อมูลสำคัญชั่วคราว");
  privacyShieldTimer = setTimeout(() => deactivatePrivacyShield(), 1600);
}, { capture: true });
window.addEventListener("pagehide", persistBeforeSuspension);
window.addEventListener("storage", (event) => {
  if (
    vault
    && (event.key === VAULT_STORAGE_KEY
      || event.key === VAULT_BACKUP_STORAGE_KEY)
  ) {
    lockVault("Vault ถูกอัปเดตจากแท็บอื่น กรุณาปลดล็อกอีกครั้ง", { save: false });
  }
});

$("#today").textContent = new Intl.DateTimeFormat("th-TH", { weekday: "long", day: "numeric", month: "long", year: "numeric" }).format(new Date());
if (localStorage.getItem(THEME_KEY) === "dark") document.body.classList.add("dark");
const initialHash = location.hash.slice(1);
if (pageTitles[initialHash]) activeView = initialHash;
updateGenerator();
refreshLockScreenMode();
initializeLiquidGlassMotion();
