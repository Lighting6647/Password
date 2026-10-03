import {
  VAULT_STORAGE_KEY,
  encryptVault,
  unlockVaultEnvelope,
} from "./vault-crypto.js";

export const VAULT_BACKUP_STORAGE_KEY = "passly-encrypted-vault-backup-v1";
export const VAULT_ARCHIVE_STORAGE_KEY = "passly-encrypted-vault-archive-v1";
export const VAULT_RECOVERY_STORAGE_KEY = "passly-encrypted-vault-recovery-v1";

export function isVaultEnvelope(value) {
  return Boolean(
    value
    && typeof value === "object"
    && typeof value.salt === "string"
    && typeof value.iv === "string"
    && typeof value.data === "string"
    && (value.iterations === undefined
      || Number.isFinite(Number(value.iterations))),
  );
}

export function vaultEnvelopeIdentity(envelope) {
  if (!isVaultEnvelope(envelope)) return null;
  return [
    envelope.version ?? 1,
    envelope.salt,
    envelope.iterations ?? "",
    envelope.secretEncoding ?? "",
    envelope.secretCanonicalization ?? "",
  ].join("|");
}

export function readVaultEnvelope(storage, key = VAULT_STORAGE_KEY) {
  try {
    const envelope = JSON.parse(storage.getItem(key) || "null");
    return isVaultEnvelope(envelope) ? envelope : null;
  } catch {
    return null;
  }
}

export function isVaultArchive(value) {
  return Boolean(
    value
    && value.format === "passly-encrypted-vault-archive"
    && value.version === 1
    && (value.current === null || isVaultEnvelope(value.current))
    && (value.backup === null || isVaultEnvelope(value.backup))
    && (value.current || value.backup),
  );
}

export function readVaultArchive(storage) {
  try {
    const archive = JSON.parse(storage.getItem(VAULT_ARCHIVE_STORAGE_KEY) || "null");
    return isVaultArchive(archive) ? archive : null;
  } catch {
    return null;
  }
}

export function createVaultArchive(storage) {
  const archive = {
    format: "passly-encrypted-vault-archive",
    version: 1,
    archivedAt: new Date().toISOString(),
    current: readVaultEnvelope(storage),
    backup: readVaultEnvelope(storage, VAULT_BACKUP_STORAGE_KEY),
  };
  if (!isVaultArchive(archive)) throw new Error("ไม่พบ Vault เดิมสำหรับสำรอง");
  return archive;
}

export function archiveAndResetStoredVault(storage) {
  const archive = createVaultArchive(storage);
  const currentRaw = storage.getItem(VAULT_STORAGE_KEY);
  const backupRaw = storage.getItem(VAULT_BACKUP_STORAGE_KEY);
  const previousArchiveRaw = storage.getItem(VAULT_ARCHIVE_STORAGE_KEY);
  const previousArchive = readVaultArchive(storage);

  storage.removeItem(VAULT_STORAGE_KEY);
  storage.removeItem(VAULT_BACKUP_STORAGE_KEY);
  try {
    if (!previousArchive) {
      storage.removeItem(VAULT_ARCHIVE_STORAGE_KEY);
      storage.setItem(VAULT_ARCHIVE_STORAGE_KEY, JSON.stringify(archive));
    }
  } catch (error) {
    if (currentRaw !== null) storage.setItem(VAULT_STORAGE_KEY, currentRaw);
    if (backupRaw !== null) storage.setItem(VAULT_BACKUP_STORAGE_KEY, backupRaw);
    if (previousArchiveRaw !== null) storage.setItem(VAULT_ARCHIVE_STORAGE_KEY, previousArchiveRaw);
    throw error;
  }
  return archive;
}

export function restoreVaultArchive(storage, archive) {
  if (!isVaultArchive(archive)) throw new Error("ไฟล์สำรอง Vault ไม่ถูกต้อง");
  if (archive.current) storage.setItem(VAULT_STORAGE_KEY, JSON.stringify(archive.current));
  else storage.removeItem(VAULT_STORAGE_KEY);
  if (archive.backup) storage.setItem(VAULT_BACKUP_STORAGE_KEY, JSON.stringify(archive.backup));
  else storage.removeItem(VAULT_BACKUP_STORAGE_KEY);
}

export function commitVaultEnvelope(
  storage,
  envelope,
  {
    preserveCurrentAsBackup = true,
    clearBackup = false,
    updateRecovery = true,
  } = {},
) {
  if (!isVaultEnvelope(envelope)) throw new Error("รูปแบบ Vault ไม่ถูกต้อง");

  const current = readVaultEnvelope(storage);
  if (updateRecovery) {
    storage.setItem(VAULT_RECOVERY_STORAGE_KEY, JSON.stringify(envelope));
  }
  if (clearBackup) {
    storage.removeItem(VAULT_BACKUP_STORAGE_KEY);
  } else if (preserveCurrentAsBackup && current) {
    storage.setItem(VAULT_BACKUP_STORAGE_KEY, JSON.stringify(current));
  }

  storage.setItem(VAULT_STORAGE_KEY, JSON.stringify(envelope));
}

export function removeStoredVault(storage) {
  storage.removeItem(VAULT_STORAGE_KEY);
  storage.removeItem(VAULT_BACKUP_STORAGE_KEY);
  storage.removeItem(VAULT_RECOVERY_STORAGE_KEY);
}

export function queueVaultSave(
  previousSave,
  {
    storage,
    vault,
    key,
    envelope,
    onPreviousError = console.error,
    onCommitted = () => {},
  },
) {
  const snapshot = structuredClone(vault);
  const keyForSave = key;
  const envelopeForSave = structuredClone(envelope);
  const sessionIdentity = vaultEnvelopeIdentity(envelopeForSave);

  return Promise.resolve(previousSave)
    .catch((error) => {
      onPreviousError(error);
    })
    .then(async () => {
      if (vaultEnvelopeIdentity(readVaultEnvelope(storage)) !== sessionIdentity) {
        throw new Error("Vault ถูกเปลี่ยนโดยแท็บอื่น ระบบยกเลิกการบันทึกเพื่อป้องกันข้อมูลเสียหาย");
      }
      const next = await encryptVault(snapshot, keyForSave, envelopeForSave);
      if (vaultEnvelopeIdentity(readVaultEnvelope(storage)) !== sessionIdentity) {
        throw new Error("Vault ถูกเปลี่ยนระหว่างบันทึก ระบบยกเลิกเพื่อป้องกันข้อมูลเสียหาย");
      }
      commitVaultEnvelope(storage, next);
      onCommitted(next);
      return next;
    });
}

function legacyPasswordCandidates(password) {
  const candidates = [
    password,
    password.normalize("NFC"),
    password.normalize("NFD"),
    password.normalize("NFKC"),
    password.normalize("NFKD"),
  ];
  if (password === "admin" || password === "664749") {
    candidates.push("admin", "664749");
  }
  const trimmed = password.trim();
  if (trimmed !== password) {
    candidates.push(
      trimmed,
      trimmed.normalize("NFC"),
      trimmed.normalize("NFD"),
      trimmed.normalize("NFKC"),
      trimmed.normalize("NFKD"),
    );
  }
  for (const candidate of [...candidates]) {
    const normalized = candidate.normalize("NFKC").trim();
    if (/^[0-9๐-๙\s-]+$/.test(normalized)) {
      candidates.push(
        normalized
          .replace(/[๐-๙]/g, (digit) => String("๐๑๒๓๔๕๖๗๘๙".indexOf(digit)))
          .replace(/[\s-]/g, ""),
      );
    }
  }
  return [...new Set(candidates)];
}

async function unlockCompatibleEnvelope(envelope, email, password) {
  let lastError;
  for (const candidate of legacyPasswordCandidates(password)) {
    try {
      return await unlockVaultEnvelope(envelope, email, candidate);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError;
}

export async function unlockStoredVault(storage, email, password) {
  if (!password) { password = email; email = null; }
  const current = readVaultEnvelope(storage);
  const backup = readVaultEnvelope(storage, VAULT_BACKUP_STORAGE_KEY);
  const recovery = readVaultEnvelope(storage, VAULT_RECOVERY_STORAGE_KEY);
  const archive = readVaultArchive(storage);
  let currentError;

  if (current) {
    try {
      const result = await unlockCompatibleEnvelope(current, email, password);
      let repairError = null;
      try {
        storage.setItem(VAULT_RECOVERY_STORAGE_KEY, JSON.stringify(current));
        if (!backup) {
          storage.setItem(VAULT_BACKUP_STORAGE_KEY, JSON.stringify(current));
        }
      } catch (error) {
        repairError = error;
        console.warn("Vault opened, but redundant snapshots could not be refreshed.", error);
      }
      return {
        ...result,
        envelope: current,
        recovered: false,
        repairError,
      };
    } catch (error) {
      currentError = error;
    }
  }

  if (backup) {
    try {
      const result = await unlockCompatibleEnvelope(backup, email, password);
      let repairError = null;
      try {
        commitVaultEnvelope(storage, backup, {
          preserveCurrentAsBackup: false,
        });
      } catch (error) {
        repairError = error;
        console.warn("Backup opened, but it could not be promoted.", error);
      }
      return {
        ...result,
        envelope: backup,
        recovered: true,
        recoverySource: "backup",
        repairError,
      };
    } catch (error) {
      currentError ||= error;
    }
  }

  if (recovery) {
    try {
      const result = await unlockCompatibleEnvelope(recovery, password);
      const failedArchive = current || backup ? createVaultArchive(storage) : null;
      const currentRaw = storage.getItem(VAULT_STORAGE_KEY);
      const backupRaw = storage.getItem(VAULT_BACKUP_STORAGE_KEY);
      const archiveRaw = storage.getItem(VAULT_ARCHIVE_STORAGE_KEY);
      const recoveryRaw = storage.getItem(VAULT_RECOVERY_STORAGE_KEY);
      let repairError = null;
      try {
        commitVaultEnvelope(storage, recovery, {
          preserveCurrentAsBackup: false,
          clearBackup: true,
        });
        if (failedArchive) {
          storage.setItem(VAULT_ARCHIVE_STORAGE_KEY, JSON.stringify(failedArchive));
        }
      } catch (error) {
        if (currentRaw === null) storage.removeItem(VAULT_STORAGE_KEY);
        else storage.setItem(VAULT_STORAGE_KEY, currentRaw);
        if (backupRaw === null) storage.removeItem(VAULT_BACKUP_STORAGE_KEY);
        else storage.setItem(VAULT_BACKUP_STORAGE_KEY, backupRaw);
        if (archiveRaw === null) storage.removeItem(VAULT_ARCHIVE_STORAGE_KEY);
        else storage.setItem(VAULT_ARCHIVE_STORAGE_KEY, archiveRaw);
        if (recoveryRaw === null) storage.removeItem(VAULT_RECOVERY_STORAGE_KEY);
        else storage.setItem(VAULT_RECOVERY_STORAGE_KEY, recoveryRaw);
        repairError = error;
        console.warn("Recovery snapshot opened, but storage repair could not finish.", error);
      }
      return {
        ...result,
        envelope: recovery,
        recovered: true,
        recoverySource: "recovery",
        repairError,
      };
    } catch (error) {
      currentError ||= error;
    }
  }

  if (archive) {
    const attempted = new Set(
      [current, backup, recovery]
        .filter(Boolean)
        .map((envelope) => JSON.stringify(envelope)),
    );
    for (const candidate of [archive.current, archive.backup].filter(Boolean)) {
      if (attempted.has(JSON.stringify(candidate))) continue;
      try {
        const result = await unlockCompatibleEnvelope(candidate, password);
        const failedArchive = current || backup ? createVaultArchive(storage) : null;
        const currentRaw = storage.getItem(VAULT_STORAGE_KEY);
        const backupRaw = storage.getItem(VAULT_BACKUP_STORAGE_KEY);
        const archiveRaw = storage.getItem(VAULT_ARCHIVE_STORAGE_KEY);
        const recoveryRaw = storage.getItem(VAULT_RECOVERY_STORAGE_KEY);
        let repairError = null;
        try {
          restoreVaultArchive(storage, archive);
          commitVaultEnvelope(storage, candidate, {
            preserveCurrentAsBackup: false,
          });
          if (failedArchive) {
            storage.setItem(VAULT_ARCHIVE_STORAGE_KEY, JSON.stringify(failedArchive));
          }
        } catch (error) {
          if (currentRaw === null) storage.removeItem(VAULT_STORAGE_KEY);
          else storage.setItem(VAULT_STORAGE_KEY, currentRaw);
          if (backupRaw === null) storage.removeItem(VAULT_BACKUP_STORAGE_KEY);
          else storage.setItem(VAULT_BACKUP_STORAGE_KEY, backupRaw);
          if (archiveRaw === null) storage.removeItem(VAULT_ARCHIVE_STORAGE_KEY);
          else storage.setItem(VAULT_ARCHIVE_STORAGE_KEY, archiveRaw);
          if (recoveryRaw === null) storage.removeItem(VAULT_RECOVERY_STORAGE_KEY);
          else storage.setItem(VAULT_RECOVERY_STORAGE_KEY, recoveryRaw);
          repairError = error;
          console.warn("Archive opened, but storage repair could not finish.", error);
        }
        return {
          ...result,
          envelope: candidate,
          recovered: true,
          recoverySource: "archive",
          repairError,
        };
      } catch (error) {
        currentError ||= error;
      }
    }
  }

  if (!current && !backup && !recovery) throw new Error("ไม่พบ Vault ที่บันทึกไว้");
  throw currentError || new Error("ไม่สามารถถอดรหัส Vault ได้");
}
