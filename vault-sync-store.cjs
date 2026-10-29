const fs = require('fs');
const path = require('path');
const MAX_ENVELOPE_BYTES = 5_000_000;

function isEncryptedVaultEnvelope(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const allowedFields = new Set([
    'version', 'algorithm', 'kdf', 'iterations', 'salt',
    'passwordNormalization', 'secretCanonicalization', 'secretEncoding',
    'iv', 'data', 'updatedAt', 'keyrings', 'keyrings', 'keyrings', 'keyrings',
  ]);
  if (Object.keys(value).some((key) => !allowedFields.has(key))) return false;
  if (typeof value.salt !== 'string' || value.salt.length < 8 || value.salt.length > 512) return false;
  if (typeof value.iv !== 'string' || value.iv.length < 8 || value.iv.length > 512) return false;
  if (typeof value.data !== 'string' || value.data.length < 16) return false;
  if (value.data.length > MAX_ENVELOPE_BYTES) return false;
  if (value.algorithm !== undefined && value.algorithm !== 'AES-GCM-256') return false;
  if (value.kdf !== undefined && value.kdf !== 'PBKDF2-SHA256') return false;
  if (value.updatedAt !== undefined && Number.isNaN(Date.parse(value.updatedAt))) return false;
  const iterations = Number(value.iterations);
  return value.iterations === undefined
    || (Number.isSafeInteger(iterations) && iterations >= 100_000 && iterations <= 10_000_000);
}

class VaultConflictError extends Error {
  constructor(currentRevision) {
    super('Vault บน Server มีข้อมูลรุ่นใหม่กว่า กรุณาโหลดข้อมูลล่าสุดก่อนบันทึกอีกครั้ง');
    this.name = 'VaultConflictError';
    this.code = 'vault_conflict';
    this.currentRevision = currentRevision;
  }
}

class PostgresVaultStore {
  constructor(pool) {
    this.pool = pool;
    this.ready = null;
  }

  ensureSchema() {
    if (!this.ready) {
      this.ready = this.pool.query(`
        CREATE TABLE IF NOT EXISTS passly_encrypted_vault (
          singleton_id SMALLINT PRIMARY KEY CHECK (singleton_id = 1),
          envelope JSONB NOT NULL,
          revision BIGINT NOT NULL CHECK (revision > 0),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `).catch((error) => {
        this.ready = null;
        throw error;
      });
    }
    return this.ready;
  }

  async get() {
    await this.ensureSchema();
    const result = await this.pool.query(
      'SELECT envelope, revision, updated_at FROM passly_encrypted_vault WHERE singleton_id = 1',
    );
    if (!result.rows[0]) return null;
    return {
      envelope: result.rows[0].envelope,
      revision: Number(result.rows[0].revision),
      updatedAt: new Date(result.rows[0].updated_at).toISOString(),
    };
  }

  async put(envelope, baseRevision) {
    if (!isEncryptedVaultEnvelope(envelope)) throw new Error('รูปแบบ Encrypted Vault ไม่ถูกต้อง');
    if (!Number.isSafeInteger(baseRevision) || baseRevision < 0) {
      throw new Error('baseRevision ไม่ถูกต้อง');
    }

    await this.ensureSchema();
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const current = await client.query(
        'SELECT revision FROM passly_encrypted_vault WHERE singleton_id = 1 FOR UPDATE',
      );
      const currentRevision = current.rows[0] ? Number(current.rows[0].revision) : 0;
      if (currentRevision !== baseRevision) throw new VaultConflictError(currentRevision);

      const nextRevision = currentRevision + 1;
      const saved = currentRevision === 0
        ? await client.query(
          `INSERT INTO passly_encrypted_vault (singleton_id, envelope, revision, updated_at)
           VALUES (1, $1::jsonb, $2, NOW())
           RETURNING revision, updated_at`,
          [JSON.stringify(envelope), nextRevision],
        )
        : await client.query(
          `UPDATE passly_encrypted_vault
           SET envelope = $1::jsonb, revision = $2, updated_at = NOW()
           WHERE singleton_id = 1
           RETURNING revision, updated_at`,
          [JSON.stringify(envelope), nextRevision],
        );
      await client.query('COMMIT');
      return {
        revision: Number(saved.rows[0].revision),
        updatedAt: new Date(saved.rows[0].updated_at).toISOString(),
      };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async close() {
    await this.pool.end();
  }
}

class LocalVaultStore {
  constructor(filePath) {
    this.filePath = filePath;
  }
  async get() {
    try {
      return JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
    } catch (e) {
      return null;
    }
  }
  async put(envelope, baseRevision) {
    if (!isEncryptedVaultEnvelope(envelope)) throw new Error('รูปแบบ Encrypted Vault ไม่ถูกต้อง');
    if (!Number.isSafeInteger(baseRevision) || baseRevision < 0) {
      throw new Error('baseRevision ไม่ถูกต้อง');
    }
    const current = await this.get();
    const currentRevision = current ? current.revision : 0;
    if (currentRevision !== baseRevision) throw new VaultConflictError(currentRevision);
    const nextRevision = currentRevision + 1;
    const nextState = {
      envelope,
      revision: nextRevision,
      updatedAt: new Date().toISOString(),
    };
    fs.writeFileSync(this.filePath, JSON.stringify(nextState));
    return { revision: nextRevision, updatedAt: nextState.updatedAt };
  }
  async close() {}
}

const os = require('os');

function resolveDefaultDataDir() {
  if (process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || __dirname.startsWith('/var/task')) {
    return path.join(os.tmpdir(), 'passly-data');
  }
  return path.join(__dirname, 'data');
}

function createVaultStore(databaseUrl = process.env.DATABASE_URL) {
  if (!databaseUrl) {
    const dataDir = process.env.DATA_DIR || resolveDefaultDataDir();
    try {
      if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    } catch {}
    return new LocalVaultStore(path.join(dataDir, 'vault.json'));
  }
  const { Pool } = require('pg');
  return new PostgresVaultStore(new Pool({
    connectionString: databaseUrl,
    max: 5,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
  }));
}

module.exports = {
  MAX_ENVELOPE_BYTES,
  PostgresVaultStore,
  VaultConflictError,
  createVaultStore,
  isEncryptedVaultEnvelope,
};
