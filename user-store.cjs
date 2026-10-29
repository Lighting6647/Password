const fs = require('fs');
const path = require('path');

class PostgresUserStore {
  constructor(pool) {
    this.pool = pool;
    this.ready = null;
  }

  ensureSchema() {
    if (!this.ready) {
      this.ready = this.pool.query(`
        CREATE TABLE IF NOT EXISTS passly_users (
          singleton_id SMALLINT PRIMARY KEY CHECK (singleton_id = 1),
          users JSONB NOT NULL DEFAULT '[]'::jsonb,
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
      'SELECT users FROM passly_users WHERE singleton_id = 1',
    );
    return Array.isArray(result.rows[0]?.users) ? result.rows[0].users : [];
  }

  async put(users) {
    const normalized = Array.isArray(users) ? users : [];
    await this.ensureSchema();
    await this.pool.query(
      `INSERT INTO passly_users (singleton_id, users, updated_at)
       VALUES (1, $1::jsonb, NOW())
       ON CONFLICT (singleton_id) DO UPDATE
       SET users = EXCLUDED.users, updated_at = NOW()`,
      [JSON.stringify(normalized)],
    );
    return normalized;
  }
}

class LocalUserStore {
  constructor(filePath) {
    this.filePath = filePath;
  }

  async get() {
    try {
      const users = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
      return Array.isArray(users) ? users : [];
    } catch {
      return [];
    }
  }

  async put(users) {
    const normalized = Array.isArray(users) ? users : [];
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    fs.writeFileSync(this.filePath, JSON.stringify(normalized, null, 2));
    return normalized;
  }
}

const os = require('os');

function createUserStore(databaseUrl = process.env.DATABASE_URL) {
  const isServerless = Boolean(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || __dirname.startsWith('/var/task'));
  const defaultDataDir = isServerless ? path.join(os.tmpdir(), 'passly-data') : path.join(__dirname, 'data');
  const dataDir = process.env.DATA_DIR || defaultDataDir;
  if (!databaseUrl) return new LocalUserStore(path.join(dataDir, 'users.json'));
  const { Pool } = require('pg');
  return new PostgresUserStore(new Pool({
    connectionString: databaseUrl,
    max: 2,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
  }));
}

module.exports = {
  LocalUserStore,
  PostgresUserStore,
  createUserStore,
};
