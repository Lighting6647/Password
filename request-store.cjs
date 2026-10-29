const fs = require('fs');
const path = require('path');

class PostgresRequestStore {
  constructor(pool) {
    this.pool = pool;
    this.ready = null;
  }

  ensureSchema() {
    if (!this.ready) {
      this.ready = this.pool.query(`
        CREATE TABLE IF NOT EXISTS passly_line_requests (
          singleton_id SMALLINT PRIMARY KEY CHECK (singleton_id = 1),
          requests JSONB NOT NULL DEFAULT '[]'::jsonb,
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
      'SELECT requests FROM passly_line_requests WHERE singleton_id = 1',
    );
    return Array.isArray(result.rows[0]?.requests) ? result.rows[0].requests : [];
  }

  async put(requests) {
    const normalized = Array.isArray(requests) ? requests.slice(0, 500) : [];
    await this.ensureSchema();
    await this.pool.query(
      `INSERT INTO passly_line_requests (singleton_id, requests, updated_at)
       VALUES (1, $1::jsonb, NOW())
       ON CONFLICT (singleton_id) DO UPDATE
       SET requests = EXCLUDED.requests, updated_at = NOW()`,
      [JSON.stringify(normalized)],
    );
    return normalized;
  }
}

class LocalRequestStore {
  constructor(filePath) {
    this.filePath = filePath;
  }

  async get() {
    try {
      const requests = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
      return Array.isArray(requests) ? requests : [];
    } catch {
      return [];
    }
  }

  async put(requests) {
    const normalized = Array.isArray(requests) ? requests.slice(0, 500) : [];
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    fs.writeFileSync(this.filePath, JSON.stringify(normalized, null, 2));
    return normalized;
  }
}

const os = require('os');

function createRequestStore(databaseUrl = process.env.DATABASE_URL) {
  const isServerless = Boolean(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || __dirname.startsWith('/var/task'));
  const defaultDataDir = isServerless ? path.join(os.tmpdir(), 'passly-data') : path.join(__dirname, 'data');
  const dataDir = process.env.DATA_DIR || defaultDataDir;
  if (!databaseUrl) return new LocalRequestStore(path.join(dataDir, 'requests.json'));
  const { Pool } = require('pg');
  return new PostgresRequestStore(new Pool({
    connectionString: databaseUrl,
    max: 2,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
  }));
}

module.exports = {
  LocalRequestStore,
  PostgresRequestStore,
  createRequestStore,
};
