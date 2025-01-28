// src/db/config.ts
import { Pool, PoolConfig,PoolClient } from 'pg';
import { config } from '@/config';
import logger from '@/utils/logger';

const dbLogger = logger.child({ module: 'database' });

const poolConfig: PoolConfig = {
  host: config.db.host,
  port: config.db.port,
  user: config.db.user,
  password: config.db.password,
  database: config.db.name,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  application_name: 'ecommerce_api', // Helps identify connections in pg_stat_activity
  statement_timeout: 10000, // 10s query timeout
  query_timeout: 10000,     // 10s network timeout
  ssl: config.env === 'production' ? { rejectUnauthorized: false } : undefined,
};

const pool = new Pool(poolConfig);

// Automatically close idle clients
pool.on('connect', (client) => {
  dbLogger.debug('New client connected to database');
  client.on('error', (err) => {
    dbLogger.error({ err }, 'Database client error');
  });
});

pool.on('error', (err) => {
  dbLogger.error({ err }, 'Unexpected error on idle client');
});

pool.on('remove', () => {
  dbLogger.debug('Client removed from pool');
});

export async function testConnection(): Promise<boolean> {
  let client;
  try {
    client = await pool.connect();
    const result = await client.query('SELECT version(), NOW() as now');
    dbLogger.info({
      version: result.rows[0].version,
      timestamp: result.rows[0].now
    }, 'Database connection test successful');
    return true;
  } catch (error) {
    dbLogger.error({ error }, 'Database connection test failed');
    throw error;
  } finally {
    if (client) {
      client.release();
    }
  }
}

// Helper function for transactions
export async function withTransaction<T>(
  callback: (client: PoolClient) => Promise<T>
): Promise<T> {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

export default pool;