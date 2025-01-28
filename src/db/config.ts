// src/db/config.ts
import { Pool } from 'pg';
import dotenv from 'dotenv';
import logger from '@/utils/logger';

const dbLogger = logger.child({ module: 'database' });

dotenv.config();

const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  user: process.env.DB_USER || 'prasanth',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'ecommerce',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
};

const pool = new Pool(dbConfig);

pool.on('error', (err) => {
  dbLogger.error({ err }, 'Unexpected error on idle client');
  process.exit(-1);
});

export async function testConnection() {
  let client;
  try {
    client = await pool.connect();
    await client.query('SELECT NOW() as now');
    dbLogger.info('Database connection test successful');
    return true;
  } catch (error) {
    dbLogger.error({ error }, 'Database connection test failed');
    throw error;
  } finally {
    if (client) client.release();
  }
}

export default pool;