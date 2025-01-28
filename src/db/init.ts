// src/db/init.ts
import { readFile } from 'fs/promises';
import { join } from 'path';
import pool from './config';
import { pino } from 'pino';

const logger = pino({
  transport: {
    target: 'pino-pretty',
    options: {
      colorize: true,
    },
  },
});

async function initializeDatabase() {
  try {
    // Read the schema file
    const schemaPath = join(__dirname, 'schema.sql');
    const schemaSQL = await readFile(schemaPath, 'utf8');

    // Get a client from the pool
    const client = await pool.connect();

    try {
      // Start a transaction
      await client.query('BEGIN');

      // Execute the schema SQL
      await client.query(schemaSQL);

      // Commit the transaction
      await client.query('COMMIT');

      logger.info('✅ Database schema created successfully');
    } catch (error) {
      // If there's an error, roll back the transaction
      await client.query('ROLLBACK');
      throw error;
    } finally {
      // Release the client back to the pool
      client.release();
    }
  } catch (error) {
    logger.error({ error }, '❌ Error initializing database');
    process.exit(1);
  }
}

// Run the initialization
(async () => {
  logger.info('Starting database initialization...');
  await initializeDatabase();
})().catch((error) => {
  logger.error({ error }, 'Unhandled error in database initialization');
  process.exit(1);
});