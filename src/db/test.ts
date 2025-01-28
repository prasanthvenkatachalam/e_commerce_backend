// src/db/config.ts
import { Pool } from 'pg';
import { pino } from 'pino';

// Initialize logger
const logger = pino({
  transport: {
    target: 'pino-pretty',
    options: {
      colorize: true,
      translateTime: 'HH:MM:ss Z',
      ignore: 'pid,hostname',
    },
  },
});

// Create a new Pool instance for PostgreSQL connection
const pool = new Pool({
  user: 'ecommerce_user',     // PostgreSQL username
  host: 'localhost',          // Database host
  database: 'ecommerce',      // Database name
  password: 'your_password',  // User password
  port: 5432,                 // Default PostgreSQL port
});

// Test the connection
async function testConnection() {
  try {
    // Get a client from the pool
    const client = await pool.connect();
    
    try {
      // Execute a simple query
      const result = await client.query('SELECT NOW() as current_time');
      logger.info({ timestamp: result.rows[0].current_time }, '✅ Successfully connected to PostgreSQL');
    } finally {
      // Release the client back to the pool
      client.release();
    }
  } catch (error) {
    logger.error({ error }, '❌ Error connecting to PostgreSQL');
    process.exit(1);
  }
}

// Run the test
(async () => {
  logger.info('Starting database connection test...');
  await testConnection();
})().catch((error) => {
  logger.error({ error }, 'Unhandled error in database connection test');
  process.exit(1);
});

// Export pool for use in other files
export default pool;