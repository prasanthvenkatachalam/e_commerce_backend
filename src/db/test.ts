// src/db/config.ts

//======================= IMPORTS =======================//
/**
 * POSTGRESQL CLIENT
 * Why use Pool?
 * - Manages multiple database connections
 * - Reuses connections instead of creating new ones
 * - Better performance than single connections
 * - Handles connection limits automatically
 */
import { Pool } from 'pg';

/**
 * LOGGING LIBRARY
 * Why use Pino?
 * - High-performance logging
 * - Structured JSON output
 * - Support for pretty printing
 * - Better than console.log
 */
import { pino } from 'pino';

//======================= LOGGER SETUP =======================//
/**
 * LOGGER CONFIGURATION
 * Why these options?
 * 
 * transport.target: 'pino-pretty'
 * - Makes logs readable in development
 * - Formats JSON logs into human-friendly format
 * 
 * options.colorize: true
 * - Adds colors to different log levels
 * - Makes logs easier to scan visually
 * 
 * translateTime: 'HH:MM:ss Z'
 * - Formats timestamps consistently
 * - Includes timezone information
 * 
 * ignore: 'pid,hostname'
 * - Removes unnecessary information
 * - Makes logs cleaner
 */
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

//======================= DATABASE CONFIGURATION =======================//
/**
 * DATABASE POOL CONFIGURATION
 * Why these settings?
 * 
 * user: 'ecommerce_user'
 * - Dedicated database user for the application
 * - Better than using default postgres user
 * - Should have limited permissions
 * 
 * host: 'localhost'
 * - Local development setup
 * - Would be different in production
 * - Could be environment variable
 * 
 * database: 'ecommerce'
 * - Specific database for the application
 * - Isolated from other applications
 * 
 * port: 5432
 * - Default PostgreSQL port
 * - Can be changed if needed
 * 
 * SECURITY NOTE:
 * In production:
 * - Never hardcode credentials
 * - Use environment variables
 * - Use connection strings
 * - Enable SSL if possible
 */
const pool = new Pool({
  user: 'ecommerce_user',     // Database username
  host: 'localhost',          // Database server location
  database: 'ecommerce',      // Database name
  password: 'your_password',  // Database password (use env vars!)
  port: 5432,                 // PostgreSQL port number
});

//======================= CONNECTION TESTING =======================//
/**
 * DATABASE CONNECTION TEST
 * Why test connection?
 * - Verifies database is accessible
 * - Checks credentials are correct
 * - Ensures pool is working
 * - Early error detection
 * 
 * Steps:
 * 1. Get client from pool
 * 2. Run test query
 * 3. Log success/failure
 * 4. Release client
 */
async function testConnection() {
  try {
    /**
     * GET CLIENT
     * Why use pool.connect()?
     * - Gets a client from the connection pool
     * - Automatic connection management
     * - Must be released when done
     */
    const client = await pool.connect();
    
    try {
      /**
       * TEST QUERY
       * Why SELECT NOW()?
       * - Simple, fast query
       * - Verifies database is responding
       * - Returns current timestamp
       * - Shows database time
       */
      const result = await client.query('SELECT NOW() as current_time');
      
      // Log successful connection with timestamp
      logger.info(
        { timestamp: result.rows[0].current_time },
        '✅ Successfully connected to PostgreSQL'
      );
    } finally {
      /**
       * RELEASE CLIENT
       * Why release?
       * - Returns client to pool
       * - Prevents connection leaks
       * - Required for proper pool management
       * - Always in finally block
       */
      client.release();
    }
  } catch (error) {
    /**
     * ERROR HANDLING
     * Why exit process?
     * - Can't continue without database
     * - Allows process manager to restart
     * - Clear error indication
     */
    logger.error({ error }, '❌ Error connecting to PostgreSQL');
    process.exit(1);  // Exit with error code
  }
}

//======================= IMMEDIATE EXECUTION =======================//
/**
 * SELF-EXECUTING ASYNC FUNCTION
 * Why use this pattern?
 * - Runs test immediately
 * - Handles promises properly
 * - Provides clean error handling
 * - Supports top-level await
 */
(async () => {
  logger.info('Starting database connection test...');
  await testConnection();
})().catch((error) => {
  logger.error({ error }, 'Unhandled error in database connection test');
  process.exit(1);
});

/**
 * POOL EXPORT
 * Why export pool?
 * - Single connection pool for app
 * - Can be imported by other modules
 * - Prevents multiple pools
 * - Centralized database access
 * 
 * Usage example:
 * import pool from './db/config';
 * const result = await pool.query('SELECT * FROM users');
 */
export default pool;

/**
 * PRODUCTION CONSIDERATIONS:
 * 1. Use environment variables for:
 *    - Database credentials
 *    - Host information
 *    - Port numbers
 * 
 * 2. Add SSL configuration:
 *    ssl: {
 *      rejectUnauthorized: false,
 *      ca: fs.readFileSync('path/to/ca.crt').toString()
 *    }
 * 
 * 3. Add pool settings:
 *    - max: Maximum connections
 *    - idleTimeoutMillis: Connection timeout
 *    - connectionTimeoutMillis: Connection retry timeout
 * 
 * 4. Add error handlers:
 *    pool.on('error', (err) => {
 *      logger.error('Unexpected error on idle client', err);
 *    });
 */