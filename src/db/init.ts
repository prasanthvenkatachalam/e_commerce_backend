// src/db/init.ts

//======================= IMPORTS =======================//
/**
 * FILE SYSTEM PROMISE FUNCTIONS
 * Why use promises version?
 * - Cleaner async/await syntax
 * - Better error handling
 * - No callback hell
 * - Modern Node.js approach
 */
import { readFile } from 'fs/promises';

/**
 * PATH MANIPULATION
 * Why use join?
 * - Cross-platform compatibility
 * - Handles path separators correctly
 * - More reliable than string concatenation
 * Example: Windows vs Unix paths
 */
import { join } from 'path';

/**
 * DATABASE POOL
 * Why import pool?
 * - Manages database connections
 * - Handles connection lifecycle
 * - Provides transaction support
 */
import pool from './config';

/**
 * LOGGING LIBRARY
 * Why use Pino?
 * - High performance
 * - Structured logging
 * - JSON output
 * - Supports pretty printing
 */
import { pino } from 'pino';

//======================= LOGGER SETUP =======================//
/**
 * LOGGER CONFIGURATION
 * Why these options?
 * - colorize: Makes logs readable in development
 * - transport: Uses pretty printer for development
 * - Structured output for production use
 */
const logger = pino({
  transport: {
    target: 'pino-pretty',   // Makes logs human-readable
    options: {
      colorize: true,        // Adds colors for better visibility
    },
  },
});

//======================= DATABASE INITIALIZATION =======================//
/**
 * DATABASE INITIALIZER
 * Purpose:
 * - Sets up initial database schema
 * - Creates required tables
 * - Runs in a transaction for safety
 * - Handles errors gracefully
 * 
 * Why use a function?
 * - Encapsulates initialization logic
 * - Better error handling
 * - Can be called programmatically
 * - Easier to test
 */
async function initializeDatabase() {
  try {
    /**
     * SCHEMA FILE READING
     * Steps:
     * 1. Get path to schema file
     * 2. Read file contents
     * 3. Parse as UTF-8 text
     * 
     * Why use __dirname?
     * - Provides absolute path
     * - Works regardless of where app is run
     * - Reliable path resolution
     */
    const schemaPath = join(__dirname, 'schema.sql');
    const schemaSQL = await readFile(schemaPath, 'utf8');

    /**
     * DATABASE CLIENT
     * Why get a client?
     * - Needed for transaction
     * - Ensures consistent connection
     * - Must be released after use
     */
    const client = await pool.connect();

    try {
      /**
       * TRANSACTION BLOCK
       * Why use transactions?
       * - All-or-nothing execution
       * - Data consistency
       * - Can rollback on error
       * - Prevents partial initialization
       */
      
      // Start transaction
      await client.query('BEGIN');

      /**
       * SCHEMA EXECUTION
       * Why execute as one statement?
       * - Maintains schema consistency
       * - Faster execution
       * - Part of transaction
       */
      await client.query(schemaSQL);

      /**
       * COMMIT TRANSACTION
       * Why commit?
       * - Saves all changes
       * - Ends transaction
       * - Makes changes permanent
       */
      await client.query('COMMIT');

      // Log success
      logger.info('✅ Database schema created successfully');
    } catch (error) {
      /**
       * ERROR HANDLING
       * Why rollback?
       * - Undoes partial changes
       * - Maintains database consistency
       * - Prevents corrupt state
       */
      await client.query('ROLLBACK');
      throw error;  // Re-throw for outer catch
    } finally {
      /**
       * CLIENT RELEASE
       * Why release?
       * - Returns client to pool
       * - Prevents connection leaks
       * - Frees up resources
       * - ALWAYS needed
       */
      client.release();
    }
  } catch (error) {
    /**
     * FATAL ERROR HANDLING
     * Why exit process?
     * - Can't continue without database
     * - Allows process manager to restart
     * - Clear error state
     */
    logger.error({ error }, '❌ Error initializing database');
    process.exit(1);  // Exit with error code
  }
}

//======================= EXECUTION =======================//
/**
 * SELF-EXECUTING ASYNC FUNCTION
 * Why use this pattern?
 * - Allows top-level await
 * - Proper error handling
 * - Clean async execution
 * - Immediate execution
 * 
 * Structure:
 * 1. Log start
 * 2. Run initialization
 * 3. Catch any unhandled errors
 */
(async () => {
  logger.info('Starting database initialization...');
  await initializeDatabase();
})().catch((error) => {
  logger.error({ error }, 'Unhandled error in database initialization');
  process.exit(1);
});

/**
 * USAGE EXAMPLE:
 * 
 * // Run directly:
 * node -r ts-node/register src/db/init.ts
 * 
 * // Or import in your app:
 * import { initializeDatabase } from './db/init';
 * 
 * // Before starting server:
 * await initializeDatabase();
 * startServer();
 */