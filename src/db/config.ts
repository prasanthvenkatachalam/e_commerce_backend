// src/db/config.ts

//======================= IMPORTS =======================//
/**
 * POSTGRESQL CLIENT IMPORTS
 * Pool: Manages database connections
 * PoolConfig: Type for pool configuration
 * PoolClient: Individual database connection
 * 
 * Why use a connection pool?
 * - Reuses connections instead of creating new ones
 * - Improves performance
 * - Manages connection lifecycle
 * - Handles connection limits
 */
import { Pool, PoolConfig, PoolClient } from 'pg';

/**
 * APPLICATION CONFIG
 * Why import?
 * - Database credentials
 * - Environment-specific settings
 * - Consistent configuration across app
 */
import { config } from '@/config';

/**
 * CUSTOM LOGGER
 * Why use a custom logger?
 * - Structured logging
 * - Better error tracking
 * - Environment-specific logging levels
 */
import logger from '@/utils/logger';

/**
 * DATABASE-SPECIFIC LOGGER
 * Why create a child logger?
 * - Groups all database-related logs
 * - Easier to filter and debug
 * - Adds database context automatically
 */
const dbLogger = logger.child({ module: 'database' });

//======================= POOL CONFIGURATION =======================//
/**
 * DATABASE POOL CONFIGURATION
 * This defines how the connection pool behaves and its limits
 */
const poolConfig: PoolConfig = {
  // Basic connection settings
  host: config.db.host,         // Database server address
  port: config.db.port,         // PostgreSQL port (default: 5432)
  user: config.db.user,         // Database user
  password: config.db.password, // User password
  database: config.db.name,     // Database name

  // Pool settings
  max: 20,                      // Maximum number of clients in pool
                               // Why 20? Balances resource usage with concurrent connections

  // Timeout settings
  idleTimeoutMillis: 30000,    // How long a client can be idle (30 seconds)
                               // Helps clean up unused connections
  
  connectionTimeoutMillis: 2000, // How long to wait for connection (2 seconds)
                                // Prevents hanging on connection issues

  // Application settings
  application_name: 'ecommerce_api',  // Identifies your app in database logs
                                     // Helpful for monitoring and debugging

  // Query timeouts
  statement_timeout: 10000,    // Maximum query execution time (10 seconds)
                              // Prevents long-running queries from blocking
  
  query_timeout: 10000,       // Network timeout for queries (10 seconds)
                             // Handles network issues gracefully

  // SSL Configuration
  ssl: config.env === 'production' 
    ? { rejectUnauthorized: false }  // Required for some cloud providers
    : undefined,                      // No SSL in development
};

//======================= CONNECTION POOL =======================//
/**
 * CREATE CONNECTION POOL
 * This is the main database interface that your app will use
 * It manages all database connections automatically
 */
const pool = new Pool(poolConfig);

//======================= EVENT HANDLERS =======================//
/**
 * CONNECT EVENT HANDLER
 * When does this fire?
 * - Every time a new client connects to the database
 * - Good place to setup client-specific error handling
 */
pool.on('connect', (client) => {
  dbLogger.debug('New client connected to database');
  
  // Setup error handling for this client
  client.on('error', (err) => {
    dbLogger.error({ err }, 'Database client error');
  });
});

/**
 * POOL ERROR HANDLER
 * When does this fire?
 * - Unexpected errors on idle clients
 * - Pool-level issues
 * - Connection problems
 */
pool.on('error', (err) => {
  dbLogger.error({ err }, 'Unexpected error on idle client');
});

/**
 * REMOVE EVENT HANDLER
 * When does this fire?
 * - Client is removed from pool
 * - Connection is closed
 * - Pool is cleaning up
 */
pool.on('remove', () => {
  dbLogger.debug('Client removed from pool');
});

//======================= UTILITY FUNCTIONS =======================//
/**
 * TEST DATABASE CONNECTION
 * Why is this useful?
 * - Verifies database is accessible
 * - Checks credentials work
 * - Gets database version info
 * - Good for health checks
 * 
 * Returns: Promise<boolean>
 * Throws: If connection fails
 */
export async function testConnection(): Promise<boolean> {
  let client;
  try {
    // Get a client from the pool
    client = await pool.connect();
    
    // Run test query
    const result = await client.query('SELECT version(), NOW() as now');
    
    // Log successful connection
    dbLogger.info({
      version: result.rows[0].version,
      timestamp: result.rows[0].now
    }, 'Database connection test successful');
    
    return true;
  } catch (error) {
    // Log and rethrow connection errors
    dbLogger.error({ error }, 'Database connection test failed');
    throw error;
  } finally {
    // Always release the client back to the pool
    if (client) {
      client.release();
    }
  }
}

/**
 * TRANSACTION HELPER
 * Why use this?
 * - Simplifies transaction management
 * - Ensures proper cleanup
 * - Handles rollback automatically
 * - Prevents connection leaks
 * 
 * How to use:
 * await withTransaction(async (client) => {
 *   await client.query('INSERT INTO users...');
 *   await client.query('UPDATE accounts...');
 * });
 */
export async function withTransaction<T>(
  callback: (client: PoolClient) => Promise<T>
): Promise<T> {
  // Get client from pool
  const client = await pool.connect();
  
  try {
    // Start transaction
    await client.query('BEGIN');
    
    // Run the callback with transaction client
    const result = await callback(client);
    
    // Commit if successful
    await client.query('COMMIT');
    return result;
  } catch (error) {
    // Rollback on error
    await client.query('ROLLBACK');
    throw error;
  } finally {
    // Always release client
    client.release();
  }
}

/**
 * EXPORT POOL
 * Why default export?
 * - Main database interface
 * - Most commonly used export
 * - Follows Node.js conventions
 * 
 * Usage:
 * import pool from './db/config';
 * const result = await pool.query('SELECT * FROM users');
 */
export default pool;