// src/utils/logger.ts

//======================= IMPORTS =======================//
/**
 * PINO LOGGER
 * Why use Pino?
 * - Extremely fast logging framework
 * - Low overhead on your application
 * - Supports structured JSON logging
 * - Built-in pretty printing
 * - Extensible with plugins
 */
import pino from 'pino';

/**
 * ENVIRONMENT VARIABLES
 * Why use dotenv?
 * - Loads environment variables from .env file
 * - Keeps sensitive data out of code
 * - Different configs for different environments
 * - Standard practice for configuration
 */
import dotenv from 'dotenv';

//======================= ENV SETUP =======================//
/**
 * LOAD ENVIRONMENT VARIABLES
 * Why call config()?
 * - Loads variables from .env file
 * - Makes them available in process.env
 * - Should be called early in application
 * - Only needs to be done once
 */
dotenv.config();

//======================= LOGGER CONFIGURATION =======================//
/**
 * MAIN LOGGER INSTANCE
 * 
 * Configuration Breakdown:
 * 
 * 1. level: process.env.LOG_LEVEL || 'info'
 *    Why?
 *    - Configurable log level via environment
 *    - Falls back to 'info' if not set
 *    - Available levels: trace, debug, info, warn, error, fatal
 *    Example:
 *    LOG_LEVEL=debug -> Will show debug and above
 *    LOG_LEVEL=error -> Will only show error and fatal
 * 
 * 2. transport.target: 'pino-pretty'
 *    Why?
 *    - Formats logs for human readability
 *    - Adds colors and formatting
 *    - Great for development
 *    - In production, you might want to disable this for performance
 * 
 * 3. options.colorize: true
 *    Why?
 *    - Makes logs easier to read
 *    - Different colors for different log levels
 *    - Error logs in red
 *    - Warning logs in yellow
 *    - Info logs in blue
 * 
 * 4. translateTime: 'SYS:yyyy-mm-dd HH:MM:ss'
 *    Why?
 *    - Converts timestamps to readable format
 *    - Shows date and time
 *    - Consistent time format
 *    - Makes logs easier to parse
 * 
 * 5. ignore: 'pid,hostname'
 *    Why?
 *    - Removes unnecessary information
 *    - Cleaner log output
 *    - Focus on important data
 *    - pid and hostname rarely needed in development
 */
const logger = pino({
  // Log level configuration
  level: (process.env.LOG_LEVEL || 'info'),
  
  // Transport configuration for pretty printing
  transport: {
    target: 'pino-pretty',
    options: {
      colorize: true,                          // Add colors
      translateTime: 'SYS:yyyy-mm-dd HH:MM:ss',// Human-readable timestamps
      ignore: 'pid,hostname',                  // Remove noise
    },
  },
});

//======================= MODULE LOGGER FACTORY =======================//
/**
 * CREATE MODULE-SPECIFIC LOGGER
 * 
 * Purpose:
 * - Creates a child logger for specific modules
 * - Adds module context to all logs
 * - Makes debugging easier
 * - Groups related logs together
 * 
 * @param moduleName - Name of the module (e.g., 'auth', 'database', 'api')
 * @returns A child logger instance with module context
 * 
 * Why use child loggers?
 * - Adds module name to all logs automatically
 * - Maintains consistent context
 * - Makes filtering logs easier
 * - Better organization
 * 
 * Example Usage:
 * const authLogger = createModuleLogger('auth');
 * authLogger.info('User logged in');
 * // Output: {"module":"auth", "msg":"User logged in", ...}
 */
export const createModuleLogger = (moduleName: string) => {
  return logger.child({ module: moduleName });
};

/**
 * EXPORT DEFAULT LOGGER
 * Why default export?
 * - Main logger instance
 * - Can be imported directly
 * - Common pattern in Node.js
 * - Use when module context not needed
 */
export default logger;

/**
 * USAGE EXAMPLES:
 * 
 * 1. Basic Logging:
 * import logger from '@/utils/logger';
 * logger.info('Application started');
 * 
 * 2. Module-Specific Logging:
 * import { createModuleLogger } from '@/utils/logger';
 * const dbLogger = createModuleLogger('database');
 * dbLogger.error({ err }, 'Database connection failed');
 * 
 * 3. Different Log Levels:
 * logger.debug('Detailed debugging info');
 * logger.info('Normal application events');
 * logger.warn('Warning messages');
 * logger.error('Error conditions');
 * logger.fatal('System crash information');
 * 
 * 4. Structured Logging:
 * logger.info({
 *   user: 'john',
 *   action: 'login',
 *   timestamp: new Date()
 * }, 'User logged in');
 */

/**
 * PRODUCTION CONSIDERATIONS:
 * 
 * 1. Log Levels:
 *    - Use appropriate levels for different environments
 *    - Production might want 'info' and above
 *    - Development might want 'debug'
 * 
 * 2. Pretty Printing:
 *    - Disable in production for better performance
 *    - Use JSON format for log aggregation
 * 
 * 3. Sensitive Data:
 *    - Never log passwords or secrets
 *    - Sanitize user data
 *    - Be careful with error messages
 * 
 * 4. Performance:
 *    - Use appropriate log levels
 *    - Don't over-log
 *    - Consider log rotation
 *    - Monitor log size
 */