// src/config/index.ts

//======================= IMPORTS =======================//
/**
 * ZOD VALIDATION LIBRARY
 * Why use Zod?
 * - Strong TypeScript integration
 * - Runtime validation
 * - Automatic type inference
 * - Transform values during validation
 * 
 * Example:
 * z.string().email() validates email format
 */
import { z } from 'zod';

/**
 * CUSTOM LOGGER
 * Why have a config-specific logger?
 * - Track configuration issues
 * - Debug environment problems
 * - Monitor config changes
 */
import logger from '@/utils/logger';

/**
 * CREATE CONFIG LOGGER
 * Why create a child logger?
 * - Adds 'config' context to all logs
 * - Makes debugging easier
 * - Groups all config-related logs
 */
const configLogger = logger.child({ module: 'config' });

//======================= ENVIRONMENT SCHEMA =======================//
/**
 * ENVIRONMENT VARIABLES SCHEMA
 * Why validate environment variables?
 * - Catch misconfigurations early
 * - Ensure required values exist
 * - Transform values to correct types
 * - Provide sensible defaults
 */
const envSchema = z.object({
  /**
   * NODE ENVIRONMENT
   * Purpose: Determines application behavior
   * Options: 
   * - development: Local development
   * - production: Live environment
   * - test: Testing environment
   */
  NODE_ENV: z.enum(['development', 'production', 'test'])
    .default('development'),
  
  /**
   * SERVER PORT
   * Validation:
   * - Must be a number
   * - Between 1 and 65535 (valid port range)
   * - Defaults to 3000
   * 
   * Example: PORT=8080
   */
  PORT: z.string()
    .regex(/^\d+$/)              // Must be numeric string
    .transform(Number)           // Convert to number
    .pipe(z.number().min(1).max(65535))  // Validate port range
    .default('3000'),
  
  /**
   * DATABASE CONFIGURATION
   * Why these fields?
   * - Required for PostgreSQL connection
   * - Supports both URL and individual params
   * - Ensures secure storage of credentials
   */
  DB_HOST: z.string().default('localhost'),
  DB_PORT: z.string()
    .regex(/^\d+$/)
    .transform(Number)
    .pipe(z.number().min(1).max(65535))
    .default('5432'),
  DB_NAME: z.string().min(1),    // Database name required
  DB_USER: z.string().min(1),    // Username required
  DB_PASSWORD: z.string().min(1), // Password required
  DATABASE_URL: z.string().url().optional(), // Optional connection string

  /**
   * JWT AUTHENTICATION
   * Why these settings?
   * - Secure token generation
   * - Configurable expiration times
   * - Separate refresh token handling
   */
  JWT_SECRET: z.string().min(32),  // Minimum 32 chars for security
  JWT_ACCESS_EXPIRES: z.string().default('15m'),  // Short-lived access tokens
  JWT_REFRESH_EXPIRES: z.string().default('7d'),  // Longer refresh tokens
  
  /**
   * REDIS CONFIGURATION
   * Why optional?
   * - Not always needed
   * - Used for caching/sessions
   * - Can be added later
   */
  REDIS_URL: z.string().url().optional(),
  
  /**
   * API CONFIGURATION
   * Purpose:
   * - Version control
   * - Rate limiting
   * - API organization
   */
  API_PREFIX: z.string().default('/api/v1'),
  RATE_LIMIT: z.string()
    .regex(/^\d+$/)
    .transform(Number)
    .default('100'),           // 100 requests per window
  RATE_LIMIT_WINDOW: z.string()
    .regex(/^\d+$/)
    .transform(Number)
    .default('900000'),        // 15 minutes in milliseconds
    
  /**
   * LOGGING CONFIGURATION
   * Levels:
   * - debug: Detailed debugging
   * - info: General information
   * - warn: Warning conditions
   * - error: Error conditions
   */
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error'])
    .default('info'),
});

//======================= CONFIGURATION PARSING =======================//
/**
 * PARSE ENVIRONMENT VARIABLES
 * Why use safeParse?
 * - Doesn't throw on invalid input
 * - Returns success/error object
 * - Better error handling
 */
const parseEnv = () => {
  const result = envSchema.safeParse(process.env);
  
  if (!result.success) {
    // Log validation errors and exit
    configLogger.error(
      { errors: result.error.format() },
      'Invalid environment variables'
    );
    process.exit(1);  // Exit if config is invalid
  }
  
  return result.data;
};

// Parse environment variables
const env = parseEnv();

//======================= CONFIG OBJECT =======================//
/**
 * CONFIGURATION OBJECT
 * Why structured this way?
 * - Organized by feature
 * - Easy to access
 * - Type-safe
 * - Immutable (as const)
 */
export const config = {
  // Environment flags for conditional logic
  env: env.NODE_ENV,
  isProduction: env.NODE_ENV === 'production',
  isDevelopment: env.NODE_ENV === 'development',
  isTest: env.NODE_ENV === 'test',
  
  // Server configuration
  server: {
    port: env.PORT,
    apiPrefix: env.API_PREFIX,
    rateLimit: {
      max: env.RATE_LIMIT,
      windowMs: env.RATE_LIMIT_WINDOW,
    },
  },
  
  // Database configuration
  db: {
    host: env.DB_HOST,
    port: env.DB_PORT,
    name: env.DB_NAME,
    user: env.DB_USER,
    password: env.DB_PASSWORD,
    url: env.DATABASE_URL,
  },
  
  // JWT configuration
  jwt: {
    secret: env.JWT_SECRET,
    accessExpiresIn: env.JWT_ACCESS_EXPIRES,
    refreshExpiresIn: env.JWT_REFRESH_EXPIRES,
  },
  
  // Redis configuration
  redis: {
    url: env.REDIS_URL,
  },
  
  // Logging configuration
  logging: {
    level: env.LOG_LEVEL,
  },
} as const;  // Make config immutable

// Export config type for TypeScript
export type Config = typeof config;

//======================= CONFIG VALIDATION =======================//
/**
 * VALIDATE CONFIGURATION
 * Why additional validation?
 * - Check related fields together
 * - Validate business rules
 * - Ensure security requirements
 */
function validateConfig() {
  // Check database configuration
  if (!config.db.url && (!config.db.host || !config.db.name)) {
    throw new Error('Either DATABASE_URL or DB_HOST and DB_NAME must be provided');
  }

  // Validate JWT secret length
  if (config.jwt.secret.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters long');
  }

  // Log successful configuration
  configLogger.info({ 
    env: config.env,
    apiPrefix: config.server.apiPrefix 
  }, 'Configuration loaded successfully');
}

// Run validation
validateConfig();

/**
 * USAGE EXAMPLE:
 * 
 * import { config } from '@/config';
 * 
 * // Access configuration values
 * const port = config.server.port;
 * const isDev = config.isDevelopment;
 * const dbConfig = config.db;
 * 
 * // Type-safe access
 * const jwtSecret: string = config.jwt.secret;
 */