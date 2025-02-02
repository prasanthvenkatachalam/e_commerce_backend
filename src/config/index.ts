// src/config/index.ts

/**
 * APPLICATION CONFIGURATION MODULE
 * 
 * This module centralizes all configuration settings for the application.
 * It provides:
 * 1. Environment variable validation
 * 2. Type-safe configuration access
 * 3. Default values for optional settings
 * 4. Configuration validation
 * 
 * The configuration is structured by feature area (database, auth, etc.)
 * and uses Zod for runtime validation of all settings.
 */

import { z } from 'zod';
import type { StringValue } from 'ms';
import logger from '@/utils/logger';

/**
 * Create a configuration-specific logger
 * This helps track configuration-related issues separately
 */
const configLogger = logger.child({ module: 'config' });

/**
 * ENVIRONMENT VARIABLES SCHEMA
 * 
 * This schema defines and validates all environment variables.
 * Each variable is validated and transformed as needed.
 * Default values are provided where appropriate.
 */
const envSchema = z.object({
    /**
     * Node Environment
     * Determines various runtime behaviors:
     * - development: Enhanced logging, debug features
     * - production: Optimized for performance
     * - test: Testing-specific settings
     */
    NODE_ENV: z.enum(['development', 'production', 'test'])
        .default('development'),

    /**
     * Server Configuration
     * Port: Must be a valid port number (1-65535)
     */
    PORT: z.string()
        .regex(/^\d+$/)
        .transform(Number)
        .pipe(z.number().min(1).max(65535))
        .default('3000'),

    /**
     * Database Configuration
     * Supports both URL and individual parameter configurations
     */
    DB_HOST: z.string().default('localhost'),
    DB_PORT: z.string()
        .regex(/^\d+$/)
        .transform(Number)
        .pipe(z.number().min(1).max(65535))
        .default('5432'),
    DB_NAME: z.string().min(1),
    DB_USER: z.string().min(1),
    DB_PASSWORD: z.string().min(1),
    DATABASE_URL: z.string().url().optional(),

    /**
     * Redis Configuration
     * Required for session management and rate limiting
     */
    REDIS_URL: z.string()
        .url('Invalid Redis URL format')
        .default('redis://localhost:6379'),
    
    REDIS_PREFIX: z.string()
        .default('ecommerce:'),

    /**
     * JWT Authentication Settings
     * Configures token generation and validation
     */
    JWT_SECRET: z.string()
        .min(32, 'JWT secret must be at least 32 characters'),
    
    JWT_ACCESS_EXPIRES: z.string()
        .regex(/^(\d+(\.\d+)?(ms|s|m|h|d|w|y))$/)
        .or(z.string().regex(/^\d+$/))
        .transform((value) => {
            if (/^\d+$/.test(value)) {
                return parseInt(value, 10)
            }
            return value as StringValue;
        })
        .default('15m'),
    
    JWT_REFRESH_EXPIRES: z.string()
        .regex(/^(\d+(\.\d+)?(ms|s|m|h|d|w|y))$/)
        .or(z.string().regex(/^\d+$/))
        .transform((value) => {
            if (/^\d+$/.test(value)) {
                return parseInt(value, 10)
            }
            return value as StringValue;
        })
        .default('7d'),

    JWT_AUDIENCE: z.string().optional(),
    JWT_ISSUER: z.string().optional(),

    /**
     * Security Settings
     * Configures various security features
     */
    RATE_LIMIT: z.string()
        .regex(/^\d+$/)
        .transform(Number)
        .default('100'),  // 100 requests per window
    
    RATE_LIMIT_WINDOW: z.string()
        .regex(/^\d+$/)
        .transform(Number)
        .default('900000'),  // 15 minutes in milliseconds

    /**
     * API Configuration
     * General API settings
     */
    API_PREFIX: z.string()
        .default('/api/v1'),

    /**
     * Logging Configuration
     * Controls log level and format
     */
    LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error'])
        .default('info'),

    /**
     * Cookie Settings
     * Configures secure cookie options
     */
    COOKIE_SECRET: z.string()
        .min(32, 'Cookie secret must be at least 32 characters')
        .optional(),
    
    COOKIE_DOMAIN: z.string()
        .optional(),
});

/**
 * Parse Environment Variables
 * 
 * Safely parses and validates all environment variables.
 * Exits the process if validation fails to prevent unsafe startup.
 */
const parseEnv = () => {
    const result = envSchema.safeParse(process.env);

    if (!result.success) {
        configLogger.error(
            { errors: result.error.format() },
            'Invalid environment configuration'
        );
        process.exit(1);
    }

    return result.data;
};

// Parse environment variables
const env = parseEnv();

/**
 * MAIN CONFIGURATION OBJECT
 * 
 * Organizes all configuration settings into logical groups.
 * Makes configuration immutable using 'as const'.
 */
export const config = {
    // Environment flags
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

    // Redis configuration
    redis: {
        url: env.REDIS_URL,
        keyPrefix: {
            session: `${env.REDIS_PREFIX}session:`,
            rateLimit: `${env.REDIS_PREFIX}rate-limit:`,
            lockout: `${env.REDIS_PREFIX}lockout:`,
            token: `${env.REDIS_PREFIX}token:`
        }
    },

    // JWT configuration
    jwt: {
        secret: env.JWT_SECRET,
        accessExpiresIn: env.JWT_ACCESS_EXPIRES,
        refreshExpiresIn: env.JWT_REFRESH_EXPIRES,
        audience: env.JWT_AUDIENCE,
        issuer: env.JWT_ISSUER,
    },

    // Cookie configuration
    cookie: {
        secret: env.COOKIE_SECRET,
        domain: env.COOKIE_DOMAIN,
        secure: env.NODE_ENV === 'production',
        sameSite: 'strict' as const,
        httpOnly: true,
    },

    // Logging configuration
    logging: {
        level: env.LOG_LEVEL,
    },
} as const;

// Export config type for TypeScript
export type Config = typeof config;

/**
 * Configuration Validation
 * 
 * Performs additional validation on the configuration object.
 * Checks relationships between different settings.
 */
function validateConfig() {
    // Validate database configuration
    if (!config.db.url && (!config.db.host || !config.db.name)) {
        throw new Error(
            'Either DATABASE_URL or both DB_HOST and DB_NAME must be provided'
        );
    }

    // Validate JWT secret length
    if (config.jwt.secret.length < 32) {
        throw new Error('JWT_SECRET must be at least 32 characters long');
    }

    // Validate rate limiting
    if (config.server.rateLimit.max < 1) {
        throw new Error('Rate limit maximum must be positive');
    }

    // Validate Redis prefix
    if (!config.redis.keyPrefix.session.endsWith(':')) {
        throw new Error('Redis key prefixes must end with a colon (:)');
    }

    configLogger.info({
        env: config.env,
        apiPrefix: config.server.apiPrefix
    }, 'Configuration validated successfully');
}

// Validate configuration
validateConfig();

/**
 * USAGE EXAMPLES:
 * 
 * import { config } from '@/config';
 * 
 * // Access database configuration
 * const dbConfig = config.db;
 * 
 * // Check environment
 * if (config.isDevelopment) {
 *     // Enable development features
 * }
 * 
 * // Use Redis prefix
 * const sessionKey = `${config.redis.keyPrefix.session}${userId}`;
 */