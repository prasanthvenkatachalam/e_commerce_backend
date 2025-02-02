// src/config/auth.config.ts

/**
 * AUTHENTICATION CONFIGURATION
 * 
 * This module contains all configuration settings related to
 * authentication, including JWT settings, session management,
 * and security parameters.
 */

import { z } from 'zod';
import { TokenVerificationOptions } from '@/types/auth.types';

//======================= CONFIGURATION SCHEMA =======================//

/**
 * Environment variables schema for authentication
 * Validates and transforms authentication-related env vars
 */
const authEnvSchema = z.object({
  JWT_SECRET: z.string().min(32, 'JWT secret must be at least 32 characters'),
  JWT_ACCESS_EXPIRES: z.string().default('15m'),
  JWT_REFRESH_EXPIRES: z.string().default('7d'),
  JWT_AUDIENCE: z.string().optional(),
  JWT_ISSUER: z.string().optional(),
  
  REDIS_URL: z.string().url('Invalid Redis URL'),
  
  SESSION_DURATION: z.string()
    .transform(val => parseInt(val, 10))
    .default('86400'), // 24 hours in seconds
    
  PASSWORD_HASH_ROUNDS: z.string()
    .transform(val => parseInt(val, 10))
    .default('12'),
    
  RATE_LIMIT_WINDOW: z.string()
    .transform(val => parseInt(val, 10))
    .default('900000'), // 15 minutes in milliseconds
    
  RATE_LIMIT_MAX: z.string()
    .transform(val => parseInt(val, 10))
    .default('100'),
    
  LOCKOUT_DURATION: z.string()
    .transform(val => parseInt(val, 10))
    .default('900'), // 15 minutes in seconds
    
  MAX_FAILED_ATTEMPTS: z.string()
    .transform(val => parseInt(val, 10))
    .default('5')
});

//======================= CONFIGURATION OBJECT =======================//

/**
 * Parse and validate environment variables
 */
const env = authEnvSchema.parse(process.env);

/**
 * JWT verification options
 * Default configuration for token verification
 */
const jwtVerificationOptions: TokenVerificationOptions = {
  algorithms: ['HS256'],
  audience: env.JWT_AUDIENCE,
  issuer: env.JWT_ISSUER,
  complete: true
};

/**
 * Authentication configuration object
 * Contains all authentication-related settings
 */
export const authConfig = {
  jwt: {
    secret: env.JWT_SECRET,
    accessExpiresIn: env.JWT_ACCESS_EXPIRES,
    refreshExpiresIn: env.JWT_REFRESH_EXPIRES,
    audience: env.JWT_AUDIENCE,
    issuer: env.JWT_ISSUER,
    verificationOptions: jwtVerificationOptions
  },
  
  redis: {
    url: env.REDIS_URL,
    keyPrefix: {
      session: 'session:',
      tokenBlacklist: 'token:blacklist:',
      rateLimit: 'rate-limit:',
      failedAttempts: 'failed-attempts:'
    }
  },
  
  session: {
    duration: env.SESSION_DURATION,
    cleanupInterval: 3600 // Cleanup every hour
  },
  
  security: {
    passwordHashRounds: env.PASSWORD_HASH_ROUNDS,
    maxFailedAttempts: env.MAX_FAILED_ATTEMPTS,
    lockoutDuration: env.LOCKOUT_DURATION,
    rateLimit: {
      windowMs: env.RATE_LIMIT_WINDOW,
      max: env.RATE_LIMIT_MAX
    }
  },
  
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict' as const,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
} as const;

//======================= TYPE EXPORTS =======================//

/**
 * Export configuration type for type-safe access
 */
export type AuthConfig = typeof authConfig;

/**
 * Export parsed environment type
 */
export type AuthEnv = z.infer<typeof authEnvSchema>;

//======================= CONFIGURATION VALIDATION =======================//

/**
 * Validate critical configuration values
 * Throws error if configuration is invalid
 */
export function validateAuthConfig(): void {
  if (authConfig.jwt.secret.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters long');
  }

  if (authConfig.security.passwordHashRounds < 10) {
    throw new Error('PASSWORD_HASH_ROUNDS must be at least 10');
  }

  if (authConfig.security.maxFailedAttempts < 3) {
    throw new Error('MAX_FAILED_ATTEMPTS must be at least 3');
  }

  // Validate session duration is reasonable
  if (authConfig.session.duration < 300 || authConfig.session.duration > 86400) {
    throw new Error('SESSION_DURATION must be between 5 minutes and 24 hours');
  }
}

// Validate configuration on load
validateAuthConfig();

export default authConfig;