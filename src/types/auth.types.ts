// src/types/auth.types.ts

/**
 * AUTHENTICATION TYPES MODULE
 * 
 * This module provides comprehensive type definitions for the authentication system.
 * It includes user types, roles, permissions, and related interfaces.
 * 
 * Key components:
 * - User and role enumerations
 * - Authentication interfaces
 * - Error handling types
 * - Session management types
 * - JWT token types
 */

import { JwtPayload, Algorithm } from 'jsonwebtoken';
import { Request, Response } from 'express';

//======================= USER TYPES =======================//

/**
 * User Categories
 * Defines the fundamental types of users in the system
 * Each type has different base permissions and access levels
 */
export const USER_TYPES = {
    ADMIN: 'admin',         // System administrators
    CUSTOMER: 'customer',   // Regular users/buyers
    VENDOR: 'vendor'        // Sellers/merchants
} as const;

export type UserType = typeof USER_TYPES[keyof typeof USER_TYPES];

/**
 * Role Permissions
 * Defines specific operational roles within the system
 * Used for fine-grained access control
 */
export const ROLE_TYPES = {
    SUPER_ADMIN: 'super_admin',  // Highest level access
    ADMIN: 'admin',              // General administrative access
    SUPPORT: 'support',          // Customer service roles
    INVENTORY: 'inventory',      // Stock management
    ORDERS: 'orders'            // Order processing
} as const;

export type RoleType = typeof ROLE_TYPES[keyof typeof ROLE_TYPES];

/**
 * User Account Status
 * Defines possible states of a user account
 */
export const USER_STATUS = {
    ACTIVE: 'active',         // Normal functioning account
    INACTIVE: 'inactive',     // Dormant account
    SUSPENDED: 'suspended'    // Temporarily disabled account
} as const;

export type UserStatus = typeof USER_STATUS[keyof typeof USER_STATUS];

//======================= DATABASE TYPES =======================//

/**
 * Database User Record
 * Represents a user entry in the database
 */
export interface DatabaseUser {
    id: string;
    email: string;
    password_hash: string;
    user_type: UserType;
    role_type: RoleType;
    status: UserStatus;
    failed_login_attempts: number;
    last_failed_login: Date | null;
    last_login: Date | null;
}

//======================= AUTHENTICATION TYPES =======================//

/**
 * Login Request Credentials
 * Expected structure when users attempt to log in
 */
export interface LoginCredentials {
    email: string;
    password: string;
    deviceInfo?: {
        ipAddress?: string;
        userAgent?: string;
    };
}

/**
 * Successful Login Response
 * Data structure returned after successful authentication
 */
export interface LoginResponse {
    accessToken: string;
    user: {
        id: string;
        email: string;
        userType: UserType;
        roleType: RoleType;
    };
    sessionId: string;
}

//======================= SESSION TYPES =======================//

/**
 * Session Information
 * Tracks user session details
 */
export interface SessionInfo {
    id: string;
    userId: string;
    token: string;
    userAgent?: string;
    ipAddress?: string;
    expiresAt: Date;
    createdAt: Date;
    lastActivityAt?: Date;
}

/**
 * Session Creation Parameters
 * Required data for creating new sessions
 */
export interface CreateSessionParams {
    userId: string;
    token: string;
    deviceInfo?: {
        ipAddress?: string;
        userAgent?: string;
    };
}

//======================= TOKEN TYPES =======================//

/**
 * JWT Token Payload
 * Extended JWT payload with custom claims
 */
export interface TokenPayload extends JwtPayload {
    userId: string;
    userType: UserType;
    roleType: RoleType;
    jti?: string;
}

/**
 * Token Verification Options
 * Configuration for token validation
 */
export interface TokenVerificationOptions {
    ignoreExpiration?: boolean;
    audience?: string | string[];
    issuer?: string;
    algorithms?: Algorithm[];
    complete?: boolean;
}

//======================= ERROR TYPES =======================//

/**
 * Authentication Error Types
 * Defines all possible authentication failure scenarios
 */
export const AUTH_ERROR_TYPES = {
    INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
    ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
    TOKEN_EXPIRED: 'TOKEN_EXPIRED',
    TOKEN_INVALID: 'TOKEN_INVALID',
    SESSION_EXPIRED: 'SESSION_EXPIRED',
    UNAUTHORIZED: 'UNAUTHORIZED',
    RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED'
} as const;

export type AuthErrorType = typeof AUTH_ERROR_TYPES[keyof typeof AUTH_ERROR_TYPES];

/**
 * Authentication Error Structure
 * Standard format for authentication-related errors
 */
export interface AuthError extends Error {
    type: AuthErrorType;
    statusCode: number;
    context?: Record<string, unknown>;
}

/**
 * Creates a standardized authentication error
 */
export function createAuthError(
    type: AuthErrorType,
    message: string,
    statusCode: number,
    context?: Record<string, unknown>
): AuthError {
    const error = new Error(message) as AuthError;
    error.type = type;
    error.statusCode = statusCode;
    error.context = context;
    return error;
}

//======================= RATE LIMITING TYPES =======================//

/**
 * Rate Limiting Information
 * Tracks request limits and usage
 */
export interface RateLimitInfo {
    limit: number;
    remaining: number;
    reset: number;
    key: string;
}

/**
 * Rate Limiting Configuration
 * Settings for request rate limiting
 */
export interface RateLimitOptions {
    windowMs: number;
    max: number;
    keyGenerator?: (req: Request) => string;
    handler?: (req: Request, res: Response) => void;
    skipSuccessfulRequests?: boolean;
}

//======================= CONSTANTS =======================//

/**
 * Authentication Constants
 * System-wide authentication settings
 */
export const AUTH_CONSTANTS = {
    MAX_LOGIN_ATTEMPTS: 5,
    LOCKOUT_DURATION: 1800,    // 30 minutes in seconds
    LOGIN_WINDOW: 3600,        // 1 hour window for attempts
    TOKEN_PREFIX: 'auth:token:',
    LOCKOUT_PREFIX: 'auth:lockout:'
} as const;

/**
 * Redis Key Prefixes
 * Standardized prefixes for Redis keys
 */
export const REDIS_PREFIXES = {
    SESSION: 'session:',
    LOCKOUT: 'lockout:',
    TOKEN_BLACKLIST: 'blacklist:',
    RATE_LIMIT: 'rate-limit:'
} as const;


/**
 * JWT Token Payload
 * Extended JWT payload with custom claims
 */
export interface TokenPayload extends JwtPayload {
    userId: string;
    userType: UserType;
    roleType: RoleType;
    email: string;
}