// src/api/middlewares/auth.middleware.ts

/**
 * AUTHENTICATION MIDDLEWARE
 * 
 * This middleware manages request authentication and authorization.
 * It provides several key security features:
 * 
 * 1. Token validation and verification
 * 2. Role-based access control
 * 3. Rate limiting for security endpoints
 * 4. Session validation
 * 5. Request logging and monitoring
 * 
 * The middleware uses Redis for:
 * - Rate limiting counters
 * - Token blacklist checking
 * - Session state management
 */

//======================= IMPORTS =======================//

import { Request, Response, NextFunction } from 'express';
import { verify, JwtPayload, JsonWebTokenError, TokenExpiredError, Algorithm } from 'jsonwebtoken';
import { z } from 'zod';
import { Redis } from 'ioredis';

import { authConfig } from '../../config/auth.config';
import { sessionService } from '../services/session.service';
import logger from '../../utils/logger';
import {
    TokenPayload,
    AUTH_ERROR_TYPES,
    AuthError,
    AuthErrorType,
    createAuthError,
    UserType,
    RoleType,
    USER_TYPES,
    ROLE_TYPES
} from '@/types/auth.types';

//======================= TYPE DEFINITIONS =======================//

/**
 * Extended Request type for authenticated requests
 * Adds user and session information to the base Request
 */
export interface AuthenticatedRequest extends Request {
    user: TokenPayload & {
        userId: string;
        userType: UserType;
        roleType: RoleType;
    };
    sessionId: string;
}

/**
 * Request type during authentication process
 * Makes user and session properties optional
 */
export interface AuthRequest extends Request {
    user?: TokenPayload;
    sessionId?: string;
}

/**
 * Redis multi-command result type
 * Used for rate limiting operations
 */
type RedisMultiResult = [Error | null, unknown][];

//======================= VALIDATION SCHEMAS =======================//

/**
 * Token payload validation schema
 * Ensures token contains required claims
 */
const tokenValidationSchema = z.object({
    userId: z.string().uuid('Invalid user ID format'),
    userType: z.enum([USER_TYPES.ADMIN, USER_TYPES.CUSTOMER, USER_TYPES.VENDOR] as const),
    roleType: z.enum([
        ROLE_TYPES.SUPER_ADMIN,
        ROLE_TYPES.ADMIN,
        ROLE_TYPES.SUPPORT,
        ROLE_TYPES.INVENTORY,
        ROLE_TYPES.ORDERS
    ] as const),
    jti: z.string(),
    iat: z.number().optional(),
    exp: z.number().optional(),
    aud: z.string().optional(),
    iss: z.string().optional()
});

type ValidatedTokenPayload = z.infer<typeof tokenValidationSchema>;

//======================= MIDDLEWARE SETUP =======================//

/**
 * Create middleware-specific logger
 * Adds context to all middleware logs
 */
const authLogger = logger.child({
    module: 'auth-middleware',
    layer: 'middleware'
});

/**
 * Configure Redis client with error handling
 * Used for rate limiting and token management
 */
const redis = new Redis(authConfig.redis.url, {
    enableOfflineQueue: false,
    maxRetriesPerRequest: 3,
    retryStrategy(times: number) {
        const delay = Math.min(times * 200, 2000);
        if (times > 3) {
            authLogger.error({ times }, 'Redis retry limit exceeded');
            return null;
        }
        return delay;
    }
});

//======================= UTILITY FUNCTIONS =======================//

/**
 * Extracts authentication token from request
 * Checks multiple sources in order:
 * 1. Authorization header (Bearer token)
 * 2. Cookie
 * 3. Query parameter (development only)
 */
function extractTokenFromRequest(req: AuthRequest): string {
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
        return authHeader.substring(7);
    }

    const cookieToken = req.cookies?.auth_token;
    if (cookieToken) {
        return cookieToken;
    }

    if (process.env.NODE_ENV === 'development' && req.query.token) {
        if (typeof req.query.token !== 'string') {
            throw createAuthError(
                AUTH_ERROR_TYPES.TOKEN_INVALID,
                'Invalid token format in query',
                401
            );
        }
        return req.query.token;
    }

    throw createAuthError(
        AUTH_ERROR_TYPES.TOKEN_INVALID,
        'No authentication token provided',
        401
    );
}

/**
 * Checks if token is blacklisted
 * Uses Redis for fast blacklist checking
 */
async function verifyTokenBlacklist(jti: string): Promise<boolean> {
    try {
        const blacklistKey = `${authConfig.redis.keyPrefix.tokenBlacklist}${jti}`;
        const exists = await redis.exists(blacklistKey);
        return exists === 1;
    } catch (error) {
        authLogger.error({ error, jti }, 'Error checking token blacklist');
        return false;
    }
}

/**
 * Validates token payload structure and content
 * Uses Zod schema for validation
 */
function validateTokenPayload(payload: unknown): ValidatedTokenPayload {
    const result = tokenValidationSchema.safeParse(payload);
    if (!result.success) {
        throw createAuthError(
            AUTH_ERROR_TYPES.TOKEN_INVALID,
            'Invalid token payload',
            401,
            { validationErrors: result.error.errors }
        );
    }
    return result.data;
}

/**
 * Generates rate limit key for Redis
 * Combines IP and path for unique identification
 */
function getRateLimitKey(ip: string, path: string): string {
    return `${authConfig.redis.keyPrefix.rateLimit}${ip}:${path}`;
}

//======================= MIDDLEWARE FUNCTIONS =======================//

/**
 * Main authentication middleware
 * Verifies and validates JWT tokens
 */
export async function authenticateToken(
    req: AuthRequest,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        // Extract and validate token
        const token = extractTokenFromRequest(req);

        // Verify JWT
        let decodedToken: JwtPayload;
        try {
            decodedToken = verify(token, authConfig.jwt.secret, {
                ...authConfig.jwt.verificationOptions,
                algorithms: authConfig.jwt.verificationOptions.algorithms as Algorithm[]
            }) as JwtPayload;
        } catch (error) {
            if (error instanceof TokenExpiredError) {
                throw createAuthError(
                    AUTH_ERROR_TYPES.TOKEN_EXPIRED,
                    'Token has expired',
                    401
                );
            }
            if (error instanceof JsonWebTokenError) {
                throw createAuthError(
                    AUTH_ERROR_TYPES.TOKEN_INVALID,
                    'Invalid token',
                    401
                );
            }
            throw error;
        }

        // Validate token payload
        const validatedPayload = validateTokenPayload(decodedToken);

        // Check token blacklist
        if (validatedPayload.jti && await verifyTokenBlacklist(validatedPayload.jti)) {
            throw createAuthError(
                AUTH_ERROR_TYPES.TOKEN_INVALID,
                'Token has been revoked',
                401
            );
        }

        // Validate session
        const isValidSession = await sessionService.validateSession(token);
        if (!isValidSession) {
            throw createAuthError(
                AUTH_ERROR_TYPES.SESSION_EXPIRED,
                'Session has expired',
                401
            );
        }

        // Attach validated data to request
        req.user = validatedPayload;
        req.sessionId = token;

        // Log successful authentication
        authLogger.info({
            userId: validatedPayload.userId,
            userType: validatedPayload.userType,
            sessionId: token,
            ip: req.ip
        }, 'Authentication successful');

        next();
    } catch (error) {
        // Handle known auth errors
        if (
            error instanceof Error && 
            'type' in error && 
            'statusCode' in error && 
            typeof error.type === 'string' && 
            Object.values(AUTH_ERROR_TYPES).includes(error.type as AuthErrorType)
        ) {
            next(error as AuthError);
            return;
        }

        // Log and handle unknown errors
        authLogger.error({
            error: error instanceof Error ? error.message : 'Unknown error',
            stack: error instanceof Error ? error.stack : undefined,
            ip: req.ip,
            path: req.path
        }, 'Authentication error occurred');

        next(createAuthError(
            AUTH_ERROR_TYPES.TOKEN_INVALID,
            'Authentication failed',
            401
        ));
    }
}

/**
 * Role-based authorization middleware
 * Checks if authenticated user has required role
 */
export function authorize(allowedRoles: RoleType[]) {
    return function authorizeMiddleware(
        req: AuthRequest,
        res: Response,
        next: NextFunction
    ): void {
        try {
            if (!req.user) {
                throw createAuthError(
                    AUTH_ERROR_TYPES.TOKEN_INVALID,
                    'Authentication required',
                    401
                );
            }

            if (!allowedRoles.includes(req.user.roleType)) {
                authLogger.warn({
                    userId: req.user.userId,
                    userRole: req.user.roleType,
                    requiredRoles: allowedRoles,
                    ip: req.ip,
                    path: req.path
                }, 'Insufficient permissions');

                throw createAuthError(
                    AUTH_ERROR_TYPES.UNAUTHORIZED,
                    'Insufficient permissions',
                    403
                );
            }

            authLogger.info({
                userId: req.user.userId,
                roleType: req.user.roleType,
                path: req.path
            }, 'Authorization successful');

            next();
        } catch (error) {
            next(error);
        }
    };
}

/**
 * Rate limiting middleware
 * Limits request frequency based on IP and path
 */
export async function rateLimiter(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    const ip = req.ip || req.socket.remoteAddress || '0.0.0.0';
    const path = req.path;
    const key = getRateLimitKey(ip, path);
    const now = Math.floor(Date.now() / 1000);
    const windowSize = authConfig.security.rateLimit.windowMs / 1000;

    try {
        const multi = redis.multi();
        
        // Setup Redis commands for rate limiting
        multi
            .zremrangebyscore(key, 0, now - windowSize)
            .zadd(key, now, `${now}-${Math.random()}`)
            .zcard(key)
            .expire(key, windowSize);

        const results = await multi.exec() as RedisMultiResult;
        if (!results) {
            throw new Error('Redis transaction failed');
        }

        const [,, countResult] = results;
        const count = typeof countResult?.[1] === 'number' ? countResult[1] : 0;

        if (count > authConfig.security.rateLimit.max) {
            throw createAuthError(
                AUTH_ERROR_TYPES.RATE_LIMIT_EXCEEDED,
                'Too many requests',
                429
            );
        }

        // Set rate limit headers
        res.setHeader('X-RateLimit-Limit', authConfig.security.rateLimit.max);
        res.setHeader('X-RateLimit-Remaining', 
            Math.max(0, authConfig.security.rateLimit.max - count));
        res.setHeader('X-RateLimit-Reset', now + windowSize);

        next();
    } catch (error) {
        if (error instanceof Error && 'type' in error) {
            next(error);
            return;
        }

        authLogger.error({
            error: error instanceof Error ? error.message : 'Unknown error',
            ip,
            path
        }, 'Rate limiting error occurred');

        next(createAuthError(
            AUTH_ERROR_TYPES.RATE_LIMIT_EXCEEDED,
            'Rate limiting error',
            429
        ));
    }
}

//======================= ERROR HANDLING =======================//

// Handle Redis connection errors
redis.on('error', (error: Error) => {
    authLogger.error({
        error: error.message,
        stack: error.stack
    }, 'Redis connection error');
});

// Cleanup Redis connection on application shutdown
process.on('SIGTERM', async () => {
    await redis.quit();
});