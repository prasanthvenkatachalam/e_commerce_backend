/**
 * PRODUCTS MIDDLEWARE
 *
 * This middleware manages request validation and authorization for product-related endpoints.
 * It provides key functionalities such as:
 *
 * 1. Request validation for product creation and updates
 * 2. Role-based access control for product management
 * 3. Rate limiting for product-related actions
 * 4. Request logging and monitoring
 *
 * The middleware uses Redis for:
 * - Rate limiting to prevent excessive API calls
 * - Caching frequently accessed product data
 */

//======================= IMPORTS =======================//

import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { Redis } from 'ioredis';

import { authConfig } from '../../config/auth.config';
import logger from '../../utils/logger';
import { AuthenticatedRequest } from './auth.middleware';
import { createAuthError, AUTH_ERROR_TYPES, RoleType, ROLE_TYPES } from '@/types/auth.types';

//======================= VALIDATION SCHEMAS =======================//

/**
 * Schema for validating product data in request body
 */
const productValidationSchema = z.object({
    name: z.string().min(3, 'Product name must be at least 3 characters long'),
    price: z.number().positive('Price must be a positive number'),
    stock: z.number().int().nonnegative('Stock must be a non-negative integer'),
    description: z.string().optional()
});

//======================= MIDDLEWARE SETUP =======================//

/**
 * Create middleware-specific logger
 */
const productLogger = logger.child({
    module: 'products-middleware',
    layer: 'middleware'
});

/**
 * Configure Redis client
 */
const redis = new Redis(authConfig.redis.url, {
    enableOfflineQueue: false,
    maxRetriesPerRequest: 3,
    retryStrategy(times: number) {
        const delay = Math.min(times * 200, 2000);
        if (times > 3) {
            productLogger.error({ times }, 'Redis retry limit exceeded');
            return null;
        }
        return delay;
    }
});

//======================= MIDDLEWARE FUNCTIONS =======================//

/**
 * Middleware to validate product data in request body
 */
export function validateProductData(req: Request, res: Response, next: NextFunction): void {
    const validationResult = productValidationSchema.safeParse(req.body);
    if (!validationResult.success) {
        next(createAuthError(
            AUTH_ERROR_TYPES.VALIDATION_ERROR,
            'Invalid product data',
            400,
            { validationErrors: validationResult.error.errors }
        ));
        return;
    }
    next();
}

/**
 * Middleware to enforce role-based authorization for product management
 */
export function authorizeProductManagement(allowedRoles: RoleType[]) {
    return function authorizeMiddleware(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
        try {
            if (!req.user) {
                throw createAuthError(AUTH_ERROR_TYPES.TOKEN_INVALID, 'Authentication required', 401);
            }

            if (!allowedRoles.includes(req.user.roleType)) {
                productLogger.warn({
                    userId: req.user.userId,
                    userRole: req.user.roleType,
                    requiredRoles: allowedRoles,
                    ip: req.ip,
                    path: req.path
                }, 'Insufficient permissions');

                throw createAuthError(AUTH_ERROR_TYPES.UNAUTHORIZED, 'Insufficient permissions', 403);
            }

            productLogger.info({
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
 * Rate limiting middleware for product-related actions
 */
export async function rateLimitProducts(req: Request, res: Response, next: NextFunction): Promise<void> {
    const ip = req.ip || req.socket.remoteAddress || '0.0.0.0';
    const path = req.path;
    const key = `rate-limit:products:${ip}:${path}`;
    const now = Math.floor(Date.now() / 1000);
    const windowSize = 60; // 1-minute window

    try {
        const multi = redis.multi();
        multi.zremrangebyscore(key, 0, now - windowSize)
            .zadd(key, now, `${now}-${Math.random()}`)
            .zcard(key)
            .expire(key, windowSize);

        const results = await multi.exec();
        const count = results ? (results[2][1] as number) : 0;

        if (count > 10) {
            throw createAuthError(AUTH_ERROR_TYPES.RATE_LIMIT_EXCEEDED, 'Too many requests', 429);
        }

        res.setHeader('X-RateLimit-Limit', 10);
        res.setHeader('X-RateLimit-Remaining', Math.max(0, 10 - count));
        res.setHeader('X-RateLimit-Reset', now + windowSize);

        next();
    } catch (error) {
        next(createAuthError(AUTH_ERROR_TYPES.RATE_LIMIT_EXCEEDED, 'Rate limiting error', 429));
    }
}

//======================= ERROR HANDLING =======================//

redis.on('error', (error: Error) => {
    productLogger.error({ error: error.message, stack: error.stack }, 'Redis connection error');
});

process.on('SIGTERM', async () => {
    await redis.quit();
});
