// src/api/services/auth.service.ts

import bcrypt from 'bcrypt';
import jwt, { SignOptions } from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import { PoolClient } from 'pg';
import { z } from 'zod';
import pool from '@/db/config';
import { config } from '@/config';
import logger from '@/utils/logger';
import redisClient, { withRedis } from '@/config/redis.config';
import { sessionService } from './session.service';
import {
    USER_STATUS,
    DatabaseUser,
    LoginCredentials,
    LoginResponse,
    TokenPayload,
    AUTH_CONSTANTS
} from '@/types/auth.types';

const authLogger = logger.child({
    service: 'auth',
    module: 'authentication'
});

// Validation schema for login credentials
const loginSchema = z.object({
    email: z.string()
        .email('Invalid email format')
        .min(1, 'Email is required')
        .max(255, 'Email exceeds maximum length')
        .trim()
        .toLowerCase(),
    password: z.string()
        .min(6, 'Password must be at least 6 characters')
        .max(100, 'Password exceeds maximum length'),
    deviceInfo: z.object({
        ipAddress: z.string().optional(),
        userAgent: z.string().optional()
    }).optional()
});
export const authService = {
    /**
     * Checks if an account is currently locked out
     * Returns lockout status and remaining time if locked
     */
    async isAccountLocked(user: DatabaseUser): Promise<[boolean, number?]> {
        const lockoutKey = `${AUTH_CONSTANTS.LOCKOUT_PREFIX}${user.id}`;
        
        try {
            return await withRedis(async () => {
                const attempts = await redisClient.get(lockoutKey);
                if (!attempts) return [false];

                const currentAttempts = parseInt(attempts, 10);
                if (currentAttempts >= AUTH_CONSTANTS.MAX_LOGIN_ATTEMPTS) {
                    const remainingLockout = await redisClient.ttl(lockoutKey);
                    if (remainingLockout > 0) {
                        return [true, remainingLockout];
                    }
                }
                return [false];
            }, { userId: user.id, operation: 'checkLockout' });
        } catch (error) {
            authLogger.error({ error, userId: user.id }, 'Error checking lockout status');
            return [false];
        }
    },

    /**
     * Handles a failed login attempt
     * Updates both Redis and database records
     */
    async handleFailedLogin(client: PoolClient, user: DatabaseUser): Promise<void> {
        const lockoutKey = `${AUTH_CONSTANTS.LOCKOUT_PREFIX}${user.id}`;
        
        try {
            await withRedis(async () => {
                const attempts = await redisClient.incr(lockoutKey);
                
                if (attempts === 1) {
                    await redisClient.expire(lockoutKey, AUTH_CONSTANTS.LOGIN_WINDOW);
                }
                
                if (attempts >= AUTH_CONSTANTS.MAX_LOGIN_ATTEMPTS) {
                    await redisClient.expire(lockoutKey, AUTH_CONSTANTS.LOCKOUT_DURATION);
                }
            }, { userId: user.id, operation: 'handleFailedLogin' });

            await client.query(
                `UPDATE users 
                SET failed_login_attempts = failed_login_attempts + 1,
                    last_failed_login = NOW()
                WHERE id = $1`,
                [user.id]
            );

            authLogger.warn({
                userId: user.id,
                isLocked: true
            }, 'Failed login attempt recorded');

        } catch (error) {
            authLogger.error({ error, userId: user.id }, 'Error handling failed login');
            throw error;
        }
    },
    /**
     * Processes successful login
     * Clears lockout data and updates login timestamp
     */
    async handleSuccessfulLogin(client: PoolClient, user: DatabaseUser): Promise<void> {
        try {
            await withRedis(async () => {
                const lockoutKey = `${AUTH_CONSTANTS.LOCKOUT_PREFIX}${user.id}`;
                await redisClient.del(lockoutKey);
            }, { userId: user.id, operation: 'clearLockout' });

            await client.query(
                `UPDATE users 
                SET failed_login_attempts = 0,
                    last_login = NOW(),
                    last_failed_login = NULL
                WHERE id = $1`,
                [user.id]
            );

            authLogger.info({ userId: user.id }, 'Successful login recorded');
        } catch (error) {
            authLogger.error({ error, userId: user.id }, 'Error handling successful login');
            throw error;
        }
    },

    /**
     * Creates JWT tokens for authenticated sessions
     */
    async generateAuthToken(user: DatabaseUser): Promise<string> {
        const payload: TokenPayload = {
            userId: user.id,
            email: user.email,
            userType: user.user_type,
            roleType: user.role_type,
            iat: Math.floor(Date.now() / 1000)
        };

        const signOptions: SignOptions = {
            expiresIn: config.jwt.accessExpiresIn,
            algorithm: 'HS256'
        };

        if (config.jwt.audience) {
            signOptions.audience = config.jwt.audience;
        }
        if (config.jwt.issuer) {
            signOptions.issuer = config.jwt.issuer;
        }

        return jwt.sign(
            payload,
            config.jwt.secret,
            signOptions
        );
    },
    /**
     * Main login method handling the entire authentication process
     */
    async login(credentials: LoginCredentials): Promise<LoginResponse> {
        let client: PoolClient | null = null;

        try {
            const validatedData = loginSchema.parse(credentials);
            client = await pool.connect();
            await client.query('BEGIN');

            const userResult = await client.query<DatabaseUser>(
                `SELECT 
                    id,
                    email,
                    password_hash,
                    user_type,
                    role_type,
                    status,
                    failed_login_attempts,
                    last_failed_login
                FROM users 
                WHERE email = $1
                FOR UPDATE`,
                [validatedData.email]
            );

            const user = userResult.rows[0];
            if (!user || user.status !== USER_STATUS.ACTIVE) {
                await client.query('ROLLBACK');
                throw new Error('Invalid credentials');
            }

            const [isLocked, remainingTime] = await this.isAccountLocked(user);
            if (isLocked) {
                await client.query('ROLLBACK');
                throw new Error(`Account is temporarily locked. Try again in ${Math.ceil(remainingTime! / 60)} minutes`);
            }

            const isValidPassword = await bcrypt.compare(
                validatedData.password,
                user.password_hash
            );

            if (!isValidPassword) {
                await this.handleFailedLogin(client, user);
                await client.query('COMMIT');
                throw new Error('Invalid credentials');
            }

            const accessToken = await this.generateAuthToken(user);
            await sessionService.createSession(client, {
                userId: user.id,
                token: accessToken,
                deviceInfo: validatedData.deviceInfo
            });

            await this.handleSuccessfulLogin(client, user);
            await client.query('COMMIT');

            return {
                accessToken,
                sessionId: randomUUID(),
                user: {
                    id: user.id,
                    email: user.email,
                    userType: user.user_type,
                    roleType: user.role_type
                }
            };

        } catch (error) {
            if (client) {
                await client.query('ROLLBACK');
            }

            authLogger.error({
                error: error instanceof Error ? error.message : 'Unknown error',
                stack: error instanceof Error ? error.stack : undefined,
                email: credentials.email
            }, 'Authentication failed');

            throw error;

        } finally {
            if (client) {
                client.release();
            }
        }
    },
    /**
     * Validates JWT tokens and extracts payload
     */
    async verifyToken(token: string): Promise<TokenPayload> {
        try {
            const decoded = jwt.verify(token, config.jwt.secret, {
                algorithms: ['HS256']
            }) as TokenPayload;

            return decoded;

        } catch (error) {
            authLogger.error({
                error: error instanceof Error ? error.message : 'Unknown error'
            }, 'Token verification failed');
            throw error;
        }
    }
};

// Handle Redis connection errors
redisClient.on('error', (error: Error) => {
    authLogger.error({ error }, 'Redis connection error');
});

// Clean up Redis connection on application shutdown
process.on('SIGTERM', async () => {
    await redisClient.quit();
});