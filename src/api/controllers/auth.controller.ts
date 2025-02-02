// src/api/controllers/auth.controller.ts

/**
 * AUTHENTICATION CONTROLLER
 *
 * This controller handles HTTP requests related to authentication:
 * - User login
 * - Token verification
 * - Session management
 *
 * It follows REST API best practices and includes comprehensive
 * error handling and request validation.
 */

import { Request, Response, NextFunction } from 'express';
import { z } from 'zod'; // For request validation
import { authService } from '../services/auth.service';
import { sessionService } from '../services/session.service'; // Import session service
import { LoginCredentials, TokenPayload } from '@/types/auth.types';
import logger from '../../utils/logger';

/**
 * Controller-specific logger configuration
 * Adds context to all log entries from this controller
 */
const authControllerLogger = logger.child({
    module: 'authController',
    context: 'http'
});

/**
 * Request validation schemas
 * Ensures incoming requests meet our requirements
 */
const loginRequestSchema = z.object({
    email: z.string().email('Invalid email format'),
    password: z.string().min(6, 'Password must be at least 6 characters')
});

/**
 * Type for standardized API responses
 * Ensures consistent response format
 */
interface ApiResponse<T> {
    success: boolean;
    message: string;
    data?: T;
    error?: string;
}

export const authController = {
    /**
     * LOGIN HANDLER
     *
     * Processes user login requests and returns authentication tokens
     *
     * Endpoint: POST /api/auth/login
     *
     * Request body:
     * - email: string
     * - password: string
     *
     * Responses:
     * - 200: Successful login
     * - 400: Invalid request data
     * - 401: Invalid credentials
     * - 429: Too many failed attempts
     * - 500: Server error
     */
    async login(
        req: Request<{}, {}, LoginCredentials>,
        res: Response<ApiResponse<{ token: string; user: any }>>,
        next: NextFunction
    ): Promise<void> {
        try {
            // Log request initiation with safe data
            authControllerLogger.info({
                ip: req.ip,
                userAgent: req.get('user-agent')
            }, 'Login request initiated');

            // Validate request body
            const validatedData = loginRequestSchema.parse(req.body);

            // Attempt login
            const loginResponse = await authService.login(validatedData);

            // Set secure cookie with token
            res.cookie('auth_token', loginResponse.accessToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 24 * 60 * 60 * 1000 // 24 hours
            });

            // Send success response
            res.status(200).json({
                success: true,
                message: 'Login successful',
                data: {
                    token: loginResponse.accessToken,
                    user: {
                        id: loginResponse.user.id,
                        email: loginResponse.user.email,
                        userType: loginResponse.user.userType
                    }
                }
            });

        } catch (error) {
            // Log error with context but without sensitive data
            authControllerLogger.error({
                error: error instanceof Error ? error.message : 'Unknown error',
                stack: error instanceof Error ? error.stack : undefined,
                ip: req.ip
            }, 'Login failed');

            // Handle specific error types
            if (error instanceof z.ZodError) {
                res.status(400).json({
                    success: false,
                    message: 'Invalid request data',
                    error: error.errors[0].message
                });
                return;
            }

            // Pass other errors to global error handler
            next(error);
        }
    },

    /**
     * LOGOUT HANDLER
     *
     * Processes user logout requests and invalidates the session
     *
     * Endpoint: POST /api/auth/logout
     *
     * Headers Required:
     * - Authorization: Bearer <token>
     *
     * Responses:
     * - 204: Logout Successful
     * - 400: Missing token
     * - 401: Invalid Token
     * - 500: Server error
     */
    async logout(
        req: Request,
        res: Response,
        next: NextFunction
    ): Promise<void> {
        try {
            authControllerLogger.info({
                ip: req.ip,
                userAgent: req.get('user-agent')
            }, 'Logout request initiated');

            const token = req.headers.authorization?.split(' ')[1];

             if (!token) {
                 res.status(400).json({
                     success: false,
                     message: 'No token provided in headers',
                     error: 'Missing token'
                 });
                return;
             }
              const user = await authService.verifyToken(token);


            if (!user) {
                res.status(401).json({
                    success: false,
                    message: 'Invalid token',
                    error: 'Authentication failed'
                });
                return;
            }
             await sessionService.terminateSession(user.userId, token);

           // Send success response
           res.status(204).send();

        } catch (error) {
            authControllerLogger.error({
                error: error instanceof Error ? error.message : 'Unknown error',
                stack: error instanceof Error ? error.stack : undefined,
                 ip: req.ip
            }, 'Logout failed');
              // Pass other errors to global error handler
            next(error);
        }
    },


    /**
     * TOKEN VERIFICATION
     *
     * Validates JWT tokens and returns decoded payload
     *
     * Endpoint: POST /api/auth/verify
     *
     * Headers required:
     * - Authorization: Bearer <token>
     *
     * Responses:
     * - 200: Token is valid
     * - 401: Invalid or missing token
     * - 500: Server error
     */
    async verifyToken(
        req: Request,
        res: Response<ApiResponse<TokenPayload>>,
        next: NextFunction
    ): Promise<void> {
        try {
            // Log verification attempt
            authControllerLogger.info({
                ip: req.ip,
                userAgent: req.get('user-agent')
            }, 'Token verification initiated');

            // Extract token from header
            const authHeader = req.headers.authorization;
            if (!authHeader?.startsWith('Bearer ')) {
                res.status(401).json({
                    success: false,
                    message: 'Unauthorized - Bearer token missing',
                    error: 'Authentication required'
                });
                return;
            }

            // Verify token
            const token = authHeader.split(' ')[1];
            const decodedToken = await authService.verifyToken(token);

            // Send success response
            res.status(200).json({
                success: true,
                message: 'Token is valid',
                data: decodedToken
            });

        } catch (error) {
            // Log verification failure
            authControllerLogger.error({
                error: error instanceof Error ? error.message : 'Unknown error',
                stack: error instanceof Error ? error.stack : undefined,
                ip: req.ip
            }, 'Token verification failed');

            // Handle JWT-specific errors
            if (error instanceof Error && error.name === 'JsonWebTokenError') {
                res.status(401).json({
                    success: false,
                    message: 'Invalid token',
                    error: 'Authentication failed'
                });
                return;
            }

            if (error instanceof Error && error.name === 'TokenExpiredError') {
                res.status(401).json({
                    success: false,
                    message: 'Token has expired',
                    error: 'Authentication expired'
                });
                return;
            }

            // Pass other errors to global handler
            next(error);
        }
    }
};