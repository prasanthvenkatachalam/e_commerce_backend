// src/api/services/session.service.ts

/**
 * SESSION MANAGEMENT SERVICE
 *
 * Primary responsibility: Handles all session-related operations
 *
 * This service manages:
 * 1. Session creation and deletion
 * 2. Session validation
 * 3. Token tracking
 * 4. Session cleanup
 *
 * Security Features:
 * - Session expiration
 * - Token invalidation
 * - Concurrent session control
 * - Activity tracking
 *
 * Design Philosophy:
 * Separates session management from core authentication to maintain
 * single responsibility principle and enable independent scaling
 * of session management functionality.
 */

//======================= IMPORTS =======================//

/**
 * DATABASE & UTILITIES
 *
 * pg: PostgreSQL client
 * - Connection pooling
 * - Transaction support
 * - Prepared statements
 *
 * crypto: Secure random generation
 * - Session ID creation
 * - Cryptographic security
 */
import { Pool, PoolClient } from 'pg';
import { randomUUID } from 'crypto';

/**
 * CONFIGURATION & LOGGING
 *
 * config: Application settings
 * - Session timeouts
 * - Security parameters
 *
 * logger: Structured logging
 * - Security events
 * - Error tracking
 */
import { config } from '@/config';
import logger from '@/utils/logger';
import pool from '@/db/config'; // Import the database pool

//======================= TYPE DEFINITIONS =======================//

/**
 * SESSION CREATION PARAMETERS
 *
 * Purpose: Type safety for session creation
 *
 * @interface
 * @property {string} userId - Associated user ID
 * @property {string} token - Authentication token
 * @property {string} [deviceInfo] - Optional device information
 */
interface CreateSessionParams {
    userId: string;
    token: string;
    deviceInfo?: {
        userAgent?: string;
        ipAddress?: string;
    };
}

/**
 * SESSION RECORD INTERFACE
 *
 * Purpose: Represents a session in the database
 *
 * @interface
 * @property {string} id - Unique session identifier
 * @property {string} userId - Associated user ID
 * @property {string} token - Authentication token
 * @property {Date} createdAt - Session creation timestamp
 * @property {Date} expiresAt - Session expiration timestamp
 *  @property {object | null} deviceInfo - Optional device information
 */
interface SessionRecord {
    id: string;
    userId: string;
    token: string;
    createdAt: Date;
    expiresAt: Date;
     deviceInfo: object | null;
}

//======================= SERVICE IMPLEMENTATION =======================//

export const sessionService = {
    /**
     * SESSION CREATION
     *
     * Purpose: Establishes new user session
     *
     * Process Flow:
     * 1. Generate unique session ID
     * 2. Store session details
     * 3. Set expiration
     * 4. Log creation
     *
     * Security Features:
     * - Cryptographic session IDs
     * - Automatic expiration
     * - Activity tracking
     *
     * @param {PoolClient} client - Database client
     * @param {CreateSessionParams} params - Session parameters
     * @returns {Promise<string>} Created session ID
     */
    async createSession(
        client: PoolClient,
        params: CreateSessionParams
    ): Promise<string> {
        const sessionId = randomUUID();
        const expirationHours = 24; // Configurable session length

        try {
            await client.query(
                `INSERT INTO user_sessions (
                    id,
                    user_id,
                    token,
                    device_info,
                    expires_at
                ) VALUES ($1, $2, $3, $4, NOW() + interval '${expirationHours} hours')`,
                [
                    sessionId,
                    params.userId,
                    params.token,
                    params.deviceInfo ? JSON.stringify(params.deviceInfo) : null
                ]
            );

            logger.info({
                sessionId,
                userId: params.userId,
                expirationHours
            }, 'New session created');

            return sessionId;

        } catch (error) {
            logger.error({
                error: error instanceof Error ? error.message : 'Unknown error',
                userId: params.userId
            }, 'Session creation failed');
            throw error;
        }
    },

    /**
     * SESSION VALIDATION
     *
     * Purpose: Verifies session validity
     *
     * Checks:
     * 1. Session exists
     * 2. Not expired
     * 3. Token matches
     * 4. User is active
     *
     * @param {string} token - Session token to validate
     * @returns {Promise<boolean>} Validation result
     */
    async validateSession(token: string): Promise<boolean> {
        try {
            const result = await pool.query(
                `SELECT EXISTS (
                    SELECT 1
                    FROM user_sessions s
                    JOIN users u ON s.user_id = u.id
                    WHERE s.token = $1
                    AND s.expires_at > NOW()
                    AND u.status = 'active'
                )`,
                [token]
            );

            return result.rows[0].exists;

        } catch (error) {
            logger.error({
                error: error instanceof Error ? error.message : 'Unknown error'
            }, 'Session validation failed');
            return false;
        }
    },

    /**
     * SESSION TERMINATION
     *
     * Purpose: Ends user session
     *
     * Actions:
     * 1. Invalidate session
     * 2. Clear token
     * 3. Log activity
     *
     * @param {string} userId - User ID
     * @param {string} token - Session token
     * @returns {Promise<void>}
     */
    async terminateSession(userId: string, token: string): Promise<void> {
        try {
            await pool.query(
                `WITH deleted_session AS (
                    DELETE FROM user_sessions
                    WHERE user_id = $1 AND token = $2
                    RETURNING id
                )
                INSERT INTO user_activity_logs (
                    user_id,
                    action,
                    details
                ) VALUES ($1, 'logout', $3)`,
                [
                    userId,
                    token,
                    JSON.stringify({
                        timestamp: new Date(),
                        action: 'logout'
                    })
                ]
            );

            logger.info({ userId }, 'Session terminated');

        } catch (error) {
            logger.error({
                error: error instanceof Error ? error.message : 'Unknown error',
                userId
            }, 'Session termination failed');
            throw error;
        }
    },

    /**
     * INACTIVE SESSION CLEANUP
     *
     * Purpose: Removes expired sessions
     *
     * Process:
     * 1. Identify expired sessions
     * 2. Log terminations
     * 3. Remove records
     *
     * @returns {Promise<number>} Number of sessions cleaned
     */
    async cleanupInactiveSessions(): Promise<number> {
        try {
            const result = await pool.query(
                `DELETE FROM user_sessions
                 WHERE expires_at < NOW()
                 RETURNING id`
            );

            const cleanedCount = result.rowCount;

            if (cleanedCount&&cleanedCount > 0) {
                logger.info({
                    cleanedCount
                }, 'Inactive sessions cleaned up');
            }

            return cleanedCount||0;

        } catch (error) {
            logger.error({
                error: error instanceof Error ? error.message : 'Unknown error'
            }, 'Session cleanup failed');
            throw error;
        }
    },

    /**
     * USER SESSION QUERY
     *
     * Purpose: Retrieves active sessions for user
     *
     * Returns:
     * - Session list
     * - Device info
     * - Creation times
     *
     * @param {string} userId - User to query
     * @returns {Promise<SessionRecord[]>} Active sessions
     */
    async getUserSessions(userId: string): Promise<SessionRecord[]> {
        try {
            const result = await pool.query<SessionRecord>(
                `SELECT
                    id,
                    user_id,
                    token,
                    created_at,
                    expires_at,
                    device_info
                FROM user_sessions
                WHERE user_id = $1
                AND expires_at > NOW()
                ORDER BY created_at DESC`,
                [userId]
            );

            return result.rows;

        } catch (error) {
            logger.error({
                error: error instanceof Error ? error.message : 'Unknown error',
                userId
            }, 'Session query failed');
            throw error;
        }
    },

    /**
     * TERMINATE ALL USER SESSIONS
     *
     * Purpose: Ends all sessions for a user
     *
     * Use Cases:
     * - Password change
     * - Security breach
     * - Account deactivation
     *
     * @param {string} userId - User whose sessions to end
     * @returns {Promise<number>} Number of sessions terminated
     */
    async terminateAllUserSessions(userId: string): Promise<number> {
        try {
            const result = await pool.query(
                `DELETE FROM user_sessions
                 WHERE user_id = $1
                 RETURNING id`,
                [userId]
            );

            const terminatedCount = result.rowCount ?? 0;

            if (terminatedCount > 0) {
                logger.info({
                    userId,
                    terminatedCount
                }, 'All user sessions terminated');
            }

            return terminatedCount;

        } catch (error) {
            logger.error({
                error: error instanceof Error ? error.message : 'Unknown error',
                userId
            }, 'Multiple session termination failed');
            throw error;
        }
    }
};