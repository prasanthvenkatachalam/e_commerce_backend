// src/config/redis.config.ts

import { Redis, RedisOptions } from 'ioredis';
import logger from '@/utils/logger';
import { config } from '@/config/index';
import { URL } from 'url';

// Create Redis-specific logger
const redisLogger = logger.child({
    module: 'redis',
    context: 'connection'
});

// Define Redis error types for better error handling
type RedisErrorCode = 
    | 'ECONNREFUSED' 
    | 'ECONNRESET'
    | 'ETIMEDOUT'
    | 'READONLY'
    | 'LOADING'
    | 'CLUSTERDOWN';

interface RedisError extends Error {
    code: RedisErrorCode;
}

// Interface for health check responses
interface RedisHealthCheck {
    isHealthy: boolean;
    latency?: number;
    error?: string;
    lastChecked: Date;
    memory?: {
        used: number;
        peak: number;
        fragmentationRatio: number;
    };
    stats?: {
        totalConnections: number;
        activeConnections: number;
        blockedConnections: number;
        usedMemoryPeak: number;
    };
}
// Parse Redis connection URL
const parsedRedisUrl = new URL(config.redis.url);

/**
 * Redis Client Configuration
 * Comprehensive setup with error handling and connection management
 */
const redisConfig: RedisOptions = {
    // Connection settings
    host: parsedRedisUrl.hostname,
    port: parseInt(parsedRedisUrl.port, 10) || 6379,
    username: parsedRedisUrl.username || undefined,
    password: parsedRedisUrl.password || undefined,
    db: parseInt(parsedRedisUrl.pathname.slice(1), 10) || 0,
    // Performance settings
    maxRetriesPerRequest: 3,
    connectTimeout: 10000,    // 10 seconds
    commandTimeout: 5000,     // 5 seconds
    keepAlive: 30000,        // 30 seconds
    // Retry strategy with exponential backoff
    retryStrategy(times: number): number | null {
        const maxRetryDelay = 5000;  // 5 seconds max delay
        const delay = Math.min(times * 100, maxRetryDelay);
        redisLogger.info({
            attempt: times,
            delay,
            nextRetryIn: `${delay}ms`
        }, 'Retrying Redis connection');
        // Stop retrying after 50 attempts (adjust as needed)
        if (times > 50) {
            redisLogger.error('Maximum Redis retry attempts reached');
            return null;
        }
        return delay;
    },
    // Reconnection error handling
    reconnectOnError(err: Error): boolean {
        const reconnectErrors = ['READONLY', 'LOADING', 'CLUSTERDOWN'];
        const shouldReconnect = reconnectErrors.some(code => err.message.includes(code));
        
        if (shouldReconnect) {
            redisLogger.warn({ error: err.message }, 'Reconnecting due to recoverable error');
        }
        
        return shouldReconnect;
    },
    // Feature flags
    enableOfflineQueue: true, // Enable offline queue to prevent immediate failures
    enableReadyCheck: true,
    autoResubscribe: true,
    autoResendUnfulfilledCommands: true,
    lazyConnect: false,
    // Security and debugging
    tls: config.redis.tls ? { rejectUnauthorized: true } : undefined,
    showFriendlyErrorStack: !config.isProduction
};
/**
 * Redis Client Instance
 * Create and configure the Redis client with event handlers
 */
const redisClient = new Redis(redisConfig);

// Connection event handlers
redisClient.on('connect', () => {
    redisLogger.info({
        host: redisConfig.host,
        port: redisConfig.port,
        timestamp: new Date().toISOString()
    }, 'Redis connected successfully! 🚀');
});

redisClient.on('ready', () => {
    redisLogger.info({
        timestamp: new Date().toISOString()
    }, 'Redis client is ready to accept commands');
});

redisClient.on('error', (error: RedisError) => {
    redisLogger.error({
        code: error.code,
        message: error.message,
        stack: error.stack,
        timestamp: new Date().toISOString()
    }, 'Redis connection error occurred');
});

redisClient.on('close', () => {
    redisLogger.warn({
        timestamp: new Date().toISOString()
    }, 'Redis connection closed');
});

/**
 * Redis Info Retrieval
 * Get detailed Redis server information
 */
async function getRedisInfo(): Promise<Record<string, string>> {
    try {
        const info = await redisClient.info();
        return info
            .split('\n')
            .filter(line => line.includes(':'))
            .reduce((acc, line) => {
                const [key, value] = line.split(':');
                acc[key.trim()] = value.trim();
                return acc;
            }, {} as Record<string, string>);
    } catch (error) {
        redisLogger.error({ 
            error,
            timestamp: new Date().toISOString()
        }, "Failed to retrieve Redis info");
        return {};
    }
}

/**
 * Redis Health Check
 * Comprehensive health check with performance metrics
 */
export async function checkRedisHealth(): Promise<RedisHealthCheck> {
    const startTime = process.hrtime();
    let attempts = 0;
    const maxAttempts = 5; // Maximum retry attempts
    const retryDelay = 2000; // 2 seconds between retries

    while (attempts < maxAttempts) {
        try {
            attempts++;
            const pingResult = await redisClient.ping();
            const [seconds, nanoseconds] = process.hrtime(startTime);
            const latency = seconds * 1000 + nanoseconds / 1000000;

            const info = await getRedisInfo();

            return {
                isHealthy: pingResult === 'PONG',
                latency,
                lastChecked: new Date(),
                memory: {
                    used: parseInt(info['used_memory'] || '0', 10),
                    peak: parseInt(info['used_memory_peak'] || '0', 10),
                    fragmentationRatio: parseFloat(info['mem_fragmentation_ratio'] || '0')
                },
                stats: {
                    totalConnections: parseInt(info['total_connections_received'] || '0', 10),
                    activeConnections: parseInt(info['connected_clients'] || '0', 10),
                    blockedConnections: parseInt(info['blocked_clients'] || '0', 10),
                    usedMemoryPeak: parseInt(info['used_memory_peak'] || '0', 10)
                }
            };
        } catch (error) {
            redisLogger.error({
                attempt: attempts,
                error: error instanceof Error ? {
                    message: error.message,
                    stack: error.stack,
                    name: error.name
                } : 'Unknown error',
                timestamp: new Date().toISOString()
            }, 'Redis health check failed');

            if (attempts < maxAttempts) {
                redisLogger.info(`Retrying Redis health check in ${retryDelay}ms...`);
                await new Promise(resolve => setTimeout(resolve, retryDelay));
            } else {
                // Ensure we return a valid RedisHealthCheck object after max retries
                return {
                    isHealthy: false,
                    error: error instanceof Error ? error.message : 'Unknown error',
                    lastChecked: new Date()
                };
            }
        }
    }

    // Fallback return in case the loop exits unexpectedly
    return {
        isHealthy: false,
        error: 'Unexpected error during Redis health check',
        lastChecked: new Date()
    };
}

/**
 * Graceful Connection Closure
 * Properly close Redis connection with cleanup
 */
export async function closeRedisConnection(): Promise<void> {
    try {
        redisLogger.info('Initiating graceful Redis connection closure...');
        
        // Attempt graceful shutdown with QUIT command
        await redisClient.quit();
        redisLogger.info('Redis connection closed successfully');
    } catch (error) {
        redisLogger.error({ error }, 'Error during graceful Redis shutdown');
        
        // Force disconnect as fallback
        redisClient.disconnect();
        redisLogger.warn('Forced Redis disconnect after failed graceful shutdown');
    }
}
/**
 * Process Shutdown Handlers
 * Ensure clean shutdown on process termination
 */
process.on('SIGTERM', async () => {
    redisLogger.info({
        signal: 'SIGTERM',
        timestamp: new Date().toISOString()
    }, 'Application shutting down, closing Redis connection...');
    await closeRedisConnection();
});

process.on('SIGINT', async () => {
    redisLogger.info({
        signal: 'SIGINT',
        timestamp: new Date().toISOString()
    }, 'Application interrupted, closing Redis connection...');
    await closeRedisConnection();
});

/**
 * Redis Operation Wrapper
 * Execute Redis operations with health checks and error handling
 */
export async function withRedis<T>(
    operation: () => Promise<T>,
    context: Record<string, unknown> = {}
): Promise<T> {
    try {
        // Verify Redis health before operation
        const health = await checkRedisHealth();
        if (!health.isHealthy) {
            throw new Error(`Redis is not healthy: ${health.error}`);
        }

        // Execute the operation
        const result = await operation();

        // Log success if context is provided
        if (Object.keys(context).length > 0) {
            redisLogger.debug({
                ...context,
                success: true,
                timestamp: new Date().toISOString()
            }, 'Redis operation completed successfully');
        }

        return result;
    } catch (error) {
        // Log detailed error information
        redisLogger.error({ 
            ...context,
            error: error instanceof Error ? {
                message: error.message,
                stack: error.stack,
                name: error.name
            } : 'Unknown error',
            timestamp: new Date().toISOString()
        }, 'Redis operation failed');
        
        throw error;
    }
}

// Export Redis client and types
export type { RedisError, RedisHealthCheck };
export default redisClient;