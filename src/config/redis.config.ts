// src/config/redis.config.ts
import { Redis, RedisOptions } from 'ioredis'; // Import the Redis library
import logger from '@/utils/logger'; // Import our logging utility
import { config } from '@/config'; // Import our application configuration
import { URL } from 'url'; // Import the URL class for parsing URLs

// Our Redis-specific logger (helps us categorize logs)
const redisLogger = logger.child({
    module: 'redis',
    service: 'connection'
});

// Define types for Redis error codes (for better error handling)
type RedisErrorCode =
    | 'ECONNREFUSED' // Connection refused
    | 'ECONNRESET'  // Connection reset
    | 'ETIMEDOUT'  // Connection timed out
    | 'ENOTFOUND'  // Host not found
    | 'READONLY'   // Read-only mode
    | 'LOADING'    // Redis is still loading data
    | 'NOAUTH'     // Authentication failed
    | 'CLUSTERDOWN'; // Cluster is down

// Interface to extend the standard Error object with Redis-specific properties
interface RedisError extends Error {
    code: RedisErrorCode; // The Redis error code
    errno?: number;       // The system error number (optional)
    syscall?: string;     // The system call that failed (optional)
}

// Interface for Redis health check results
interface RedisHealthCheck {
    isHealthy: boolean; // Is Redis healthy?
    latency?: number;  // Latency (in milliseconds)
    error?: string;    // Error message (if any)
    lastChecked: Date; // Last time the health was checked
    memory?: {       // Memory usage information (optional)
        used: number;
        peak: number;
        fragmentationRatio: number;
    };
    clients?: {      // Client connection information (optional)
        connected: number;
        blocked: number;
    };
}

// Interface for our custom Redis configuration (extends ioredis's RedisOptions)
interface TypedRedisConfig extends RedisOptions {
    host: string;       // Redis host
    port: number;       // Redis port
    username?: string;  // Redis username (optional)
    password?: string;  // Redis password (optional)
    db?: number;       // Redis database number (optional)
    tls?: {            // TLS/SSL options (optional)
        rejectUnauthorized: boolean;
        ca?: string;
        cert?: string;
        key?: string;
    };
    maxRetriesPerRequest: number; // Maximum retries per request
    retryStrategy: (times: number) => number | null; // Retry strategy function
    reconnectOnError: (error: Error) => boolean;   // Reconnect on error function
    connectTimeout: number;    // Connection timeout
    commandTimeout: number;   // Command timeout
    keepAlive: number;      // Keep-alive interval
    enableOfflineQueue: boolean; // Enable offline queueing
    enableReadyCheck: boolean; // Enable ready check
    autoResubscribe: boolean; // Auto-resubscribe to channels
    autoResendUnfulfilledCommands: boolean; // Auto-resend unfulfilled commands
    lazyConnect: boolean;    // Lazy connect
    showFriendlyErrorStack: boolean; // Show friendly error stack
}


// Parse the Redis URL from the configuration
const parsedRedisUrl = new URL(config.redis.url);

// Our Redis configuration object
const redisConfig: TypedRedisConfig = {
    host: parsedRedisUrl.hostname, // Extract the hostname from the URL
    port: parseInt(parsedRedisUrl.port, 10) || 6379, // Extract the port (default to 6379 if not specified)
    username: parsedRedisUrl.username || undefined, // Extract the username (optional)
    password: parsedRedisUrl.password || undefined, // Extract the password (optional)
    db: parseInt(parsedRedisUrl.pathname.slice(1), 10) || 0, // Extract the database number (default to 0)
    maxRetriesPerRequest: 3, // Maximum number of retries for each request
    retryStrategy(times: number): number | null { // Function to determine the delay between retries
        const maxRetryDelay = 2000; // Maximum delay of 2 seconds
        const delay = Math.min(times * 50, maxRetryDelay); // Calculate the delay (increases with each attempt)

        redisLogger.info({
            attempt: times,
            delay,
            nextRetryIn: `${delay}ms`
        }, 'Retrying Redis connection'); // Log the retry attempt

        if (times > 20) { // Stop retrying after 20 attempts
            redisLogger.error('Maximum Redis retry attempts reached');
            return null; // Return null to stop retrying
        }

        return delay; // Return the delay in milliseconds
    },

    reconnectOnError(err: Error): boolean { // Function to determine if we should reconnect on error
        const reconnectErrors: RedisErrorCode[] = ['READONLY', 'LOADING', 'CLUSTERDOWN']; // List of errors to reconnect on
        return reconnectErrors.some(code => err.message.includes(code)); // Check if the error message contains any of the reconnect errors
    },

    connectTimeout: 10000, // Connection timeout of 10 seconds
    commandTimeout: 5000, // Command timeout of 5 seconds
    keepAlive: 30000, // Keep-alive interval of 30 seconds
    enableOfflineQueue: false, // Disable offline queueing
    enableReadyCheck: true, // Enable ready check
    autoResubscribe: true, // Auto-resubscribe to channels
    autoResendUnfulfilledCommands: true, // Auto-resend unfulfilled commands
    lazyConnect: false, // Connect immediately
    tls: config.redis.tls ? { rejectUnauthorized: true } : undefined, // Use config.redis.tls
    showFriendlyErrorStack: !config.isProduction // Use config.isProduction
};

// Create the Redis client instance
const redisClient = new Redis(redisConfig);

// ... (Previous code from redis.config.ts)

// Event handlers for the Redis client
redisClient.on('connect', () => { // When a connection to Redis is established
    redisLogger.info({ // Log the connection information
        host: redisConfig.host,
        port: redisConfig.port
    }, 'Redis connected successfully! 🎉');
});

redisClient.on('ready', () => { // When the Redis client is ready to accept commands
    redisLogger.info('Redis client is ready to accept commands');
});

redisClient.on('error', (error: RedisError) => { // When a Redis error occurs
    redisLogger.error({ // Log the error details
        code: error.code,
        message: error.message,
        stack: error.stack,
        syscall: error.syscall
    }, 'Redis connection error occurred');
});

redisClient.on('close', () => { // When the Redis connection is closed
    redisLogger.warn('Redis connection closed');
});

redisClient.on('end', () => { // When the Redis connection has ended
    redisLogger.warn('Redis connection ended');
});

// Function to retrieve Redis server information
async function getRedisInfo(): Promise<Record<string, string>> {
    try {
        const info = await redisClient.info(); // Get the Redis info string
        return info.split('\n') // Split the string into lines
            .filter(line => line.includes(':')) // Filter out lines that don't contain a colon (key-value separator)
            .reduce((acc, line) => { // Reduce the lines into an object
                const [key, value] = line.split(':'); // Split each line into key and value
                acc[key.trim()] = value.trim(); // Add the key-value pair to the object
                return acc;
            }, {} as Record<string, string>); // Initialize an empty object
    } catch (error) { // If there's an error retrieving info
        redisLogger.error({ error }, "Failed to retrieve Redis info"); // Log the error
        return {}; // Return an empty object
    }
}

// Function to check the health of the Redis connection
export async function checkRedisHealth(): Promise<RedisHealthCheck> {
    const startTime = process.hrtime(); // Record the start time for latency calculation

    try {
        const pingResult = await redisClient.ping(); // Send a PING command to Redis
        const [seconds, nanoseconds] = process.hrtime(startTime); // Calculate the time elapsed
        const latency = seconds * 1000 + nanoseconds / 1000000; // Convert nanoseconds to milliseconds

        const info = await getRedisInfo(); // Get Redis server info

        return { // Return the health check result
            isHealthy: pingResult === 'PONG', // Check if the PING command returned PONG
            latency, // The latency in milliseconds
            lastChecked: new Date(), // The time the health check was performed
            memory: { // Memory usage information
                used: parseInt(info['used_memory'] || '0', 10), // Used memory
                peak: parseInt(info['used_memory_peak'] || '0', 10), // Peak memory usage
                fragmentationRatio: parseFloat(info['mem_fragmentation_ratio'] || '0') // Memory fragmentation ratio
            },
            clients: { // Client connection information
                connected: parseInt(info['connected_clients'] || '0', 10), // Number of connected clients
                blocked: parseInt(info['blocked_clients'] || '0', 10) // Number of blocked clients
            }
        };
    } catch (error) { // If there's an error during the health check
        redisLogger.error({ error }, 'Redis health check failed'); // Log the error
        return { // Return an unhealthy result
            isHealthy: false,
            error: error instanceof Error ? error.message : 'Unknown error',
            lastChecked: new Date()
        };
    }
}

// ... (Previous code from redis.config.ts)

// Function to gracefully close the Redis connection
export async function closeRedisConnection(): Promise<void> {
    try {
        redisLogger.info('Gracefully closing Redis connection...'); // Log that we're closing the connection
        await redisClient.quit(); // Send the QUIT command to Redis (tells it we're disconnecting)
        redisLogger.info('Redis connection closed successfully'); // Log that the connection was closed
    } catch (error) { // If there's an error closing the connection
        redisLogger.error({ error }, 'Error closing Redis connection'); // Log the error
        redisClient.disconnect(); // Forcefully disconnect the client (as a last resort)
    }
}

// Event handlers for application shutdown (SIGTERM and SIGINT signals)
// These signals are sent when the application is being shut down
process.on('SIGTERM', async () => { // When the application receives a SIGTERM signal (termination request)
    redisLogger.info('Application shutting down, closing Redis connection...'); // Log that we're shutting down
    await closeRedisConnection(); // Close the Redis connection
});

process.on('SIGINT', async () => { // When the application receives a SIGINT signal (interrupt, usually Ctrl+C)
    redisLogger.info('Application interrupted, closing Redis connection...'); // Log that we were interrupted
    await closeRedisConnection(); // Close the Redis connection
});

// Utility function to wrap Redis operations with error handling and health checks
// This makes it easier to use Redis and ensures that we handle potential errors gracefully
export async function withRedis<T>(
    operation: () => Promise<T>, // The Redis operation to perform (a function that returns a Promise)
    context: Record<string, unknown> = {} // Additional context for logging (optional)
): Promise<T> {
    try {
        const health = await checkRedisHealth(); // Check the Redis connection health
        if (!health.isHealthy) { // If Redis is not healthy
            throw new Error('Redis is not healthy'); // Throw an error
        }
        return await operation(); // Perform the Redis operation
    } catch (error) { // If there's an error during the operation
        redisLogger.error({ ...context, error }, 'Redis operation failed'); // Log the error with context
        throw error; // Re-throw the error so it can be handled by the caller
    }
}

// Export the Redis client instance (so other parts of the application can use it)
export default redisClient;

