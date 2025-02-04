// src/config/index.ts

// Import Zod for schema validation.  Zod helps us define the *shape* of our data (in this case, environment variables) and check if the data matches that shape.  It's like a type checker for runtime data.
import { z } from 'zod';

// Import the type for time durations (e.g., '10ms', '2s', '5m'). This lets us work with time values in a clear and type-safe way.
import type { StringValue } from 'ms';

// Import our custom logging utility.  This helps us record what's happening in our application, especially during configuration.
import logger from '@/utils/logger';

// Define interfaces for Redis key prefixes and TTLs (Time-To-Live).
// These help us organize and manage the data we store in Redis (our database).

// Redis Key Prefixes: These are like labels that we attach to the keys we store in Redis. They help us categorize our data. For example, all session data could have the prefix "session:".
interface RedisKeyPrefixes {
    readonly session: `${string}session:`;      // Prefix for session keys (e.g., "user123:session:")
    readonly rateLimit: `${string}rate-limit:`; // Prefix for rate limiting keys (used to track how many requests a user has made)
    readonly lockout: `${string}lockout:`;     // Prefix for lockout keys (used to lock accounts after too many failed login attempts)
    readonly token: `${string}token:`;         // Prefix for token keys (used for authentication)
    readonly cache: `${string}cache:`;         // Prefix for cache keys (used to store frequently accessed data)
}

// Redis TTLs (Time-To-Live): These define how long data should be kept in Redis before it's automatically deleted.
interface RedisTTL {
    readonly session: number;   // Time (in seconds) that user session data should be kept
    readonly cache: number;     // Time (in seconds) that cached data should be kept
    readonly rateLimit: number; // Time (in seconds) that rate limit counters should be kept
    readonly lockout: number;   // Time (in seconds) that an account lockout should last
    readonly temp: number;     // Time (in seconds) that temporary data should be kept
}

// ... (Previous code from index.ts)

// Create a logger specifically for configuration-related messages. This helps us keep configuration errors separate from other application logs, making debugging easier.  It's like having a dedicated notebook for configuration issues.
const configLogger = logger.child({ module: 'config' });

// Zod schema for environment variable validation.  This is a *crucial* step. We define a schema that describes the structure and types of our expected environment variables.  Then, at runtime, we check if the *actual* environment variables match this schema.  This prevents common errors caused by missing or incorrectly typed environment variables.

const envSchema = z.object({
    // NODE_ENV: The environment our application is running in.  This is usually 'development', 'production', or 'test'.  It affects how the application behaves (e.g., logging level, caching).
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),

    // PORT: The port number our server will listen on.  Ports are like numbered doors on a computer, and this tells other programs how to reach our application.
    PORT: z.string().regex(/^\d+$/).transform(Number).pipe(z.number().min(1).max(65535)).default('3000'),

    // Database Configuration (PostgreSQL in this example)
    DB_HOST: z.string().default('localhost'), // The hostname or IP address of our database server.  'localhost' means it's running on the same computer.
    DB_PORT: z.string().regex(/^\d+$/).transform(Number).pipe(z.number().min(1).max(65535)).default('5432'), // The port the database server is listening on.
    DB_NAME: z.string().default('postgres'), // The name of the database we want to connect to.
    DB_USER: z.string().default('postgres'), // The username for connecting to the database.
    DB_PASSWORD: z.string().default('postgres'), // The password for connecting to the database.
    DATABASE_URL: z.string().url().optional(), // A URL that contains all the database connection details in one string.  This is an alternative to providing the host, port, name, user, and password separately.

    // Redis Configuration (for caching, sessions, etc.)
    REDIS_URL: z.string().default('redis://localhost:6379'), // The URL for connecting to Redis.  It might include the host, port, username, and password.
    API_PREFIX: z.string().default('/api'), // A prefix for all our API routes. This helps organize our API endpoints.  For example, if the prefix is '/api', our user routes might be `/api/users`.
    RATE_LIMIT: z.string().default('1000'), // The maximum number of requests a user can make within a certain time window.  This helps prevent abuse.
    RATE_LIMIT_WINDOW: z.string().default('1m'), // The time window for rate limiting.  For example, '1m' means 1 minute, '1h' means 1 hour.  So, if RATE_LIMIT is 1000 and RATE_LIMIT_WINDOW is '1m', a user can make a maximum of 1000 requests per minute.
    REDIS_PREFIX: z.string().default('ecommerce:'), // A prefix for all keys we store in Redis.  This helps organize our data in Redis.  For example, all user sessions could start with 'user:'.

    // JWT (JSON Web Token) Configuration (for authentication)
    JWT_SECRET: z.string().min(32, 'JWT secret must be at least 32 characters'), // A secret key used to sign and verify JWTs. This is *extremely* important for security.
    JWT_ACCESS_EXPIRES: z.string().regex(/^(\d+(\.\d+)?(ms|s|m|h|d|w|y))$/).or(z.string().regex(/^\d+$/)).transform((value) => {
        if (/^\d+$/.test(value)) {
            return parseInt(value, 10);
        }
        return value as StringValue;
    }).default('15m'), // How long a JWT access token is valid for (e.g., 15 minutes).  Access tokens are used to grant access to protected resources.
    JWT_REFRESH_EXPIRES: z.string().regex(/^(\d+(\.\d+)?(ms|s|m|h|d|w|y))$/).or(z.string().regex(/^\d+$/)).transform((value) => {
        if (/^\d+$/.test(value)) {
            return parseInt(value, 10);
        }
        return value as StringValue;
    }).default('7d'), // How long a JWT refresh token is valid for (e.g., 7 days).  Refresh tokens are used to get new access tokens without requiring the user to log in again.
    JWT_AUDIENCE: z.string().optional(), // The intended recipient of the JWT (optional).
    JWT_ISSUER: z.string().optional(), // The party that issued the JWT (optional).

    // Logging Configuration
    LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'), // The minimum level of log messages we want to record.  'debug' is the most detailed, 'error' is the least.

    // Cookie Configuration
    COOKIE_SECRET: z.string().min(32, 'Cookie secret must be at least 32 characters').optional(), // A secret key used to encrypt cookies (optional).  Cookies are small pieces of data stored in the user's browser.
    COOKIE_DOMAIN: z.string().optional(), // The domain for which the cookie is valid (optional).
});

// ... (Previous code from index.ts)

// Function to parse and validate environment variables.  This function uses the Zod schema we defined earlier to check if the environment variables are correct.
const parseEnv = () => {
    const result = envSchema.safeParse(process.env); // Try to parse the environment variables using our schema.  Zod will check if all required variables are present and have the correct types.

    if (!result.success) { // If the parsing fails (meaning some variables are missing or have the wrong format)
        configLogger.error({ errors: result.error.format() }, 'Invalid environment configuration'); // Log the error messages so we know what went wrong.  The `result.error.format()` gives us nicely formatted error details.
        process.exit(1); // Stop the application from starting because it's in an invalid state.  We don't want to run with incorrect configuration.
    }

    return result.data; // If the parsing is successful, return the *validated* environment variables.  We can now be sure they have the correct types.
};

// Parse the environment variables (and exit if there's an error). This line actually *runs* the `parseEnv` function and stores the result in the `env` variable.
const env = parseEnv();

// Our main configuration object. This object will hold all the settings for our application, making them easily accessible throughout the code.  It's like a central control panel for our configuration.
export const config = {
    env: env.NODE_ENV, // Set the environment (development, production, or test).  This tells our application how to behave in different situations.
    isProduction: env.NODE_ENV === 'production', // A boolean value that's `true` if we're in production mode, and `false` otherwise.  We often use this to enable/disable certain features in production.
    isDevelopment: env.NODE_ENV === 'development', // A boolean value that's `true` if we're in development mode.
    isTest: env.NODE_ENV === 'test', // A boolean value that's `true` if we're in test mode.
    server: {
        port: env.PORT, // The port our server will listen on.
        apiPrefix: env.API_PREFIX, // The prefix for our API routes.
        rateLimit: {
            max: parseInt(env.RATE_LIMIT, 10), // The maximum number of requests allowed. We parse the string from the environment to an integer.
            windowMs: env.RATE_LIMIT_WINDOW.endsWith('m') ? parseInt(env.RATE_LIMIT_WINDOW, 10) * 60 * 1000 : parseInt(env.RATE_LIMIT_WINDOW, 10), // The time window for rate limiting (converted to milliseconds).  We check if the window is in minutes ('m') or another unit and convert accordingly.
        },
    },
    db: {
        host: env.DB_HOST, // Database host.
        port: env.DB_PORT, // Database port.
        name: env.DB_NAME, // Database name.
        user: env.DB_USER, // Database user.
        password: env.DB_PASSWORD, // Database password.
        url: env.DATABASE_URL, // Database URL (if provided).
    },
    redis: {
        url: env.REDIS_URL, // Redis connection URL.
        keyPrefix: {
            session: `${env.REDIS_PREFIX}session:`, // Prefixes for Redis keys (helps organize data).
            rateLimit: `${env.REDIS_PREFIX}rate-limit:`,
            lockout: `${env.REDIS_PREFIX}lockout:`,
            token: `${env.REDIS_PREFIX}token:`,
            cache: `${env.REDIS_PREFIX}cache:`,
        },
        ttl: { // Time-To-Live values for Redis keys.
            session: 86400, // Session TTL (24 hours in seconds).
            cache: 3600, // Cache TTL (1 hour).
            rateLimit: 60, // Rate limit TTL (1 minute).
            lockout: 3600, // Lockout TTL (1 hour).
            temp: 300, // Temporary data TTL (5 minutes).
        },
        tls: env.REDIS_URL.startsWith('rediss://'), //  Check if Redis URL uses TLS (rediss://).
    },
    jwt: { // JWT configuration.
        secret: env.JWT_SECRET, // JWT secret.
        accessExpiresIn: env.JWT_ACCESS_EXPIRES, // JWT access token expiration.
        refreshExpiresIn: env.JWT_REFRESH_EXPIRES, // JWT refresh token expiration.
        audience: env.JWT_AUDIENCE, // JWT audience.
        issuer: env.JWT_ISSUER, // JWT issuer.
    },
    cookie: { // Cookie configuration.
        secret: env.COOKIE_SECRET, // Cookie secret.
        domain: env.COOKIE_DOMAIN, // Cookie domain.
        secure: env.NODE_ENV === 'production', // Set secure flag for production.
        sameSite: 'strict' as const, // Set sameSite attribute to strict.
        httpOnly: true, // Set httpOnly flag.
    },
    logging: { // Logging configuration.
        level: env.LOG_LEVEL, // Log level.
    },
} as const;



// Define a type for our configuration object.  This helps TypeScript understand the structure of our configuration and prevents errors.
export type Config = typeof config;

// Function to perform additional validation on the configuration *after* it's been created.  This is where we can check for things that Zod can't easily handle, like relationships between different configuration values.
function validateConfig() {
    // Validate database configuration.  We require either a DATABASE_URL *or* all the individual database connection parameters (host, port, name, user, password).
    if (!config.db.url && (!config.db.host || !config.db.name || !config.db.user || !config.db.password)) {
        throw new Error( // If the database configuration is incomplete, we throw an error.
            'Either DATABASE_URL or all of DB_HOST, DB_PORT, DB_NAME, DB_USER and DB_PASSWORD must be provided'
        );
    }

    // Validate JWT secret length.  The JWT secret should be long enough to be cryptographically secure.
    if (config.jwt.secret.length < 32) {
        throw new Error('JWT_SECRET must be at least 32 characters long');
    }

    // Validate rate limiting.  The maximum number of requests should be at least 1.
    if (config.server.rateLimit.max < 1) {
        throw new Error('Rate limit maximum must be positive');
    }

    // Validate Redis prefix.  Redis key prefixes should always end with a colon (':').
    if (!config.redis.keyPrefix.session.endsWith(':')) {
        throw new Error('Redis key prefixes must end with a colon (:)');
    }

    // Log that the configuration has been successfully validated.
    configLogger.info({
        env: config.env,
        apiPrefix: config.server.apiPrefix
    }, 'Configuration validated successfully');
}

// Validate the configuration.  This line actually *runs* the `validateConfig` function and will throw an error if the configuration is invalid.
validateConfig();


// Example usage comments (These are just for demonstration and are not part of the executable code).
/**
 * USAGE EXAMPLES:
 * 
 * import { config } from '@/config'; // Import the configuration object.
 * 
 * // Access database configuration.
 * const dbConfig = config.db;
 * 
 * // Check environment.
 * if (config.isDevelopment) {
 *     // Enable development-specific features.
 * }
 * 
 * // Use Redis prefix.
 * const sessionKey = `${config.redis.keyPrefix.session}${userId}`; // Construct a Redis key for a user session.
 */

// ... (End of index.ts file)