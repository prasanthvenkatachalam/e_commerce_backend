  // src/config/index.ts
import { z } from 'zod';
import logger from '@/utils/logger';

const configLogger = logger.child({ module: 'config' });

// Environment variables schema with stricter validation
const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test'])
    .default('development'),
  
  PORT: z.string()
    .regex(/^\d+$/)
    .transform(Number)
    .pipe(z.number().min(1).max(65535))
    .default('3000'),
  
  // Database configuration
  DB_HOST: z.string().default('localhost'),
  DB_PORT: z.string()
    .regex(/^\d+$/)
    .transform(Number)
    .pipe(z.number().min(1).max(65535))
    .default('5432'),
  DB_NAME: z.string().min(1),
  DB_USER: z.string().min(1),
  DB_PASSWORD: z.string().min(1),
  DATABASE_URL: z.string().url().optional(),

  // Authentication
  JWT_SECRET: z.string().min(32),
  JWT_ACCESS_EXPIRES: z.string().default('15m'),
  JWT_REFRESH_EXPIRES: z.string().default('7d'),
  
  // Redis (if needed)
  REDIS_URL: z.string().url().optional(),
  
  // API Configuration
  API_PREFIX: z.string().default('/api/v1'),
  RATE_LIMIT: z.string()
    .regex(/^\d+$/)
    .transform(Number)
    .default('100'),
  RATE_LIMIT_WINDOW: z.string()
    .regex(/^\d+$/)
    .transform(Number)
    .default('900000'), // 15 minutes in ms
    
  // Logging
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error'])
    .default('info'),
});

// Parse and validate environment variables
const parseEnv = () => {
  const result = envSchema.safeParse(process.env);
  
  if (!result.success) {
    configLogger.error(
      { errors: result.error.format() },
      'Invalid environment variables'
    );
    process.exit(1);
  }
  
  return result.data;
};

const env = parseEnv();

// Configuration object
export const config = {
  env: env.NODE_ENV,
  isProduction: env.NODE_ENV === 'production',
  isDevelopment: env.NODE_ENV === 'development',
  isTest: env.NODE_ENV === 'test',
  
  server: {
    port: env.PORT,
    apiPrefix: env.API_PREFIX,
    rateLimit: {
      max: env.RATE_LIMIT,
      windowMs: env.RATE_LIMIT_WINDOW,
    },
  },
  
  db: {
    host: env.DB_HOST,
    port: env.DB_PORT,
    name: env.DB_NAME,
    user: env.DB_USER,
    password: env.DB_PASSWORD,
    url: env.DATABASE_URL,
  },
  
  jwt: {
    secret: env.JWT_SECRET,
    accessExpiresIn: env.JWT_ACCESS_EXPIRES,
    refreshExpiresIn: env.JWT_REFRESH_EXPIRES,
  },
  
  redis: {
    url: env.REDIS_URL,
  },
  
  logging: {
    level: env.LOG_LEVEL,
  },
} as const;

// Type for the config object
export type Config = typeof config;

// Validate the configuration
function validateConfig() {
  // Database configuration checks
  if (!config.db.url && (!config.db.host || !config.db.name)) {
    throw new Error('Either DATABASE_URL or DB_HOST and DB_NAME must be provided');
  }

  // JWT secret length check
  if (config.jwt.secret.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters long');
  }

  configLogger.info({ 
    env: config.env,
    apiPrefix: config.server.apiPrefix 
  }, 'Configuration loaded successfully');
}

validateConfig();