// src/config/index.ts
import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.string().transform(Number).default('3000'),
  DATABASE_URL: z.string(),
  JWT_SECRET: z.string(),
  // Add more environment variables as needed
});

// Validate environment variables at startup
const parsedEnv = envSchema.safeParse(process.env);

if (!parsedEnv.success) {
  console.error('❌ Invalid environment variables:', parsedEnv.error.toString());
  process.exit(1);
}

const env = parsedEnv.data;

export const config = {
  env: env.NODE_ENV,
  port: env.PORT,
  db: {
    url: env.DATABASE_URL,
    // Parse connection string to get individual components
    ...(() => {
      const url = new URL(env.DATABASE_URL);
      return {
        host: url.hostname,
        port: parseInt(url.port || '5432'),
        user: url.username,
        password: url.password,
        name: url.pathname.slice(1),
      };
    })(),
  },
  jwt: {
    secret: env.JWT_SECRET,
    expiresIn: '7d',
  },
} as const;

// Type for the config object
export type Config = typeof config;