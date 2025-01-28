// src/utils/logger.ts
import pino from 'pino';
import dotenv from 'dotenv';

dotenv.config();

const logger = pino({
  level: (process.env.LOG_LEVEL || 'info'),
  transport: {
    target: 'pino-pretty',
    options: {
      colorize: true,
      translateTime: 'SYS:yyyy-mm-dd HH:MM:ss',
      ignore: 'pid,hostname',
    },
  },
});

export const createModuleLogger = (moduleName: string) => {
  return logger.child({ module: moduleName });
};

export default logger;