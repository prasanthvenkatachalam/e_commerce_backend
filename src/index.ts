// src/index.ts
import dotenv from 'dotenv';
import { testConnection } from '@/db/config';
import logger from '@/utils/logger';

dotenv.config();

const appLogger = logger.child({ module: 'app' });

async function startServer() {
  try {
    // Test database connection
    await testConnection();
    appLogger.info('Server initialized successfully');
  } catch (error) {
    appLogger.error({ error }, 'Failed to start server');
    process.exit(1);
  }
}

// Handle application shutdown
process.on('SIGINT', () => {
  appLogger.info('Shutting down application...');
  process.exit(0);
});

// Start the server
startServer();