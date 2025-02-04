// src/index.ts

/**
 * ENVIRONMENT VARIABLES
 * Load these first before anything else
 */
import 'dotenv/config';

/**
 * STANDARD IMPORTS
 */
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';

/**
 * REQUEST AND RESPONSE TYPES
 */
import type { Request, Response, NextFunction } from 'express';

/**
 * CUSTOM UTILITIES AND CONFIGURATIONS
 */
import { testConnection } from './db/config';
import { checkRedisHealth } from './config/redis.config';
import logger from './utils/logger';
import { config } from './config';
import { errorHandler } from './middlewares/error.middleware';
import { requestLogger } from './middlewares/logging.middleware';
import routes from '@/api/routes';

/**
 * APPLICATION LOGGER
 */
const appLogger = logger.child({ 
    module: 'app',
    context: 'server'
});
/**
 * CREATE EXPRESS APPLICATION
 * Initializes and configures the Express application
 */
async function createApp() {
  const app = express();

  // Basic middleware setup
  app.use(helmet());
  app.use(cors());
  app.use(compression());
  app.use(express.json());
  app.use(requestLogger);

  // Health check endpoint
  app.get('/health', (req: Request, res: Response) => {
      res.status(200).json({
          status: 'success',
          message: 'Server is healthy',
          timestamp: new Date().toISOString()
      });
  });

  // API routes
  app.use('/api', routes);

  // Error handler (must be last)
  app.use(errorHandler);

  return app;
}
/**
 * SERVER STARTUP FUNCTION
 * Handles the entire startup sequence including service checks
 */
async function startServer() {
  try {
      // Check Redis connection
      const redisHealth = await checkRedisHealth();
      if (!redisHealth.isHealthy) {
          appLogger.warn({
              error: redisHealth.error,
              timestamp: new Date().toISOString()
          }, 'Redis health check failed. Proceeding without Redis...');
      } else {
          appLogger.info({ latency: redisHealth.latency }, 'Redis health check passed');
      }

      // Check database connection
      await testConnection();
      appLogger.info('Database connection test passed');

      // Create and configure Express app
      const app = await createApp();
      const port = config.server.port || 3000;

      // Start the server
      app.listen(port, () => {
          appLogger.info({
              port,
              env: config.env,
              apiPrefix: '/api',
              redisLatency: redisHealth.latency
          }, 'Server started successfully 🚀');
      });
  } catch (error) {
      appLogger.error({
          error: error instanceof Error ? error.message : 'Unknown error',
          stack: error instanceof Error ? error.stack : undefined
      }, 'Failed to start server');

      // Exit with error code
      process.exit(1);
  }
}
/**
 * PROCESS EVENT HANDLERS
 * Handle various process events and signals
 */

// Handle uncaught exceptions
process.on('uncaughtException', (error: Error) => {
  appLogger.error({ 
      error: error.message,
      stack: error.stack,
      type: 'UncaughtException'
  }, 'Uncaught exception occurred');
  
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason: unknown, promise: Promise<unknown>) => {
  appLogger.error({ 
      reason,
      promise,
      type: 'UnhandledRejection'
  }, 'Unhandled promise rejection');
  
  process.exit(1);
});

// Handle termination signals
process.on('SIGTERM', () => {
  appLogger.info('SIGTERM signal received. Starting graceful shutdown...');
  process.exit(0);
});

process.on('SIGINT', () => {
  appLogger.info('SIGINT signal received. Starting graceful shutdown...');
  process.exit(0);
});

/**
* START THE SERVER
* Initialize the application
*/
startServer();