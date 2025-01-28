// src/index.ts
import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import { testConnection } from './db/config';
import logger from './utils/logger';
import { config } from './config';
import { errorHandler } from './middlewares/error.middleware';
import { requestLogger } from './middlewares/logging.middleware';
import routes from '@/api/routes';

const appLogger = logger.child({ module: 'app' });

async function createApp() {
  const app = express();

  // Basic middlewares
  app.use(helmet());
  app.use(cors());
  app.use(compression());
  app.use(express.json());
  app.use(requestLogger);

  // API routes with prefix
  app.use('/api', routes);

  // Error handler must be after all other middleware and routes
  app.use(errorHandler);

  return app;
}

async function startServer() {
  try {
    await testConnection();
    const app = await createApp();
    
    const port = config.server.port || 3000;
    app.listen(port, () => {
      appLogger.info(
        { 
          port,
          env: config.env 
        },
        'Server started successfully'
      );
    });
  } catch (error) {
    appLogger.error({ error }, 'Failed to start server');
    process.exit(1);
  }
}

startServer();