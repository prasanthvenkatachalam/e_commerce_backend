// src/index.ts

//======================= IMPORTS =======================//
/**
 * ENVIRONMENT VARIABLES
 * Why import first?
 * - Must load environment variables before anything else
 * - Ensures config is available to other modules
 * - Required for configuration
 */
import 'dotenv/config';

/**
 * EXPRESS FRAMEWORK
 * Why Express?
 * - Popular Node.js web framework
 * - Easy to use and understand
 * - Large ecosystem of middleware
 * - Great for REST APIs
 */
import express from 'express';

/**
 * SECURITY MIDDLEWARE
 * Why Helmet?
 * - Sets security HTTP headers
 * - Protects against common web vulnerabilities
 * - Industry standard security practice
 * Examples:
 * - XSS Protection
 * - Content Security Policy
 * - Prevent Clickjacking
 */
import helmet from 'helmet';

/**
 * CORS MIDDLEWARE
 * Why CORS?
 * - Enables Cross-Origin Resource Sharing
 * - Required for frontend to backend communication
 * - Controls which domains can access your API
 * - Essential for web applications
 */
import cors from 'cors';

/**
 * COMPRESSION MIDDLEWARE
 * Why Compression?
 * - Compresses response bodies
 * - Reduces bandwidth usage
 * - Faster response times
 * - Better user experience
 */
import compression from 'compression';

/**
 * DATABASE CONNECTION TEST
 * Why test connection?
 * - Ensures database is available
 * - Fails fast if database is down
 * - Required for application startup
 */
import { testConnection } from './db/config';

/**
 * CUSTOM LOGGER
 * Why custom logger?
 * - Consistent logging format
 * - Better than console.log
 * - Structured logging
 * - Environment-based configuration
 */
import logger from './utils/logger';

/**
 * APPLICATION CONFIGURATION
 * Why centralized config?
 * - Single source of truth
 * - Environment-based settings
 * - Easy to maintain
 * - Type-safe configuration
 */
import { config } from './config';

/**
 * ERROR HANDLING MIDDLEWARE
 * Why centralized error handling?
 * - Consistent error responses
 * - Better error tracking
 * - Cleaner code
 * - Proper error logging
 */
import { errorHandler } from './middlewares/error.middleware';

/**
 * REQUEST LOGGING MIDDLEWARE
 * Why log requests?
 * - Track API usage
 * - Debug issues
 * - Monitor performance
 * - Audit trail
 */
import { requestLogger } from './middlewares/logging.middleware';

/**
 * API ROUTES
 * Why separate routes?
 * - Better organization
 * - Modular code
 * - Easier to maintain
 * - Clear structure
 */
import routes from '@/api/routes';

//======================= LOGGER SETUP =======================//
/**
 * APPLICATION LOGGER
 * Why create a child logger?
 * - Adds 'app' context to all logs
 * - Makes debugging easier
 * - Groups application-level logs
 */
const appLogger = logger.child({ module: 'app' });

//======================= APPLICATION SETUP =======================//
/**
 * CREATE EXPRESS APPLICATION
 * Why separate function?
 * - Clean initialization
 * - Better error handling
 * - Easy to test
 * - Clear middleware order
 */
async function createApp() {
  const app = express();

  /**
   * MIDDLEWARE STACK
   * Order is important!
   * 
   * 1. helmet() - Security headers first
   * 2. cors() - Handle cross-origin requests
   * 3. compression() - Compress responses
   * 4. express.json() - Parse JSON requests
   * 5. requestLogger - Log all requests
   * 6. routes - API endpoints
   * 7. errorHandler - Catch all errors
   */
  app.use(helmet());         // Security
  app.use(cors());          // Cross-origin
  app.use(compression());   // Response compression
  app.use(express.json());  // Body parsing
  app.use(requestLogger);   // Request logging

  // Mount API routes with prefix
  app.use('/api', routes);

  // Error handler must be last
  app.use(errorHandler);

  return app;
}

//======================= SERVER STARTUP =======================//
/**
 * START SERVER
 * Why separate function?
 * - Sequential startup
 * - Proper error handling
 * - Clear startup process
 * - Easy to extend
 */
async function startServer() {
  try {
    /**
     * STARTUP SEQUENCE
     * 1. Test database connection
     * 2. Create Express application
     * 3. Start listening on port
     */
    await testConnection();
    const app = await createApp();
    
    // Get port from config or use default
    const port = config.server.port || 3000;

    // Start server
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
    /**
     * FATAL ERROR HANDLING
     * Why exit process?
     * - Can't run without critical services
     * - Clear error indication
     * - Allows process manager to restart
     */
    appLogger.error({ error }, 'Failed to start server');
    process.exit(1);
  }
}

/**
 * START APPLICATION
 * Why immediate invocation?
 * - Begins startup process
 * - No need to call explicitly
 * - Clear entry point
 */
startServer();

/**
 * USAGE AND CONSIDERATIONS:
 * 
 * 1. Environment Variables:
 *    - Set NODE_ENV appropriately
 *    - Configure ports and hosts
 *    - Set security keys
 * 
 * 2. Production Setup:
 *    - Use process manager (PM2/Nodemon)
 *    - Set up monitoring
 *    - Configure proper logging
 * 
 * 3. Development:
 *    - Use nodemon for auto-reload
 *    - Set DEBUG env for more logs
 *    - Use development config
 * 
 * 4. Testing:
 *    - Export app for testing
 *    - Use test database
 *    - Mock external services
 */

/**
 * EXAMPLE TEST SETUP:
 * 
 * import { createApp } from './index';
 * import request from 'supertest';
 * 
 * describe('API Tests', () => {
 *   let app;
 *   
 *   beforeAll(async () => {
 *     app = await createApp();
 *   });
 * 
 *   it('should respond to health check', async () => {
 *     const response = await request(app).get('/api/health');
 *     expect(response.status).toBe(200);
 *   });
 * });
 */