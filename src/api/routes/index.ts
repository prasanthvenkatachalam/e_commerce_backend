import { Router } from 'express';

/**
 * REQUEST AND RESPONSE TYPES
 * Why import these?
 * - Provides TypeScript type safety
 * - Enables better IDE autocomplete
 * - Helps catch errors during development
 *
 * Example:
 * req.query.page -> TypeScript knows this might be undefined
 */
import type { Request, Response, NextFunction } from 'express';

/**
 * CUSTOM LOGGER
 * Why use a custom logger?
 * - Consistent log format
 * - Better than console.log
 * - Supports different log levels
 * - Can write to files/services
 */
import logger from '@/utils/logger';

// Import auth routes
import authRoutes from './auth.routes';



//======================= ROUTER SETUP =======================//
/**
 * CREATE EXPRESS ROUTER
 * Why create a new router?
 * - Modular routing
 * - Better code organization
 * - Can be mounted at different paths
 * - Easier to maintain
 */
const router = Router();

/**
 * CREATE ROUTE-SPECIFIC LOGGER
 * Why create a child logger?
 * - Adds 'routes' context to all logs
 * - Makes debugging easier
 * - Helps track route-specific issues
 *
 * Example log output:
 * {
 *   module: 'routes',
 *   message: 'Test route accessed',
 *   timestamp: '2024-01-28T...'
 * }
 */
const routeLogger = logger.child({ module: 'routes' });

//======================= HEALTH CHECK ROUTE =======================//
/**
 * HEALTH CHECK ENDPOINT
 * Purpose:
 * - Monitors application health
 * - Used by load balancers
 * - Kubernetes readiness/liveness probes
 * - DevOps monitoring
 *
 * When to use:
 * - Container orchestration
 * - Cloud deployments
 * - Monitoring systems
 *
 * Example usage:
 * curl http://your-api/health
 */
router.get('/health', (req: Request, res: Response) => {
    res.status(200).json({
        status: 'success',
        message: 'Server is healthy'
    });
});

//======================= TEST ROUTE =======================//
/**
 * TEST ENDPOINT
 * Purpose:
 * - Verifies API is working
 * - Tests logging system
 * - Simple ping endpoint
 *
 * Why log access?
 * - Tracks test endpoint usage
 * - Helps debug deployment issues
 * - Monitors unauthorized testing
 *
 * Example usage:
 * curl http://your-api/test
 */
router.get('/test', (req: Request, res: Response) => {
    // Log that this route was accessed
    routeLogger.info('Test route accessed');

    // Send success response
    res.status(200).json({
        status: 'success',
        message: 'Test route works!'
    });
});

// Mount the auth routes
router.use('/auth', authRoutes);

//======================= 404 HANDLER =======================//
/**
 * 404 NOT FOUND HANDLER
 * Purpose:
 * - Catches undefined routes
 * - Provides consistent 404 response
 * - Logs attempted access to invalid routes
 *
 * Why use router.use?
 * - Catches all HTTP methods (GET, POST, etc.)
 * - Acts as a catch-all middleware
 * - Runs after all other routes
 *
 * Security benefit:
 * - Logs potential security probe attempts
 * - Helps identify misconfigured clients
 * - Tracks invalid route access patterns
 *
 * Example scenario:
 * Request to /api/nonexistent-route will:
 * 1. Log a warning with the path
 * 2. Return 404 status
 * 3. Send JSON error response
 */
router.use((req: Request, res: Response) => {
    // Log the attempted access with path
    routeLogger.warn({
        path: req.path  // Log which path was attempted
    }, 'Route not found');

    // Send consistent 404 response
    res.status(404).json({
        status: 'error',
        message: 'Route not found'
    });
});

/**
 * EXPORT ROUTER
 * Why default export?
 * - Single router per file
 * - Clear import syntax
 * - Common Express pattern
 *
 * Usage in main app:
 * import routes from './routes';
 * app.use('/api', routes);
 */
export default router;

/**
 * COMPLETE USAGE EXAMPLE:
 *
 * // In your main app.ts:
 * import express from 'express';
 * import routes from './routes';
 *
 * const app = express();
 *
 * // Mount routes with /api prefix
 * app.use('/api', routes);
 *
 * // Now your endpoints are:
 * // - GET /api/health
 * // - GET /api/test
 * // - 404 handler for any other /api/* routes
 */