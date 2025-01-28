//======================= IMPORTS =======================//
/**
 * WHY THESE IMPORTS?
 * 
 * 1. Express Types (Request, Response, NextFunction):
 * - Required for TypeScript to understand Express objects
 * - Provides type safety and autocomplete in your IDE
 * - Helps catch errors before running the code
 */
import { Request, Response, NextFunction } from 'express';

/**
 * 2. Custom Logger:
 * - Consistent logging format across the application
 * - Better than console.log because it:
 *   a) Adds timestamps
 *   b) Supports log levels (error, warn, info)
 *   c) Can write to files or external services
 *   d) Includes contextual information
 */
import logger from '@/utils/logger';

/**
 * 3. UUID Generator:
 * - Creates unique identifiers for each request
 * - Built into Node.js (no extra dependencies)
 * - Cryptographically secure (important for production)
 * - Format: 550e8400-e29b-41d4-a716-446655440000
 */
import { randomUUID } from 'crypto';

//=================== TYPE DEFINITIONS ===================//
/**
 * EXTENDING THE REQUEST TYPE
 * 
 * WHY DO THIS?
 * - Express's Request type doesn't include our custom properties
 * - TypeScript needs to know about these additional properties
 * - Prevents "Property 'id' does not exist on type 'Request'" errors
 * 
 * WHAT WE'RE ADDING:
 * 1. id: Unique identifier for each request
 *    - Helps track individual requests in logs
 *    - Used for debugging specific issues
 * 
 * 2. correlationId: Links related requests together
 *    - Essential for microservices architecture
 *    - Example: User checkout process might involve:
 *      a) Order service
 *      b) Payment service
 *      c) Inventory service
 *      All these would share the same correlationId
 */
type RequestWithId = Request & {
  id?: string;
  correlationId?: string;
};

//=================== UTILITY FUNCTIONS ===================//
/**
 * REQUEST DURATION CALCULATOR
 * 
 * WHY IS THIS IMPORTANT?
 * - Helps monitor application performance
 * - Identifies slow requests that need optimization
 * - Essential for maintaining good user experience
 * 
 * HOW IT WORKS:
 * 1. Takes high-resolution time from process.hrtime()
 * 2. Converts it to milliseconds
 * 3. Returns formatted string for consistency
 * 
 * WHY USE process.hrtime()?
 * - More precise than Date.now()
 * - Provides nanosecond precision
 * - Not affected by system clock changes
 * 
 * @example
 * const start = process.hrtime();
 * // ... some operation ...
 * console.log(getDuration(start)); // "123.45ms"
 */
const getDuration = (startTime: [number, number]): string => {
  const [seconds, nanoseconds] = process.hrtime(startTime);
  const duration = seconds * 1000 + nanoseconds / 1000000;
  return `${duration.toFixed(2)}ms`;
};

/**
 * REQUEST CONTEXT CREATOR
 * 
 * WHY IS THIS NEEDED?
 * - Standardizes log format across the application
 * - Captures all relevant request information in one place
 * - Makes debugging easier with consistent data structure
 * 
 * WHAT IT CAPTURES:
 * 1. requestId: Unique identifier for this request
 * 2. path: URL path being accessed
 * 3. method: HTTP method (GET, POST, etc.)
 * 4. query: URL parameters
 * 5. body: Request body data (except for GET requests)
 * 6. ip: Client's IP address
 * 7. userAgent: Client's browser/application info
 * 
 * WHY EXCLUDE BODY FOR GET REQUESTS?
 * - GET requests shouldn't have a body according to HTTP standards
 * - Prevents logging unnecessary data
 * - Keeps logs cleaner
 */
const createRequestContext = (req: RequestWithId) => ({
  requestId: req.id,
  path: req.path,
  method: req.method,
  query: req.query,
  body: req.method !== 'GET' ? req.body : undefined,
  ip: req.ip,
  userAgent: req.get('user-agent'),
  handler: 'requestLogger'
});

//=================== MIDDLEWARE FUNCTIONS ===================//
/**
 * MAIN REQUEST LOGGER MIDDLEWARE
 * 
 * PURPOSE:
 * - Tracks every request to your application
 * - Provides debugging information
 * - Monitors application performance
 * - Helps with security auditing
 * 
 * HOW IT WORKS:
 * 1. Request comes in
 * 2. Generate unique ID
 * 3. Start timing
 * 4. Log request details
 * 5. Wait for completion
 * 6. Log response details
 * 
 * WHY ALL THIS LOGGING?
 * - Helps debug production issues
 * - Monitors application health
 * - Tracks user behavior
 * - Identifies performance issues
 * - Assists in security monitoring
 */
export const requestLogger = (
  req: RequestWithId,
  res: Response,
  next: NextFunction
) => {
  /**
   * Step 1: Generate Unique ID
   * WHY? 
   * - Tracks specific requests through the system
   * - Essential for debugging in production
   * - Links log entries from the same request
   */
  req.id = randomUUID();

  /**
   * Step 2: Start Timer
   * WHY?
   * - Measures request duration
   * - Helps identify slow requests
   * - Important for performance monitoring
   */
  const startTime = process.hrtime();

  /**
   * Step 3: Create Context
   * WHY?
   * - Organizes request information
   * - Makes logs consistent
   * - Easier to analyze later
   */
  const context = createRequestContext(req);
  const requestLogger = logger.child(context);

  /**
   * Step 4: Log Initial Request
   * WHY?
   * - Confirms receipt of request
   * - Starts the request trail
   * - Useful for traffic analysis
   */
  requestLogger.info('Incoming request');

  /**
   * Step 5: Setup Response Logging
   * WHY?
   * - Captures response status
   * - Records request duration
   * - Completes the request trail
   */
  res.on('finish', () => {
    requestLogger.info({
      statusCode: res.statusCode,
      duration: getDuration(startTime)
    }, 'Request completed');
  });

  /**
   * Step 6: Setup Error Logging
   * WHY?
   * - Catches unexpected errors
   * - Helps with debugging
   * - Important for error tracking
   */
  req.on('error', (error) => {
    requestLogger.error({ error }, 'Request error');
  });

  /**
   * Step 7: Add Request ID to Headers
   * WHY?
   * - Allows client to reference specific requests
   * - Useful for support tickets
   * - Helps with client-side debugging
   */
  res.setHeader('X-Request-Id', req.id);

  /**
   * Step 8: Continue Chain
   * WHY?
   * - Passes request to next middleware
   * - Keeps application flow going
   * - Required for Express middleware
   */
  next();
};

/**
 * CORRELATION ID MIDDLEWARE
 * 
 * WHAT IS A CORRELATION ID?
 * - A unique identifier that follows a request through multiple services
 * - Like a tracking number for a package that goes through multiple carriers
 * 
 * WHY DO WE NEED IT?
 * - Essential for microservices architecture
 * - Tracks requests across multiple services
 * - Helps debug complex operations
 * 
 * EXAMPLE USE CASE:
 * User checkout process might involve:
 * 1. Cart service
 * 2. Payment service
 * 3. Inventory service
 * 4. Notification service
 * All these services will use the same correlationId
 */
export const addCorrelationId = (
  req: RequestWithId,
  res: Response,
  next: NextFunction
) => {
  // Either use existing ID or create new one
  const correlationId = req.get('X-Correlation-Id') || randomUUID();
  
  // Make ID available to application code
  req.correlationId = correlationId;
  
  // Make ID available to client
  res.setHeader('X-Correlation-Id', correlationId);
  
  // Continue middleware chain
  next();
};