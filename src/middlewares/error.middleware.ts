// src/middlewares/error.middleware.ts

//======================= IMPORTS =======================//
/**
 * EXPRESS TYPES
 * Why these imports?
 * - Request: Type for incoming HTTP requests
 * - Response: Type for server responses
 * - NextFunction: Type for passing control to next middleware
 * - ErrorRequestHandler: Special type for error handling middleware
 */
import { Request, Response, NextFunction, ErrorRequestHandler } from 'express';

/**
 * ZOD ERROR TYPE
 * Why Zod?
 * - Used for request validation
 * - Provides strong TypeScript integration
 * - Helps catch invalid data before processing
 * Example: Validating user registration data
 */
import { ZodError } from 'zod';

/**
 * CUSTOM LOGGER
 * Why custom logger?
 * - Consistent error logging format
 * - Better than console.error()
 * - Supports different log levels
 * - Can send logs to external services
 */
import logger from '@/utils/logger';

//======================= TYPE DEFINITIONS =======================//
/**
 * CUSTOM ERROR TYPE
 * Why create a custom error type?
 * - Standardizes error structure across application
 * - Includes HTTP status codes
 * - Makes error handling predictable
 * 
 * Properties:
 * - statusCode: HTTP status code (e.g., 400, 401, 500)
 * - message: Human-readable error message
 * - error?: Optional additional error details
 * 
 * Example usage:
 * throw createError(404, 'User not found');
 */
type AppError = {
  statusCode: number;  // HTTP status code
  message: string;     // Error message
  error?: any;         // Additional error details (optional)
};

//======================= ERROR FACTORY =======================//
/**
 * ERROR CREATOR FUNCTION
 * Why have this?
 * - Creates consistent error objects
 * - Makes error creation cleaner
 * - Ensures all required fields are present
 * 
 * @example
 * // Create a not found error
 * const error = createError(404, 'User not found');
 * 
 * // Create an error with additional details
 * const error = createError(400, 'Validation failed', validationErrors);
 */
const createError = (
  statusCode: number, 
  message: string, 
  error?: any
): AppError => ({
  statusCode,
  message,
  error
});

//======================= MAIN ERROR HANDLER =======================//
/**
 * GLOBAL ERROR HANDLING MIDDLEWARE
 * 
 * PURPOSE:
 * - Catches all unhandled errors in the application
 * - Provides consistent error responses
 * - Handles different types of errors differently
 * - Logs errors for debugging
 * 
 * HOW TO USE:
 * 1. Add this middleware last in your Express app
 * 2. Errors will be caught and handled automatically
 * 
 * TYPES OF ERRORS HANDLED:
 * 1. Validation Errors (Zod)
 * 2. Custom Application Errors
 * 3. JWT Authentication Errors
 * 4. Database Errors
 * 5. Generic Errors
 */
export const errorHandler: ErrorRequestHandler = (
  err: Error | AppError | ZodError,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  /**
   * CREATE ERROR LOGGER
   * Why?
   * - Adds request context to error logs
   * - Makes debugging easier
   * - Tracks where errors occur
   */
  const errorLogger = logger.child({ 
    handler: 'errorHandler',
    path: req.path,      // Which endpoint failed
    method: req.method   // Which HTTP method failed
  });

  // Log the error for debugging
  errorLogger.error({ err }, 'Error occurred');

  /**
   * HANDLE VALIDATION ERRORS
   * When does this happen?
   * - Invalid request data
   * - Missing required fields
   * - Wrong data types
   * 
   * Example:
   * {
   *   email: "invalid email format",
   *   age: "must be a number"
   * }
   */
  if (err instanceof ZodError) {
    res.status(400).json({
      status: 'error',
      message: 'Validation error',
      errors: err.errors  // Detailed validation errors
    });
    return;
  }

  /**
   * HANDLE CUSTOM APP ERRORS
   * When does this happen?
   * - Business logic errors
   * - Known error conditions
   * - Controlled failure cases
   * 
   * Example:
   * throw createError(404, 'Product not found');
   */
  if ('statusCode' in err) {
    res.status(err.statusCode).json({
      status: 'error',
      message: err.message,
      // Only include error details in development
      ...(process.env.NODE_ENV === 'development' && { error: err.error })
    });
    return;
  }

  /**
   * HANDLE JWT ERRORS
   * When does this happen?
   * - Invalid authentication tokens
   * - Expired tokens
   * - Tampered tokens
   */
  if (err.name === 'JsonWebTokenError') {
    res.status(401).json({
      status: 'error',
      message: 'Invalid token'
    });
    return;
  }

  if (err.name === 'TokenExpiredError') {
    res.status(401).json({
      status: 'error',
      message: 'Token expired'
    });
    return;
  }

  /**
   * HANDLE DATABASE ERRORS
   * Why check error codes?
   * - Different DB errors need different responses
   * - Helps provide meaningful error messages
   * - Maintains security by not exposing DB details
   * 
   * Common PostgreSQL Error Codes:
   * 23505 - Unique violation (duplicate key)
   * 23503 - Foreign key violation (invalid reference)
   */
  if ('code' in err) {
    switch (err.code) {
      case '23505': // Unique violation
        res.status(409).json({
          status: 'error',
          message: 'Resource already exists'
        });
        return;
      case '23503': // Foreign key violation
        res.status(400).json({
          status: 'error',
          message: 'Invalid reference'
        });
        return;
    }
  }

  /**
   * HANDLE DEFAULT/UNKNOWN ERRORS
   * Why needed?
   * - Catches any unhandled errors
   * - Provides safe error response
   * - Prevents application crash
   * 
   * Security Considerations:
   * - Don't expose error details in production
   * - Only show stack trace in development
   * - Use generic messages for unknown errors
   */
  const statusCode = res.statusCode !== 200 ? res.statusCode : 500;
  res.status(statusCode).json({
    status: 'error',
    // Use generic message in production, actual message in development
    message: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message,
    // Only include stack trace in development
    ...(process.env.NODE_ENV === 'development' && { 
      stack: err.stack 
    })
  });
};

/**
 * USAGE EXAMPLE:
 * 
 * // In your Express app:
 * import { errorHandler } from './middlewares/error.middleware';
 * 
 * // Add other middlewares first
 * app.use(express.json());
 * app.use(routes);
 * 
 * // Add error handler last
 * app.use(errorHandler);
 * 
 * // In your routes/controllers:
 * try {
 *   // Some operation that might fail
 *   throw createError(404, 'User not found');
 * } catch (error) {
 *   next(error);  // Pass to error handler
 * }
 */