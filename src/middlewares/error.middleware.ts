// src/middlewares/error.middleware.ts
import { Request, Response, NextFunction, ErrorRequestHandler } from 'express';
import { ZodError } from 'zod';
import logger from '@/utils/logger';

type AppError = {
  statusCode: number;
  message: string;
  error?: any;
};

const createError = (
  statusCode: number, 
  message: string, 
  error?: any
): AppError => ({
  statusCode,
  message,
  error
});

export const errorHandler: ErrorRequestHandler = (
  err: Error | AppError | ZodError,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const errorLogger = logger.child({ 
    handler: 'errorHandler',
    path: req.path,
    method: req.method 
  });

  errorLogger.error({ err }, 'Error occurred');

  if (err instanceof ZodError) {
    res.status(400).json({
      status: 'error',
      message: 'Validation error',
      errors: err.errors
    });
    return;
  }

  // Handle custom app errors
  if ('statusCode' in err) {
    res.status(err.statusCode).json({
      status: 'error',
      message: err.message,
      ...(process.env.NODE_ENV === 'development' && { error: err.error })
    });
    return;
  }

  // Handle JWT errors
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

  // Handle database errors
  if ('code' in err) {
    switch (err.code) {
      case '23505': // PostgreSQL unique violation
        res.status(409).json({
          status: 'error',
          message: 'Resource already exists'
        });
        return;
      case '23503': // PostgreSQL foreign key violation
        res.status(400).json({
          status: 'error',
          message: 'Invalid reference'
        });
        return;
    }
  }

  // Default error
  const statusCode = res.statusCode !== 200 ? res.statusCode : 500;
  res.status(statusCode).json({
    status: 'error',
    message: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message,
    ...(process.env.NODE_ENV === 'development' && { 
      stack: err.stack 
    })
  });
};