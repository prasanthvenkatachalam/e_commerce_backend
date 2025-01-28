// src/middlewares/logging.middleware.ts
import { Request, Response, NextFunction } from 'express';
import logger from '@/utils/logger';
import { randomUUID } from 'crypto';

// Type for extended request
type RequestWithId = Request & {
  id?: string;
  correlationId?: string;
};

// Calculate request duration
const getDuration = (startTime: [number, number]): string => {
  const [seconds, nanoseconds] = process.hrtime(startTime);
  const duration = seconds * 1000 + nanoseconds / 1000000;
  return `${duration.toFixed(2)}ms`;
};

// Create request context
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

export const requestLogger = (
  req: RequestWithId,
  res: Response,
  next: NextFunction
) => {
  // Generate unique request ID
  req.id = randomUUID();

  // Get request start time
  const startTime = process.hrtime();

  // Create request context
  const context = createRequestContext(req);

  // Get child logger with context
  const requestLogger = logger.child(context);

  // Log incoming request
  requestLogger.info('Incoming request');

  // Log response when finished
  res.on('finish', () => {
    requestLogger.info({
      statusCode: res.statusCode,
      duration: getDuration(startTime)
    }, 'Request completed');
  });

  // Log if request errors
  req.on('error', (error) => {
    requestLogger.error({ error }, 'Request error');
  });

  // Add request ID to response headers
  res.setHeader('X-Request-Id', req.id);

  next();
};

export const addCorrelationId = (
  req: RequestWithId,
  res: Response,
  next: NextFunction
) => {
  const correlationId = req.get('X-Correlation-Id') || randomUUID();
  req.correlationId = correlationId;
  res.setHeader('X-Correlation-Id', correlationId);
  next();
};