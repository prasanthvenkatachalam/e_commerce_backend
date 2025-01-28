// src/routes/index.ts
import { Router } from 'express';
import type { Request, Response } from 'express';
import logger from '@/utils/logger';

const router = Router();
const routeLogger = logger.child({ module: 'routes' });

// Health check route
router.get('/health', (req: Request, res: Response) => {
  res.status(200).json({ 
    status: 'success',
    message: 'Server is healthy' 
  });
});

// Test route
router.get('/test', (req: Request, res: Response) => {
  routeLogger.info('Test route accessed');
  res.status(200).json({ 
    status: 'success',
    message: 'Test route works!' 
  });
});

// 404 handler for undefined routes
router.use((req: Request, res: Response) => {
  routeLogger.warn({ path: req.path }, 'Route not found');
  res.status(404).json({ 
    status: 'error',
    message: 'Route not found' 
  });
});

export default router;