import { Router } from 'express';
import { auditRouter } from './audit.routes.js';

export const apiRouter = Router();

// Health check endpoint
apiRouter.get('/health', (_req, res) => {
  res.status(200).json({
    status: 'UP',
    platform: 'DPDP-Audit Compliance Engine',
    timestamp: new Date().toISOString(),
  });
});

// Audit routes
apiRouter.use(auditRouter);
