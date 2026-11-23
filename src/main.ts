import express, { Express, Request, Response, NextFunction } from 'express';
import { appConfig } from './config/app.config.js';
import { apiRouter } from './routes/index.js';
import { Logger } from './utils/logger.util.js';
import { PathUtil } from './utils/path.util.js';
import pc from 'picocolors';

export function createApp(): Express {
  const app = express();

  // Ensure directories exist
  PathUtil.ensureDirSync(appConfig.paths.public);
  PathUtil.ensureDirSync(appConfig.paths.uploads);

  // Global Middleware
  app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ extended: true, limit: '50mb' }));

  // Static Frontend Assets
  app.use(express.static(appConfig.paths.public));

  // Mount API Router
  app.use('/api', apiRouter);

  // Global Error Handler
  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    Logger.error('Unhandled request error', err, 'Main');
    const statusCode = err.status || err.statusCode || 500;
    res.status(statusCode).json({
      success: false,
      error: err.message || 'Internal Server Error',
    });
  });

  return app;
}

export function startServer(port = appConfig.port): ReturnType<Express['listen']> {
  const app = createApp();
  return app.listen(port, () => {
    console.log(pc.bold(pc.green(`\n=================================================================`)));
    console.log(pc.bold(pc.cyan(` [DPDP-Audit] Enterprise Compliance Platform Live!`)));
    console.log(pc.bold(pc.white(` Architecture: `) + pc.yellow(`Config -> Utils -> Pipeline -> Service -> Controller -> Router`)));
    console.log(pc.bold(pc.white(` Dashboard URL: `) + pc.green(`http://localhost:${port}`)));
    console.log(pc.bold(pc.green(`=================================================================\n`)));
  });
}

// Auto-run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  startServer();
}
