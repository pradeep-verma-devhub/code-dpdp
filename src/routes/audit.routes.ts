import { Router } from 'express';
import multer from 'multer';
import { appConfig } from '../config/app.config.js';
import { PathUtil } from '../utils/path.util.js';
import { AuditController } from '../controllers/audit.controller.js';

export const auditRouter = Router();

// Configure Multer storage
const uploadDestination = PathUtil.ensureDirSync(appConfig.paths.uploads);

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, uploadDestination);
  },
  filename: (_req, file, cb) => {
    const timestamp = Date.now();
    const random = Math.round(Math.random() * 1e9);
    cb(null, `upload-${timestamp}-${random}-${file.originalname}`);
  },
});

const uploadMiddleware = multer({
  storage,
  limits: { fileSize: appConfig.upload.maxSizeBytes },
  fileFilter: (_req, file, cb) => {
    const isZip = file.originalname.toLowerCase().endsWith('.zip') ||
      appConfig.upload.allowedMimeTypes.includes(file.mimetype);

    if (isZip) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file format. Only .zip archives are accepted.'));
    }
  },
});

// Route mappings
auditRouter.post('/scan-zip', uploadMiddleware.single('codebase'), AuditController.uploadAndScan);
auditRouter.post('/scan-sample', AuditController.scanSample);
auditRouter.get('/download-pdf/:sessionId', AuditController.downloadPdf);
auditRouter.get('/download-patches/:sessionId', AuditController.downloadPatches);
auditRouter.get('/rules', AuditController.getRules);
