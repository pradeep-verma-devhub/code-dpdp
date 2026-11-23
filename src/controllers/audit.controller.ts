import { Request, Response, NextFunction } from 'express';
import { AuditService } from '../services/audit.service.js';
import { Logger } from '../utils/logger.util.js';

export class AuditController {
  /**
   * POST /api/scan-zip
   * Accepts .zip file upload and executes complete audit pipeline.
   */
  public static async uploadAndScan(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!req.file) {
        res.status(400).json({
          success: false,
          error: 'No .zip archive uploaded. Please attach a codebase zip file under the field "codebase".',
        });
        return;
      }

      Logger.info(`Received zip upload: ${req.file.originalname} (${req.file.size} bytes)`, 'AuditController');

      const result = await AuditService.scanZipArchive(req.file.path, req.file.originalname);

      if (!result.success) {
        res.status(500).json(result);
        return;
      }

      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/scan-sample
   * Executes audit on pre-configured benchmark codebase (OWASP Juice Shop).
   */
  public static async scanSample(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      Logger.info('Received sample benchmark scan request', 'AuditController');
      const result = await AuditService.scanSampleCodebase();

      if (!result.success) {
        res.status(500).json(result);
        return;
      }

      res.status(200).json(result);
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/download-pdf/:sessionId
   * Streams the generated PDF compliance report.
   */
  public static async downloadPdf(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const sessionId = String(req.params.sessionId);
      const pdfPath = AuditService.getPdfReportPath(sessionId);

      if (!pdfPath) {
        res.status(404).json({
          success: false,
          error: 'Compliance PDF report not found for the requested session.',
        });
        return;
      }

      res.download(pdfPath, 'DPDP_Compliance_Report.pdf');
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/download-patches/:sessionId
   * Streams the generated unified diff patch file.
   */
  public static async downloadPatches(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const sessionId = String(req.params.sessionId);
      const patchPath = AuditService.getPatchesPath(sessionId);

      if (!patchPath) {
        res.status(404).json({
          success: false,
          error: 'Remediation patches not found for the requested session.',
        });
        return;
      }

      res.download(patchPath, 'dpdp_remediations.patch');
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/rules
   * Returns all 46 external YAML rules and DPDP statutory provisions.
   */
  public static async getRules(_req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const rulesData = AuditService.getRegisteredRules();
      res.status(200).json({
        success: true,
        count: rulesData.rules.length,
        rules: rulesData.rules,
        dpdpMap: rulesData.dpdpMap,
      });
    } catch (err) {
      next(err);
    }
  }
}
