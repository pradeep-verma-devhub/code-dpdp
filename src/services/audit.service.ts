import path from 'node:path';
import fs from 'node:fs';
import { appConfig } from '../config/app.config.js';
import { PathUtil } from '../utils/path.util.js';
import { ArchiveUtil } from '../utils/archive.util.js';
import { Logger } from '../utils/logger.util.js';
import { ScanPipeline } from '../pipeline/scan.pipeline.js';
import { RuleLoader } from '../rules/loader.js';
import { ScanResult, RuleDefinition, DPDPRef } from '../types.js';

export interface ScanServiceResult {
  success: boolean;
  sessionId: string;
  targetName: string;
  durationMs: number;
  data?: ScanResult;
  error?: string;
}

export class AuditService {

  public static async scanZipArchive(
    zipFilePath: string,
    originalFileName: string
  ): Promise<ScanServiceResult> {
    const sessionId = `session-${Date.now()}-${Math.round(Math.random() * 1e6)}`;
    const sessionDir = path.join(appConfig.paths.uploads, sessionId);
    const extractDir = path.join(sessionDir, 'extracted');

    PathUtil.ensureDirSync(extractDir);

    try {

      const extractResult = ArchiveUtil.extractZip(zipFilePath, extractDir);
      if (!extractResult.success) {
        throw new Error(extractResult.error || 'Failed to extract .zip archive');
      }

      if (fs.existsSync(zipFilePath)) {
        fs.unlinkSync(zipFilePath);
      }

      const pipelineResult = await ScanPipeline.execute({
        targetPath: extractDir,
        sessionDir,
        generatePdf: true,
        generatePatches: true,
      });

      if (!pipelineResult.success || !pipelineResult.data) {
        throw new Error(pipelineResult.error || 'Audit pipeline execution failed');
      }

      return {
        success: true,
        sessionId,
        targetName: originalFileName.replace(/\.zip$/i, ''),
        durationMs: pipelineResult.durationMs,
        data: pipelineResult.data,
      };
    } catch (err: any) {
      Logger.error(`AuditService.scanZipArchive failed for ${originalFileName}`, err, 'AuditService');
      return {
        success: false,
        sessionId,
        targetName: originalFileName,
        durationMs: 0,
        error: err.message || 'Internal audit service error',
      };
    }
  }

  public static async scanSampleCodebase(): Promise<ScanServiceResult> {
    const sampleDir = appConfig.paths.sampleTarget;

    if (!fs.existsSync(sampleDir)) {
      return {
        success: false,
        sessionId: '',
        targetName: 'OWASP Juice Shop',
        durationMs: 0,
        error: `Sample directory not found at ${sampleDir}. Ensure target is cloned.`,
      };
    }

    const sessionId = `sample-${Date.now()}`;
    const sessionDir = path.join(appConfig.paths.uploads, sessionId);
    PathUtil.ensureDirSync(sessionDir);

    const pipelineResult = await ScanPipeline.execute({
      targetPath: sampleDir,
      sessionDir,
      generatePdf: true,
      generatePatches: true,
    });

    if (!pipelineResult.success || !pipelineResult.data) {
      return {
        success: false,
        sessionId,
        targetName: 'OWASP Juice Shop',
        durationMs: pipelineResult.durationMs,
        error: pipelineResult.error || 'Failed to scan sample repository',
      };
    }

    return {
      success: true,
      sessionId,
      targetName: 'OWASP Juice Shop (Benchmark)',
      durationMs: pipelineResult.durationMs,
      data: pipelineResult.data,
    };
  }

  public static getPdfReportPath(sessionId: string): string | null {
    const sessionPdf = path.join(appConfig.paths.uploads, sessionId, 'report.pdf');
    if (fs.existsSync(sessionPdf)) {
      return sessionPdf;
    }

    const rootPdf = path.resolve(appConfig.paths.root, 'report.pdf');
    if (fs.existsSync(rootPdf)) {
      return rootPdf;
    }

    return null;
  }

  public static getPatchesPath(sessionId: string): string | null {
    const sessionPatch = path.join(appConfig.paths.uploads, sessionId, 'patches', 'all_remediations.patch');
    if (fs.existsSync(sessionPatch)) {
      return sessionPatch;
    }

    const rootPatch = path.resolve(appConfig.paths.root, 'patches', 'all_remediations.patch');
    if (fs.existsSync(rootPatch)) {
      return rootPatch;
    }

    return null;
  }

  public static getRegisteredRules(): { rules: RuleDefinition[]; dpdpMap: Record<string, DPDPRef> } {
    const { dpdpMap, rules } = RuleLoader.loadRules(appConfig.paths.rules);
    return { rules, dpdpMap };
  }
}
