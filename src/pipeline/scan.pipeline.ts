import path from 'node:path';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import { appConfig } from '../config/app.config.js';
import { Logger } from '../utils/logger.util.js';
import { ScanResult } from '../types.js';

export interface PipelineOptions {
  targetPath: string;
  sessionDir: string;
  generatePdf?: boolean;
  generatePatches?: boolean;
}

export interface PipelineExecutionResult {
  success: boolean;
  durationMs: number;
  data?: ScanResult;
  error?: string;
}

export class ScanPipeline {
  /**
   * Execute the full scanning pipeline: reads codebase, dispatches AST & config analyzers,
   * detects third-party egress, checks code malfunctions, and writes PDF/patches into sessionDir.
   */
  public static async execute(options: PipelineOptions): Promise<PipelineExecutionResult> {
    const startTime = Date.now();
    const { targetPath, sessionDir } = options;

    const pythonExec = appConfig.paths.pythonVenv;
    const pythonModulePath = path.resolve(appConfig.paths.root, 'python');

    const env = {
      ...process.env,
      PYTHONPATH: process.env.PYTHONPATH ? `${pythonModulePath}:${process.env.PYTHONPATH}` : pythonModulePath,
    };

    Logger.info(`Starting audit pipeline for: ${targetPath}`, 'ScanPipeline');

    const child = spawnSync(
      pythonExec,
      ['-m', 'dpdp_audit.pipeline', '--target', targetPath, '--session-dir', sessionDir],
      {
        env,
        encoding: 'utf-8',
        maxBuffer: 50 * 1024 * 1024,
      }
    );

    const durationMs = Date.now() - startTime;

    if (child.status !== 0 || child.error) {
      const errMsg = child.stderr || child.error?.message || 'Pipeline execution failed';
      Logger.error(`Pipeline failure: ${errMsg}`, child.error, 'ScanPipeline');
      return {
        success: false,
        durationMs,
        error: errMsg,
      };
    }

    try {
      const outputJson = JSON.parse(child.stdout.trim());
      if (!outputJson.success) {
        return {
          success: false,
          durationMs,
          error: outputJson.error || 'Pipeline returned unsuccessful status',
        };
      }

      Logger.success(`Pipeline completed in ${durationMs}ms`, 'ScanPipeline');
      return {
        success: true,
        durationMs,
        data: outputJson.data as ScanResult,
      };
    } catch (parseErr: any) {
      // Check if out.json was written to disk
      const jsonFile = path.join(sessionDir, 'out.json');
      if (fs.existsSync(jsonFile)) {
        const fileData = JSON.parse(fs.readFileSync(jsonFile, 'utf-8'));
        return {
          success: true,
          durationMs,
          data: fileData as ScanResult,
        };
      }

      Logger.error('Failed to parse pipeline output JSON', parseErr, 'ScanPipeline');
      return {
        success: false,
        durationMs,
        error: `Invalid output from pipeline: ${parseErr.message}`,
      };
    }
  }
}
