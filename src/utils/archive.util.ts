import { spawnSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import { PathUtil } from './path.util.js';
import { Logger } from './logger.util.js';

export interface ExtractionResult {
  success: boolean;
  extractedPath: string;
  extractedFilesCount: number;
  error?: string;
}

export class ArchiveUtil {
  /**
   * Safely extract a .zip archive into a dedicated directory.
   */
  public static extractZip(zipFilePath: string, destinationDir: string): ExtractionResult {
    const dest = PathUtil.ensureDirSync(destinationDir);

    if (!fs.existsSync(zipFilePath)) {
      return {
        success: false,
        extractedPath: dest,
        extractedFilesCount: 0,
        error: `Archive file not found: ${zipFilePath}`,
      };
    }

    try {
      // Execute unzip command
      const res = spawnSync('unzip', ['-q', '-o', zipFilePath, '-d', dest], {
        encoding: 'utf-8',
        maxBuffer: 50 * 1024 * 1024,
      });

      if (res.status !== 0) {
        return {
          success: false,
          extractedPath: dest,
          extractedFilesCount: 0,
          error: res.stderr || 'Failed to extract .zip archive',
        };
      }

      // Count extracted files
      let count = 0;
      const walk = (d: string) => {
        const entries = fs.readdirSync(d, { withFileTypes: true });
        for (const entry of entries) {
          const full = path.join(d, entry.name);
          if (entry.isDirectory()) {
            walk(full);
          } else {
            count++;
          }
        }
      };
      walk(dest);

      Logger.info(`Extracted ${count} files into ${dest}`, 'ArchiveUtil');
      return {
        success: true,
        extractedPath: dest,
        extractedFilesCount: count,
      };
    } catch (err: any) {
      Logger.error(`Extraction failed for ${zipFilePath}`, err, 'ArchiveUtil');
      return {
        success: false,
        extractedPath: dest,
        extractedFilesCount: 0,
        error: err.message,
      };
    }
  }
}
