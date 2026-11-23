import path from 'node:path';
import fs from 'node:fs';

export class PathUtil {
  /**
   * Ensure directory exists, creating parent folders recursively.
   */
  public static ensureDirSync(dirPath: string): string {
    const resolved = path.resolve(dirPath);
    if (!fs.existsSync(resolved)) {
      fs.mkdirSync(resolved, { recursive: true });
    }
    return resolved;
  }

  /**
   * Check if a path is safely contained within an allowed base directory (prevent Path Traversal / Zip Slip).
   */
  public static isSafeSubpath(baseDir: string, targetPath: string): boolean {
    const safeBase = path.resolve(baseDir);
    const resolvedTarget = path.resolve(targetPath);
    return resolvedTarget.startsWith(safeBase);
  }

  /**
   * Safely delete a directory and all its contents.
   */
  public static removeDirSync(dirPath: string): void {
    if (fs.existsSync(dirPath)) {
      fs.rmSync(dirPath, { recursive: true, force: true });
    }
  }
}
