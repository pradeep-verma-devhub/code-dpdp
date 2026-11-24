import path from 'node:path';
import fs from 'node:fs';

export class PathUtil {

  public static ensureDirSync(dirPath: string): string {
    const resolved = path.resolve(dirPath);
    if (!fs.existsSync(resolved)) {
      fs.mkdirSync(resolved, { recursive: true });
    }
    return resolved;
  }

  public static isSafeSubpath(baseDir: string, targetPath: string): boolean {
    const safeBase = path.resolve(baseDir);
    const resolvedTarget = path.resolve(targetPath);
    return resolvedTarget.startsWith(safeBase);
  }

  public static removeDirSync(dirPath: string): void {
    if (fs.existsSync(dirPath)) {
      fs.rmSync(dirPath, { recursive: true, force: true });
    }
  }
}
