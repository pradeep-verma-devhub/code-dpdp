import path from 'node:path';
import fs from 'node:fs';

export interface AppConfig {
  env: string;
  port: number;
  paths: {
    root: string;
    public: string;
    uploads: string;
    rules: string;
    sampleTarget: string;
    pythonVenv: string;
  };
  upload: {
    maxSizeBytes: number;
    allowedMimeTypes: string[];
    allowedExtensions: string[];
  };
  statutory: {
    maxPenaltyCrores: number;
    statutoryAct: string;
    rulesVersion: string;
  };
}

const rootDir = process.cwd();

function resolvePythonBinary(): string {
  const venvPython = path.resolve(rootDir, '.venv', 'bin', 'python');
  if (fs.existsSync(venvPython)) {
    return venvPython;
  }
  return 'python3';
}

export const appConfig: AppConfig = {
  env: process.env.NODE_ENV || 'development',
  port: process.env.PORT ? parseInt(process.env.PORT, 10) : 4000,
  paths: {
    root: rootDir,
    public: path.resolve(rootDir, 'public'),
    uploads: path.resolve(rootDir, 'uploads'),
    rules: path.resolve(rootDir, 'src', 'rules'),
    sampleTarget: path.resolve(rootDir, 'target'),
    pythonVenv: resolvePythonBinary(),
  },
  upload: {
    maxSizeBytes: 100 * 1024 * 1024, // 100 MB
    allowedMimeTypes: ['application/zip', 'application/x-zip-compressed', 'application/octet-stream'],
    allowedExtensions: ['.zip'],
  },
  statutory: {
    maxPenaltyCrores: 250,
    statutoryAct: 'Digital Personal Data Protection Act 2023',
    rulesVersion: 'DPDP Rules 2025',
  },
};
