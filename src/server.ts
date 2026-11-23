import express, { Request, Response } from 'express';
import multer from 'multer';
import path from 'node:path';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';
import pc from 'picocolors';

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 4000;

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Static frontend assets
const publicDir = path.resolve(process.cwd(), 'public');
if (!fs.existsSync(publicDir)) {
  fs.mkdirSync(publicDir, { recursive: true });
}
app.use(express.static(publicDir));

// Upload workspace directory
const uploadDir = path.resolve(process.cwd(), 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer storage configuration
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, uploadDir);
  },
  filename: (_req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    cb(null, `${uniqueSuffix}-${file.originalname}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit
  fileFilter: (_req, file, cb) => {
    if (file.originalname.endsWith('.zip') || file.mimetype.includes('zip') || file.mimetype.includes('octet-stream')) {
      cb(null, true);
    } else {
      cb(new Error('Only .zip files are supported. Please upload your codebase as a zip archive.'));
    }
  },
});

// Helper: Python execution wrapper
function getPythonExecutable(): string {
  const venvPython = path.resolve(process.cwd(), '.venv', 'bin', 'python');
  if (fs.existsSync(venvPython)) {
    return venvPython;
  }
  return 'python3';
}

function runPythonScan(targetDir: string, sessionDir: string): any {
  const pythonExec = getPythonExecutable();
  const pythonPath = path.resolve(process.cwd(), 'python');

  const pdfPath = path.join(sessionDir, 'report.pdf');
  const jsonPath = path.join(sessionDir, 'out.json');
  const patchesDir = path.join(sessionDir, 'patches');

  const env = {
    ...process.env,
    PYTHONPATH: process.env.PYTHONPATH ? `${pythonPath}:${process.env.PYTHONPATH}` : pythonPath,
  };

  const script = `
import json
from dpdp_audit.core.rules_engine import RulesEngine
from dpdp_audit.analyzers.patch_generator import PatchGenerator
from dpdp_audit.report.pdf_generator import PdfGenerator

target = r"${targetDir}"
session_dir = r"${sessionDir}"
pdf_path = r"${pdfPath}"
json_path = r"${jsonPath}"
patches_dir = r"${patchesDir}"

res = RulesEngine.scan_target(target, run_consent=True)
PdfGenerator.generate(res, pdf_path)
PatchGenerator.generate_patches(res.findings, patches_dir, target, apply=False)

with open(json_path, 'w', encoding='utf-8') as f:
    json.dump(res.to_dict(), f, indent=2)

print("__SUCCESS__")
`;

  const child = spawnSync(pythonExec, ['-c', script], {
    env,
    encoding: 'utf-8',
    maxBuffer: 50 * 1024 * 1024,
  });

  if (child.error || !fs.existsSync(jsonPath)) {
    console.error('Python scan error:', child.stderr || child.error);
    throw new Error(child.stderr || 'Scanning process failed');
  }

  const rawJson = fs.readFileSync(jsonPath, 'utf-8');
  return JSON.parse(rawJson);
}

// ==========================================
// API ENDPOINTS
// ==========================================

// 1. Upload & Scan .zip codebase
app.post('/api/scan-zip', upload.single('codebase'), (req: Request, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No .zip file uploaded' });
  }

  const zipPath = req.file.path;
  const sessionId = `session-${Date.now()}`;
  const sessionDir = path.join(uploadDir, sessionId);
  const extractDir = path.join(sessionDir, 'extracted');

  fs.mkdirSync(extractDir, { recursive: true });

  try {
    // Unzip archive safely
    const unzipRes = spawnSync('unzip', ['-q', '-o', zipPath, '-d', extractDir]);
    if (unzipRes.status !== 0) {
      return res.status(400).json({ error: 'Failed to extract zip file. Ensure it is a valid zip archive.' });
    }

    // Clean up uploaded zip file
    try { fs.unlinkSync(zipPath); } catch {}

    // Run DPDP Compliance Scan
    const scanData = runPythonScan(extractDir, sessionDir);

    return res.json({
      success: true,
      sessionId,
      targetName: req.file.originalname.replace('.zip', ''),
      data: scanData,
    });
  } catch (err: any) {
    console.error('Scan error:', err);
    return res.status(500).json({ error: err.message || 'Internal scanning error' });
  }
});

// 2. Scan pre-configured sample (OWASP Juice Shop)
app.post('/api/scan-sample', (_req: Request, res: Response) => {
  const targetDir = path.resolve(process.cwd(), 'target');
  if (!fs.existsSync(targetDir)) {
    return res.status(404).json({ error: 'Sample target not found. Run clone command first.' });
  }

  const sessionId = `sample-${Date.now()}`;
  const sessionDir = path.join(uploadDir, sessionId);
  fs.mkdirSync(sessionDir, { recursive: true });

  try {
    const scanData = runPythonScan(targetDir, sessionDir);
    return res.json({
      success: true,
      sessionId,
      targetName: 'OWASP Juice Shop (Benchmark)',
      data: scanData,
    });
  } catch (err: any) {
    console.error('Sample scan error:', err);
    return res.status(500).json({ error: err.message || 'Error scanning sample repository' });
  }
});

// 3. Download PDF Report
app.get('/api/download-pdf/:sessionId', (req: Request, res: Response) => {
  const sessionId = String(req.params.sessionId);
  const pdfPath = path.join(uploadDir, sessionId, 'report.pdf');

  if (fs.existsSync(pdfPath)) {
    return res.download(pdfPath, 'DPDP_Compliance_Report.pdf');
  }

  // Fallback to root report.pdf if available
  const rootPdf = path.resolve(process.cwd(), 'report.pdf');
  if (fs.existsSync(rootPdf)) {
    return res.download(rootPdf, 'DPDP_Compliance_Report.pdf');
  }

  return res.status(404).json({ error: 'PDF report not found for this session' });
});

// 4. Download Patches
app.get('/api/download-patches/:sessionId', (req: Request, res: Response) => {
  const sessionId = String(req.params.sessionId);
  const patchPath = path.join(uploadDir, sessionId, 'patches', 'all_remediations.patch');

  if (fs.existsSync(patchPath)) {
    return res.download(patchPath, 'dpdp_remediations.patch');
  }

  const rootPatch = path.resolve(process.cwd(), 'patches', 'all_remediations.patch');
  if (fs.existsSync(rootPatch)) {
    return res.download(rootPatch, 'dpdp_remediations.patch');
  }

  return res.status(404).json({ error: 'Patches not found for this session' });
});

// 5. List all active rules
app.get('/api/rules', (_req: Request, res: Response) => {
  const pythonExec = getPythonExecutable();
  const pythonPath = path.resolve(process.cwd(), 'python');

  const script = `
import json
from dpdp_audit.core.rules_engine import RulesEngine
from dpdp_audit.core.dpdp_mapper import DpdpMapper

rules = [r.to_dict() for r in RulesEngine.load_rules()]
dpdp_map = {k: v.to_dict() for k, v in DpdpMapper.load_map().items()}
print(json.dumps({"rules": rules, "dpdpMap": dpdp_map}))
`;

  const child = spawnSync(pythonExec, ['-c', script], {
    env: { ...process.env, PYTHONPATH: pythonPath },
    encoding: 'utf-8',
  });

  try {
    return res.json(JSON.parse(child.stdout));
  } catch {
    return res.status(500).json({ error: 'Failed to load rules metadata' });
  }
});

// Start Server
export function startServer(port = PORT): void {
  app.listen(port, () => {
    console.log(pc.bold(pc.green(`\n=================================================================`)));
    console.log(pc.bold(pc.cyan(` [DPDP-Audit] Real Interactive Web Platform Live!`)));
    console.log(pc.bold(pc.white(` Open in browser: `) + pc.yellow(`http://localhost:${port}`)));
    console.log(pc.bold(pc.green(`=================================================================\n`)));
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  startServer();
}
