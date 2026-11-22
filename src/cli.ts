#!/usr/bin/env node

import { Command } from 'commander';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import pc from 'picocolors';

const program = new Command();

function getPythonExecutable(): string {
  // Check local .venv first
  const venvPython = path.resolve(process.cwd(), '.venv', 'bin', 'python');
  if (fs.existsSync(venvPython)) {
    return venvPython;
  }
  return 'python3';
}

function runPythonCli(args: string[]): void {
  const pythonPath = path.resolve(process.cwd(), 'python');
  const pythonExec = getPythonExecutable();

  const env = {
    ...process.env,
    PYTHONPATH: process.env.PYTHONPATH ? `${pythonPath}:${process.env.PYTHONPATH}` : pythonPath,
  };

  const res = spawnSync(pythonExec, ['-m', 'dpdp_audit.cli', ...args], {
    env,
    stdio: 'inherit',
  });

  if (res.error) {
    console.error(pc.red(`[!] Error executing DPDP-Audit Python backend: ${res.error.message}`));
    process.exit(1);
  }
  process.exit(res.status ?? 0);
}

program
  .name('dpdp-audit')
  .description("Automated Compliance Scanner for India's Digital Personal Data Protection Act 2023 & DPDP Rules 2025")
  .version('1.0.0');

// 1. scan command
program
  .command('scan <path>')
  .description('Scan an application directory for DPDP non-compliance and personal data mishandling')
  .option('-o, --out <report.pdf>', 'Generate official PDF compliance report')
  .option('-j, --json <out.json>', 'Export scan findings and summary to JSON')
  .option('--html <report.html>', 'Export interactive HTML report')
  .option('-p, --patches <patchesDir>', 'Generate unified diff (.patch) remediation files')
  .option('--apply', 'Apply generated patches to a new git branch in the target repo')
  .action((targetPath, options) => {
    const pythonArgs = ['scan', targetPath];
    if (options.out) pythonArgs.push('--out', options.out);
    if (options.json) pythonArgs.push('--json', options.json);
    if (options.html) pythonArgs.push('--html', options.html);
    if (options.patches) pythonArgs.push('--patches', options.patches);
    if (options.apply) pythonArgs.push('--apply');

    runPythonCli(pythonArgs);
  });

// 2. consent command
program
  .command('consent <path>')
  .description('Assess application consent architecture against DPDP Act Sections 5 & 6 and Rules 3 & 4')
  .action((targetPath) => {
    runPythonCli(['consent', targetPath]);
  });

// 3. live command
program
  .command('live <baseUrl>')
  .description('Execute non-destructive live API compliance tests against a running endpoint')
  .action((baseUrl) => {
    runPythonCli(['live', baseUrl]);
  });

// 4. list-rules command
program
  .command('list-rules')
  .description('List all registered static analysis checks, rules, and DPDP provisions')
  .action(() => {
    runPythonCli(['list-rules']);
  });

program.parse(process.argv);
