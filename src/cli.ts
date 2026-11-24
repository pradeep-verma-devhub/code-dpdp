#!/usr/bin/env node

import { Command } from 'commander';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import pc from 'picocolors';

const program = new Command();

function getPythonExecutable(): string {
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
    console.error(pc.red(`[!] Error executing code-dpdp Python engine: ${res.error.message}`));
    process.exit(1);
  }
  process.exit(res.status ?? 0);
}

program
  .name('code-dpdp')
  .description("Automated Compliance Scanner for India's Digital Personal Data Protection Act 2023 & DPDP Rules 2025")
  .version('1.0.0');

// 1. scan command
program
  .command('scan [path]', { isDefault: true })
  .description('Scan an application directory for DPDP non-compliance and personal data mishandling')
  .option('--pdf <report.pdf>', 'Generate official PDF compliance report (e.g. result.pdf)')
  .option('-o, --out <report.pdf>', 'Generate official PDF compliance report')
  .option('-j, --json <out.json>', 'Export scan findings and summary to JSON')
  .option('--html <report.html>', 'Export interactive HTML report')
  .option('-p, --patches <patchesDir>', 'Generate unified diff (.patch) remediation files')
  .option('--apply', 'Apply generated patches to a new git branch in the target repo')
  .option('--severity <level>', 'Filter findings by minimum severity (critical, high, medium, low)')
  .option('--fail-on <severity>', 'Exit with non-zero status code if findings match threshold')
  .action((targetPath = '.', options) => {
    const pythonArgs = ['scan', targetPath];
    if (options.pdf) pythonArgs.push('--pdf', options.pdf);
    else if (options.out) pythonArgs.push('--pdf', options.out);
    if (options.json) pythonArgs.push('--json', options.json);
    if (options.html) pythonArgs.push('--html', options.html);
    if (options.patches) pythonArgs.push('--patches', options.patches);
    if (options.apply) pythonArgs.push('--apply');
    if (options.severity) pythonArgs.push('--severity', options.severity);
    if (options.failOn) pythonArgs.push('--fail-on', options.failOn);

    runPythonCli(pythonArgs);
  });

// 2. pii command
program
  .command('pii [path]')
  .description('Detect Indian PII (Aadhaar, PAN, Passport, Voter ID, phone, cards, secrets)')
  .option('--no-redact', 'Display unredacted values in terminal')
  .option('-j, --json <out.json>', 'Export PII detections to JSON')
  .action((targetPath = '.', options) => {
    const pythonArgs = ['pii', targetPath];
    if (options.redact === false) pythonArgs.push('--no-redact');
    if (options.json) pythonArgs.push('--json', options.json);
    runPythonCli(pythonArgs);
  });

// 3. consent command
program
  .command('consent [path]')
  .description('Assess application consent architecture against DPDP Act Sections 5 & 6 and Rules 3 & 4')
  .action((targetPath = '.') => {
    runPythonCli(['consent', targetPath]);
  });

// 4. egress command
program
  .command('egress [path]')
  .description('Audit third-party tracker & SDK data egress without affirmative consent')
  .action((targetPath = '.') => {
    runPythonCli(['egress', targetPath]);
  });

// 5. live command
program
  .command('live <baseUrl>')
  .description('Execute non-destructive live API compliance tests against a running endpoint')
  .action((baseUrl) => {
    runPythonCli(['live', baseUrl]);
  });

// 6. penalty command
program
  .command('penalty [path]')
  .description('Calculate statutory penalty exposure under the DPDP Act 2023 Schedule (Up to ₹250 Crore)')
  .action((targetPath = '.') => {
    runPythonCli(['penalty', targetPath]);
  });

// 7. patch command
program
  .command('patch [path]')
  .description('Generate unified remediation diff patches (.patch) for detected violations')
  .option('--patches-dir <dir>', 'Directory for patch files', 'patches')
  .option('--apply', 'Apply patches directly to repository')
  .action((targetPath = '.', options) => {
    const pythonArgs = ['patch', targetPath, '--patches-dir', options.patchesDir];
    if (options.apply) pythonArgs.push('--apply');
    runPythonCli(pythonArgs);
  });

// 8. coderabbit command
program
  .command('coderabbit [path]')
  .description('Generate DPDP Act 2023 compliant .coderabbit.yaml rule contract for PR review gating')
  .action((targetPath = '.') => {
    runPythonCli(['coderabbit', targetPath]);
  });

// 9. list-rules / rules command
program
  .command('rules')
  .description('List all registered static analysis checks, rules, and DPDP provisions')
  .action(() => {
    runPythonCli(['rules']);
  });

program
  .command('list-rules')
  .description('List all registered static analysis checks, rules, and DPDP provisions')
  .action(() => {
    runPythonCli(['list-rules']);
  });

// 10. info command
program
  .command('info')
  .description('Display engine health, active rules count, and system information')
  .action(() => {
    runPythonCli(['info']);
  });

program.parse(process.argv);
