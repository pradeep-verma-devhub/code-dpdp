import { describe, it, expect } from 'vitest';
import { AuditService } from '../src/services/audit.service.js';
import { appConfig } from '../src/config/app.config.js';
import { PathUtil } from '../src/utils/path.util.js';

describe('Layered Architecture Verification', () => {
  it('appConfig has valid statutory and path configurations', () => {
    expect(appConfig.port).toBe(4000);
    expect(appConfig.statutory.maxPenaltyCrores).toBe(250);
    expect(appConfig.upload.allowedExtensions).toContain('.zip');
    expect(appConfig.paths.root).toBeDefined();
  });

  it('PathUtil handles safe subpaths properly', () => {
    const base = '/home/user/project';
    expect(PathUtil.isSafeSubpath(base, '/home/user/project/extracted')).toBe(true);
    expect(PathUtil.isSafeSubpath(base, '/etc/passwd')).toBe(false);
  });

  it('AuditService loads all registered rules via service layer', () => {
    const { rules, dpdpMap } = AuditService.getRegisteredRules();
    expect(rules.length).toBeGreaterThanOrEqual(40);
    expect(Object.keys(dpdpMap).length).toBeGreaterThanOrEqual(15);
  });
});
