import { describe, it, expect } from 'vitest';
import { RuleLoader } from '../src/rules/loader.js';

describe('Rule Loader & DPDP Mapping Verification', () => {
  it('loads all rule files and verifies dpdp-map.yaml references', () => {
    const { dpdpMap, rules } = RuleLoader.loadRules();

    expect(Object.keys(dpdpMap).length).toBeGreaterThanOrEqual(15);
    expect(rules.length).toBeGreaterThanOrEqual(40);

    for (const rule of rules) {
      expect(dpdpMap[rule.dpdpRef]).toBeDefined();
      expect(dpdpMap[rule.dpdpRef].provision).toBeDefined();
      expect(dpdpMap[rule.dpdpRef].title).toBeDefined();
      expect(['Act 2023', 'Rules 2025']).toContain(dpdpMap[rule.dpdpRef].law);
    }
  });

  it('covers all 8 required categories', () => {
    const { rules } = RuleLoader.loadRules();
    const categories = new Set(rules.map((r) => r.category));

    expect(categories.has('logging')).toBe(true);
    expect(categories.has('storage')).toBe(true);
    expect(categories.has('transfer')).toBe(true);
    expect(categories.has('exposure')).toBe(true);
    expect(categories.has('config')).toBe(true);
    expect(categories.has('lifecycle')).toBe(true);
    expect(categories.has('children')).toBe(true);
    expect(categories.has('breach')).toBe(true);
  });

  it('ensures each rule has a valid severity level', () => {
    const { rules } = RuleLoader.loadRules();
    const validSeverities = ['critical', 'high', 'medium', 'low'];
    for (const rule of rules) {
      expect(validSeverities).toContain(rule.severity);
    }
  });
});
