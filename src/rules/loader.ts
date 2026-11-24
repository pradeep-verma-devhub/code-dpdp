import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';
import { RuleDefinition, DPDPRef } from '../types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface LoadedRulesData {
  dpdpMap: Record<string, DPDPRef>;
  rules: RuleDefinition[];
}

export class RuleLoader {
  private static cachedData: LoadedRulesData | null = null;

  public static getRulesDir(): string {

    const possiblePaths = [
      path.resolve(__dirname),
      path.resolve(process.cwd(), 'src/rules'),
      path.resolve(process.cwd(), 'dist/rules'),
    ];
    for (const p of possiblePaths) {
      if (fs.existsSync(path.join(p, 'dpdp-map.yaml'))) {
        return p;
      }
    }
    return path.resolve(process.cwd(), 'src/rules');
  }

  public static loadRules(rulesDir?: string): LoadedRulesData {
    if (this.cachedData && !rulesDir) {
      return this.cachedData;
    }

    const dir = rulesDir || this.getRulesDir();
    const mapPath = path.join(dir, 'dpdp-map.yaml');

    if (!fs.existsSync(mapPath)) {
      throw new Error(`Master DPDP mapping not found at ${mapPath}`);
    }

    const rawMap = yaml.load(fs.readFileSync(mapPath, 'utf8')) as Record<string, DPDPRef>;

    const rules: RuleDefinition[] = [];
    const files = fs.readdirSync(dir);

    for (const file of files) {
      if (file.endsWith('.yaml') || file.endsWith('.yml')) {
        if (file === 'dpdp-map.yaml') continue;
        const filePath = path.join(dir, file);
        const parsed = yaml.load(fs.readFileSync(filePath, 'utf8'));
        if (Array.isArray(parsed)) {
          for (const item of parsed) {
            this.validateRule(item, rawMap, file);
            rules.push(item as RuleDefinition);
          }
        }
      }
    }

    this.cachedData = { dpdpMap: rawMap, rules };
    return this.cachedData;
  }

  private static validateRule(
    rule: any,
    dpdpMap: Record<string, DPDPRef>,
    fileName: string
  ): void {
    const required = ['id', 'title', 'category', 'severity', 'dpdpRef', 'description'];
    for (const field of required) {
      if (!rule[field]) {
        throw new Error(`Rule in ${fileName} missing required field '${field}'`);
      }
    }

    if (!dpdpMap[rule.dpdpRef]) {
      throw new Error(
        `Rule ${rule.id} references unknown dpdpRef '${rule.dpdpRef}'. Check dpdp-map.yaml`
      );
    }
  }

  public static getRuleById(id: string): RuleDefinition | undefined {
    const { rules } = this.loadRules();
    return rules.find((r) => r.id === id);
  }

  public static getDpdpProvision(key: string): DPDPRef | undefined {
    const { dpdpMap } = this.loadRules();
    return dpdpMap[key];
  }
}
