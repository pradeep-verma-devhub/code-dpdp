/**
 * Core type definitions for DPDP-Audit
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type DataFlow = 'collected' | 'stored' | 'logged' | 'transferred' | 'exposed';

export type PiiType =
  | 'name'
  | 'email'
  | 'phone'
  | 'aadhaar'
  | 'pan'
  | 'dob'
  | 'address'
  | 'ip'
  | 'geolocation'
  | 'health'
  | 'financial'
  | 'password'
  | 'device_id'
  | 'biometrics'
  | 'children_data';

export interface PiiDetection {
  type: PiiType;
  confidence: number; // 0 to 1
  matchedTerm: string;
  dataFlow: DataFlow;
  line: number;
  column?: number;
  valueSnippet?: string;
  isRedacted?: boolean;
}

export interface DPDPRef {
  provision: string; // e.g. "Section 8(6)", "Rule 6"
  law: 'Act 2023' | 'Rules 2025';
  title: string;
  summary: string;
  penaltyClause?: string;
}

export interface RuleDefinition {
  id: string;
  title: string;
  category:
    | 'logging'
    | 'storage'
    | 'transfer'
    | 'exposure'
    | 'config'
    | 'lifecycle'
    | 'children'
    | 'breach';
  severity: Severity;
  dpdpRef: string; // Key in dpdp-map.yaml
  description: string;
  piiTypes: PiiType[];
  dataFlow: DataFlow;
  targetFiles: string[]; // file patterns e.g. ["*.ts", "*.js"]
  targetType: 'ast' | 'regex' | 'config' | 'schema';
  pattern?: string; // Regex pattern if regex-based
  astQuery?: {
    type: string;
    callee?: string;
    property?: string;
    context?: string;
  };
  remediation: string;
  patchTemplate?: string;
}

export interface Finding {
  id: string; // Unique finding ID (e.g. DPDP-LOG-001-A1B2)
  ruleId: string;
  title: string;
  file: string;
  line: number;
  column?: number;
  snippet: string;
  piiTypes: PiiType[];
  dataFlow: DataFlow;
  dpdpRef: {
    sectionOrRule: string;
    explanation: string;
    penaltyClause?: string;
  };
  severity: Severity;
  justification: string;
  fix: string;
  patchAvailable?: boolean;
  patchUnifiedDiff?: string;
}

export interface ScanSummary {
  scannedFilesCount: number;
  scanDurationMs: number;
  findingsCount: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<string, number>;
  byDataFlow: Record<DataFlow, number>;
  topViolations: Array<{ ruleId: string; title: string; count: number }>;
  complianceScore: number; // 0 to 100
  dpdpCoverage: Array<{
    provision: string;
    law: string;
    title: string;
    status: 'VIOLATION' | 'COMPLIANT' | 'NOT_APPLICABLE';
    findingCount: number;
  }>;
}

export interface ScanResult {
  targetPath: string;
  timestamp: string;
  summary: ScanSummary;
  findings: Finding[];
  consentScorecard?: ConsentScorecard;
}

export interface ConsentCheck {
  id: string;
  pillar: 'recorded' | 'withdrawable' | 'enforced' | 'granular' | 'plain_notice';
  name: string;
  description: string;
  passed: boolean;
  evidence?: string;
  recommendation: string;
}

export interface ConsentScorecard {
  overallScore: number; // 0 to 100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  pillars: {
    recorded: { score: number; passed: boolean; details: string };
    withdrawable: { score: number; passed: boolean; details: string };
    enforced: { score: number; passed: boolean; details: string };
    granular: { score: number; passed: boolean; details: string };
    plain_notice: { score: number; passed: boolean; details: string };
  };
  checks: ConsentCheck[];
  recommendations: string[];
}

export interface LiveTestFinding {
  id: string;
  testName: string;
  endpoint: string;
  method: string;
  status: 'FAIL' | 'PASS' | 'WARN';
  details: string;
  dpdpRef: string;
  severity: Severity;
  evidence?: string;
}

export interface LiveTestResult {
  baseUrl: string;
  timestamp: string;
  endpointsTested: number;
  summary: {
    passed: number;
    failed: number;
    warnings: number;
  };
  findings: LiveTestFinding[];
}
