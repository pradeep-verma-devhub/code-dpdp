import { PiiType, DataFlow } from '../types.js';

export interface PiiFieldDefinition {
  type: PiiType;
  keywords: string[];
  exactMatches?: string[];
  sensitivity: 'critical' | 'high' | 'medium';
  defaultFlow?: DataFlow;
}

export interface PiiRegexDefinition {
  type: PiiType;
  pattern: RegExp;
  validator?: (value: string) => boolean;
  sensitivity: 'critical' | 'high' | 'medium';
  description: string;
}
