import { PiiType, DataFlow, PiiDetection } from '../types.js';
import { PII_DICTIONARY } from './dictionary.js';
import { PII_PATTERNS } from './patterns.js';

export class PiiClassifier {

  public static matchIdentifier(identifier: string): PiiType | null {
    if (!identifier || identifier.length < 2) return null;
    const cleanId = identifier.toLowerCase().replace(/[^a-z0-9]/g, '');

    const tokens = (identifier.match(/[A-Z]?[a-z0-9]+|[A-Z]+(?=[A-Z][a-z]|\b)/g) || [])
      .map((t) => t.toLowerCase());
    const tokenSet = new Set(tokens);

    for (const entry of PII_DICTIONARY) {
      if (entry.exactMatches) {
        for (const exact of entry.exactMatches) {
          const cleanExact = exact.toLowerCase().replace(/[^a-z0-9]/g, '');
          if (cleanId === cleanExact || tokenSet.has(cleanExact)) {
            return entry.type;
          }
        }
      }
    }

    for (const entry of PII_DICTIONARY) {
      for (const kw of entry.keywords) {
        if (kw.length < 5) {
          if (tokenSet.has(kw)) {
            return entry.type;
          }
        } else {
          if (cleanId.includes(kw) || tokens.some((t) => t.includes(kw))) {
            return entry.type;
          }
        }
      }
    }

    return null;
  }

  public static scanTextForPii(
    text: string,
    defaultFlow: DataFlow = 'exposed',
    lineNumber: number = 1
  ): PiiDetection[] {
    const detections: PiiDetection[] = [];

    for (const piiRegex of PII_PATTERNS) {

      piiRegex.pattern.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = piiRegex.pattern.exec(text)) !== null) {
        const value = match[0];

        if (piiRegex.validator && !piiRegex.validator(value)) {
          continue;
        }

        detections.push({
          type: piiRegex.type,
          confidence: 0.95,
          matchedTerm: value,
          dataFlow: defaultFlow,
          line: lineNumber,
          valueSnippet: this.maskPiiValue(piiRegex.type, value),
          isRedacted: true,
        });
      }
    }

    return detections;
  }

  public static classifyDataFlow(context: {
    isLogCall?: boolean;
    isDbOperation?: boolean;
    isNetworkCall?: boolean;
    isHttpResponse?: boolean;
    isHttpRequestBody?: boolean;
    isStorageWrite?: boolean;
  }): DataFlow {
    if (context.isLogCall) return 'logged';
    if (context.isHttpResponse) return 'exposed';
    if (context.isNetworkCall) return 'transferred';
    if (context.isDbOperation || context.isStorageWrite) return 'stored';
    if (context.isHttpRequestBody) return 'collected';
    return 'collected';
  }

  public static maskPiiValue(type: PiiType, value: string): string {
    if (!value) return '';
    const clean = value.trim();

    switch (type) {
      case 'aadhaar': {
        const digits = clean.replace(/\D/g, '');
        if (digits.length >= 12) {
          return `XXXX-XXXX-${digits.slice(-4)}`;
        }
        return 'XXXX-XXXX-XXXX';
      }
      case 'pan': {
        if (clean.length === 10) {
          return `XXXXX${clean.slice(5, 9)}X`;
        }
        return 'XXXXXXXXXX';
      }
      case 'email': {
        const parts = clean.split('@');
        if (parts.length === 2) {
          const user = parts[0];
          const domain = parts[1];
          const maskedUser = user.length > 2 ? `${user[0]}***${user[user.length - 1]}` : '***';
          return `${maskedUser}@${domain}`;
        }
        return '***@***.***';
      }
      case 'phone': {
        const digits = clean.replace(/\D/g, '');
        if (digits.length >= 10) {
          return `+91 XXXXX ${digits.slice(-4)}`;
        }
        return 'XXXXX XXXXX';
      }
      case 'password':
        return '[REDACTED_CREDENTIAL]';
      case 'financial': {
        const digits = clean.replace(/\D/g, '');
        if (digits.length >= 12) {
          return `XXXX-XXXX-XXXX-${digits.slice(-4)}`;
        }
        return '[REDACTED_FINANCIAL_INFO]';
      }
      case 'biometrics':
      case 'health':
        return `[REDACTED_${type.toUpperCase()}_DATA]`;
      default:
        if (clean.length <= 4) return '****';
        return `${clean.slice(0, 2)}****${clean.slice(-2)}`;
    }
  }

  public static maskSnippet(snippet: string): string {
    let result = snippet;

    result = result.replace(
      /(password|passwd|secret|apikey|token|private_key|auth_token)\s*[:=]\s*["']([^"']+)["']/gi,
      (_m, k) => `${k}: "[REDACTED_SECRET]"`
    );

    for (const p of PII_PATTERNS) {
      p.pattern.lastIndex = 0;
      result = result.replace(p.pattern, (matched) => {
        if (p.validator && !p.validator(matched)) return matched;
        return PiiClassifier.maskPiiValue(p.type, matched);
      });
    }

    return result;
  }
}
