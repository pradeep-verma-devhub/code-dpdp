import { describe, it, expect } from 'vitest';
import { PiiClassifier, validateVerhoeff, validateLuhn } from '../src/pii/index.js';

describe('PII Detection Engine', () => {
  it('correctly validates Aadhaar using Verhoeff algorithm', () => {
    // Valid Aadhaar numbers generated via Verhoeff
    expect(validateVerhoeff('234567890124')).toBe(true);
    // Invalid checksum
    expect(validateVerhoeff('234567890120')).toBe(false);
    // Disallowed starting digit (0 or 1)
    expect(validateVerhoeff('012345678901')).toBe(false);
  });

  it('validates PAN card format and holder code', () => {
    const text = 'PAN card number is ABCPE1234F for individual';
    const detections = PiiClassifier.scanTextForPii(text);
    expect(detections.some((d) => d.type === 'pan')).toBe(true);
  });

  it('validates Credit Card using Luhn algorithm', () => {
    // Sample test card (Visa valid)
    expect(validateLuhn('4532015112830366')).toBe(true);
    // Invalid card
    expect(validateLuhn('4532015112830367')).toBe(false);
  });

  it('matches identifier names to appropriate PII types', () => {
    expect(PiiClassifier.matchIdentifier('user_email')).toBe('email');
    expect(PiiClassifier.matchIdentifier('phoneNumber')).toBe('phone');
    expect(PiiClassifier.matchIdentifier('aadhaar_no')).toBe('aadhaar');
    expect(PiiClassifier.matchIdentifier('pan_card')).toBe('pan');
    expect(PiiClassifier.matchIdentifier('user_password')).toBe('password');
    expect(PiiClassifier.matchIdentifier('client_ip')).toBe('ip');
    expect(PiiClassifier.matchIdentifier('upi_id')).toBe('financial');
    expect(PiiClassifier.matchIdentifier('medical_history')).toBe('health');
    expect(PiiClassifier.matchIdentifier('parental_consent')).toBe('children_data');
    expect(PiiClassifier.matchIdentifier('random_var_xyz')).toBeNull();
  });

  it('masks sensitive PII in snippets without breaking context', () => {
    const snippet = 'const apiKey = "secret_12345"; const email = "testuser@gmail.com";';
    const masked = PiiClassifier.maskSnippet(snippet);
    expect(masked).not.toContain('secret_12345');
    expect(masked).toContain('[REDACTED_SECRET]');
    expect(masked).not.toContain('testuser@gmail.com');
  });

  it('classifies data flows based on AST contexts', () => {
    expect(PiiClassifier.classifyDataFlow({ isLogCall: true })).toBe('logged');
    expect(PiiClassifier.classifyDataFlow({ isDbOperation: true })).toBe('stored');
    expect(PiiClassifier.classifyDataFlow({ isHttpResponse: true })).toBe('exposed');
    expect(PiiClassifier.classifyDataFlow({ isNetworkCall: true })).toBe('transferred');
    expect(PiiClassifier.classifyDataFlow({ isHttpRequestBody: true })).toBe('collected');
  });
});
