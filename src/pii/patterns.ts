import { PiiRegexDefinition } from './types.js';

// Verhoeff algorithm tables for Aadhaar checksum verification
const verhoeffD = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const verhoeffP = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

export function validateVerhoeff(numStr: string): boolean {
  const clean = numStr.replace(/\s+/g, '');
  if (!/^\d{12}$/.test(clean)) return false;
  // Aadhaar does not start with 0 or 1
  if (clean[0] === '0' || clean[0] === '1') return false;

  let c = 0;
  const invertedArray = clean.split('').map(Number).reverse();
  for (let i = 0; i < invertedArray.length; i++) {
    c = verhoeffD[c][verhoeffP[i % 8][invertedArray[i]]];
  }
  return c === 0;
}

export function validateLuhn(ccNum: string): boolean {
  const clean = ccNum.replace(/[\s-]+/g, '');
  if (!/^\d{13,19}$/.test(clean)) return false;
  let sum = 0;
  let alternate = false;
  for (let i = clean.length - 1; i >= 0; i--) {
    let n = parseInt(clean.substring(i, i + 1), 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n = (n % 10) + 1;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

export const PII_PATTERNS: PiiRegexDefinition[] = [
  // 1. Aadhaar (12 digits, format: 2-9xxx xxxx xxxx or continuous)
  {
    type: 'aadhaar',
    pattern: /\b[2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4}\b/g,
    validator: validateVerhoeff,
    sensitivity: 'critical',
    description: 'Indian Aadhaar Number (UIDAI with Verhoeff validation)',
  },

  // 2. PAN (Permanent Account Number)
  {
    type: 'pan',
    pattern: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,
    validator: (v: string) => {
      // 4th char is status: P (Person), C (Company), H (HUF), F (Firm), A (AOP), T (Trust)
      const valid4th = ['P', 'C', 'H', 'F', 'A', 'T', 'B', 'L', 'J', 'G'];
      return valid4th.includes(v.charAt(3).toUpperCase());
    },
    sensitivity: 'critical',
    description: 'Indian Permanent Account Number (Income Tax PAN)',
  },

  // 3. Indian Phone Numbers
  {
    type: 'phone',
    pattern: /(?:\+91[-\s]?|91[-\s]?|0)?[6-9]\d{4}[-\s]?\d{5}\b/g,
    validator: (v: string) => {
      const digits = v.replace(/\D/g, '');
      const last10 = digits.slice(-10);
      return last10.length === 10 && /^[6-9]/.test(last10);
    },
    sensitivity: 'high',
    description: 'Indian Mobile Phone Number',
  },

  // 4. Email Address
  {
    type: 'email',
    pattern: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
    validator: (v: string) => !v.endsWith('.example.com') && !v.endsWith('.local') && v.length < 254,
    sensitivity: 'high',
    description: 'Electronic Mail Address',
  },

  // 5. Indian PIN Code
  {
    type: 'address',
    pattern: /\b[1-9][0-9]{2}\s?[0-9]{3}\b/g,
    validator: (v: string) => {
      const digits = v.replace(/\s+/g, '');
      return digits.length === 6 && /^[1-9]/.test(digits);
    },
    sensitivity: 'medium',
    description: 'Indian Postal Index Number (PIN Code)',
  },

  // 6. Financial: UPI ID / VPA
  {
    type: 'financial',
    pattern: /\b[a-zA-Z0-9._-]{2,256}@(okaxis|okhdfcbank|okicici|oksbi|paytm|ybl|ibl|upi|axl|apl|barodampay|mahb)\b/gi,
    sensitivity: 'critical',
    description: 'Unified Payments Interface (UPI Virtual Payment Address)',
  },

  // 7. Financial: Credit/Debit Card
  {
    type: 'financial',
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15})\b/g,
    validator: validateLuhn,
    sensitivity: 'critical',
    description: 'Payment Card Number (Visa, MC, RuPay, Amex with Luhn)',
  },

  // 8. Financial: Indian IFSC Code
  {
    type: 'financial',
    pattern: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g,
    sensitivity: 'high',
    description: 'Indian Financial System Code (IFSC)',
  },

  // 9. IP Address (IPv4 & IPv6)
  {
    type: 'ip',
    pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    validator: (v: string) => {
      // Exclude localhost/zeros
      return v !== '127.0.0.1' && v !== '0.0.0.0' && !v.startsWith('192.168.') && !v.startsWith('10.');
    },
    sensitivity: 'medium',
    description: 'Public IPv4 Address',
  },

  // 10. Geolocation Coordinates
  {
    type: 'geolocation',
    pattern: /[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)/g,
    sensitivity: 'high',
    description: 'GPS Latitude/Longitude Coordinates',
  },

  // 11. DOB (Date of Birth)
  {
    type: 'dob',
    pattern: /\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b/g,
    sensitivity: 'high',
    description: 'Date of Birth (YYYY-MM-DD or YYYY/MM/DD)',
  },

  // 12. Indian Passport
  {
    type: 'name',
    pattern: /\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b/g,
    sensitivity: 'critical',
    description: 'Indian Passport Number',
  },

  // 13. MAC Address / Hardware Identifier
  {
    type: 'device_id',
    pattern: /\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b/g,
    sensitivity: 'medium',
    description: 'Media Access Control (MAC) Address',
  },
];
