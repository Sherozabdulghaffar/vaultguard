// ============================================
// VaultGuard - CSV Import/Export Utilities
// Parse and generate CSV for password entries
// ============================================

import { PasswordEntry } from './index';
import { generateId } from './crypto';

// CSV column mappings (supports common password manager formats)
const COLUMN_MAPPINGS = {
  // Common column names for each field
  title: ['name', 'title', 'site', 'website', 'url_name', 'entry_name', 'label'],
  url: ['url', 'website', 'site', 'website_url', 'login_url', 'web_address'],
  username: ['username', 'user', 'email', 'login', 'user_name', 'email_address', 'account'],
  password: ['password', 'pass', 'pwd', 'secret', 'login_password'],
  notes: ['notes', 'note', 'comment', 'comments', 'description', 'memo'],
  category: ['group', 'category', 'folder', 'tag', 'tags', 'type'],
};

/**
 * Parse a CSV string into password entries
 */
export function parseCSV(csvContent: string): PasswordEntry[] {
  const lines = csvContent.split(/\r?\n/).filter(line => line.trim());
  
  if (lines.length < 2) {
    throw new Error('CSV file is empty or has no data rows');
  }

  // Parse header row
  const header = parseCSVRow(lines[0]);
  const columnMap = mapColumns(header);

  const entries: PasswordEntry[] = [];

  // Parse data rows
  for (let i = 1; i < lines.length; i++) {
    const row = parseCSVRow(lines[i]);
    
    if (row.length === 0 || (row.length === 1 && !row[0].trim())) {
      continue; // Skip empty rows
    }

    const entry = extractEntry(row, columnMap);
    if (entry) {
      entries.push(entry);
    }
  }

  return entries;
}

/**
 * Parse a single CSV row, handling quoted fields
 */
function parseCSVRow(row: string): string[] {
  const result: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < row.length; i++) {
    const char = row[i];
    const nextChar = row[i + 1];

    if (inQuotes) {
      if (char === '"') {
        if (nextChar === '"') {
          // Escaped quote
          current += '"';
          i++; // Skip next quote
        } else {
          // End of quoted field
          inQuotes = false;
        }
      } else {
        current += char;
      }
    } else {
      if (char === '"') {
        inQuotes = true;
      } else if (char === ',') {
        result.push(current.trim());
        current = '';
      } else {
        current += char;
      }
    }
  }

  result.push(current.trim());
  return result;
}

/**
 * Map CSV columns to our field names
 */
function mapColumns(headers: string[]): { [key: string]: number } {
  const map: { [key: string]: number } = {};

  for (const [field, aliases] of Object.entries(COLUMN_MAPPINGS)) {
    for (const alias of aliases) {
      const index = headers.findIndex(h => 
        h.toLowerCase().replace(/[\s_-]/g, '') === alias.toLowerCase().replace(/[\s_-]/g, '')
      );
      if (index !== -1) {
        map[field] = index;
        break;
      }
    }
  }

  // If no title column found, use first column
  if (map['title'] === undefined && headers.length > 0) {
    map['title'] = 0;
  }

  return map;
}

/**
 * Extract a password entry from a CSV row
 */
function extractEntry(row: string[], columnMap: { [key: string]: number }): PasswordEntry | null {
  const title = columnMap['title'] !== undefined ? row[columnMap['title']] : '';
  const username = columnMap['username'] !== undefined ? row[columnMap['username']] : '';
  const password = columnMap['password'] !== undefined ? row[columnMap['password']] : '';

  // Skip rows without at least a title or username
  if (!title && !username) {
    return null;
  }

  // Sanitize inputs - truncate excessively long fields and remove control characters
  const sanitize = (str: string, maxLength: number = 1000): string => {
    if (!str) return '';
    // Remove control characters except newlines and tabs
    let cleaned = str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
    // Truncate to max length
    return cleaned.substring(0, maxLength);
  };

  // Validate URL format if provided
  let url = columnMap['url'] !== undefined ? row[columnMap['url']] : undefined;
  if (url) {
    try {
      // Try to parse as URL, add https:// if missing scheme
      if (url && !url.match(/^https?:\/\//i) && url.includes('.')) {
        url = 'https://' + url;
      }
      new URL(url);
    } catch {
      // If URL is invalid, keep as-is (might be just a domain)
    }
  }

  return {
    id: generateId(),
    title: sanitize(title || username, 200),
    username: sanitize(username, 500),
    password: sanitize(password, 1000),
    url: url ? sanitize(url, 2000) : undefined,
    notes: columnMap['notes'] !== undefined ? sanitize(row[columnMap['notes']], 5000) : undefined,
    category: columnMap['category'] !== undefined ? sanitize(row[columnMap['category']], 100) : undefined,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
}

/**
 * Convert password entries to CSV string
 */
export function entriesToCSV(entries: PasswordEntry[]): string {
  // CSV header
  const header = ['name', 'url', 'username', 'password', 'notes', 'group'];
  
  const rows = [header.join(',')];

  for (const entry of entries) {
    const row = [
      escapeCSVField(entry.title),
      escapeCSVField(entry.url || ''),
      escapeCSVField(entry.username),
      escapeCSVField(entry.password),
      escapeCSVField(entry.notes || ''),
      escapeCSVField(entry.category || ''),
    ];
    rows.push(row.join(','));
  }

  return rows.join('\n');
}

/**
 * Escape a field for CSV output
 */
function escapeCSVField(field: string): string {
  if (!field) return '""';
  
  // If field contains comma, quote, or newline, wrap in quotes
  if (field.includes(',') || field.includes('"') || field.includes('\n')) {
    // Escape existing quotes by doubling them
    const escaped = field.replace(/"/g, '""');
    return `"${escaped}"`;
  }
  
  return field;
}

/**
 * Validate CSV content before import
 */
export function validateCSV(csvContent: string): { valid: boolean; errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];

  const lines = csvContent.split(/\r?\n/).filter(line => line.trim());

  if (lines.length === 0) {
    errors.push('CSV file is empty');
    return { valid: false, errors, warnings };
  }

  const header = parseCSVRow(lines[0]);
  const columnMap = mapColumns(header);

  // Check for required columns
  if (columnMap['title'] === undefined && columnMap['username'] === undefined) {
    warnings.push('No name or username column detected. First column will be used as name.');
  }

  // Count data rows
  let dataRows = 0;
  for (let i = 1; i < lines.length; i++) {
    const row = parseCSVRow(lines[i]);
    if (row.length > 0 && row.some(cell => cell.trim())) {
      dataRows++;
    }
  }

  if (dataRows === 0) {
    errors.push('No data rows found in CSV');
    return { valid: false, errors, warnings };
  }

  warnings.push(`Found ${dataRows} entries to import`);

  // Check for passwords
  if (columnMap['password'] === undefined) {
    warnings.push('No password column detected. Entries will be imported without passwords.');
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}
