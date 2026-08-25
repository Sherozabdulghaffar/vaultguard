// ============================================
// VaultGuard - Local Encrypted Database
// SQLite with AES-256-GCM encryption at rest
// ============================================

import Database from 'better-sqlite3';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import {
  PasswordEntry,
  TwoFactorEntry,
  VaultData,
  AuthConfig,
  AppSettings,
  BiometricConfig,
} from '@vaultguard/shared';
import {
  encrypt,
  decrypt,
  encryptPasswordEntry,
  decryptPasswordEntry,
  encryptTotpEntry,
  decryptTotpEntry,
  generateRandomHex,
  generateId,
} from '@vaultguard/shared/crypto';

const DB_DIR = path.join(os.homedir(), '.vaultguard');
const DB_PATH = path.join(DB_DIR, 'vault.db');

export class VaultDatabase {
  private db: Database.Database;
  private encryptionKey: string | null = null;

  constructor() {
    // Ensure the directory exists
    if (!fs.existsSync(DB_DIR)) {
      fs.mkdirSync(DB_DIR, { recursive: true, mode: 0o700 });
    }

    this.db = new Database(DB_PATH);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.initializeSchema();
  }

  private initializeSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS auth_config (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        master_password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        iterations INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        last_login INTEGER,
        auto_lock_minutes INTEGER DEFAULT 5
      );

      CREATE TABLE IF NOT EXISTS encrypted_vault (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        vault_data TEXT NOT NULL,
        iv TEXT NOT NULL,
        tag TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        settings_json TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS session_tokens (
        token TEXT PRIMARY KEY,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS biometric_config (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        enabled INTEGER NOT NULL DEFAULT 0,
        credential_id TEXT,
        authenticator_data TEXT,
        encrypted_key TEXT,
        created_at INTEGER
      );
    `);

    // Schema migration: rename public_key to authenticator_data if it exists
    try {
      const columns = this.db.prepare("PRAGMA table_info(biometric_config)").all() as any[];
      const hasPublicKey = columns.some(c => c.name === 'public_key');
      const hasAuthData = columns.some(c => c.name === 'authenticator_data');
      if (hasPublicKey && !hasAuthData) {
        this.db.exec('ALTER TABLE biometric_config RENAME COLUMN public_key TO authenticator_data');
      }
    } catch {
      // Column rename might fail if already renamed or table doesn't exist
    }
  }

  // --- Auth Methods ---

  hasAuthConfig(): boolean {
    const row = this.db.prepare('SELECT id FROM auth_config WHERE id = 1').get();
    return !!row;
  }

  getAuthConfig(): AuthConfig | null {
    const row = this.db.prepare('SELECT * FROM auth_config WHERE id = 1').get() as any;
    if (!row) return null;
    return {
      masterPasswordHash: row.master_password_hash,
      salt: row.salt,
      iterations: row.iterations,
      createdAt: row.created_at,
      lastLogin: row.last_login,
      autoLockMinutes: row.auto_lock_minutes,
    };
  }

  saveAuthConfig(config: {
    masterPasswordHash: string;
    salt: string;
    iterations: number;
  }): void {
    this.db.prepare(`
      INSERT OR REPLACE INTO auth_config (id, master_password_hash, salt, iterations, created_at, auto_lock_minutes)
      VALUES (1, ?, ?, ?, ?, 5)
    `).run(
      config.masterPasswordHash,
      config.salt,
      config.iterations,
      Date.now()
    );
  }

  updateLastLogin(): void {
    this.db.prepare('UPDATE auth_config SET last_login = ? WHERE id = 1').run(Date.now());
  }

  // --- Session Management ---

  createSessionToken(): string {
    const token = generateRandomHex(32);
    const now = Date.now();
    const settings = this.getSettings();
    const lockMinutes = settings.autoLockMinutes > 0 ? settings.autoLockMinutes : 30;
    const expiresAt = now + lockMinutes * 60 * 1000;

    this.db.prepare('DELETE FROM session_tokens WHERE expires_at < ?').run(now);
    this.db.prepare('INSERT INTO session_tokens (token, created_at, expires_at) VALUES (?, ?, ?)')
      .run(token, now, expiresAt);

    return token;
  }

  isSessionValid(token: string): boolean {
    const row = this.db.prepare('SELECT id FROM session_tokens WHERE token = ? AND expires_at > ?')
      .get(token, Date.now());
    return !!row;
  }

  invalidateSession(token: string): void {
    this.db.prepare('DELETE FROM session_tokens WHERE token = ?').run(token);
  }

  invalidateAllSessions(): void {
    this.db.prepare('DELETE FROM session_tokens').run();
  }

  // --- Vault Data Methods ---

  setEncryptionKey(key: string): void {
    this.encryptionKey = key;
  }

  getEncryptionKey(): string | null {
    return this.encryptionKey;
  }

  clearEncryptionKey(): void {
    this.encryptionKey = null;
  }

  isUnlocked(): boolean {
    return this.encryptionKey !== null;
  }

  saveVaultData(data: VaultData): void {
    if (!this.encryptionKey) throw new Error('Vault is locked');

    const jsonData = JSON.stringify(data);
    const encrypted = encrypt(jsonData, this.encryptionKey);

    this.db.prepare(`
      INSERT OR REPLACE INTO encrypted_vault (id, vault_data, iv, tag, updated_at)
      VALUES (1, ?, ?, ?, ?)
    `).run(encrypted.ciphertext, encrypted.iv, encrypted.tag, Date.now());
  }

  loadVaultData(): VaultData {
    if (!this.encryptionKey) throw new Error('Vault is locked');

    const row = this.db.prepare('SELECT * FROM encrypted_vault WHERE id = 1').get() as any;
    if (!row) return { passwords: [], twoFactor: [] };

    const decrypted = decrypt(
      { ciphertext: row.vault_data, iv: row.iv, tag: row.tag },
      this.encryptionKey
    );

    return JSON.parse(decrypted);
  }

  // --- Password CRUD ---

  getPasswords(): PasswordEntry[] {
    const vault = this.loadVaultData();
    return vault.passwords;
  }

  addPassword(entry: Omit<PasswordEntry, 'id' | 'createdAt' | 'updatedAt'>): PasswordEntry {
    const vault = this.loadVaultData();
    const newEntry: PasswordEntry = {
      ...entry,
      id: generateId(),
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
    vault.passwords.push(newEntry);
    this.saveVaultData(vault);
    return newEntry;
  }

  updatePassword(id: string, updates: Partial<PasswordEntry>): PasswordEntry | null {
    const vault = this.loadVaultData();
    const index = vault.passwords.findIndex((p) => p.id === id);
    if (index === -1) return null;

    vault.passwords[index] = {
      ...vault.passwords[index],
      ...updates,
      updatedAt: Date.now(),
    };
    this.saveVaultData(vault);
    return vault.passwords[index];
  }

  deletePassword(id: string): boolean {
    const vault = this.loadVaultData();
    const initialLength = vault.passwords.length;
    vault.passwords = vault.passwords.filter((p) => p.id !== id);

    if (vault.passwords.length < initialLength) {
      this.saveVaultData(vault);
      return true;
    }
    return false;
  }

  searchPasswords(query: string): PasswordEntry[] {
    const vault = this.loadVaultData();
    const lowerQuery = query.toLowerCase();
    return vault.passwords.filter(
      (p: PasswordEntry) =>
        p.title.toLowerCase().includes(lowerQuery) ||
        p.username.toLowerCase().includes(lowerQuery) ||
        (p.url && p.url.toLowerCase().includes(lowerQuery)) ||
        (p.notes && p.notes.toLowerCase().includes(lowerQuery))
    );
  }

  getPasswordsForUrl(url: string): PasswordEntry[] {
    const vault = this.loadVaultData();
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname;

      return vault.passwords.filter((p: PasswordEntry) => {
        if (!p.url) return false;
        try {
          const pUrl = new URL(p.url);
          return (
            pUrl.hostname === domain ||
            domain.endsWith('.' + pUrl.hostname) ||
            pUrl.hostname.endsWith('.' + domain)
          );
        } catch {
          return p.url.toLowerCase().includes(domain.toLowerCase());
        }
      });
    } catch {
      return [];
    }
  }

  // --- TOTP CRUD ---

  getTotpEntries(): TwoFactorEntry[] {
    const vault = this.loadVaultData();
    return vault.twoFactor;
  }

  addTotpEntry(entry: Omit<TwoFactorEntry, 'id' | 'createdAt' | 'updatedAt'>): TwoFactorEntry {
    const vault = this.loadVaultData();
    const newEntry: TwoFactorEntry = {
      ...entry,
      id: generateId(),
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
    vault.twoFactor.push(newEntry);
    this.saveVaultData(vault);
    return newEntry;
  }

  updateTotpEntry(id: string, updates: Partial<TwoFactorEntry>): TwoFactorEntry | null {
    const vault = this.loadVaultData();
    const index = vault.twoFactor.findIndex((t) => t.id === id);
    if (index === -1) return null;

    vault.twoFactor[index] = {
      ...vault.twoFactor[index],
      ...updates,
      updatedAt: Date.now(),
    };
    this.saveVaultData(vault);
    return vault.twoFactor[index];
  }

  deleteTotpEntry(id: string): boolean {
    const vault = this.loadVaultData();
    const initialLength = vault.twoFactor.length;
    vault.twoFactor = vault.twoFactor.filter((t) => t.id !== id);

    if (vault.twoFactor.length < initialLength) {
      this.saveVaultData(vault);
      return true;
    }
    return false;
  }

  searchTotpEntries(query: string): TwoFactorEntry[] {
    const vault = this.loadVaultData();
    const lowerQuery = query.toLowerCase();
    return vault.twoFactor.filter(
      (t: TwoFactorEntry) =>
        t.title.toLowerCase().includes(lowerQuery) ||
        (t.issuer && t.issuer.toLowerCase().includes(lowerQuery)) ||
        (t.account && t.account.toLowerCase().includes(lowerQuery))
    );
  }

  getTotpEntriesForUrl(url: string): TwoFactorEntry[] {
    const vault = this.loadVaultData();
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname;

      return vault.twoFactor.filter((t: TwoFactorEntry) => {
        if (t.uri) {
          try {
            const tUrl = new URL(t.uri.replace('otpauth://', 'https://'));
            return tUrl.hostname.includes(domain) || domain.includes(tUrl.hostname);
          } catch { /* ignore */ }
        }
        if (t.issuer) {
          const issuerLower = t.issuer.toLowerCase();
          return domain.toLowerCase().includes(issuerLower) || issuerLower.includes(domain.toLowerCase().split('.')[0]);
        }
        return false;
      });
    } catch {
      return [];
    }
  }

  // --- Settings ---

  getSettings(): AppSettings {
    const row = this.db.prepare('SELECT settings_json FROM settings WHERE id = 1').get() as any;
    if (!row) {
      return {
        autoLockMinutes: 5,
        clipboardClearSeconds: 30,
        autoFillOnPageLoad: true,
        showNotifications: true,
        theme: 'system',
        language: 'en',
        minimizeToTray: true,
        startWithWindows: false,
        biometricEnabled: false,
      };
    }
    return JSON.parse(row.settings_json);
  }

  saveSettings(settings: AppSettings): void {
    this.db.prepare(`
      INSERT OR REPLACE INTO settings (id, settings_json, updated_at)
      VALUES (1, ?, ?)
    `).run(JSON.stringify(settings), Date.now());
  }

  // --- Export/Import ---

  exportVaultData(): VaultData {
    if (!this.encryptionKey) throw new Error('Vault is locked');
    return this.loadVaultData();
  }

  importVaultData(data: VaultData): void {
    if (!this.encryptionKey) throw new Error('Vault is locked');
    this.saveVaultData(data);
  }

  // --- Biometric Methods ---

  getBiometricConfig(): BiometricConfig | null {
    const row = this.db.prepare('SELECT * FROM biometric_config WHERE id = 1').get() as any;
    if (!row) return null;
    return {
      enabled: !!row.enabled,
      credentialId: row.credential_id,
      authenticatorData: row.authenticator_data,
      createdAt: row.created_at,
    };
  }

  saveBiometricConfig(config: BiometricConfig): void {
    this.db.prepare(`
      INSERT OR REPLACE INTO biometric_config (id, enabled, credential_id, authenticator_data, created_at)
      VALUES (1, ?, ?, ?, ?)
    `).run(
      config.enabled ? 1 : 0,
      config.credentialId || null,
      config.authenticatorData || null,
      config.createdAt || Date.now()
    );
  }

  saveBiometricKey(key: string): void {
    // Use Electron safeStorage for encryption if available
    // This leverages the OS keychain (DPAPI on Windows, Keychain on macOS)
    try {
      const { safeStorage } = require('electron');
      if (safeStorage && safeStorage.isEncryptionAvailable()) {
        const encrypted = safeStorage.encryptString(key);
        this.db.prepare(
          'UPDATE biometric_config SET encrypted_key = ? WHERE id = 1'
        ).run(encrypted.toString('base64'));
        return;
      }
    } catch {
      // Fall through to basic encryption
    }
    
    // Fallback: encrypt with machine-specific key (less secure)
    const deviceSecret = this.getDeviceSecret();
    const encryptedKey = encrypt(key, deviceSecret);
    this.db.prepare(
      'UPDATE biometric_config SET encrypted_key = ? WHERE id = 1'
    ).run(JSON.stringify(encryptedKey));
  }

  getBiometricKey(): string | null {
    const row = this.db.prepare('SELECT encrypted_key FROM biometric_config WHERE id = 1').get() as any;
    if (!row || !row.encrypted_key) return null;
    
    try {
      // Try Electron safeStorage first
      const { safeStorage } = require('electron');
      if (safeStorage && safeStorage.isEncryptionAvailable()) {
        const buffer = Buffer.from(row.encrypted_key, 'base64');
        return safeStorage.decryptString(buffer);
      }
    } catch {
      // Fall through to basic decryption
    }
    
    try {
      const deviceSecret = this.getDeviceSecret();
      const encrypted = JSON.parse(row.encrypted_key);
      return decrypt(encrypted, deviceSecret);
    } catch {
      return null;
    }
  }

  clearBiometricKey(): void {
    this.db.prepare(
      'UPDATE biometric_config SET encrypted_key = NULL WHERE id = 1'
    ).run();
  }

  private getDeviceSecret(): string {
    // Fallback device-specific secret when safeStorage is not available
    // Uses deterministic machine-specific secret for biometric key persistence
    // WARNING: This is weaker than safeStorage - biometric should ideally use safeStorage
    const machineId = os.hostname() + os.platform() + os.arch() + (os.cpus()[0]?.model || '');
    const crypto = require('crypto');
    // Use PBKDF2 with high iterations to strengthen the weak machine ID
    return crypto.pbkdf2Sync(machineId, 'vaultguard-salt', 100000, 32, 'sha512').toString('hex');
  }

  isSafeStorageAvailable(): boolean {
    try {
      const { safeStorage } = require('electron');
      if (!safeStorage) return false;
      // isEncryptionAvailable() is synchronous in Electron
      return safeStorage.isEncryptionAvailable();
    } catch {
      return false;
    }
  }

  // --- Export/Import CSV Methods ---

  getPasswordsAsCSV(): string {
    const passwords = this.getPasswords();
    const { entriesToCSV } = require('@vaultguard/shared/csv-utils');
    return entriesToCSV(passwords);
  }

  importPasswordsFromCSV(csvContent: string): { success: boolean; count?: number; errors?: string[] } {
    try {
      const { parseCSV, validateCSV } = require('@vaultguard/shared/csv-utils');
      const validation = validateCSV(csvContent);
      if (!validation.valid) {
        return { success: false, errors: validation.errors };
      }
      const entries = parseCSV(csvContent);
      for (const entry of entries) {
        this.addPassword(entry);
      }
      return { success: true, count: entries.length };
    } catch (err: any) {
      return { success: false, errors: [err.message] };
    }
  }

  // --- Cleanup ---

  close(): void {
    this.clearEncryptionKey();
    this.db.close();
  }
}
