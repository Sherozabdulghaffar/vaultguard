// ============================================
// VaultGuard - Cryptographic Utilities
// AES-256-GCM encryption, PBKDF2 key derivation
// ============================================

import * as crypto from 'crypto';
import QRCode from 'qrcode';
import {
  EncryptionResult,
  DerivedKey,
  TwoFactorEntry,
  PasswordEntry,
} from './index';
import {
  generateOtp,
  generateNextCode as otpNextCode,
  verifyOtp,
  buildOtpauthUri,
  parseOtpauthUri as otpParseUri,
  parseMigrationUri as otpParseMigration,
  generateSecret as otpGenerateSecret,
  validateSecret as otpValidateSecret,
  remainingSeconds as otpRemainingSeconds,
  timeStep as otpTimeStep,
  normalizeSecret,
  type OtpAlgorithm,
  type OtpParams,
  type OtpResult,
  type ParsedOtpUri,
  type SecretEncoding,
} from './otp';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const PBKDF2_ITERATIONS = 600000;
const DIGEST = 'sha512';

// The stored password verifier used to be *identical* to the AES key,
// which meant anyone who could read vault.db could decrypt the vault
// without knowing the master password. v2 stores an HMAC of the key
// instead. Legacy (bare-hex) verifiers still validate and are upgraded
// in place on the next successful unlock.
const VERIFIER_V2_PREFIX = 'v2$';
const VERIFIER_INFO = 'vaultguard/master-verifier/v2';

/**
 * Generate a cryptographically secure random hex string
 */
export function generateRandomHex(bytes: number): string {
  return crypto.randomBytes(bytes).toString('hex');
}

/**
 * Derive an encryption key from a master password using PBKDF2
 */
export function deriveKey(masterPassword: string, salt: string, iterations: number = PBKDF2_ITERATIONS): DerivedKey {
  const saltBuffer = Buffer.from(salt, 'hex');
  const keyBuffer = crypto.pbkdf2Sync(
    masterPassword,
    saltBuffer,
    iterations,
    KEY_LENGTH,
    DIGEST
  );
  return {
    key: keyBuffer.toString('hex'),
    salt,
  };
}

/**
 * Derive the storage verifier from an encryption key.
 * Knowing the verifier does not reveal the key.
 */
export function computeVerifier(keyHex: string): string {
  const hmac = crypto.createHmac('sha256', Buffer.from(keyHex, 'hex'));
  return VERIFIER_V2_PREFIX + hmac.update(VERIFIER_INFO).digest('hex');
}

/**
 * Hash a master password for storage (never store the raw password).
 * Returns: { hash, salt, iterations } - store all three in the database.
 *
 * `hash` is a v2 verifier, NOT the encryption key. Call `deriveKey` with
 * the same salt/iterations to obtain the key for encrypt/decrypt.
 */
export function hashMasterPassword(masterPassword: string): { hash: string; salt: string; iterations: number } {
  const salt = generateRandomHex(32);
  const iterations = PBKDF2_ITERATIONS;
  const derived = deriveKey(masterPassword, salt, iterations);

  return {
    hash: computeVerifier(derived.key),
    salt,
    iterations,
  };
}

/**
 * Verify a master password and return the derived encryption key in one
 * pass, so callers do not have to run a 600k-iteration PBKDF2 twice.
 *
 * `needsUpgrade` is true for legacy vaults whose stored verifier is the
 * raw encryption key; callers should re-save `newHash` when they see it.
 */
export function verifyMasterPasswordDetailed(
  masterPassword: string,
  storedHash: string,
  storedSalt: string,
  storedIterations: number
): { valid: boolean; key: string | null; needsUpgrade: boolean; newHash?: string } {
  const fail = { valid: false, key: null, needsUpgrade: false };
  try {
    const derived = deriveKey(masterPassword, storedSalt, storedIterations);

    if (storedHash.startsWith(VERIFIER_V2_PREFIX)) {
      if (!timingSafeEqualHex(storedHash.slice(VERIFIER_V2_PREFIX.length), computeVerifier(derived.key).slice(VERIFIER_V2_PREFIX.length))) {
        return fail;
      }
      return { valid: true, key: derived.key, needsUpgrade: false };
    }

    // Legacy: stored hash === derived key.
    if (!timingSafeEqualHex(storedHash, derived.key)) return fail;
    return {
      valid: true,
      key: derived.key,
      needsUpgrade: true,
      newHash: computeVerifier(derived.key),
    };
  } catch (error) {
    console.error('Password verification failed:', error);
    return fail;
  }
}

/**
 * Verify a master password against a stored hash.
 * Accepts both v2 verifiers and legacy (raw-key) hashes.
 */
export function verifyMasterPassword(
  masterPassword: string,
  storedHash: string,
  storedSalt: string,
  storedIterations: number
): boolean {
  return verifyMasterPasswordDetailed(masterPassword, storedHash, storedSalt, storedIterations).valid;
}

function timingSafeEqualHex(a: string, b: string): boolean {
  try {
    const bufA = Buffer.from(a, 'hex');
    const bufB = Buffer.from(b, 'hex');
    if (bufA.length === 0 || bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

/**
 * Encrypt data using AES-256-GCM
 */
export function encrypt(plaintext: string, keyHex: string): EncryptionResult {
  const key = Buffer.from(keyHex, 'hex');
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
    authTagLength: TAG_LENGTH,
  });

  let ciphertext = cipher.update(plaintext, 'utf8', 'base64');
  ciphertext += cipher.final('base64');

  const tag = cipher.getAuthTag();

  return {
    ciphertext,
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
  };
}

/**
 * Decrypt data using AES-256-GCM
 */
export function decrypt(encryptionResult: EncryptionResult, keyHex: string): string {
  try {
    const key = Buffer.from(keyHex, 'hex');
    const iv = Buffer.from(encryptionResult.iv, 'hex');
    const tag = Buffer.from(encryptionResult.tag || '', 'hex');

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
      authTagLength: TAG_LENGTH,
    });
    decipher.setAuthTag(tag);

    let plaintext = decipher.update(encryptionResult.ciphertext, 'base64', 'utf8');
    plaintext += decipher.final('utf8');

    return plaintext;
  } catch (error) {
    throw new Error('Decryption failed - incorrect key or corrupted data');
  }
}

/**
 * Encrypt a password entry
 */
export function encryptPasswordEntry(entry: PasswordEntry, keyHex: string): string {
  const data = JSON.stringify(entry);
  const result = encrypt(data, keyHex);
  return JSON.stringify(result);
}

/**
 * Decrypt a password entry
 */
export function decryptPasswordEntry(encryptedData: string, keyHex: string): PasswordEntry {
  const result: EncryptionResult = JSON.parse(encryptedData);
  const data = decrypt(result, keyHex);
  return JSON.parse(data);
}

/**
 * Encrypt a TOTP entry
 */
export function encryptTotpEntry(entry: TwoFactorEntry, keyHex: string): string {
  const data = JSON.stringify(entry);
  const result = encrypt(data, keyHex);
  return JSON.stringify(result);
}

/**
 * Decrypt a TOTP entry
 */
export function decryptTotpEntry(encryptedData: string, keyHex: string): TwoFactorEntry {
  const result: EncryptionResult = JSON.parse(encryptedData);
  const data = decrypt(result, keyHex);
  return JSON.parse(data);
}

// ============================================
// TOTP / HOTP Utilities
// Backed by ./otp — every option is honoured.
// ============================================

export {
  generateOtp,
  verifyOtp,
  buildOtpauthUri,
  base32Encode,
  base32Decode,
  decodeSecret,
  normalizeSecret,
  normalizeAlgorithm,
  normalizeDigits,
  normalizePeriod,
  timeStep,
  remainingSeconds,
  isValidBase32,
} from './otp';
export type { OtpAlgorithm, OtpParams, OtpResult, ParsedOtpUri, SecretEncoding, OtpType } from './otp';

export interface TotpOptions {
  algorithm?: OtpAlgorithm | string;
  digits?: number;
  period?: number;
  counter?: number;
  type?: 'TOTP' | 'HOTP';
  encoding?: SecretEncoding;
  steam?: boolean;
  timestamp?: number;
}

/**
 * Generate a new TOTP secret (base32, 160-bit as recommended by RFC 4226).
 */
export function generateTotpSecret(bytes: number = 20): string {
  return otpGenerateSecret(bytes);
}

/**
 * Generate an OTP from a secret.
 *
 * Unlike the previous implementation, `options` is actually used — so
 * SHA256/SHA512 secrets, 7/8-digit codes, 15/60-second periods and HOTP
 * counters all produce codes the server will accept.
 */
export function generateTotpCode(secret: string, options?: TotpOptions): string {
  return generateOtp(toOtpParams(secret, options)).code;
}

/** Full result: code plus the countdown metadata the UI needs. */
export function generateTotpDetailed(secret: string, options?: TotpOptions): OtpResult {
  return generateOtp(toOtpParams(secret, options));
}

/** The code for the following time-step (shown as "next" near expiry). */
export function generateNextTotpCode(secret: string, options?: TotpOptions): string {
  return otpNextCode(toOtpParams(secret, options));
}

/**
 * Verify a submitted OTP, tolerating one step of clock drift for TOTP or
 * scanning forward for HOTP.
 */
export function verifyTotpCode(
  token: string,
  secret: string,
  options?: TotpOptions & { window?: number }
): boolean {
  return verifyOtp(token, { ...toOtpParams(secret, options), window: options?.window }).valid;
}

/** Verify and report which counter matched (needed to resync HOTP). */
export function verifyTotpDetailed(
  token: string,
  secret: string,
  options?: TotpOptions & { window?: number }
): { valid: boolean; counter: number | null; delta: number | null } {
  return verifyOtp(token, { ...toOtpParams(secret, options), window: options?.window });
}

function toOtpParams(secret: string, options?: TotpOptions): OtpParams {
  return {
    secret,
    type: options?.type === 'HOTP' ? 'HOTP' : 'TOTP',
    algorithm: options?.algorithm,
    digits: options?.digits,
    period: options?.period,
    counter: options?.counter,
    encoding: options?.encoding,
    steam: options?.steam,
    timestamp: options?.timestamp,
  };
}

/** Seconds left in the current window for an entry's period. */
export function totpRemainingSeconds(period?: number, timestamp?: number): number {
  return otpRemainingSeconds(period ?? 30, timestamp ?? Date.now());
}

/** Current time-step counter for an entry's period. */
export function totpTimeStep(period?: number, timestamp?: number): number {
  return otpTimeStep(period ?? 30, timestamp ?? Date.now());
}

/** Validate a secret before saving so bad input is caught immediately. */
export function validateTotpSecret(secret: string, encoding?: SecretEncoding) {
  return otpValidateSecret(secret, encoding);
}

/**
 * Build a spec-compliant otpauth:// URI. The label is `issuer:account`,
 * and algorithm/digits/period/counter are all included.
 */
export function generateOtpauthUri(
  account: string,
  issuer: string,
  secret: string,
  options?: TotpOptions
): string {
  return buildOtpauthUri({
    type: options?.type === 'HOTP' ? 'HOTP' : 'TOTP',
    issuer,
    account,
    secret,
    algorithm: options?.algorithm,
    digits: options?.digits,
    period: options?.period,
    counter: options?.counter,
  });
}

/** Build the otpauth:// URI for a stored entry. */
export function entryToOtpauthUri(entry: Partial<TwoFactorEntry> & { secret: string }): string {
  return buildOtpauthUri({
    type: entry.type === 'HOTP' ? 'HOTP' : 'TOTP',
    issuer: entry.issuer,
    account: entry.account || entry.title,
    secret: entry.secret,
    algorithm: entry.algorithm,
    digits: entry.digits,
    period: entry.period,
    counter: entry.counter,
  });
}

/**
 * Generate a QR code as data URL from an otpauth URI
 */
export async function generateQrCodeDataUrl(uri: string): Promise<string> {
  return QRCode.toDataURL(uri, {
    width: 256,
    margin: 2,
    color: {
      dark: '#000000',
      light: '#ffffff',
    },
  });
}

/**
 * Parse an otpauth:// URI into a vault entry.
 *
 * Note: the Key URI spec defines the label as `issuer:account`. The old
 * implementation read it as `account:issuer`, so every scanned QR code
 * came out with the issuer and account swapped.
 */
export function parseOtpauthUri(uri: string): Partial<TwoFactorEntry> | null {
  const parsed = otpParseUri(uri);
  if (!parsed) return null;
  return parsedToEntry(parsed);
}

/**
 * Parse a Google Authenticator `otpauth-migration://` export payload
 * (base64 protobuf) into vault entries.
 */
export function parseMigrationUri(uri: string): Partial<TwoFactorEntry>[] {
  return otpParseMigration(uri).map(parsedToEntry);
}

/**
 * Accept anything the user pastes: a single otpauth:// URI, a Google
 * Authenticator migration URI, or several of either separated by
 * newlines. Returns every entry it could understand.
 */
export function parseOtpInput(input: string): Partial<TwoFactorEntry>[] {
  const entries: Partial<TwoFactorEntry>[] = [];
  const lines = String(input || '')
    .split(/[\r\n]+/)
    .map((l) => l.trim())
    .filter(Boolean);

  for (const line of lines) {
    if (/^otpauth-migration:\/\//i.test(line)) {
      entries.push(...parseMigrationUri(line));
    } else if (/^otpauth:\/\//i.test(line)) {
      const one = parseOtpauthUri(line);
      if (one) entries.push(one);
    }
  }
  return entries;
}

function parsedToEntry(parsed: ParsedOtpUri): Partial<TwoFactorEntry> {
  const entry: Partial<TwoFactorEntry> = {
    type: parsed.type,
    title: parsed.title,
    issuer: parsed.issuer,
    account: parsed.account,
    secret: normalizeSecret(parsed.secret),
    algorithm: parsed.algorithm,
    digits: parsed.digits,
    period: parsed.period,
    uri: parsed.uri,
  };
  if (parsed.type === 'HOTP') entry.counter = parsed.counter ?? 0;
  return entry;
}

/**
 * Clear sensitive data from memory (overwrite buffer)
 */
export function secureClear(buffer: Buffer): void {
  crypto.randomBytes(buffer.length).copy(buffer);
}

/**
 * JavaScript strings are immutable, so a string cannot actually be
 * wiped. Keep secrets in Buffers and use `secureClear` when it matters;
 * this helper exists only to make the intent explicit at call sites.
 */
export function secureClearString(_str: string): void {
  /* no-op by design — see doc comment */
}

/**
 * Generate a unique ID
 */
export function generateId(): string {
  return crypto.randomUUID();
}
