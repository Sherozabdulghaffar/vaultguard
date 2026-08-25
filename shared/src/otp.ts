// ============================================
// VaultGuard - OTP Engine (Node)
// RFC 4226 (HOTP) + RFC 6238 (TOTP) + Steam Guard
// ============================================
//
// This module is deliberately self-contained instead of leaning on
// otplib's `authenticator` singleton. That singleton is hard-wired to
// SHA1 / 6 digits / 30s and silently ignores per-entry options, which is
// why entries using SHA256, SHA512, 7-8 digits, a non-30s period or HOTP
// produced codes that no server would ever accept.
//
// Every parameter that appears in an `otpauth://` URI is honoured here.

import * as crypto from 'crypto';

// --- Types -------------------------------------------------------------

export type OtpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';
export type OtpType = 'TOTP' | 'HOTP';
export type SecretEncoding = 'base32' | 'hex' | 'ascii';

export interface OtpParams {
  secret: string;
  type?: OtpType;
  algorithm?: OtpAlgorithm | string;
  digits?: number;
  period?: number;
  counter?: number;
  encoding?: SecretEncoding;
  /** Steam Guard uses a 5-char alphanumeric alphabet instead of digits. */
  steam?: boolean;
  /** Milliseconds. Defaults to Date.now(). */
  timestamp?: number;
  /** Seconds of clock offset to apply (device vs. server drift). */
  skewSeconds?: number;
}

export interface OtpResult {
  code: string;
  /** Time-step counter used to produce `code`. */
  counter: number;
  /** Seconds until `code` expires (TOTP only; 0 for HOTP). */
  remainingSeconds: number;
  /** Unix ms at which `code` expires (TOTP only; 0 for HOTP). */
  expiresAt: number;
  period: number;
  digits: number;
}

// --- Constants ---------------------------------------------------------

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEAM_ALPHABET = '23456789BCDFGHJKMNPQRTVWXY';

export const DEFAULT_ALGORITHM: OtpAlgorithm = 'SHA1';
export const DEFAULT_DIGITS = 6;
export const DEFAULT_PERIOD = 30;
export const VALID_DIGITS = [6, 7, 8];
export const VALID_ALGORITHMS: OtpAlgorithm[] = ['SHA1', 'SHA256', 'SHA512'];

// --- Secret handling ---------------------------------------------------

/**
 * Normalise a user-supplied secret: strip whitespace, dashes and any
 * `=` padding, and upper-case it. Authenticator QR codes and manual
 * entry both produce grouped/lower-cased variants of the same secret.
 */
export function normalizeSecret(secret: string): string {
  const s = String(secret || '');
  if (s.length > 256) throw new Error('Secret too long');
  return s
    .replace(/[\s\-_]/g, '')
    .replace(/=+$/, '')
    .toUpperCase();
}

/** True when the string is valid RFC 4648 base32 (padding optional). */
export function isValidBase32(secret: string): boolean {
  const s = normalizeSecret(secret);
  return s.length > 0 && /^[A-Z2-7]+$/.test(s);
}

/**
 * Decode a base32 secret to raw bytes.
 * Tolerates missing padding, lower case, spaces and dashes.
 */
export function base32Decode(secret: string): Buffer {
  const input = normalizeSecret(secret);
  if (!input) throw new Error('Secret is empty');

  let bits = 0;
  let value = 0;
  const out: number[] = [];

  for (const char of input) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) {
      throw new Error(`Invalid base32 character "${char}" in secret`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }

  if (out.length === 0) {
    throw new Error('Secret is too short to decode');
  }
  return Buffer.from(out);
}

/** Encode raw bytes as base32 (no padding) — used for migration imports. */
export function base32Encode(bytes: Buffer | Uint8Array): string {
  const buf = Buffer.from(bytes);
  let bits = 0;
  let value = 0;
  let out = '';

  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_ALPHABET[(value >>> bits) & 31];
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

/**
 * Turn a secret string into key bytes, auto-detecting the encoding when
 * one is not declared. Some issuers (notably a few enterprise SSO
 * portals) hand out hex secrets.
 */
export function decodeSecret(secret: string, encoding?: SecretEncoding): Buffer {
  const raw = String(secret || '').trim();
  if (!raw) throw new Error('Secret is empty');

  if (encoding === 'hex') return Buffer.from(stripHexPrefix(raw), 'hex');
  if (encoding === 'ascii') return Buffer.from(raw, 'utf8');
  if (encoding === 'base32') return base32Decode(raw);

  // Auto-detect: an explicit 0x prefix, or a pure-hex string that is not
  // also valid base32 (i.e. it contains 0, 1, 8 or 9).
  const cleaned = raw.replace(/[\s\-_]/g, '');
  if (/^0x/i.test(cleaned)) return Buffer.from(stripHexPrefix(cleaned), 'hex');
  if (/^[0-9a-f]+$/i.test(cleaned) && cleaned.length % 2 === 0 && /[0189]/.test(cleaned)) {
    return Buffer.from(cleaned, 'hex');
  }
  return base32Decode(cleaned);
}

function stripHexPrefix(s: string): string {
  const cleaned = s.replace(/[\s\-_]/g, '').replace(/^0x/i, '');
  if (cleaned.length % 2 !== 0) throw new Error('Hex secret has an odd length');
  if (!/^[0-9a-f]+$/i.test(cleaned)) throw new Error('Invalid hex secret');
  return cleaned;
}

/** Generate a fresh base32 TOTP secret (default 20 bytes = 160 bits, per RFC 4226). */
export function generateSecret(bytes: number = 20): string {
  return base32Encode(crypto.randomBytes(bytes));
}

// --- Parameter normalisation -------------------------------------------

export function normalizeAlgorithm(algorithm?: string): OtpAlgorithm {
  if (!algorithm) return DEFAULT_ALGORITHM;
  const upper = String(algorithm).toUpperCase().replace(/[-\s]/g, '');
  if (upper === 'SHA1' || upper === 'SHA') return 'SHA1';
  if (upper === 'SHA256' || upper === 'SHA2') return 'SHA256';
  if (upper === 'SHA512') return 'SHA512';
  return DEFAULT_ALGORITHM;
}

export function normalizeDigits(digits?: number | string): number {
  const n = typeof digits === 'string' ? parseInt(digits, 10) : digits;
  if (!n || !Number.isFinite(n)) return DEFAULT_DIGITS;
  // Clamp rather than throw: a malformed QR should still yield a usable code.
  return Math.min(10, Math.max(6, Math.trunc(n)));
}

export function normalizePeriod(period?: number | string): number {
  const n = typeof period === 'string' ? parseInt(period, 10) : period;
  if (!n || !Number.isFinite(n) || n <= 0) return DEFAULT_PERIOD;
  return Math.min(300, Math.trunc(n));
}

// --- Core HOTP ---------------------------------------------------------

function counterToBuffer(counter: number): Buffer {
  const buf = Buffer.alloc(8);
  // Write as a 64-bit big-endian integer. Split to stay exact past 2^32.
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter % 0x100000000, 4);
  return buf;
}

function hmacDigest(algorithm: OtpAlgorithm, key: Buffer, message: Buffer): Buffer {
  const nodeAlgo = algorithm.toLowerCase(); // sha1 | sha256 | sha512
  return crypto.createHmac(nodeAlgo, key).update(message).digest();
}

/**
 * RFC 4226 dynamic truncation. Returns the 31-bit integer that the
 * digit/alphabet formatting is derived from.
 */
function dynamicTruncate(digest: Buffer): number {
  const offset = digest[digest.length - 1] & 0x0f;
  return (
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff)
  );
}

function formatSteam(value: number): string {
  let v = value;
  let code = '';
  for (let i = 0; i < 5; i++) {
    code += STEAM_ALPHABET[v % STEAM_ALPHABET.length];
    v = Math.floor(v / STEAM_ALPHABET.length);
  }
  return code;
}

/** Raw HOTP: one code for one counter value. */
export function hotp(params: {
  secret: string;
  counter: number;
  algorithm?: OtpAlgorithm | string;
  digits?: number;
  encoding?: SecretEncoding;
  steam?: boolean;
}): string {
  const key = decodeSecret(params.secret, params.encoding);
  const algorithm = normalizeAlgorithm(params.algorithm);
  const counter = Math.max(0, Math.trunc(params.counter || 0));

  const digest = hmacDigest(algorithm, key, counterToBuffer(counter));
  const value = dynamicTruncate(digest);

  if (params.steam) return formatSteam(value);

  const digits = normalizeDigits(params.digits);
  return String(value % Math.pow(10, digits)).padStart(digits, '0');
}

/** Current TOTP time-step for a given period. */
export function timeStep(period: number = DEFAULT_PERIOD, timestamp: number = Date.now(), skewSeconds = 0): number {
  return Math.floor((Math.floor(timestamp / 1000) + skewSeconds) / normalizePeriod(period));
}

/** Seconds remaining in the current time-step. */
export function remainingSeconds(period: number = DEFAULT_PERIOD, timestamp: number = Date.now(), skewSeconds = 0): number {
  const p = normalizePeriod(period);
  const seconds = Math.floor(timestamp / 1000) + skewSeconds;
  return p - (seconds % p);
}

// --- Public generate / verify -----------------------------------------

/**
 * Generate an OTP honouring every parameter. Works for both TOTP and
 * HOTP; for HOTP pass `counter`.
 */
export function generateOtp(params: OtpParams): OtpResult {
  const type: OtpType = params.type === 'HOTP' ? 'HOTP' : 'TOTP';
  const digits = params.steam ? 5 : normalizeDigits(params.digits);
  const period = normalizePeriod(params.period);
  const timestamp = params.timestamp ?? Date.now();
  const skew = params.skewSeconds || 0;

  if (type === 'HOTP') {
    const counter = Math.max(0, Math.trunc(params.counter ?? 0));
    return {
      code: hotp({
        secret: params.secret,
        counter,
        algorithm: params.algorithm,
        digits,
        encoding: params.encoding,
        steam: params.steam,
      }),
      counter,
      remainingSeconds: 0,
      expiresAt: 0,
      period,
      digits,
    };
  }

  const counter = timeStep(period, timestamp, skew);
  const remaining = remainingSeconds(period, timestamp, skew);

  return {
    code: hotp({
      secret: params.secret,
      counter,
      algorithm: params.algorithm,
      digits,
      encoding: params.encoding,
      steam: params.steam,
    }),
    counter,
    remainingSeconds: remaining,
    expiresAt: (counter + 1) * period * 1000 - skew * 1000,
    period,
    digits,
  };
}

/** Convenience wrapper returning just the code string. */
export function generateCode(params: OtpParams): string {
  return generateOtp(params).code;
}

/** The code for the *next* time-step — shown in the UI near expiry. */
export function generateNextCode(params: OtpParams): string {
  const period = normalizePeriod(params.period);
  if (params.type === 'HOTP') {
    return generateCode({ ...params, counter: (params.counter ?? 0) + 1 });
  }
  const timestamp = (params.timestamp ?? Date.now()) + period * 1000;
  return generateCode({ ...params, timestamp });
}

/**
 * Verify a submitted code, tolerating clock drift of +/- `window`
 * time-steps (TOTP) or scanning forward `window` counters (HOTP).
 * Returns the matching counter, or null.
 */
export function verifyOtp(token: string, params: OtpParams & { window?: number }): { valid: boolean; counter: number | null; delta: number | null } {
  const candidate = String(token || '').replace(/\s/g, '').toUpperCase();
  if (!candidate) return { valid: false, counter: null, delta: null };

  const window = params.window ?? (params.type === 'HOTP' ? 10 : 1);
  const type: OtpType = params.type === 'HOTP' ? 'HOTP' : 'TOTP';
  const digits = params.steam ? 5 : normalizeDigits(params.digits);
  const period = normalizePeriod(params.period);

  const base =
    type === 'HOTP'
      ? Math.max(0, Math.trunc(params.counter ?? 0))
      : timeStep(period, params.timestamp ?? Date.now(), params.skewSeconds || 0);

  // HOTP only looks forward; TOTP looks both ways.
  const from = type === 'HOTP' ? 0 : -window;
  const to = window;

  for (let delta = from; delta <= to; delta++) {
    const counter = base + delta;
    if (counter < 0) continue;
    const expected = hotp({
      secret: params.secret,
      counter,
      algorithm: params.algorithm,
      digits,
      encoding: params.encoding,
      steam: params.steam,
    });
    if (timingSafeEqualString(expected, candidate)) {
      return { valid: true, counter, delta };
    }
  }
  return { valid: false, counter: null, delta: null };
}

function timingSafeEqualString(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// --- otpauth:// URIs ---------------------------------------------------

export interface ParsedOtpUri {
  type: OtpType;
  issuer: string;
  account: string;
  title: string;
  secret: string;
  algorithm: OtpAlgorithm;
  digits: number;
  period: number;
  counter?: number;
  steam?: boolean;
  encoding?: SecretEncoding;
  uri: string;
}

/**
 * Parse an `otpauth://` URI.
 *
 * Per the Key URI spec the label is `issuer:account` — NOT
 * `account:issuer`. The previous implementation had these swapped, which
 * mislabelled every scanned QR code.
 */
export function parseOtpauthUri(uri: string): ParsedOtpUri | null {
  const raw = String(uri || '').trim();
  if (!raw) return null;

  // `new URL` mangles otpauth:// on some runtimes, so parse by hand.
  const match = /^otpauth:\/\/(totp|hotp)\/([^?]*)(?:\?(.*))?$/i.exec(raw);
  if (!match) return null;

  const type: OtpType = match[1].toLowerCase() === 'hotp' ? 'HOTP' : 'TOTP';
  const label = safeDecode(match[2] || '');
  const params = new URLSearchParams(match[3] || '');

  // Label may be "Issuer:account", "Issuer: account" or just "account".
  let issuer = '';
  let account = label;
  const sep = label.indexOf(':');
  if (sep !== -1) {
    issuer = label.slice(0, sep).trim();
    account = label.slice(sep + 1).trim();
  }

  // The `issuer` query parameter is authoritative when present.
  const issuerParam = params.get('issuer');
  if (issuerParam) issuer = issuerParam.trim();

  const secret = normalizeSecret(params.get('secret') || '');
  if (!secret) return null;

  const isSteam =
    /steam/i.test(issuer) ||
    /steam/i.test(params.get('encoder') || '') ||
    (params.get('digits') === '5' && /steam/i.test(label));

  const parsed: ParsedOtpUri = {
    type,
    issuer,
    account,
    title: issuer || account || 'Unnamed',
    secret,
    algorithm: normalizeAlgorithm(params.get('algorithm') || undefined),
    digits: isSteam ? 5 : normalizeDigits(params.get('digits') || undefined),
    period: normalizePeriod(params.get('period') || undefined),
    uri: raw,
  };

  if (type === 'HOTP') {
    const counter = parseInt(params.get('counter') || '0', 10);
    parsed.counter = Number.isFinite(counter) && counter >= 0 ? counter : 0;
  }
  if (isSteam) parsed.steam = true;

  const enc = (params.get('encoding') || '').toLowerCase();
  if (enc === 'hex' || enc === 'base32' || enc === 'ascii') {
    parsed.encoding = enc as SecretEncoding;
  }

  return parsed;
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** Build a spec-compliant `otpauth://` URI for QR export. */
export function buildOtpauthUri(entry: {
  type?: OtpType;
  issuer?: string;
  account?: string;
  title?: string;
  secret: string;
  algorithm?: OtpAlgorithm | string;
  digits?: number;
  period?: number;
  counter?: number;
}): string {
  const type = (entry.type === 'HOTP' ? 'hotp' : 'totp') as string;
  const issuer = (entry.issuer || '').trim();
  const account = (entry.account || entry.title || 'account').trim();

  const label = issuer ? `${issuer}:${account}` : account;

  const params = new URLSearchParams();
  params.set('secret', normalizeSecret(entry.secret));
  if (issuer) params.set('issuer', issuer);
  params.set('algorithm', normalizeAlgorithm(entry.algorithm));
  params.set('digits', String(normalizeDigits(entry.digits)));

  if (type === 'hotp') {
    params.set('counter', String(Math.max(0, Math.trunc(entry.counter ?? 0))));
  } else {
    params.set('period', String(normalizePeriod(entry.period)));
  }

  // encodeURIComponent leaves ':' alone in the label on purpose — the
  // spec shows an unencoded colon between issuer and account.
  return `otpauth://${type}/${encodeURIComponent(label).replace(/%3A/gi, ':')}?${params.toString()}`;
}

// --- Google Authenticator migration (otpauth-migration://) -------------

/**
 * Decode a Google Authenticator export payload.
 *
 * The payload is base64-encoded protobuf, not text — the old code ran a
 * regex over `atob(data)` and therefore never imported anything.
 */
export function parseMigrationUri(uri: string): ParsedOtpUri[] {
  const raw = String(uri || '').trim();
  const match = /^otpauth-migration:\/\/(?:offline)?\?(.*)$/i.exec(raw);
  if (!match) return [];

  const data = new URLSearchParams(match[1]).get('data');
  if (!data) return [];

  let bytes: Buffer;
  try {
    // Payload is standard base64 but often arrives URL-encoded.
    const b64 = safeDecode(data).replace(/-/g, '+').replace(/_/g, '/');
    bytes = Buffer.from(b64, 'base64');
  } catch {
    return [];
  }
  if (!bytes.length) return [];

  const ALGO: Record<number, OtpAlgorithm> = { 1: 'SHA1', 2: 'SHA256', 3: 'SHA512' };
  const DIGITS: Record<number, number> = { 1: 6, 2: 8 };

  const results: ParsedOtpUri[] = [];

  for (const field of protoFields(bytes)) {
    if (field.number !== 1 || !(field.value instanceof Buffer)) continue; // otp_parameters

    let secretBytes: Buffer | null = null;
    let name = '';
    let issuer = '';
    let algorithm: OtpAlgorithm = 'SHA1';
    let digits = 6;
    let type: OtpType = 'TOTP';
    let counter = 0;

    for (const sub of protoFields(field.value)) {
      switch (sub.number) {
        case 1:
          if (sub.value instanceof Buffer) secretBytes = sub.value;
          break;
        case 2:
          if (sub.value instanceof Buffer) name = sub.value.toString('utf8');
          break;
        case 3:
          if (sub.value instanceof Buffer) issuer = sub.value.toString('utf8');
          break;
        case 4:
          if (typeof sub.value === 'number') algorithm = ALGO[sub.value] || 'SHA1';
          break;
        case 5:
          if (typeof sub.value === 'number') digits = DIGITS[sub.value] || 6;
          break;
        case 6:
          if (typeof sub.value === 'number') type = sub.value === 1 ? 'HOTP' : 'TOTP';
          break;
        case 7:
          if (typeof sub.value === 'number') counter = sub.value;
          break;
      }
    }

    if (!secretBytes || !secretBytes.length) continue;

    // A migration label is "issuer:account" too.
    let account = name;
    if (!issuer && name.includes(':')) {
      const idx = name.indexOf(':');
      issuer = name.slice(0, idx).trim();
      account = name.slice(idx + 1).trim();
    }

    const secret = base32Encode(secretBytes);
    const entry: ParsedOtpUri = {
      type,
      issuer,
      account,
      title: issuer || account || 'Imported',
      secret,
      algorithm,
      digits,
      period: DEFAULT_PERIOD,
      uri: '',
    };
    if (type === 'HOTP') entry.counter = counter;
    entry.uri = buildOtpauthUri(entry);
    results.push(entry);
  }

  return results;
}

type ProtoField = { number: number; value: Buffer | number };

/** Minimal protobuf wire-format reader (varint, 64-bit, length-delimited, 32-bit). */
function* protoFields(buf: Buffer): Generator<ProtoField> {
  let offset = 0;
  while (offset < buf.length) {
    const [tag, tagLen] = readVarint(buf, offset);
    if (tagLen === 0) return;
    offset += tagLen;

    const fieldNumber = Math.floor(tag / 8);
    const wireType = tag & 0x07;

    if (wireType === 0) {
      const [value, len] = readVarint(buf, offset);
      if (len === 0) return;
      offset += len;
      yield { number: fieldNumber, value };
    } else if (wireType === 1) {
      offset += 8;
    } else if (wireType === 2) {
      const [len, lenLen] = readVarint(buf, offset);
      if (lenLen === 0) return;
      offset += lenLen;
      if (offset + len > buf.length) return;
      yield { number: fieldNumber, value: buf.subarray(offset, offset + len) };
      offset += len;
    } else if (wireType === 5) {
      offset += 4;
    } else {
      return; // unknown wire type — bail out rather than misparse
    }
  }
}

function readVarint(buf: Buffer, start: number): [number, number] {
  let result = 0;
  let shift = 0;
  let i = start;
  while (i < buf.length) {
    const byte = buf[i++];
    result += (byte & 0x7f) * Math.pow(2, shift);
    if ((byte & 0x80) === 0) return [result, i - start];
    shift += 7;
    if (shift > 63) break;
  }
  return [0, 0];
}

// --- Validation --------------------------------------------------------

export interface SecretValidation {
  valid: boolean;
  error?: string;
  /** Decoded key length in bytes — very short keys are usually typos. */
  keyBytes?: number;
}

/** Validate a secret before saving so the user finds out immediately. */
export function validateSecret(secret: string, encoding?: SecretEncoding): SecretValidation {
  const raw = String(secret || '').trim();
  if (!raw) return { valid: false, error: 'Secret is required' };

  try {
    const key = decodeSecret(raw, encoding);
    if (key.length < 10) {
      return {
        valid: false,
        error: `Secret decodes to only ${key.length} byte${key.length === 1 ? '' : 's'} — it looks incomplete`,
        keyBytes: key.length,
      };
    }
    return { valid: true, keyBytes: key.length };
  } catch (err: any) {
    return { valid: false, error: err?.message || 'Secret is not valid base32' };
  }
}
