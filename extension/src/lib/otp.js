// ============================================
// VaultGuard - OTP Engine (WebCrypto)
// RFC 4226 (HOTP) + RFC 6238 (TOTP) + Steam Guard
// ============================================
//
// Browser/service-worker port of shared/src/otp.ts. Keep the two in sync:
// both are validated against the RFC 4226 Appendix D and RFC 6238
// Appendix B test vectors.
//
// Codes are computed here rather than round-tripped to the desktop app,
// so the popup shows live codes instantly and keeps working when the
// desktop app is closed.

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEAM_ALPHABET = '23456789BCDFGHJKMNPQRTVWXY';

export const DEFAULT_ALGORITHM = 'SHA1';
export const DEFAULT_DIGITS = 6;
export const DEFAULT_PERIOD = 30;

// --- Secret handling ---------------------------------------------------

export function normalizeSecret(secret) {
  return String(secret || '')
    .replace(/[\s\-_]/g, '')
    .replace(/=+$/, '')
    .toUpperCase();
}

export function isValidBase32(secret) {
  const s = normalizeSecret(secret);
  return s.length > 0 && /^[A-Z2-7]+$/.test(s);
}

export function base32Decode(secret) {
  const input = normalizeSecret(secret);
  if (!input) throw new Error('Secret is empty');

  let bits = 0;
  let value = 0;
  const out = [];

  for (const char of input) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) throw new Error(`Invalid base32 character "${char}" in secret`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }

  if (out.length === 0) throw new Error('Secret is too short to decode');
  return new Uint8Array(out);
}

export function base32Encode(bytes) {
  const buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
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
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function hexToBytes(hex) {
  const cleaned = hex.replace(/[\s\-_]/g, '').replace(/^0x/i, '');
  if (cleaned.length % 2 !== 0) throw new Error('Hex secret has an odd length');
  if (!/^[0-9a-f]+$/i.test(cleaned)) throw new Error('Invalid hex secret');
  const out = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(cleaned.substr(i * 2, 2), 16);
  }
  return out;
}

/** Decode a secret to key bytes, auto-detecting base32 vs hex. */
export function decodeSecret(secret, encoding) {
  const raw = String(secret || '').trim();
  if (!raw) throw new Error('Secret is empty');

  if (encoding === 'hex') return hexToBytes(raw);
  if (encoding === 'ascii') return new TextEncoder().encode(raw);
  if (encoding === 'base32') return base32Decode(raw);

  const cleaned = raw.replace(/[\s\-_]/g, '');
  if (/^0x/i.test(cleaned)) return hexToBytes(cleaned);
  // Pure hex that cannot also be base32 (contains 0, 1, 8 or 9).
  if (/^[0-9a-f]+$/i.test(cleaned) && cleaned.length % 2 === 0 && /[0189]/.test(cleaned)) {
    return hexToBytes(cleaned);
  }
  return base32Decode(cleaned);
}

/** Generate a fresh base32 secret (default 160-bit, per RFC 4226). */
export function generateSecret(bytes = 20) {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return base32Encode(buf);
}

// --- Parameter normalisation -------------------------------------------

export function normalizeAlgorithm(algorithm) {
  if (!algorithm) return DEFAULT_ALGORITHM;
  const upper = String(algorithm).toUpperCase().replace(/[-\s]/g, '');
  if (upper === 'SHA1' || upper === 'SHA') return 'SHA1';
  if (upper === 'SHA256' || upper === 'SHA2') return 'SHA256';
  if (upper === 'SHA512') return 'SHA512';
  return DEFAULT_ALGORITHM;
}

export function normalizeDigits(digits) {
  const n = typeof digits === 'string' ? parseInt(digits, 10) : digits;
  if (!n || !Number.isFinite(n)) return DEFAULT_DIGITS;
  return Math.min(10, Math.max(6, Math.trunc(n)));
}

export function normalizePeriod(period) {
  const n = typeof period === 'string' ? parseInt(period, 10) : period;
  if (!n || !Number.isFinite(n) || n <= 0) return DEFAULT_PERIOD;
  return Math.min(300, Math.trunc(n));
}

/** WebCrypto names the SHA-1 hash "SHA-1", not "SHA1". */
function webCryptoHash(algorithm) {
  return { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' }[algorithm] || 'SHA-1';
}

// --- Core HOTP ---------------------------------------------------------

function counterToBytes(counter) {
  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter % 0x100000000);
  return buf;
}

function dynamicTruncate(digest) {
  const offset = digest[digest.length - 1] & 0x0f;
  return (
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff)
  );
}

function formatSteam(value) {
  let v = value;
  let code = '';
  for (let i = 0; i < 5; i++) {
    code += STEAM_ALPHABET[v % STEAM_ALPHABET.length];
    v = Math.floor(v / STEAM_ALPHABET.length);
  }
  return code;
}

// importKey is the slow part; cache by (secret, algorithm).
const keyCache = new Map();
const KEY_CACHE_LIMIT = 200;

async function importHmacKey(keyBytes, algorithm, cacheKey) {
  if (cacheKey && keyCache.has(cacheKey)) return keyCache.get(cacheKey);

  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: { name: webCryptoHash(algorithm) } },
    false,
    ['sign']
  );

  if (cacheKey) {
    if (keyCache.size >= KEY_CACHE_LIMIT) keyCache.clear();
    keyCache.set(cacheKey, key);
  }
  return key;
}

/** Drop cached CryptoKeys — call on vault lock. */
export function clearKeyCache() {
  keyCache.clear();
}

/** Raw HOTP: one code for one counter value. */
export async function hotp({ secret, counter, algorithm, digits, encoding, steam }) {
  const algo = normalizeAlgorithm(algorithm);
  const keyBytes = decodeSecret(secret, encoding);
  const c = Math.max(0, Math.trunc(counter || 0));

  const key = await importHmacKey(keyBytes, algo, `${algo}:${encoding || 'auto'}:${secret}`);
  const signature = await crypto.subtle.sign('HMAC', key, counterToBytes(c));
  const value = dynamicTruncate(new Uint8Array(signature));

  if (steam) return formatSteam(value);

  const d = normalizeDigits(digits);
  return String(value % Math.pow(10, d)).padStart(d, '0');
}

/** Current TOTP time-step for a given period. */
export function timeStep(period = DEFAULT_PERIOD, timestamp = Date.now(), skewSeconds = 0) {
  return Math.floor((Math.floor(timestamp / 1000) + skewSeconds) / normalizePeriod(period));
}

/** Seconds remaining in the current time-step. */
export function remainingSeconds(period = DEFAULT_PERIOD, timestamp = Date.now(), skewSeconds = 0) {
  const p = normalizePeriod(period);
  const seconds = Math.floor(timestamp / 1000) + skewSeconds;
  return p - (seconds % p);
}

// --- Public generate / verify -----------------------------------------

/**
 * Generate an OTP honouring every parameter.
 * Returns { code, counter, remainingSeconds, expiresAt, period, digits }.
 */
export async function generateOtp(params) {
  const type = params.type === 'HOTP' ? 'HOTP' : 'TOTP';
  const digits = params.steam ? 5 : normalizeDigits(params.digits);
  const period = normalizePeriod(params.period);
  const timestamp = params.timestamp ?? Date.now();
  const skew = params.skewSeconds || 0;

  if (type === 'HOTP') {
    const counter = Math.max(0, Math.trunc(params.counter ?? 0));
    return {
      code: await hotp({ ...params, counter, digits }),
      counter,
      remainingSeconds: 0,
      expiresAt: 0,
      period,
      digits,
    };
  }

  const counter = timeStep(period, timestamp, skew);
  return {
    code: await hotp({ ...params, counter, digits }),
    counter,
    remainingSeconds: remainingSeconds(period, timestamp, skew),
    expiresAt: (counter + 1) * period * 1000 - skew * 1000,
    period,
    digits,
  };
}

/** Convenience wrapper returning just the code string. */
export async function generateCode(params) {
  return (await generateOtp(params)).code;
}

/** The code for the next time-step (shown as a preview near expiry). */
export async function generateNextCode(params) {
  if (params.type === 'HOTP') {
    return generateCode({ ...params, counter: (params.counter ?? 0) + 1 });
  }
  const period = normalizePeriod(params.period);
  return generateCode({ ...params, timestamp: (params.timestamp ?? Date.now()) + period * 1000 });
}

/** Verify a submitted code, tolerating clock drift. */
export async function verifyOtp(token, params) {
  const candidate = String(token || '').replace(/\s/g, '').toUpperCase();
  if (!candidate) return { valid: false, counter: null, delta: null };

  const type = params.type === 'HOTP' ? 'HOTP' : 'TOTP';
  const window = params.window ?? (type === 'HOTP' ? 10 : 1);
  const period = normalizePeriod(params.period);
  const base =
    type === 'HOTP'
      ? Math.max(0, Math.trunc(params.counter ?? 0))
      : timeStep(period, params.timestamp ?? Date.now(), params.skewSeconds || 0);

  const from = type === 'HOTP' ? 0 : -window;

  for (let delta = from; delta <= window; delta++) {
    const counter = base + delta;
    if (counter < 0) continue;
    const expected = await hotp({ ...params, counter });
    if (constantTimeEqual(expected, candidate)) return { valid: true, counter, delta };
  }
  return { valid: false, counter: null, delta: null };
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// --- otpauth:// URIs ---------------------------------------------------

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/**
 * Parse an `otpauth://` URI.
 * Per the Key URI spec the label is `issuer:account` — not the reverse.
 */
export function parseOtpauthUri(uri) {
  const raw = String(uri || '').trim();
  if (!raw) return null;

  const match = /^otpauth:\/\/(totp|hotp)\/([^?]*)(?:\?(.*))?$/i.exec(raw);
  if (!match) return null;

  const type = match[1].toLowerCase() === 'hotp' ? 'HOTP' : 'TOTP';
  const label = safeDecode(match[2] || '');
  const params = new URLSearchParams(match[3] || '');

  let issuer = '';
  let account = label;
  const sep = label.indexOf(':');
  if (sep !== -1) {
    issuer = label.slice(0, sep).trim();
    account = label.slice(sep + 1).trim();
  }

  const issuerParam = params.get('issuer');
  if (issuerParam) issuer = issuerParam.trim();

  const secret = normalizeSecret(params.get('secret') || '');
  if (!secret) return null;

  const isSteam =
    /steam/i.test(issuer) ||
    /steam/i.test(params.get('encoder') || '') ||
    (params.get('digits') === '5' && /steam/i.test(label));

  const parsed = {
    type,
    issuer,
    account,
    title: issuer || account || 'Unnamed',
    secret,
    algorithm: normalizeAlgorithm(params.get('algorithm')),
    digits: isSteam ? 5 : normalizeDigits(params.get('digits')),
    period: normalizePeriod(params.get('period')),
    uri: raw,
  };

  if (type === 'HOTP') {
    const counter = parseInt(params.get('counter') || '0', 10);
    parsed.counter = Number.isFinite(counter) && counter >= 0 ? counter : 0;
  }
  if (isSteam) parsed.steam = true;

  const enc = (params.get('encoding') || '').toLowerCase();
  if (enc === 'hex' || enc === 'base32' || enc === 'ascii') parsed.encoding = enc;

  return parsed;
}

/** Build a spec-compliant `otpauth://` URI. */
export function buildOtpauthUri(entry) {
  const type = entry.type === 'HOTP' ? 'hotp' : 'totp';
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

  return `otpauth://${type}/${encodeURIComponent(label).replace(/%3A/gi, ':')}?${params.toString()}`;
}

// --- Google Authenticator migration ------------------------------------

/**
 * Decode an `otpauth-migration://offline?data=...` payload.
 * The payload is base64-encoded protobuf, so a text regex over atob()
 * can never work — this walks the wire format properly.
 */
export function parseMigrationUri(uri) {
  const raw = String(uri || '').trim();
  const match = /^otpauth-migration:\/\/(?:offline)?\?(.*)$/i.exec(raw);
  if (!match) return [];

  const data = new URLSearchParams(match[1]).get('data');
  if (!data) return [];

  let bytes;
  try {
    const b64 = safeDecode(data).replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(b64);
    bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  } catch {
    return [];
  }
  if (!bytes.length) return [];

  const ALGO = { 1: 'SHA1', 2: 'SHA256', 3: 'SHA512' };
  const DIGITS = { 1: 6, 2: 8 };
  const decoder = new TextDecoder();
  const results = [];

  for (const field of protoFields(bytes)) {
    if (field.number !== 1 || typeof field.value === 'number') continue;

    let secretBytes = null;
    let name = '';
    let issuer = '';
    let algorithm = 'SHA1';
    let digits = 6;
    let type = 'TOTP';
    let counter = 0;

    for (const sub of protoFields(field.value)) {
      const isBytes = typeof sub.value !== 'number';
      switch (sub.number) {
        case 1: if (isBytes) secretBytes = sub.value; break;
        case 2: if (isBytes) name = decoder.decode(sub.value); break;
        case 3: if (isBytes) issuer = decoder.decode(sub.value); break;
        case 4: if (!isBytes) algorithm = ALGO[sub.value] || 'SHA1'; break;
        case 5: if (!isBytes) digits = DIGITS[sub.value] || 6; break;
        case 6: if (!isBytes) type = sub.value === 1 ? 'HOTP' : 'TOTP'; break;
        case 7: if (!isBytes) counter = sub.value; break;
      }
    }

    if (!secretBytes || !secretBytes.length) continue;

    let account = name;
    if (!issuer && name.includes(':')) {
      const idx = name.indexOf(':');
      issuer = name.slice(0, idx).trim();
      account = name.slice(idx + 1).trim();
    }

    const entry = {
      type,
      issuer,
      account,
      title: issuer || account || 'Imported',
      secret: base32Encode(secretBytes),
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

/** Minimal protobuf wire-format reader. */
function* protoFields(buf) {
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
      return;
    }
  }
}

function readVarint(buf, start) {
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

/**
 * Accept anything pasted or scanned: one otpauth:// URI, a migration
 * URI, or several separated by newlines.
 */
export function parseOtpInput(input) {
  const entries = [];
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

// --- Validation & display ---------------------------------------------

/** Validate a secret before saving so bad input surfaces immediately. */
export function validateSecret(secret, encoding) {
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
  } catch (err) {
    return { valid: false, error: err?.message || 'Secret is not valid base32' };
  }
}

/**
 * Group a code for readability the way authenticator apps do:
 * 6 -> "123 456", 7 -> "123 4567", 8 -> "1234 5678", 5 (Steam) -> as-is.
 */
export function formatCode(code) {
  const c = String(code || '');
  if (c.length === 6) return `${c.slice(0, 3)} ${c.slice(3)}`;
  if (c.length === 7) return `${c.slice(0, 3)} ${c.slice(3)}`;
  if (c.length === 8) return `${c.slice(0, 4)} ${c.slice(4)}`;
  return c;
}
