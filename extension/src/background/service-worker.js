/**
 * VaultGuard background service worker.
 *
 * Everything here has to survive MV3 worker eviction, so there is no top-level
 * timer and no long-lived assumption: state is rebuilt on demand from
 * storage, and every entry point starts by making sure the bridge to the
 * desktop app is actually alive.
 *
 * Two transports reach the desktop app and either one is enough:
 *
 *   native messaging — trusted implicitly, because the app writes this
 *     extension's ID into the host manifest's `allowed_origins`.
 *   loopback HTTP    — needs a one-time pairing the user approves inside the
 *     desktop window, because any local process can reach 127.0.0.1.
 *
 * Connection state is only ever set from a completed handshake. The previous
 * build set `isDesktopConnected = true` right after `connectNative()` returned,
 * but that call succeeds even when no host is installed — the failure arrives
 * later on `onDisconnect`. Because the retry counter had just been zeroed, the
 * backoff always computed 1 second, which is where the console error storm and
 * the lying badge came from.
 */

import {
  generateOtp,
  parseOtpInput,
  validateSecret,
  normalizeAlgorithm,
  normalizeDigits,
  normalizePeriod,
  normalizeSecret,
} from '../lib/otp.js';

// --- Constants ---------------------------------------------------------

const NATIVE_HOST = 'com.vaultguard.native';

/** Must match HTTP_FALLBACK_PORT_RANGE in the desktop app's main process. */
const HTTP_PORTS = [19800, 19801, 19802, 19803, 19804, 19805, 19806, 19807, 19808, 19809];

const HANDSHAKE_TIMEOUT_MS = 5000;
const REQUEST_TIMEOUT_MS = 15000;
const PROBE_TIMEOUT_MS = 1200;

const RETRY_ALARM = 'vaultguard:retry';
const WATCHDOG_ALARM = 'vaultguard:watchdog';

/** Chrome clamps alarms to 30s, so 0.5 is the shortest honest first step. */
const RETRY_BACKOFF_MINUTES = [0.5, 1, 2, 5, 10, 15];

const SESSION_STATE_KEY = 'bridgeState';
const PAIRING_KEY = 'pairing';
const LOCAL_ENTRIES_KEY = 'totpEntries';

const AUTO_FILL_COOLDOWN_MS = 30000;

// --- Bridge state ------------------------------------------------------

/**
 * Live connection state. Rebuilt after every worker restart; the only pieces
 * worth persisting are the pairing token and the port we last found the app on.
 *
 * Vault contents are deliberately absent — nothing decrypted from the vault is
 * cached here or in storage, so a scanned page or a browser restart can never
 * leak a secret the extension itself does not own.
 */
const bridge = {
  transport: 'none', // 'native' | 'http' | 'none'
  ready: false, // proven by a completed handshake, never assumed
  isUnlocked: false,
  hasAuthConfig: false,
  needsPairing: false,
  httpUrl: null,
  httpToken: null,
  lastPort: null,
  epoch: 0,
  skewSeconds: 0,
  version: null,
  lastError: null,
  attempt: 0,
};

let hydration = null;
let connecting = null;

let nativePort = null;
const pendingRequests = new Map();
let requestSeq = 0;

const autoFilledTabs = new Map();

// --- Persistence -------------------------------------------------------

/** Rebuild the little state that outlives a worker restart. Idempotent. */
function hydrated() {
  hydration ??= (async () => {
    try {
      const stored = await chrome.storage.local.get(PAIRING_KEY);
      const saved = stored?.[PAIRING_KEY];
      if (saved?.token) bridge.httpToken = saved.token;
      if (saved?.port) bridge.lastPort = saved.port;
    } catch {
      // First run, or storage is unavailable — defaults are fine.
    }
    try {
      const session = await chrome.storage.session.get(SESSION_STATE_KEY);
      const snap = session?.[SESSION_STATE_KEY];
      if (snap) {
        bridge.isUnlocked = !!snap.isUnlocked;
        bridge.hasAuthConfig = !!snap.hasAuthConfig;
        bridge.epoch = snap.epoch || 0;
      }
    } catch {
      // storage.session is memory-backed; missing data just means a cold start.
    }
  })();
  return hydration;
}

/**
 * The pairing token is a capability the desktop app minted for this extension,
 * mirroring the app's own 0600 token file. It has to survive browser restarts
 * or the user would re-approve pairing every morning.
 */
function persistPairing() {
  return chrome.storage.local
    .set({ [PAIRING_KEY]: { token: bridge.httpToken, port: bridge.lastPort } })
    .catch(() => {});
}

/** Memory-backed, so it is gone when the browser closes. */
function persistSession() {
  return chrome.storage.session
    .set({
      [SESSION_STATE_KEY]: {
        isUnlocked: bridge.isUnlocked,
        hasAuthConfig: bridge.hasAuthConfig,
        epoch: bridge.epoch,
      },
    })
    .catch(() => {});
}

// --- Small helpers -----------------------------------------------------

function browserName() {
  const ua = navigator.userAgent || '';
  if (navigator.brave) return 'Brave';
  if (/Edg\//.test(ua)) return 'Microsoft Edge';
  if (/OPR\//.test(ua)) return 'Opera';
  if (/Vivaldi/.test(ua)) return 'Vivaldi';
  if (/Chrome\//.test(ua)) return 'Chrome';
  return 'Browser';
}

/** An error the desktop app answered with — a retry will not change it. */
function appError(envelope) {
  const err = new Error(envelope?.error || 'The desktop app reported an error');
  err.code = envelope?.payload?.code || envelope?.code || null;
  err.appLevel = true;
  return err;
}

function transportError(message, code) {
  const err = new Error(message);
  if (code) err.code = code;
  return err;
}

/**
 * Fold whatever the app told us into local state. Every response carries
 * `epoch` and `serverTime`, which is how the extension notices the vault
 * changed and how it corrects for a skewed browser clock.
 */
function absorb(payload) {
  if (!payload || typeof payload !== 'object') return;

  let badgeStale = false;

  if (typeof payload.isUnlocked === 'boolean' && payload.isUnlocked !== bridge.isUnlocked) {
    bridge.isUnlocked = payload.isUnlocked;
    badgeStale = true;
  }
  if (typeof payload.hasAuthConfig === 'boolean') bridge.hasAuthConfig = payload.hasAuthConfig;
  if (typeof payload.epoch === 'number' && payload.epoch >= 0) bridge.epoch = payload.epoch;

  if (typeof payload.serverTime === 'number' && payload.serverTime > 0) {
    // Loopback and stdio latency is sub-millisecond, so any meaningful delta is
    // a real clock difference. Ignore small ones to avoid jittering the codes.
    const delta = Math.round((payload.serverTime - Date.now()) / 1000);
    bridge.skewSeconds = Math.abs(delta) >= 2 ? delta : 0;
  }

  if (badgeStale) {
    updateBadge();
    persistSession();
  }
}

// --- Native messaging transport ---------------------------------------

function closeNativePort(reason) {
  const port = nativePort;
  nativePort = null;
  if (port) {
    try {
      port.disconnect();
    } catch {
      // Already gone.
    }
  }
  failPending(reason || 'Connection closed');
}

function failPending(reason) {
  for (const [id, request] of pendingRequests) {
    pendingRequests.delete(id);
    request.reject(transportError(reason));
  }
}

function openNativePort() {
  if (nativePort) return nativePort;
  if (typeof chrome.runtime.connectNative !== 'function') return null;

  let port;
  try {
    port = chrome.runtime.connectNative(NATIVE_HOST);
  } catch (err) {
    bridge.lastError = err?.message || 'Native messaging is unavailable';
    return null;
  }

  port.onMessage.addListener(onNativeMessage);
  port.onDisconnect.addListener(() => {
    // Reading lastError here is what stops Chrome logging an unchecked-error
    // warning for every missing-host disconnect.
    const err = chrome.runtime.lastError;
    const reason = err?.message || 'The desktop app closed the connection';
    nativePort = null;
    failPending(reason);
    if (bridge.transport === 'native') markDisconnected(reason);
  });

  nativePort = port;
  return port;
}

function onNativeMessage(message) {
  if (!message || typeof message !== 'object') return;

  const pending = message.requestId ? pendingRequests.get(message.requestId) : null;
  if (pending) {
    pendingRequests.delete(message.requestId);
    if (message.type === 'ERROR') pending.reject(appError(message));
    else pending.resolve(message.payload ?? {});
    return;
  }

  // Unsolicited push — the app announces lock/unlock and vault changes.
  absorb(message.payload);
}

function sendOverNative(message, timeoutMs = REQUEST_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const port = openNativePort();
    if (!port) {
      reject(transportError('Native messaging host is not registered', 'NO_NATIVE_HOST'));
      return;
    }

    const requestId = `ext-${++requestSeq}`;
    const timer = setTimeout(() => {
      if (pendingRequests.delete(requestId)) {
        reject(transportError('The desktop app did not answer in time', 'TIMEOUT'));
      }
    }, timeoutMs);

    pendingRequests.set(requestId, {
      resolve: (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      reject: (err) => {
        clearTimeout(timer);
        reject(err);
      },
    });

    try {
      port.postMessage({ ...message, requestId });
    } catch (err) {
      pendingRequests.delete(requestId);
      clearTimeout(timer);
      reject(transportError(err?.message || 'Could not write to the native host'));
    }
  });
}

// --- Loopback HTTP transport ------------------------------------------

async function probePort(port) {
  try {
    const res = await fetch(`http://127.0.0.1:${port}/health`, {
      method: 'GET',
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    if (!res.ok) return null;
    const body = await res.json().catch(() => null);
    // Something else may be squatting the port; only VaultGuard answers this.
    if (!body || body.app !== 'VaultGuard') return null;
    return { port, body };
  } catch {
    return null;
  }
}

/**
 * Find the desktop app on loopback. All ten candidate ports are probed at once
 * — the old sequential scan walked 100 ports with a 500ms timeout each, which
 * could block for the better part of a minute before admitting failure.
 */
async function discoverHttp() {
  const ordered = bridge.lastPort
    ? [bridge.lastPort, ...HTTP_PORTS.filter((p) => p !== bridge.lastPort)]
    : HTTP_PORTS.slice();

  const results = await Promise.all(ordered.map(probePort));
  const hit = results.find(Boolean);
  if (!hit) {
    bridge.httpUrl = null;
    return false;
  }

  bridge.httpUrl = `http://127.0.0.1:${hit.port}`;
  bridge.lastPort = hit.port;
  bridge.hasAuthConfig = !!hit.body.hasAuthConfig;
  bridge.version = hit.body.version || bridge.version;
  persistPairing();
  return true;
}

async function sendOverHttp(message, timeoutMs = REQUEST_TIMEOUT_MS) {
  if (!bridge.httpUrl) throw transportError('The loopback bridge address is unknown');
  if (!bridge.httpToken) throw transportError('This extension is not paired yet', 'NEEDS_PAIRING');

  let res;
  try {
    res = await fetch(`${bridge.httpUrl}/message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Vault-Token': bridge.httpToken,
        'X-Extension-Id': chrome.runtime.id,
      },
      body: JSON.stringify(message),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    throw transportError(err?.name === 'TimeoutError' ? 'The desktop app did not answer in time' : 'Could not reach the desktop app');
  }

  if (res.status === 401 || res.status === 403) {
    // The app forgot us (vault reset, token file cleared). Drop the stale
    // token so the popup offers pairing instead of failing forever.
    bridge.httpToken = null;
    await persistPairing();
    throw transportError('The desktop app no longer trusts this extension — pair again', 'NEEDS_PAIRING');
  }
  if (!res.ok) throw transportError(`The desktop app returned HTTP ${res.status}`);

  const body = await res.json().catch(() => null);
  if (!body) throw transportError('The desktop app sent a malformed reply');
  if (body.type === 'ERROR') throw appError(body);

  absorb(body.payload);
  return body.payload ?? {};
}

// --- Connection lifecycle ---------------------------------------------

function markConnected(transport, hello) {
  bridge.transport = transport;
  bridge.ready = true;
  bridge.attempt = 0;
  bridge.needsPairing = false;
  bridge.lastError = null;
  if (hello?.version) bridge.version = hello.version;
  absorb(hello);
  chrome.alarms.clear(RETRY_ALARM);
  updateBadge();
  persistSession();
}

function markDisconnected(reason) {
  const wasReady = bridge.ready;
  bridge.ready = false;
  bridge.transport = 'none';
  if (reason) bridge.lastError = reason;
  if (wasReady) bridge.attempt = 0; // a dropped live link deserves a fast retry
  updateBadge();
  scheduleRetry();
}

function scheduleRetry() {
  const index = Math.min(bridge.attempt, RETRY_BACKOFF_MINUTES.length - 1);
  bridge.attempt = Math.min(bridge.attempt + 1, RETRY_BACKOFF_MINUTES.length);
  chrome.alarms.create(RETRY_ALARM, { delayInMinutes: RETRY_BACKOFF_MINUTES[index] });
}

/**
 * Make sure a transport is live, coalescing concurrent callers. Called at the
 * top of every request, which is what makes opening the popup reconnect
 * instantly and removes any need for aggressive background polling.
 */
function ensureBridge({ force = false } = {}) {
  if (bridge.ready && !force) return Promise.resolve(true);
  connecting ??= connect().finally(() => {
    connecting = null;
  });
  return connecting;
}

async function connect() {
  await hydrated();

  const helloPayload = { extensionId: chrome.runtime.id, browser: browserName() };

  // 1. Native messaging. Preferred: the app authorises this extension by ID in
  //    the host manifest, so there is nothing for the user to approve.
  if (typeof chrome.runtime.connectNative === 'function') {
    try {
      const hello = await sendOverNative({ type: 'HELLO', payload: helloPayload }, HANDSHAKE_TIMEOUT_MS);
      if (hello && hello.app === 'VaultGuard') {
        markConnected('native', hello);
        return true;
      }
      closeNativePort('Unexpected handshake reply');
      bridge.lastError = 'The native host answered with something unexpected';
    } catch (err) {
      // A missing or unregistered host lands here, via onDisconnect.
      bridge.lastError = err?.message || 'Native messaging failed';
      closeNativePort(bridge.lastError);
    }
  } else {
    bridge.lastError = 'This browser did not grant the nativeMessaging permission';
  }

  // 2. Loopback bridge, which needs the user-approved pairing code.
  if (!(await discoverHttp())) {
    markDisconnected(bridge.lastError || 'VaultGuard desktop app is not running');
    return false;
  }

  if (!bridge.httpToken) {
    bridge.needsPairing = true;
    markDisconnected('Pair this extension with the VaultGuard desktop app');
    return false;
  }

  try {
    const hello = await sendOverHttp({ type: 'HELLO', payload: helloPayload }, HANDSHAKE_TIMEOUT_MS);
    markConnected('http', hello);
    return true;
  } catch (err) {
    bridge.needsPairing = err?.code === 'NEEDS_PAIRING';
    markDisconnected(err?.message || 'The loopback bridge refused the connection');
    return false;
  }
}

function dispatch(message, timeoutMs) {
  return bridge.transport === 'native'
    ? sendOverNative(message, timeoutMs)
    : sendOverHttp(message, timeoutMs);
}

/**
 * The single way anything in this worker talks to the desktop app.
 * Reconnects once on a transport failure, because the most common cause is the
 * worker having been evicted (or the app restarted) since the last request.
 */
async function sendBridge(type, payload, { timeoutMs } = {}) {
  await ensureBridge();
  if (!bridge.ready) {
    throw transportError(
      bridge.needsPairing
        ? 'This extension is not paired with the desktop app yet'
        : bridge.lastError || 'VaultGuard desktop app is not running',
      bridge.needsPairing ? 'NEEDS_PAIRING' : 'NOT_CONNECTED'
    );
  }

  const message = { type, payload };
  try {
    return await dispatch(message, timeoutMs);
  } catch (err) {
    if (err?.appLevel) throw err; // a real answer (locked vault, missing entry)

    markDisconnected(err?.message);
    await ensureBridge({ force: true });
    if (!bridge.ready) throw err;
    return dispatch(message, timeoutMs);
  }
}

// --- Pairing -----------------------------------------------------------

async function startPairing() {
  await hydrated();
  if (!bridge.httpUrl && !(await discoverHttp())) {
    throw new Error('VaultGuard desktop app was not found on this computer. Start it, then try again.');
  }

  const res = await fetch(`${bridge.httpUrl}/pair/request`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ extensionId: chrome.runtime.id, browser: browserName() }),
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) throw new Error(`Could not start pairing (HTTP ${res.status})`);

  const body = await res.json().catch(() => ({}));
  return { success: true, expiresIn: body.expiresIn || 120 };
}

async function confirmPairing(rawCode) {
  await hydrated();
  const code = String(rawCode || '').replace(/\D/g, '');
  if (code.length !== 6) throw new Error('Enter the 6-digit code shown in the desktop app');
  if (!bridge.httpUrl && !(await discoverHttp())) {
    throw new Error('VaultGuard desktop app was not found on this computer');
  }

  const res = await fetch(`${bridge.httpUrl}/pair/confirm`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code, extensionId: chrome.runtime.id }),
    signal: AbortSignal.timeout(8000),
  });

  if (res.status === 410) throw new Error('That request expired. Click Connect again.');
  if (res.status === 403) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || 'That code did not match');
  }
  if (!res.ok) throw new Error(`Pairing failed (HTTP ${res.status})`);

  const body = await res.json().catch(() => ({}));
  if (!body.token) throw new Error('The desktop app did not return a pairing token');

  bridge.httpToken = body.token;
  bridge.needsPairing = false;
  bridge.attempt = 0;
  await persistPairing();

  await ensureBridge({ force: true });
  return { success: true, connected: bridge.ready, error: bridge.ready ? null : bridge.lastError };
}

async function unpair() {
  bridge.httpToken = null;
  bridge.needsPairing = true;
  await persistPairing();
  closeNativePort('Unpaired');
  markDisconnected('Unpaired from the desktop app');
  return { success: true };
}

// --- Local (extension-owned) entries ----------------------------------

/**
 * Entries the extension owns, because the user scanned a QR code while the
 * vault was closed. These live in `storage.local` — it is their only copy, so
 * moving them to session storage would silently delete them on browser close.
 */
async function getLocalEntries() {
  try {
    const data = await chrome.storage.local.get(LOCAL_ENTRIES_KEY);
    const entries = data?.[LOCAL_ENTRIES_KEY];
    return Array.isArray(entries) ? entries : [];
  } catch {
    return [];
  }
}

function normalizeLocalEntry(input) {
  const type = String(input.type || 'TOTP').toUpperCase() === 'HOTP' ? 'HOTP' : 'TOTP';
  const steam = !!input.steam;
  const encoding = ['hex', 'base32', 'ascii'].includes(String(input.encoding || '').toLowerCase())
    ? String(input.encoding).toLowerCase()
    : undefined;

  const entry = {
    title: (input.title || input.issuer || input.account || '2FA code').trim(),
    issuer: (input.issuer || '').trim(),
    account: (input.account || '').trim(),
    secret: normalizeSecret(input.secret),
    algorithm: normalizeAlgorithm(input.algorithm),
    digits: steam ? 5 : normalizeDigits(input.digits),
    period: normalizePeriod(input.period),
    type,
    url: input.url || '',
    pinned: !!input.pinned,
  };
  if (type === 'HOTP') entry.counter = Math.max(0, Math.trunc(Number(input.counter) || 0));
  if (steam) entry.steam = true;
  if (encoding) entry.encoding = encoding;
  return entry;
}

async function saveLocalEntry(input) {
  const normalized = normalizeLocalEntry(input || {});
  const check = validateSecret(normalized.secret, normalized.encoding);
  if (!check.valid) throw new Error(check.error || 'That secret is not valid');

  const entries = await getLocalEntries();
  const duplicate = entries.find(
    (e) => e.secret === normalized.secret && (e.account || '') === normalized.account
  );
  if (duplicate) return duplicate;

  const entry = {
    id: `local_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    ...normalized,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  entries.push(entry);
  await chrome.storage.local.set({ [LOCAL_ENTRIES_KEY]: entries });
  return entry;
}

async function deleteLocalEntry(id) {
  const entries = await getLocalEntries();
  await chrome.storage.local.set({ [LOCAL_ENTRIES_KEY]: entries.filter((e) => e.id !== id) });
}

/** HOTP counters only move forward, and only when a code is actually taken. */
async function bumpLocalCounter(id, counter) {
  const entries = await getLocalEntries();
  const next = entries.map((e) =>
    e.id === id ? { ...e, counter: Math.max(0, Math.trunc(counter)), updatedAt: Date.now() } : e
  );
  await chrome.storage.local.set({ [LOCAL_ENTRIES_KEY]: next });
}

function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

/** Registrable-ish suffixes of a hostname, longest first. */
function domainCandidates(hostname) {
  const parts = hostname.split('.').filter(Boolean);
  const out = [];
  for (let i = 0; i < parts.length - 1; i++) out.push(parts.slice(i).join('.'));
  return out;
}

async function findLocalEntriesForUrl(url) {
  const hostname = hostOf(url);
  if (!hostname) return [];

  const entries = await getLocalEntries();
  if (!entries.length) return [];

  const candidates = domainCandidates(hostname);
  return entries.filter((entry) => {
    const entryHost = hostOf(entry.url) || String(entry.url || '').toLowerCase();
    if (entryHost && (hostname === entryHost || hostname.endsWith(`.${entryHost}`))) return true;

    const issuer = String(entry.issuer || entry.title || '')
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '');
    if (!issuer) return false;

    // "Google" should match accounts.google.com but not googlethings.example.
    return candidates.some((candidate) => {
      const label = candidate.split('.')[0].replace(/[^a-z0-9]/g, '');
      return label === issuer;
    });
  });
}

// --- Code generation ---------------------------------------------------

/**
 * Produce a code for one entry. All the arithmetic runs through the shared
 * `lib/otp.js` engine, which is validated against the RFC 4226 and RFC 6238
 * test vectors and handles HOTP, hex/ascii secrets, SHA-256/512, 7/8 digits
 * and Steam — none of which the old inline implementation supported.
 */
async function codeForEntry(entry) {
  if (!entry?.secret) throw new Error('This entry has no secret');

  const isHotp = String(entry.type || 'TOTP').toUpperCase() === 'HOTP';

  // A vault-owned HOTP counter may only be advanced by the app that owns it,
  // otherwise the two copies drift apart and every code is rejected.
  if (isHotp && entry.origin === 'desktop') {
    const result = await sendBridge('INCREMENT_HOTP', { id: entry.id });
    if (result?.error) throw new Error(result.error);
    return result;
  }

  const params = {
    secret: entry.secret,
    type: isHotp ? 'HOTP' : 'TOTP',
    algorithm: entry.algorithm,
    digits: entry.digits,
    period: entry.period,
    counter: entry.counter,
    encoding: entry.encoding,
    steam: entry.steam,
    skewSeconds: bridge.skewSeconds,
  };

  const result = await generateOtp(params);
  if (isHotp) await bumpLocalCounter(entry.id, (Number(entry.counter) || 0) + 1);

  return { id: entry.id, ...result };
}

/**
 * Everything the extension can offer for a page: vault entries when the vault
 * is open, plus whatever the extension owns itself. Codes come back with the
 * entries so the popup can render immediately.
 */
async function entriesForUrl(url) {
  const result = {
    passwords: [],
    totpEntries: [],
    codes: [],
    locked: false,
    connected: false,
    needsPairing: false,
    error: null,
  };

  try {
    const remote = await sendBridge('GET_ENTRIES_FOR_URL', { url });
    result.connected = true;
    result.passwords = Array.isArray(remote?.passwords) ? remote.passwords : [];
    result.totpEntries = (Array.isArray(remote?.totpEntries) ? remote.totpEntries : []).map((e) => ({
      ...e,
      origin: 'desktop',
    }));
    if (Array.isArray(remote?.codes)) result.codes = remote.codes;
  } catch (err) {
    result.locked = err?.code === 'VAULT_LOCKED';
    result.needsPairing = err?.code === 'NEEDS_PAIRING';
    result.connected = bridge.ready;
    result.error = err?.message || null;
  }

  const local = await findLocalEntriesForUrl(url);
  for (const entry of local) {
    result.totpEntries.push({ ...entry, origin: 'local' });
    try {
      result.codes.push(await codeForEntry({ ...entry, origin: 'local' }));
    } catch {
      // A broken stored secret should not take the whole popup down.
    }
  }

  return result;
}

// --- QR / otpauth handling --------------------------------------------

function describe(entries) {
  if (entries.length !== 1) return `${entries.length} accounts`;
  const [entry] = entries;
  return entry.title || entry.issuer || entry.account || '2FA code';
}

/**
 * Store parsed entries, preferring the vault so a scanned code lands with all
 * the others. If the vault is locked or the app is closed the entry is kept in
 * the extension rather than thrown away — the QR code is usually shown once.
 */
async function saveEntries(entries) {
  const valid = [];
  const problems = [];
  for (const candidate of entries) {
    const check = validateSecret(candidate.secret, candidate.encoding);
    if (check.valid) valid.push(candidate);
    else problems.push(check.error);
  }
  if (!valid.length) {
    return {
      success: false,
      errorAction: 'errorqr',
      error: problems[0] || 'That secret is not valid',
      secret: entries[0]?.secret || '',
    };
  }

  try {
    const saved = await sendBridge('SAVE_TOTP', { entries: valid });
    if (saved?.success) {
      return { success: true, target: 'desktop', count: saved.entries?.length || valid.length, account: describe(valid) };
    }
  } catch {
    // Fall through to extension-local storage.
  }

  const stored = [];
  for (const candidate of valid) {
    try {
      await saveLocalEntry(candidate);
      stored.push(candidate);
    } catch (err) {
      problems.push(err?.message);
    }
  }
  if (!stored.length) {
    return { success: false, errorAction: 'errorqr', error: problems[0] || 'Could not save that code' };
  }

  return { success: true, target: 'local', count: stored.length, account: describe(stored) };
}

/**
 * Handle a scanned or pasted otpauth payload. Migration URIs are decoded by
 * the shared protobuf reader; the old code ran a regex over `atob()` output,
 * which cannot work on binary protobuf and quietly imported nothing.
 */
async function processOtpauthInput(text) {
  const parsed = parseOtpInput(text);
  if (!parsed.length) {
    const isMigration = /^otpauth-migration:/i.test(String(text || '').trim());
    return {
      success: false,
      errorAction: isMigration ? 'migrationfail' : 'errorqr',
      error: isMigration ? 'That export could not be read' : 'No 2FA setup key found',
    };
  }
  return saveEntries(parsed);
}

// --- Tab messaging ----------------------------------------------------

const CONTENT_SCRIPTS = ['src/content/detector.js', 'src/content/autofill.js', 'src/content/qr-capture.js'];
const NO_RECEIVER = /Receiving end does not exist|Could not establish connection/i;

function rawTabSend(tabId, message) {
  return new Promise((resolve) => {
    try {
      chrome.tabs.sendMessage(tabId, message, (response) => {
        const err = chrome.runtime.lastError; // read it, or Chrome logs for us
        resolve(err ? { ok: false, error: err.message } : { ok: true, response });
      });
    } catch (err) {
      resolve({ ok: false, error: err?.message || 'sendMessage threw' });
    }
  });
}

async function injectContentScripts(tabId) {
  try {
    await chrome.scripting.executeScript({ target: { tabId }, files: CONTENT_SCRIPTS });
    return true;
  } catch {
    return false; // chrome://, the Web Store, a PDF viewer, a closed tab…
  }
}

/**
 * Send to a content script, swallowing the "Receiving end does not exist"
 * rejections that used to surface as unhandled errors in the console. Tabs
 * that predate the extension get the scripts injected once, then retried.
 */
async function tabSend(tabId, message, { inject = false } = {}) {
  if (!tabId) return null;

  const first = await rawTabSend(tabId, message);
  if (first.ok) return first.response;
  if (!inject || !NO_RECEIVER.test(first.error || '')) return null;

  if (!(await injectContentScripts(tabId))) return null;
  const second = await rawTabSend(tabId, message);
  return second.ok ? second.response : null;
}

async function activeTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab || null;
  } catch {
    return null;
  }
}

// --- Badge ------------------------------------------------------------

function updateBadge() {
  let text = '';
  let color = '#22c55e';
  let title = 'VaultGuard';

  if (!bridge.ready) {
    if (bridge.needsPairing) {
      text = '?';
      color = '#3b82f6';
      title = 'VaultGuard — click to pair with the desktop app';
    } else {
      text = '!';
      color = '#ef4444';
      title = `VaultGuard — ${bridge.lastError || 'desktop app not running'}`;
    }
  } else if (!bridge.isUnlocked) {
    text = '🔒';
    color = '#eab308';
    title = 'VaultGuard — vault is locked';
  } else {
    title = `VaultGuard — connected over ${bridge.transport === 'native' ? 'native messaging' : 'the local bridge'}`;
  }

  chrome.action.setBadgeText({ text }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ color }).catch(() => {});
  chrome.action.setTitle({ title }).catch(() => {});
}

function statusSnapshot() {
  return {
    connected: bridge.ready,
    transport: bridge.transport,
    unlocked: bridge.isUnlocked,
    hasAuthConfig: bridge.hasAuthConfig,
    needsPairing: bridge.needsPairing,
    version: bridge.version,
    error: bridge.lastError,
    skewSeconds: bridge.skewSeconds,
    // Kept for older callers that read the previous field names.
    isDesktopConnected: bridge.ready,
    isVaultUnlocked: bridge.isUnlocked,
    nativeHostAvailable: bridge.transport === 'native',
  };
}

// --- Auto-fill on detection -------------------------------------------

async function handlePageDetected(data, sender) {
  const tabId = sender?.tab?.id;
  const url = data?.url || sender?.tab?.url;
  if (!data?.hasTotpField || !tabId || !url) return;

  const last = autoFilledTabs.get(tabId);
  if (last && Date.now() - last < AUTO_FILL_COOLDOWN_MS) return;

  const { totpEntries, codes } = await entriesForUrl(url);
  if (totpEntries.length === 0) return;

  // Pick the best matching entry (first one by domain match priority)
  const entry = totpEntries[0];
  const known = codes.find((c) => c.id === entry.id);
  let code = known?.code;
  if (!code) {
    try {
      code = (await codeForEntry(entry)).code;
    } catch {
      return;
    }
  }
  if (!code) return;

  autoFilledTabs.set(tabId, Date.now());
  await tabSend(tabId, { type: 'DO_AUTO_FILL_TOTP', code }, { inject: true });
  await tabSend(tabId, {
    type: 'SHOW_2FA_NOTIFICATION',
    issuer: entry.issuer || entry.title || '2FA',
    code,
    period: normalizePeriod(entry.period),
  });
}

// --- Message router ---------------------------------------------------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(
    (result) => sendResponse(result),
    (err) => sendResponse({ error: err?.message || 'Something went wrong', code: err?.code || null })
  );
  return true; // async reply
});

async function handleMessage(message, sender) {
  const type = message?.type || message?.action;

  switch (type) {
    // --- status / connection ---
    case 'GET_AUTH_STATUS': {
      await ensureBridge();
      return statusSnapshot();
    }

    case 'RECONNECT': {
      bridge.attempt = 0;
      bridge.httpUrl = null;
      closeNativePort('Manual reconnect');
      await ensureBridge({ force: true });
      return statusSnapshot();
    }

    case 'START_PAIRING':
      return startPairing();

    case 'CONFIRM_PAIRING':
      return confirmPairing(message.code);

    case 'UNPAIR':
      return unpair();

    // --- vault ---
    case 'UNLOCK_VAULT': {
      const result = await sendBridge('UNLOCK_VAULT', { password: message.password });
      bridge.isUnlocked = !!result?.success;
      updateBadge();
      persistSession();
      return result;
    }

    case 'LOCK_VAULT': {
      const result = await sendBridge('LOCK_VAULT');
      bridge.isUnlocked = false;
      updateBadge();
      persistSession();
      return result;
    }

    case 'GET_BIOMETRIC_STATUS': {
      let biometricAvailable = false;
      try {
        if (globalThis.PublicKeyCredential?.isUserVerifyingPlatformAuthenticatorAvailable) {
          biometricAvailable = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        }
      } catch {
        // Not available in this context.
      }
      try {
        const config = await sendBridge('GET_BIOMETRIC_STATUS');
        return { enabled: !!config?.enabled, credentialId: config?.credentialId, biometricAvailable };
      } catch {
        return { enabled: false, biometricAvailable };
      }
    }

    case 'BIOMETRIC_UNLOCK': {
      const result = await sendBridge('BIOMETRIC_UNLOCK', { credentialId: message.credentialId });
      bridge.isUnlocked = !!result?.success;
      updateBadge();
      persistSession();
      return result;
    }

    case 'REGISTER_BIOMETRIC': {
      const { credentialId, authenticatorData } = message;
      const result = await sendBridge('BIOMETRIC_REGISTER', { credentialId, authenticatorData });
      return result;
    }

    // --- entries & codes ---
    case 'GET_ENTRIES_FOR_URL':
      return entriesForUrl(message.url);

    case 'GET_ALL_TOTP_ENTRIES': {
      const out = { entries: [], codes: [], locked: false, connected: false, error: null };
      try {
        const remote = await sendBridge('GET_TOTP');
        out.connected = true;
        out.entries = (remote?.entries || []).map((e) => ({ ...e, origin: 'desktop' }));
        out.codes = remote?.codes || [];
      } catch (err) {
        out.locked = err?.code === 'VAULT_LOCKED';
        out.connected = bridge.ready;
        out.error = err?.message || null;
      }
      for (const entry of await getLocalEntries()) {
        out.entries.push({ ...entry, origin: 'local' });
      }
      return out;
    }

    case 'GENERATE_TOTP': {
      // Callers pass either a full entry, or a bare secret plus options.
      const entry = message.entry || {
        id: message.id,
        secret: message.secret,
        ...(message.options || {}),
      };
      const result = await codeForEntry(entry);
      return { code: result.code, ...result };
    }

    case 'GENERATE_CODES': {
      const entries = Array.isArray(message.entries) ? message.entries : [];
      const codes = [];
      for (const entry of entries) {
        try {
          codes.push(await codeForEntry(entry));
        } catch (err) {
          codes.push({ id: entry.id, code: '', error: err?.message || 'Could not generate a code' });
        }
      }
      return { codes, skewSeconds: bridge.skewSeconds };
    }

    // --- extension-owned entries ---
    case 'GET_LOCAL_TOTP_ENTRIES':
      return { entries: await getLocalEntries() };

    case 'ADD_LOCAL_TOTP_ENTRY':
      return { success: true, entry: await saveLocalEntry(message.entry) };

    case 'DELETE_LOCAL_TOTP_ENTRY':
      await deleteLocalEntry(message.id);
      return { success: true };

    case 'SAVE_TOTP_FROM_QR':
      // The popup sends entries it has already parsed (so names the user typed
      // survive); the content scripts send the raw payload.
      return Array.isArray(message.entries) && message.entries.length
        ? saveEntries(message.entries)
        : processOtpauthInput(message.uri || message.data?.uri || message.text || '');

    case 'ADD_OTPAUTH_URI':
      return processOtpauthInput(message.uri || message.text || '');

    case 'PROMOTE_LOCAL_ENTRIES': {
      // Move extension-owned entries into the vault once it is open.
      const entries = await getLocalEntries();
      if (!entries.length) return { success: true, moved: 0 };
      const saved = await sendBridge('SAVE_TOTP', { entries });
      if (!saved?.success) throw new Error('The desktop app did not accept the entries');
      await chrome.storage.local.set({ [LOCAL_ENTRIES_KEY]: [] });
      return { success: true, moved: saved.entries?.length || entries.length };
    }

    // --- page interaction ---
    case 'DETECT_OTPAUTH_ON_PAGE': {
      const tab = await activeTab();
      if (!tab?.id) return { links: [] };
      try {
        const results = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: () => {
            const found = [];
            document.querySelectorAll('a[href*="otpauth"]').forEach((link) => {
              if (/^otpauth(-migration)?:\/\//i.test(link.href)) {
                found.push({ href: link.href, text: (link.textContent || '').trim() });
              }
            });
            const text = document.body?.innerText || '';
            for (const match of text.match(/otpauth(-migration)?:\/\/[^\s"'<>]+/gi) || []) {
              if (!found.some((f) => f.href === match)) found.push({ href: match, text: '' });
            }
            return found;
          },
        });
        return { links: results?.[0]?.result || [] };
      } catch {
        return { links: [] };
      }
    }

    case 'AUTO_FILL': {
      const tab = await activeTab();
      await tabSend(tab?.id, { type: 'DO_AUTO_FILL', data: message.data }, { inject: true });
      return { success: true };
    }

    case 'AUTO_FILL_TOTP': {
      const tab = await activeTab();
      await tabSend(tab?.id, { type: 'DO_AUTO_FILL_TOTP', code: message.code }, { inject: true });
      return { success: true };
    }

    case 'SCAN_PAGE': {
      const tab = await activeTab();
      const response = await tabSend(tab?.id, { type: 'SCAN_PAGE' }, { inject: true });
      return response || { fields: [], hasLoginForm: false, hasTotpField: false };
    }

    case 'START_QR_CAPTURE': {
      const tab = message.tabId ? { id: message.tabId } : await activeTab();
      if (!tab?.id) return { success: false, error: 'No active tab' };
      const started = await tabSend(tab.id, { action: 'capture' }, { inject: true });
      if (started === null) return { success: false, error: 'This page does not allow QR scanning' };
      return { success: true };
    }

    case 'PAGE_DETECTED':
      // Fire and forget: the content script does not wait for a result.
      handlePageDetected(message.data, sender).catch(() => {});
      return { success: true };

    case 'OPEN_POPUP':
      try {
        await chrome.action.openPopup();
      } catch {
        // Only allowed in response to a user gesture in some Chrome versions.
      }
      return { success: true };

    case 'OPEN_VAULT_APP':
      try {
        await sendBridge('SHOW_WINDOW');
        return { success: true };
      } catch (err) {
        return { success: false, error: err?.message || 'Could not reach the desktop app' };
      }

    // --- QR capture pipeline (content-script driven) ---
    case 'getCapture': {
      const tabId = sender?.tab?.id;
      if (!tabId) return { success: false };
      try {
        const dataUrl = await chrome.tabs.captureVisibleTab(sender.tab.windowId, { format: 'png' });
        if (!dataUrl) {
          await tabSend(tabId, { action: 'errorqr' });
          return { success: false };
        }
        await tabSend(tabId, { action: 'sendCaptureUrl', info: { ...(message.info || {}), url: dataUrl } });
        return { success: true };
      } catch (err) {
        await tabSend(tabId, { action: 'errorqr' });
        return { success: false, error: err?.message };
      }
    }

    case 'getTotp': {
      const tabId = sender?.tab?.id;
      const result = await processOtpauthInput(message.info);
      if (result.success) {
        await tabSend(tabId, { action: 'added', account: result.account });
        notify('2FA account added', `${result.account} was saved to ${result.target === 'desktop' ? 'your vault' : 'this browser'}`);
      } else {
        await tabSend(tabId, { action: result.errorAction || 'errorqr', secret: result.secret || '' });
      }
      return result;
    }

    default:
      return { error: `Unknown message type: ${type}` };
  }
}

function notify(title, message) {
  try {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: chrome.runtime.getURL('icons/icon-128.png'),
      title,
      message,
    });
  } catch {
    // Notifications can be disabled by policy.
  }
}

// --- Context menus ----------------------------------------------------

const MENU_ITEMS = [
  { id: 'vaultguard-fill-password', title: 'VaultGuard: fill password', contexts: ['editable'] },
  { id: 'vaultguard-fill-totp', title: 'VaultGuard: fill 2FA code', contexts: ['editable'] },
  { id: 'vaultguard-scan-qr', title: 'VaultGuard: scan QR code on this page', contexts: ['all'] },
];

/** removeAll first: re-creating an existing id throws on every update. */
function installContextMenus() {
  chrome.contextMenus.removeAll(() => {
    void chrome.runtime.lastError;
    for (const item of MENU_ITEMS) {
      chrome.contextMenus.create(item, () => void chrome.runtime.lastError);
    }
  });
}

chrome.contextMenus.onClicked.addListener((info, tab) => {
  handleContextMenu(info, tab).catch((err) => {
    notify('VaultGuard', err?.message || 'That did not work');
  });
});

async function handleContextMenu(info, tab) {
  if (!tab?.id) return;

  if (info.menuItemId === 'vaultguard-scan-qr') {
    const started = await tabSend(tab.id, { action: 'capture' }, { inject: true });
    if (started === null) notify('VaultGuard', 'This page does not allow QR scanning');
    return;
  }

  const { passwords, totpEntries, codes, locked, error } = await entriesForUrl(tab.url);
  if (locked) {
    notify('VaultGuard', 'Unlock the vault first');
    return;
  }

  if (info.menuItemId === 'vaultguard-fill-password') {
    if (!passwords.length) {
      notify('VaultGuard', error || 'No saved login for this site');
      return;
    }
    await tabSend(tab.id, { type: 'DO_AUTO_FILL', data: passwords[0] }, { inject: true });
    return;
  }

  if (info.menuItemId === 'vaultguard-fill-totp') {
    if (!totpEntries.length) {
      notify('VaultGuard', error || 'No 2FA account for this site');
      return;
    }
    const entry = totpEntries[0];
    const code = codes.find((c) => c.id === entry.id)?.code || (await codeForEntry(entry)).code;
    if (code) await tabSend(tab.id, { type: 'DO_AUTO_FILL_TOTP', code }, { inject: true });
  }
}

// --- Lifecycle --------------------------------------------------------

/**
 * The watchdog is what replaces the old top-level `setInterval`, which died
 * with the worker. It also re-arms the retry alarm if it was lost.
 */
function armWatchdog() {
  chrome.alarms.create(WATCHDOG_ALARM, { periodInMinutes: 1, delayInMinutes: 1 });
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === RETRY_ALARM) {
    ensureBridge({ force: true }).catch(() => {});
    return;
  }

  if (alarm.name === WATCHDOG_ALARM) {
    (async () => {
      if (bridge.ready) {
        // A native port reports its own death; HTTP has to be asked.
        if (bridge.transport === 'http') {
          try {
            await sendOverHttp({ type: 'PING' }, 4000);
          } catch (err) {
            markDisconnected(err?.message);
          }
        }
        return;
      }
      // Do not trample an in-flight backoff.
      const pending = await chrome.alarms.get(RETRY_ALARM).catch(() => null);
      if (!pending) await ensureBridge({ force: true });
    })().catch(() => {});
  }
});

chrome.runtime.onInstalled.addListener((details) => {
  installContextMenus();
  armWatchdog();
  ensureBridge({ force: true }).catch(() => {});
  if (details.reason === 'install') {
    notify('VaultGuard installed', 'Open the extension to connect it to the desktop app.');
  }
});

chrome.runtime.onStartup.addListener(() => {
  installContextMenus();
  armWatchdog();
  ensureBridge({ force: true }).catch(() => {});
});

chrome.tabs.onRemoved.addListener((tabId) => {
  autoFilledTabs.delete(tabId);
});

// A cold worker start (eviction, or a reload from chrome://extensions) does not
// fire onStartup, so the badge and alarms are restored here as well.
armWatchdog();
hydrated()
  .then(() => {
    updateBadge();
    return ensureBridge();
  })
  .catch(() => {});
