// ============================================
// VaultGuard - Electron Main Process
// Desktop app with Native Messaging Host
// ============================================

import {
  app,
  BrowserWindow,
  ipcMain,
  Tray,
  Menu,
  nativeImage,
  clipboard,
  nativeTheme,
  dialog,
  shell,
} from 'electron';
import * as http from 'http';
import * as crypto from 'crypto';
import * as path from 'path';
import * as fs from 'fs';
import { VaultDatabase } from '../database/vault-db';
import {
  hashMasterPassword,
  verifyMasterPasswordDetailed,
  generateTotpCode,
  generateTotpDetailed,
  generateNextTotpCode,
  verifyTotpCode,
  generateTotpSecret,
  generateOtpauthUri,
  entryToOtpauthUri,
  generateQrCodeDataUrl,
  parseOtpInput,
  validateTotpSecret,
  generateRandomHex,
  deriveKey,
} from '@vaultguard/shared/crypto';
import {
  IPC_CHANNELS,
  VaultData,
  PasswordEntry,
  TwoFactorEntry,
  AppSettings,
  NativeMessage,
  BiometricConfig,
  BridgeStatus,
  OtpCodeResult,
} from '@vaultguard/shared';
import { parseCSV, entriesToCSV, validateCSV } from '@vaultguard/shared/csv-utils';

// ============================================
// Global State
// ============================================

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let db: VaultDatabase;
let isUnlocked = false;
let sessionToken: string | null = null;
let autoLockTimer: NodeJS.Timeout | null = null;
let autoBackupTimer: NodeJS.Timeout | null = null;
let lastBackupTime: number = 0;

/** Extensions that completed the HELLO handshake, for Settings diagnostics. */
const connectedExtensions = new Set<string>();
let lastExtensionSeenAt: number | null = null;
let hostRegistrationErrors: string[] = [];
let hostRegisteredBrowsers: string[] = [];

/**
 * Guard for every handler that touches vault data.
 *
 * This used to `return { error: 'Vault is locked' }`, which the renderer
 * then stored in state and tried to render — producing React's
 * "Objects are not valid as a React child" crash whenever the vault
 * auto-locked while a view was open. Throwing rejects the
 * `ipcRenderer.invoke` promise instead, which the UI already handles.
 */
function requireUnlocked(): void {
  if (!isUnlocked) {
    const err = new Error('VAULT_LOCKED');
    (err as any).code = 'VAULT_LOCKED';
    throw err;
  }
}

/**
 * Turn a stored entry into the code + countdown payload the UI renders.
 * A single bad secret must not blank the whole list, so failures come
 * back as a per-entry `error` instead of throwing.
 */
function buildOtpCodeResult(
  entry: TwoFactorEntry,
  timestamp: number,
  withNext: boolean
): OtpCodeResult {
  const options = {
    type: entry.type === 'HOTP' ? ('HOTP' as const) : ('TOTP' as const),
    algorithm: entry.algorithm,
    digits: entry.digits,
    period: entry.period,
    counter: entry.counter,
    encoding: entry.encoding,
    steam: entry.steam,
    timestamp,
  };

  try {
    const result = generateTotpDetailed(entry.secret, options);
    return {
      id: entry.id,
      code: result.code,
      nextCode: withNext ? generateNextTotpCode(entry.secret, options) : undefined,
      counter: result.counter,
      period: result.period,
      digits: result.digits,
      remainingSeconds: result.remainingSeconds,
      expiresAt: result.expiresAt,
    };
  } catch (err: any) {
    return {
      id: entry.id,
      code: '',
      counter: 0,
      period: entry.period || 30,
      digits: entry.digits || 6,
      remainingSeconds: 0,
      expiresAt: 0,
      error: err?.message || 'Could not generate a code for this secret',
    };
  }
}

/** Clean up user/import-supplied entry fields before they are stored. */
function normalizeTotpEntry<T extends Partial<TwoFactorEntry>>(entry: T): T {
  const out: any = { ...entry };

  if (typeof out.secret === 'string') {
    out.secret = out.secret.replace(/[\s\-_]/g, '').toUpperCase();
  }
  if (out.algorithm) {
    const upper = String(out.algorithm).toUpperCase().replace(/[-\s]/g, '');
    out.algorithm = upper === 'SHA256' || upper === 'SHA512' ? upper : 'SHA1';
  }
  if (out.digits !== undefined) {
    const n = parseInt(String(out.digits), 10);
    out.digits = Number.isFinite(n) ? Math.min(10, Math.max(6, n)) : 6;
  }
  if (out.period !== undefined) {
    const n = parseInt(String(out.period), 10);
    out.period = Number.isFinite(n) && n > 0 ? Math.min(300, n) : 30;
  }
  if (out.counter !== undefined) {
    const n = parseInt(String(out.counter), 10);
    out.counter = Number.isFinite(n) && n >= 0 ? n : 0;
  }
  if (out.type !== 'HOTP') out.type = out.type === undefined ? undefined : 'TOTP';
  if (!out.title) {
    const fallback = out.issuer || out.account;
    if (fallback) out.title = fallback;
  }

  // Steam codes are 5 characters from a custom alphabet, not digits.
  if (out.steam) out.digits = 5;

  return out;
}

/** Identity used to skip duplicates on import. */
function otpDedupeKey(entry: Partial<TwoFactorEntry>): string {
  const secret = String(entry.secret || '').replace(/[\s\-_=]/g, '').toUpperCase();
  return `${(entry.issuer || '').toLowerCase()}|${(entry.account || '').toLowerCase()}|${secret}`;
}

// ============================================
// App Initialization
// ============================================

// Check if launched as native messaging host (Chrome calls us with this flag)
const isNativeMessagingMode = process.argv.includes('--native-messaging');

if (isNativeMessagingMode) {
  // Native-host mode is a *thin stdio proxy*, not a second copy of the app.
  //
  // Previously this opened its own VaultDatabase. That connection had its
  // own (locked) key state, so the extension was always told "Vault is
  // locked" even with the app unlocked on screen. Now we forward every
  // framed stdin message to the running instance's loopback bridge and
  // write the reply back to Chrome — one vault, one unlock state.
  app.disableHardwareAcceleration();
  app.whenReady().then(() => {
    startNativeMessagingProxy();
  });
  // No windows are ever created in this mode; don't let Electron exit.
  app.on('window-all-closed', () => {
    /* keep the proxy alive until Chrome closes stdin */
  });
} else {
  // Normal app mode - use single-instance lock
  const gotTheLock = app.requestSingleInstanceLock();

  if (!gotTheLock) {
    app.quit();
  } else {
    app.on('second-instance', () => {
      if (mainWindow) {
        // show() first: the window may be hidden in the tray, and a launch
        // attempt while hidden must make it visible or the app looks dead.
        mainWindow.show();
        if (mainWindow.isMinimized()) mainWindow.restore();
        mainWindow.focus();
      }
    });
  }
}

// ============================================
// Renderer HTTP Server
// ============================================
//
// Serving the renderer from http://localhost gives the window a *secure
// context* (Chromium treats loopback as trustworthy), which unlocks WebAuthn
// / Windows Hello directly in the desktop app. A file:// origin never gets
// one, which is why Hello setup used to be impossible here.

const RENDERER_DIR = path.join(__dirname, '../renderer');
/** Per-launch secret gating every request to the renderer server. */
const RENDERER_TOKEN = crypto.randomBytes(32).toString('hex');
let rendererBaseUrl: string | null = null;
/**
 * Must stay referenced for the lifetime of the app — a listening server
 * with no JS references gets garbage-collected and its socket silently
 * closes, which made the window load fail with ERR_FAILED at random.
 */
let rendererServer: http.Server | null = null;

const RENDERER_MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.map': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.wasm': 'application/wasm',
  '.txt': 'text/plain; charset=utf-8',
};

/**
 * True when the request carries our per-launch token, either as a query
 * param (first navigation) or as the cookie it hands out for subresources.
 * Anything else gets a 403 so other local processes cannot poke at the
 * renderer's origin.
 */
function isRendererRequestAuthorized(req: http.IncomingMessage, url: URL): boolean {
  const provided = url.searchParams.get('token');
  if (provided && timingSafeCompare(provided, RENDERER_TOKEN)) return true;

  const cookies = req.headers.cookie || '';
  const match = cookies.match(/(?:^|;\s*)vg_rt=([^;]+)/);
  return !!(match?.[1] && timingSafeCompare(match[1], RENDERER_TOKEN));
}

function startRendererServer(): Promise<string> {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      try {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          res.writeHead(405, { Allow: 'GET, HEAD' });
          res.end();
          return;
        }

        // Only answer loopback hosts (defends against DNS-rebinding games).
        const host = String(req.headers.host || '').split(':')[0].toLowerCase();
        if (host !== 'localhost' && host !== '127.0.0.1') {
          res.writeHead(403);
          res.end();
          return;
        }

        const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
        if (!isRendererRequestAuthorized(req, url)) {
          res.writeHead(403);
          res.end();
          return;
        }

        let pathname = decodeURIComponent(url.pathname);
        if (pathname === '/') pathname = '/index.html';

        const filePath = path.normalize(path.join(RENDERER_DIR, pathname));
        if (!filePath.startsWith(RENDERER_DIR)) {
          res.writeHead(403);
          res.end();
          return;
        }

        fs.readFile(filePath, (err, data) => {
          if (err) {
            res.writeHead(404);
            res.end();
            return;
          }
          const ext = path.extname(filePath).toLowerCase();
          const headers: Record<string, string> = {
            'Content-Type': RENDERER_MIME[ext] || 'application/octet-stream',
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'no-referrer',
            'Content-Security-Policy': [
              "default-src 'self'",
              "script-src 'self'",
              "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
              "font-src 'self' data: https://fonts.gstatic.com",
              "img-src 'self' data: blob:",
              "connect-src 'self' ipc:",
              "object-src 'none'",
              "base-uri 'none'",
              "form-action 'none'",
            ].join('; '),
          };
          if (pathname === '/index.html') {
            headers['Set-Cookie'] =
              `vg_rt=${RENDERER_TOKEN}; Path=/; HttpOnly; SameSite=Strict`;
          }
          res.writeHead(200, headers);
          res.end(req.method === 'HEAD' ? undefined : data);
        });
      } catch {
        try {
          res.writeHead(500);
          res.end();
        } catch {
          // Socket already gone.
        }
      }
    });

    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        reject(new Error('Unexpected renderer server address'));
        return;
      }
      rendererServer = server;
      rendererBaseUrl = `http://localhost:${address.port}`;
      resolve(rendererBaseUrl);
    });
  });
}

async function createWindow(): Promise<void> {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    title: 'VaultGuard - 2FA & Password Manager',
    icon: path.join(__dirname, '../../assets/icon.png'),
    webPreferences: {
      preload: path.join(__dirname, '../preload/index.js'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false,
    },
    backgroundColor: nativeTheme.shouldUseDarkColors ? '#1a1b2e' : '#ffffff',
    // The renderer draws its own title bar. `hiddenInset` is macOS-only, so
    // on Windows/Linux it left the native frame in place *and* the custom
    // bar below it — two title bars stacked. Go frameless there instead.
    ...(process.platform === 'darwin'
      ? { titleBarStyle: 'hiddenInset' as const }
      : { frame: false }),
    show: false,
  });

  // In development, load from Vite dev server
  if (process.env.NODE_ENV === 'development') {
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools();
  } else {
    // Loopback origin = secure context = WebAuthn/Windows Hello works.
    // If anything goes wrong (port/cache conflicts, AV interference), fall
    // back to file:// so the app still starts — biometric setup then falls
    // back to the extension popup path.
    try {
      const base = rendererBaseUrl || (await startRendererServer());
      await mainWindow.loadURL(`${base}/?token=${RENDERER_TOKEN}`);
    } catch (err) {
      console.error('Renderer server load failed, using file:// fallback:', err);
      if (!mainWindow.isDestroyed()) {
        await mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));
      }
    }
  }

  // Never let the window wander off our own origin.
  mainWindow.webContents.on('will-navigate', (_event, url) => {
    const allowed = process.env.NODE_ENV === 'development'
      ? url.startsWith('http://localhost:5173')
      : !!rendererBaseUrl && url.startsWith(rendererBaseUrl);
    if (!allowed) _event.preventDefault();
  });

  mainWindow.once('ready-to-show', () => {
    mainWindow?.show();
    pushWindowState();
  });

  // Keep the renderer's maximize button glyph in sync with reality
  // (double-clicking the drag region also toggles it).
  mainWindow.on('maximize', pushWindowState);
  mainWindow.on('unmaximize', pushWindowState);
  mainWindow.on('enter-full-screen', pushWindowState);
  mainWindow.on('leave-full-screen', pushWindowState);

  mainWindow.on('close', (e) => {
    // Closing hides to tray unless the user is really quitting. The old
    // check was `if (isUnlocked)`, so closing a *locked* window destroyed
    // it and the tray's "Open VaultGuard" did nothing.
    if (isQuitting) return;
    if (tray && safeGetSettings()?.minimizeToTray !== false) {
      e.preventDefault();
      mainWindow?.hide();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Open target=_blank / external links in the real browser, never in-app.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
}

function pushWindowState(): void {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  mainWindow.webContents.send(IPC_CHANNELS.WINDOW_STATE_CHANGED, {
    maximized: mainWindow.isMaximized(),
    fullScreen: mainWindow.isFullScreen(),
  });
}

/** Load the tray image, falling back through the icons we actually ship. */
function loadTrayIcon(): Electron.NativeImage {
  const candidates = [
    path.join(__dirname, '../../assets/tray-icon.png'),
    path.join(__dirname, '../../assets/icon.png'),
    path.join(process.resourcesPath || '', 'assets/icon.png'),
  ];

  for (const candidate of candidates) {
    if (!candidate) continue;
    const image = nativeImage.createFromPath(candidate);
    if (!image.isEmpty()) {
      // Tray icons must be small; 16px is the Windows/macOS convention.
      return image.resize({ width: 16, height: 16 });
    }
  }

  // A 1x1 transparent PNG. `new Tray(emptyImage)` throws on some
  // platforms, so never hand Tray an empty image.
  return nativeImage.createFromDataURL(
    'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='
  );
}

function createTray(): void {
  try {
    tray = new Tray(loadTrayIcon());
  } catch (err) {
    // A missing/invalid tray icon must never stop the app from starting.
    console.error('Tray unavailable:', err);
    return;
  }

  updateTrayMenu();

  tray.on('double-click', () => showMainWindow());
  // Windows convention: single left-click opens; right-click shows the menu.
  if (process.platform === 'win32') {
    tray.on('click', () => showMainWindow());
  }
}

// ============================================
// IPC Handlers
// ============================================

function setupIPC(): void {
  // --- Auth Handlers ---

  ipcMain.handle(IPC_CHANNELS.AUTH_STATUS, () => {
    return {
      hasAuthConfig: db.hasAuthConfig(),
      isUnlocked,
    };
  });

  ipcMain.handle(IPC_CHANNELS.SETUP_MASTER, async (_event, { password, biometricCredentialId, biometricAuthenticatorData }: { password: string; biometricCredentialId?: string; biometricAuthenticatorData?: string }) => {
    try {
      if (!password || password.length < 8) {
        return { success: false, error: 'Master password must be at least 8 characters' };
      }

      const config = hashMasterPassword(password);
      db.saveAuthConfig({ masterPasswordHash: config.hash, salt: config.salt, iterations: config.iterations });

      // Derive encryption key from password
      const derivedKey = deriveKey(password, config.salt, config.iterations);
      db.setEncryptionKey(derivedKey.key);

      // Initialize empty vault
      db.saveVaultData({ passwords: [], twoFactor: [] });

      // Store biometric config if provided
      if (biometricCredentialId && biometricAuthenticatorData) {
        // Check if safeStorage is available before enabling biometric
        if (!db.isSafeStorageAvailable()) {
          // Proceed without biometric - don't fail vault creation
          console.warn('Biometric requested but safeStorage unavailable - proceeding without biometric');
        } else {
          const biometricConfig: BiometricConfig = {
            enabled: true,
            credentialId: biometricCredentialId,
            authenticatorData: biometricAuthenticatorData,
            createdAt: Date.now(),
          };
          db.saveBiometricConfig(biometricConfig);
          // Store the encryption key for biometric unlock
          db.saveBiometricKey(derivedKey.key);
        }
      }

      sessionToken = db.createSessionToken();
      isUnlocked = true;
      resetAutoLockTimer();

      return { success: true, sessionToken };
    } catch (err: any) {
      console.error('Vault creation failed:', err);
      return { success: false, error: err.message || 'Failed to create vault' };
    }
  });

  ipcMain.handle(IPC_CHANNELS.UNLOCK, async (_event, password: string) => {
    try {
      const config = db.getAuthConfig();
      if (!config) {
        return { success: false, error: 'No vault configured' };
      }

      // One PBKDF2 pass returns both the verdict and the key (600k
      // iterations twice made unlocking feel broken).
      const result = verifyMasterPasswordDetailed(
        password,
        config.masterPasswordHash,
        config.salt,
        config.iterations
      );
      if (!result.valid || !result.key) {
        return { success: false, error: 'Invalid master password' };
      }

      db.setEncryptionKey(result.key);

      // Legacy vaults stored the encryption key itself as the "hash".
      // Upgrade to the v2 verifier now that we know the password is right.
      if (result.needsUpgrade && result.newHash) {
        try {
          db.saveAuthConfig({
            masterPasswordHash: result.newHash,
            salt: config.salt,
            iterations: config.iterations,
          });
        } catch (err) {
          console.error('Verifier upgrade failed (vault still usable):', err);
        }
      }

      db.updateLastLogin();

      sessionToken = db.createSessionToken();
      isUnlocked = true;
      resetAutoLockTimer();
      updateTrayMenu();
      bindBiometricKey();

      return { success: true, sessionToken };
    } catch (err: any) {
      console.error('Unlock failed:', err);
      return { success: false, error: err.message || 'Failed to unlock vault' };
    }
  });

  ipcMain.handle(IPC_CHANNELS.LOCK, () => {
    lockVault();
    return { success: true, hasAuthConfig: db.hasAuthConfig() };
  });

  ipcMain.handle(IPC_CHANNELS.CHANGE_PASSWORD, async (_event, { currentPassword, newPassword }) => {
    const config = db.getAuthConfig();
    if (!config) return { success: false, error: 'No vault configured' };

    const current = verifyMasterPasswordDetailed(
      currentPassword,
      config.masterPasswordHash,
      config.salt,
      config.iterations
    );
    if (!current.valid) return { success: false, error: 'Current password is incorrect' };

    // Re-encrypt vault with new password
    if (!db.isUnlocked()) return { success: false, error: 'Vault must be unlocked' };

    const vaultData = db.loadVaultData();

    const newConfig = hashMasterPassword(newPassword);
    db.saveAuthConfig({ masterPasswordHash: newConfig.hash, salt: newConfig.salt, iterations: newConfig.iterations });

    const newDerivedKey = deriveKey(newPassword, newConfig.salt, newConfig.iterations);
    db.setEncryptionKey(newDerivedKey.key);
    db.saveVaultData(vaultData);

    // Biometric unlock stores the old key; refresh it or biometrics break.
    try {
      const bio = db.getBiometricConfig();
      if (bio?.enabled && db.isSafeStorageAvailable()) {
        db.saveBiometricKey(newDerivedKey.key);
      }
    } catch (err) {
      console.error('Failed to refresh biometric key:', err);
    }

    return { success: true };
  });

  // --- Password Handlers ---

  ipcMain.handle(IPC_CHANNELS.GET_PASSWORDS, () => {
    requireUnlocked();
    return db.getPasswords();
  });

  ipcMain.handle(IPC_CHANNELS.ADD_PASSWORD, (_event, entry: Omit<PasswordEntry, 'id' | 'createdAt' | 'updatedAt'>) => {
    requireUnlocked();
    const created = db.addPassword(entry);
    bumpVaultEpoch();
    return created;
  });

  ipcMain.handle(IPC_CHANNELS.UPDATE_PASSWORD, (_event, { id, updates }: { id: string; updates: Partial<PasswordEntry> }) => {
    requireUnlocked();
    const updated = db.updatePassword(id, updates);
    bumpVaultEpoch();
    return updated;
  });

  ipcMain.handle(IPC_CHANNELS.DELETE_PASSWORD, (_event, id: string) => {
    requireUnlocked();
    const removed = db.deletePassword(id);
    bumpVaultEpoch();
    return removed;
  });

  ipcMain.handle(IPC_CHANNELS.SEARCH_PASSWORDS, (_event, query: string) => {
    requireUnlocked();
    return db.searchPasswords(query);
  });

  // --- TOTP Handlers ---

  ipcMain.handle(IPC_CHANNELS.GET_TOTP_ENTRIES, () => {
    requireUnlocked();
    return db.getTotpEntries();
  });

  ipcMain.handle(IPC_CHANNELS.ADD_TOTP, (_event, entry: Omit<TwoFactorEntry, 'id' | 'createdAt' | 'updatedAt'>) => {
    requireUnlocked();

    // Reject unusable secrets here rather than storing an entry that can
    // only ever render "------".
    const check = validateTotpSecret(entry.secret, entry.encoding);
    if (!check.valid) throw new Error(check.error || 'Invalid secret');

    const created = db.addTotpEntry(normalizeTotpEntry(entry));
    bumpVaultEpoch();
    return created;
  });

  ipcMain.handle(IPC_CHANNELS.UPDATE_TOTP, (_event, { id, updates }: { id: string; updates: Partial<TwoFactorEntry> }) => {
    requireUnlocked();

    if (updates.secret !== undefined) {
      const check = validateTotpSecret(updates.secret, updates.encoding);
      if (!check.valid) throw new Error(check.error || 'Invalid secret');
    }

    const updated = db.updateTotpEntry(id, normalizeTotpEntry(updates));
    bumpVaultEpoch();
    return updated;
  });

  ipcMain.handle(IPC_CHANNELS.DELETE_TOTP, (_event, id: string) => {
    requireUnlocked();
    const removed = db.deleteTotpEntry(id);
    bumpVaultEpoch();
    return removed;
  });

  ipcMain.handle(IPC_CHANNELS.GENERATE_TOTP, (_event, { secret, options }) => {
    requireUnlocked();
    return generateTotpCode(secret, options);
  });

  /**
   * Generate codes for the whole list in one round-trip.
   *
   * The vault used to invoke one IPC call *per card, per second*, so a
   * 12-entry list fired 720 requests a minute and the codes visibly
   * stuttered and flickered as the promises resolved out of order. The
   * renderer now calls this once per time-step and renders synchronously.
   */
  ipcMain.handle(
    IPC_CHANNELS.GENERATE_TOTP_BATCH,
    (_event, payload?: { ids?: string[]; timestamp?: number; withNext?: boolean }): OtpCodeResult[] => {
      requireUnlocked();

      const timestamp = payload?.timestamp ?? Date.now();
      const wanted = payload?.ids && payload.ids.length ? new Set(payload.ids) : null;
      const entries = db.getTotpEntries().filter((e) => !wanted || wanted.has(e.id));

      return entries.map((entry) => buildOtpCodeResult(entry, timestamp, payload?.withNext !== false));
    }
  );

  ipcMain.handle(IPC_CHANNELS.VERIFY_TOTP, (_event, { token, secret, options }) => {
    requireUnlocked();
    return verifyTotpCode(token, secret, options);
  });

  ipcMain.handle(IPC_CHANNELS.GENERATE_SECRET, () => {
    return generateTotpSecret();
  });

  ipcMain.handle(IPC_CHANNELS.GET_OTPAUTH_URI, (_event, { account, issuer, secret, options }) => {
    return generateOtpauthUri(account, issuer, secret, options);
  });

  /**
   * Advance an HOTP counter, persist it, and return the new code.
   * HOTP codes are single-use, so the counter must be stored before the
   * code is shown or the next code will be rejected by the server.
   */
  ipcMain.handle(IPC_CHANNELS.INCREMENT_HOTP, (_event, id: string): OtpCodeResult => {
    requireUnlocked();

    const entry = db.getTotpEntries().find((e) => e.id === id);
    if (!entry) throw new Error('Entry not found');
    if (entry.type !== 'HOTP') throw new Error('Entry is not an HOTP entry');

    const counter = Math.max(0, Math.trunc(entry.counter ?? 0)) + 1;
    const updated = db.updateTotpEntry(id, { counter });

    bumpVaultEpoch();
    return buildOtpCodeResult({ ...entry, ...(updated || {}), counter }, Date.now(), true);
  });

  /** Import one or many otpauth:// / otpauth-migration:// URIs. */
  ipcMain.handle(IPC_CHANNELS.IMPORT_OTP_URIS, (_event, input: string) => {
    requireUnlocked();

    const parsed = parseOtpInput(input);
    if (!parsed.length) {
      return {
        success: false,
        imported: 0,
        skipped: 0,
        errors: ['No otpauth:// or otpauth-migration:// URI found in the input'],
        entries: [] as TwoFactorEntry[],
      };
    }

    const existing = db.getTotpEntries();
    const seen = new Set(existing.map((e) => otpDedupeKey(e)));
    const errors: string[] = [];
    const added: TwoFactorEntry[] = [];
    let skipped = 0;

    for (const candidate of parsed) {
      if (!candidate.secret) {
        errors.push(`${candidate.title || 'Entry'}: missing secret`);
        continue;
      }

      const check = validateTotpSecret(candidate.secret, candidate.encoding);
      if (!check.valid) {
        errors.push(`${candidate.title || 'Entry'}: ${check.error}`);
        continue;
      }

      const key = otpDedupeKey(candidate);
      if (seen.has(key)) {
        skipped++;
        continue;
      }
      seen.add(key);

      try {
        added.push(
          db.addTotpEntry(
            normalizeTotpEntry({
              title: candidate.title || candidate.issuer || candidate.account || 'Imported',
              issuer: candidate.issuer,
              account: candidate.account,
              secret: candidate.secret,
              type: candidate.type === 'HOTP' ? 'HOTP' : 'TOTP',
              algorithm: candidate.algorithm,
              digits: candidate.digits,
              period: candidate.period,
              counter: candidate.counter,
              encoding: candidate.encoding,
              steam: candidate.steam,
            }) as Omit<TwoFactorEntry, 'id' | 'createdAt' | 'updatedAt'>
          )
        );
      } catch (err: any) {
        errors.push(`${candidate.title || 'Entry'}: ${err?.message || 'failed to save'}`);
      }
    }

    if (added.length) bumpVaultEpoch();
    return { success: added.length > 0, imported: added.length, skipped, errors, entries: added };
  });

  /** Persist a manual ordering (drag-and-drop / move up-down). */
  ipcMain.handle(IPC_CHANNELS.REORDER_TOTP, (_event, orderedIds: string[]) => {
    requireUnlocked();

    const data = db.loadVaultData();
    const position = new Map(orderedIds.map((id, index) => [id, index]));

    data.twoFactor = data.twoFactor.map((entry) => ({
      ...entry,
      order: position.has(entry.id) ? position.get(entry.id)! : (entry.order ?? position.size),
    }));

    db.saveVaultData(data);
    bumpVaultEpoch();
    return db.getTotpEntries();
  });

  /** Render an entry's otpauth URI as a QR code (for moving to a phone). */
  ipcMain.handle(IPC_CHANNELS.GET_TOTP_QR, async (_event, id: string) => {
    requireUnlocked();

    const entry = db.getTotpEntries().find((e) => e.id === id);
    if (!entry) throw new Error('Entry not found');

    const uri = entryToOtpauthUri(entry);
    return { uri, dataUrl: await generateQrCodeDataUrl(uri) };
  });

  /** Validate a secret while the user is still typing it. */
  ipcMain.handle(IPC_CHANNELS.VALIDATE_SECRET, (_event, { secret, encoding }) => {
    return validateTotpSecret(secret, encoding);
  });

  // --- Settings Handlers ---

  ipcMain.handle(IPC_CHANNELS.GET_SETTINGS, () => {
    return db.getSettings();
  });

  ipcMain.handle(IPC_CHANNELS.UPDATE_SETTINGS, (_event, settings: Partial<AppSettings>) => {
    const current = db.getSettings();
    const updated = { ...current, ...settings };
    db.saveSettings(updated);
    resetAutoLockTimer();
    return updated;
  });

  // --- Export/Import Handlers ---

  ipcMain.handle(IPC_CHANNELS.EXPORT_VAULT, async () => {
    if (!isUnlocked) return { error: 'Vault is locked' };

    const result = await dialog.showSaveDialog(mainWindow!, {
      title: 'Export Vault',
      defaultPath: `vaultguard-export-${Date.now()}.json`,
      filters: [{ name: 'JSON Files', extensions: ['json'] }],
    });

    if (result.canceled || !result.filePath) return { canceled: true };

    try {
      const data = db.exportVaultData();
      fs.writeFileSync(result.filePath, JSON.stringify(data, null, 2));
      return { success: true, path: result.filePath };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle(IPC_CHANNELS.IMPORT_VAULT, async () => {
    if (!isUnlocked) return { error: 'Vault is locked' };

    const result = await dialog.showOpenDialog(mainWindow!, {
      title: 'Import Vault',
      filters: [{ name: 'JSON Files', extensions: ['json'] }],
      properties: ['openFile'],
    });

    if (result.canceled || !result.filePaths[0]) return { canceled: true };

    try {
      const rawData = fs.readFileSync(result.filePaths[0], 'utf-8');
      const data: VaultData = JSON.parse(rawData);
      db.importVaultData(data);
      bumpVaultEpoch();
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  });

  // --- CSV Import/Export Handlers ---

  ipcMain.handle(IPC_CHANNELS.EXPORT_CSV, async () => {
    if (!isUnlocked) return { error: 'Vault is locked' };

    // Show warning about plaintext passwords
    const EXPORT_BUTTON_INDEX = 0;
    const CANCEL_BUTTON_INDEX = 1;
    const warningResult = await dialog.showMessageBox(mainWindow!, {
      type: 'warning',
      title: 'CSV Export Warning',
      message: 'CSV files contain passwords in plain text.',
      detail: 'This file will not be encrypted. Anyone with access to this file can read your passwords. Store it securely and delete it after use.',
      buttons: ['Export Anyway', 'Cancel'],
      defaultId: CANCEL_BUTTON_INDEX,
      cancelId: CANCEL_BUTTON_INDEX,
    });

    if (warningResult.response === CANCEL_BUTTON_INDEX) {
      return { canceled: true };
    }

    const result = await dialog.showSaveDialog(mainWindow!, {
      title: 'Export Passwords as CSV',
      defaultPath: `vaultguard-passwords-${Date.now()}.csv`,
      filters: [
        { name: 'CSV Files', extensions: ['csv'] },
        { name: 'All Files', extensions: ['*'] },
      ],
    });

    if (result.canceled || !result.filePath) return { canceled: true };

    try {
      const passwords = db.getPasswords();
      const csvContent = entriesToCSV(passwords);
      fs.writeFileSync(result.filePath, csvContent, 'utf-8');
      return { success: true, path: result.filePath, count: passwords.length };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle(IPC_CHANNELS.IMPORT_CSV, async () => {
    if (!isUnlocked) return { error: 'Vault is locked' };

    const result = await dialog.showOpenDialog(mainWindow!, {
      title: 'Import Passwords from CSV',
      filters: [
        { name: 'CSV Files', extensions: ['csv'] },
        { name: 'All Files', extensions: ['*'] },
      ],
      properties: ['openFile'],
    });

    if (result.canceled || !result.filePaths[0]) return { canceled: true };

    try {
      const csvContent = fs.readFileSync(result.filePaths[0], 'utf-8');
      
      // Validate CSV first
      const validation = validateCSV(csvContent);
      if (!validation.valid) {
        return { success: false, errors: validation.errors };
      }

      // Parse CSV
      const entries = parseCSV(csvContent);
      
      // Get existing passwords for deduplication
      // Use username + URL as key (not password) so password changes can be imported
      const existingPasswords = db.getPasswords();
      const existingKeys = new Set(
        existingPasswords.map(p => `${p.username.toLowerCase()}:${p.url?.toLowerCase() || ''}`)
      );

      // Filter out duplicates (same username + URL combination)
      // If user wants to update password, they should delete the old entry first
      const newEntries = entries.filter(entry => {
        const key = `${entry.username.toLowerCase()}:${entry.url?.toLowerCase() || ''}`;
        return !existingKeys.has(key);
      });

      // Add new entries
      for (const entry of newEntries) {
        db.addPassword(entry);
      }

      const duplicatesSkipped = entries.length - newEntries.length;

      return { 
        success: true, 
        count: newEntries.length,
        duplicatesSkipped,
        warnings: validation.warnings 
      };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle(IPC_CHANNELS.VALIDATE_CSV, async (_event, csvContent: string) => {
    return validateCSV(csvContent);
  });

  // --- Biometric Handlers ---

  ipcMain.handle(IPC_CHANNELS.BIOMETRIC_STATUS, () => {
    const config = db.getBiometricConfig();
    return {
      enabled: config?.enabled || false,
      credentialId: config?.credentialId,
      hasConfig: !!config,
    };
  });

  ipcMain.handle(IPC_CHANNELS.BIOMETRIC_REGISTER, async (_event, { credentialId, authenticatorData }: { credentialId: string; authenticatorData: string }) => {
    try {
      // Check if safeStorage is available
      if (!db.isSafeStorageAvailable()) {
        return { success: false, error: 'Biometric requires OS secure storage which is not available on this system' };
      }

      const config: BiometricConfig = {
        enabled: true,
        credentialId,
        authenticatorData,
        createdAt: Date.now(),
      };
      db.saveBiometricConfig(config);
      const keyBound = bindBiometricKey();
      return { success: true, keyBound };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle(IPC_CHANNELS.BIOMETRIC_AUTHENTICATE, async (_event, { credentialId }: { credentialId: string }) => {
    try {
      const config = db.getBiometricConfig();
      if (!config || !config.enabled || !config.credentialId) {
        return { success: false, error: 'Biometric not configured' };
      }

      if (config.credentialId !== credentialId) {
        return { success: false, error: 'Invalid biometric credential' };
      }

      // For biometric unlock, we use the stored encryption key that was encrypted
      // with Electron's safeStorage (which uses DPAPI on Windows, Keychain on macOS)
      // The WebAuthn verification happens in the renderer, and if successful,
      // we retrieve the stored key here.
      const storedKey = db.getBiometricKey();
      if (!storedKey) {
        return { success: false, error: 'No biometric key stored' };
      }

      db.setEncryptionKey(storedKey);
      sessionToken = db.createSessionToken();
      isUnlocked = true;
      resetAutoLockTimer();

      return { success: true, sessionToken };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle(IPC_CHANNELS.BIOMETRIC_DISABLE, async () => {
    try {
      db.saveBiometricConfig({ enabled: false });
      db.clearBiometricKey();
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  });

  // --- Backup Handlers ---

  ipcMain.handle(IPC_CHANNELS.GET_BACKUP_SETTINGS, () => {
    try {
      const settingsPath = path.join(app.getPath('userData'), 'backup-settings.json');
      if (fs.existsSync(settingsPath)) {
        return JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
      }
      return { enabled: false, intervalMinutes: 60, backupPath: '', maxBackups: 10, encrypted: true };
    } catch {
      return { enabled: false, intervalMinutes: 60, backupPath: '', maxBackups: 10, encrypted: true };
    }
  });

  ipcMain.handle(IPC_CHANNELS.UPDATE_BACKUP_SETTINGS, (_event, settings: any) => {
    try {
      const settingsPath = path.join(app.getPath('userData'), 'backup-settings.json');
      fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2));
      return settings;
    } catch (err: any) {
      return { error: err.message };
    }
  });

  ipcMain.handle(IPC_CHANNELS.CREATE_BACKUP, async () => {
    if (!isUnlocked) return { error: 'Vault is locked' };
    try {
      const settingsPath = path.join(app.getPath('userData'), 'backup-settings.json');
      let settings = { enabled: false, intervalMinutes: 60, backupPath: '', maxBackups: 10, encrypted: true };
      if (fs.existsSync(settingsPath)) {
        settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
      }
      const backupDir = settings.backupPath || path.join(app.getPath('userData'), 'backups');
      if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });
      const timestamp = Date.now();
      const filename = `vaultguard-backup-${timestamp}.json`;
      const filePath = path.join(backupDir, filename);
      const data = db.exportVaultData();
      fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
      // Clean old backups
      if (settings.maxBackups > 0) {
        const files = fs.readdirSync(backupDir).filter(f => f.startsWith('vaultguard-backup-')).sort();
        while (files.length > settings.maxBackups) {
          const oldFile = files.shift()!;
          fs.unlinkSync(path.join(backupDir, oldFile));
        }
      }
      return { success: true, filename, path: filePath };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle(IPC_CHANNELS.RESTORE_BACKUP, async (_event, filename: string) => {
    if (!isUnlocked) return { error: 'Vault is locked' };
    try {
      const settingsPath = path.join(app.getPath('userData'), 'backup-settings.json');
      let settings = { backupPath: '' };
      if (fs.existsSync(settingsPath)) {
        settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
      }
      const backupDir = settings.backupPath || path.join(app.getPath('userData'), 'backups');
      const filePath = path.join(backupDir, filename);
      if (!fs.existsSync(filePath)) return { success: false, error: 'Backup file not found' };
      const rawData = fs.readFileSync(filePath, 'utf-8');
      const data = JSON.parse(rawData);
      db.importVaultData(data);
      bumpVaultEpoch();
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle(IPC_CHANNELS.DELETE_BACKUP, async (_event, filename: string) => {
    try {
      const settingsPath = path.join(app.getPath('userData'), 'backup-settings.json');
      let settings = { backupPath: '' };
      if (fs.existsSync(settingsPath)) {
        settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
      }
      const backupDir = settings.backupPath || path.join(app.getPath('userData'), 'backups');
      const filePath = path.join(backupDir, filename);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle(IPC_CHANNELS.GET_BACKUP_LIST, () => {
    try {
      const settingsPath = path.join(app.getPath('userData'), 'backup-settings.json');
      let settings = { backupPath: '' };
      if (fs.existsSync(settingsPath)) {
        settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
      }
      const backupDir = settings.backupPath || path.join(app.getPath('userData'), 'backups');
      if (!fs.existsSync(backupDir)) return [];
      const files = fs.readdirSync(backupDir).filter(f => f.startsWith('vaultguard-backup-'));
      return files.map(filename => {
        const filePath = path.join(backupDir, filename);
        const stats = fs.statSync(filePath);
        const timestamp = parseInt(filename.replace('vaultguard-backup-', '').replace('.json', ''));
        return { filename, timestamp: isNaN(timestamp) ? stats.mtimeMs : timestamp, size: stats.size };
      }).sort((a, b) => b.timestamp - a.timestamp);
    } catch {
      return [];
    }
  });

  ipcMain.handle(IPC_CHANNELS.SELECT_BACKUP_FOLDER, async () => {
    const result = await dialog.showOpenDialog(mainWindow!, {
      title: 'Select Backup Folder',
      properties: ['openDirectory', 'createDirectory'],
    });
    if (result.canceled || !result.filePaths[0]) return { canceled: true };
    return { success: true, path: result.filePaths[0] };
  });

  // --- Clipboard Handler ---

  ipcMain.handle('clipboard:copy', async (_event, text: string) => {
    clipboard.writeText(text);

    // Auto-clear after configured seconds
    const settings = db.getSettings();
    const textToClear = text;
    setTimeout(() => {
      // Only clear if clipboard still contains our text
      if (clipboard.readText() === textToClear) {
        clipboard.clear();
      }
    }, settings.clipboardClearSeconds * 1000);

    return { success: true };
  });

  // --- Tray Handlers ---

  ipcMain.handle(IPC_CHANNELS.TRAY_LOCK, () => {
    lockVault();
  });

  ipcMain.handle(IPC_CHANNELS.TRAY_QUIT, () => {
    isQuitting = true;
    isUnlocked = false;
    app.quit();
  });

  // --- Window Controls (frameless title bar) ---

  ipcMain.handle(IPC_CHANNELS.WINDOW_MINIMIZE, () => {
    mainWindow?.minimize();
  });

  ipcMain.handle(IPC_CHANNELS.WINDOW_MAXIMIZE, () => {
    if (!mainWindow) return false;
    if (mainWindow.isMaximized()) {
      mainWindow.unmaximize();
    } else {
      mainWindow.maximize();
    }
    return mainWindow.isMaximized();
  });

  ipcMain.handle(IPC_CHANNELS.WINDOW_CLOSE, () => {
    // Match the tray-app convention: close hides, quit exits.
    const settings = safeGetSettings();
    if (settings?.minimizeToTray !== false && tray) {
      mainWindow?.hide();
    } else {
      mainWindow?.close();
    }
  });

  ipcMain.handle(IPC_CHANNELS.WINDOW_IS_MAXIMIZED, () => mainWindow?.isMaximized() ?? false);

  // --- Extension Bridge Diagnostics ---

  ipcMain.handle(IPC_CHANNELS.BRIDGE_STATUS, () => getBridgeStatus());

  ipcMain.handle(IPC_CHANNELS.BRIDGE_REGISTER, () => {
    registerNativeMessagingHost();
    if (!httpFallbackServer) startHttpFallbackServer();
    return getBridgeStatus();
  });

  // Renderer's answer to a `bridge:pairing-request` prompt.
  ipcMain.handle('bridge:pairing-response', (_event, approved: boolean) => {
    if (!approved) {
      pendingPairing = null;
      return { success: true, approved: false };
    }
    // Approval only marks the request as user-acknowledged; the extension
    // still has to echo the 6-digit code back to /pair/confirm.
    return { success: true, approved: true };
  });

  // Allow manually setting the extension ID (for when auto-detection fails)
  ipcMain.handle('extension:set-id', (_event, extensionId: string) => {
    try {
      if (!/^[a-z]{32}$/.test(extensionId)) {
        return { success: false, error: 'Invalid extension ID format (must be 32 lowercase letters)' };
      }
      const settingsPath = path.join(app.getPath('userData'), 'extension-id.txt');
      fs.writeFileSync(settingsPath, extensionId);
      console.log(`Manually set extension ID: ${extensionId}`);
      // Re-register native messaging host with the new ID
      registerNativeMessagingHost();
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  });
}

/** Settings read that cannot throw — used on paths that run while locked. */
function safeGetSettings(): AppSettings | null {
  try {
    return db.getSettings();
  } catch {
    return null;
  }
}

// ============================================
// Native Messaging Host (stdio <-> loopback bridge proxy)
// ============================================

const MAX_MSG_SIZE_FROM_EXT = 1024 * 1024; // 1MB
const MAX_MSG_SIZE_TO_EXT = 4 * 1024 * 1024; // 4MB
const NATIVE_HOST_NAME = 'com.vaultguard.native';

/**
 * The running app publishes its loopback bridge coordinates here so the
 * native-messaging host (a separate, short-lived process spawned by
 * Chrome) can reach it. Written with 0600 permissions.
 */
function bridgeDescriptorPath(): string {
  return path.join(app.getPath('userData'), 'bridge.json');
}

interface BridgeDescriptor {
  port: number;
  token: string;
  pid: number;
  startedAt: number;
}

function readBridgeDescriptor(): BridgeDescriptor | null {
  try {
    const parsed = JSON.parse(fs.readFileSync(bridgeDescriptorPath(), 'utf-8'));
    if (typeof parsed?.port === 'number' && typeof parsed?.token === 'string' && parsed.port > 0) {
      return parsed as BridgeDescriptor;
    }
  } catch {
    // Missing or unreadable means "app not running".
  }
  return null;
}

function writeBridgeDescriptor(port: number, token: string): void {
  const descriptor: BridgeDescriptor = { port, token, pid: process.pid, startedAt: Date.now() };
  try {
    fs.writeFileSync(bridgeDescriptorPath(), JSON.stringify(descriptor), { mode: 0o600 });
  } catch (err: any) {
    console.error('Failed to publish bridge descriptor:', err.message);
  }
}

function removeBridgeDescriptor(): void {
  try {
    fs.unlinkSync(bridgeDescriptorPath());
  } catch {
    // Already gone.
  }
}

// --- Native host mode -------------------------------------------------

/**
 * Run as Chrome's native messaging host.
 *
 * This process is a *proxy*, not a second instance of the app. Chrome
 * spawns it with pipes on stdin/stdout; we decode its 4-byte-framed JSON,
 * forward each message to the already-running app's loopback bridge, and
 * frame the reply back. That keeps a single vault, a single unlock state
 * and a single SQLite connection — the previous version opened its own
 * database here, which is why the extension was always told the vault was
 * locked even with the app unlocked on screen.
 */
function startNativeMessagingProxy(): void {
  let buffer = Buffer.alloc(0);
  // Chrome expects exactly one reply per request, in order.
  let chain: Promise<void> = Promise.resolve();

  const enqueue = (message: NativeMessage) => {
    chain = chain
      .then(async () => {
        const reply = await forwardToBridge(message);
        writeFramedMessage(reply);
      })
      .catch((err) => {
        writeFramedMessage({
          type: 'ERROR',
          error: err?.message || 'Native host failure',
          requestId: message.requestId,
        });
      });
  };

  process.stdin.on('data', (chunk: Buffer) => {
    buffer = Buffer.concat([buffer, chunk]);

    while (buffer.length >= 4) {
      const msgLength = buffer.readUInt32LE(0);

      if (msgLength > MAX_MSG_SIZE_FROM_EXT) {
        writeFramedMessage({ type: 'ERROR', error: 'Message too large' });
        buffer = Buffer.alloc(0);
        return;
      }

      if (buffer.length < 4 + msgLength) break;

      const jsonStr = buffer.toString('utf8', 4, 4 + msgLength);
      buffer = buffer.subarray(4 + msgLength);

      let message: NativeMessage | null = null;
      try {
        message = JSON.parse(jsonStr) as NativeMessage;
      } catch {
        writeFramedMessage({ type: 'ERROR', error: 'Invalid message format' });
      }
      if (message) enqueue(message);
    }
  });

  // Chrome closes stdin when the port is disconnected; that is our exit signal.
  process.stdin.on('end', () => app.quit());
  process.stdin.on('close', () => app.quit());
  process.stdin.on('error', () => app.quit());
  process.stdin.resume();
}

/** Write a message using Chrome's 4-byte little-endian length framing. */
function writeFramedMessage(message: NativeMessage): void {
  try {
    const jsonStr = JSON.stringify(message);
    const msgLength = Buffer.byteLength(jsonStr, 'utf8');

    if (msgLength > MAX_MSG_SIZE_TO_EXT) {
      // Chrome drops oversized messages and kills the port; send an error
      // the extension can actually act on instead.
      const fallback = JSON.stringify({
        type: 'ERROR',
        error: 'Response too large',
        requestId: message.requestId,
      });
      const buf = Buffer.alloc(4 + Buffer.byteLength(fallback, 'utf8'));
      buf.writeUInt32LE(Buffer.byteLength(fallback, 'utf8'), 0);
      buf.write(fallback, 4, 'utf8');
      process.stdout.write(buf);
      return;
    }

    const buffer = Buffer.alloc(4 + msgLength);
    buffer.writeUInt32LE(msgLength, 0);
    buffer.write(jsonStr, 4, 'utf8');
    process.stdout.write(buffer);
  } catch (err) {
    // stdout is a pipe owned by Chrome; if it is gone we are shutting down.
  }
}

async function forwardToBridge(message: NativeMessage): Promise<NativeMessage> {
  // Answer the handshake locally: it confirms the host is installed and
  // reachable even while the desktop app is closed.
  if (message.type === 'HELLO' || message.type === 'PING') {
    const descriptor = readBridgeDescriptor();
    if (message.type === 'HELLO') {
      return {
        type: 'HELLO',
        payload: {
          host: NATIVE_HOST_NAME,
          version: app.getVersion(),
          transport: 'native',
          appRunning: !!descriptor,
        },
        requestId: message.requestId,
      };
    }
  }

  let descriptor = readBridgeDescriptor();
  if (descriptor && !(await probeBridge(descriptor))) descriptor = null;

  if (!descriptor) {
    // Stale descriptor from a crashed run: clean up and start the app.
    descriptor = await launchDesktopAppAndWait();
  }

  if (!descriptor) {
    return {
      type: 'ERROR',
      error: 'VaultGuard desktop app is not running',
      payload: { code: 'APP_NOT_RUNNING' },
      requestId: message.requestId,
    };
  }

  if (message.type === 'PING') {
    return { type: 'PONG', payload: { appRunning: true }, requestId: message.requestId };
  }

  return postToBridge(descriptor, message);
}

/** Cheap liveness probe so we never post to a dead port. */
function probeBridge(descriptor: BridgeDescriptor): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.request(
      { host: '127.0.0.1', port: descriptor.port, path: '/health', method: 'GET', timeout: 1200 },
      (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      }
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
    req.end();
  });
}

function postToBridge(descriptor: BridgeDescriptor, message: NativeMessage): Promise<NativeMessage> {
  return new Promise((resolve) => {
    const body = Buffer.from(JSON.stringify(message), 'utf8');
    const req = http.request(
      {
        host: '127.0.0.1',
        port: descriptor.port,
        path: '/message',
        method: 'POST',
        timeout: 15000,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': String(body.length),
          'X-Vault-Token': descriptor.token,
          'X-Vault-Transport': 'native',
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
          } catch {
            resolve({
              type: 'ERROR',
              error: 'Malformed response from desktop app',
              requestId: message.requestId,
            });
          }
        });
      }
    );

    req.on('error', (err: any) =>
      resolve({
        type: 'ERROR',
        error: `Bridge unreachable: ${err.message}`,
        payload: { code: 'BRIDGE_UNREACHABLE' },
        requestId: message.requestId,
      })
    );
    req.on('timeout', () => {
      req.destroy();
      resolve({ type: 'ERROR', error: 'Desktop app timed out', requestId: message.requestId });
    });

    req.write(body);
    req.end();
  });
}

/**
 * Start the desktop app on demand and wait for its bridge to come up.
 * Without this the very first extension action after a reboot would fail
 * with a bare "not connected" and the user would have no idea why.
 */
async function launchDesktopAppAndWait(): Promise<BridgeDescriptor | null> {
  removeBridgeDescriptor();

  try {
    const { spawn } = require('child_process');
    const child = spawn(app.getPath('exe'), [], {
      detached: true,
      stdio: 'ignore',
      windowsHide: false,
    });
    child.unref();
  } catch (err: any) {
    console.error('Failed to launch desktop app:', err.message);
    return null;
  }

  // Cold start includes window creation; poll for up to ~12s.
  for (let attempt = 0; attempt < 40; attempt++) {
    await delay(300);
    const descriptor = readBridgeDescriptor();
    if (descriptor && (await probeBridge(descriptor))) return descriptor;
  }
  return null;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// --- Shared message handling (native host + HTTP fallback) -------------

/**
 * One implementation for every extension request, whatever transport it
 * arrived on. Previously stdio and HTTP each had their own copy of this
 * switch and they had already drifted apart.
 */
function handleBridgeMessage(message: NativeMessage, extensionId?: string): NativeMessage {
  const requestId = message.requestId;
  const ok = (payload: any): NativeMessage => ({ type: 'RESPONSE', payload, requestId });
  const fail = (error: string, code?: string): NativeMessage => ({
    type: 'ERROR',
    error,
    payload: code ? { code } : undefined,
    requestId,
  });

  if (extensionId) {
    connectedExtensions.add(extensionId);
    lastExtensionSeenAt = Date.now();
    notifyBridgeStatus();
  }

  try {
    switch (message.type) {
      case 'HELLO':
        return {
          type: 'HELLO',
          payload: {
            app: 'VaultGuard',
            version: app.getVersion(),
            protocol: 1,
            isUnlocked,
            hasAuthConfig: db.hasAuthConfig(),
            epoch: vaultEpoch,
            serverTime: Date.now(),
          },
          requestId,
        };

      case 'PING':
        return {
          type: 'PONG',
          payload: { isUnlocked, epoch: vaultEpoch, serverTime: Date.now() },
          requestId,
        };

      case 'AUTH_STATUS':
        return ok({
          isUnlocked,
          hasAuthConfig: db.hasAuthConfig(),
          epoch: vaultEpoch,
          serverTime: Date.now(),
        });

      case 'UNLOCK_VAULT': {
        if (!message.payload?.password) return fail('No password provided');

        const config = db.getAuthConfig();
        if (!config) return fail('No vault configured', 'NO_VAULT');

        const result = verifyMasterPasswordDetailed(
          message.payload.password,
          config.masterPasswordHash,
          config.salt,
          config.iterations
        );
        if (!result.valid || !result.key) return fail('Invalid password', 'BAD_PASSWORD');

        db.setEncryptionKey(result.key);
        if (result.needsUpgrade && result.newHash) {
          try {
            db.saveAuthConfig({
              masterPasswordHash: result.newHash,
              salt: config.salt,
              iterations: config.iterations,
            });
          } catch {
            // Non-fatal: the vault still opens.
          }
        }

        db.updateLastLogin();
        sessionToken = db.createSessionToken();
        isUnlocked = true;
        resetAutoLockTimer();
        updateTrayMenu();
        bumpVaultEpoch();
        notifyBridgeStatus();
        bindBiometricKey();
        mainWindow?.webContents.send('vault:unlocked-remotely');
        return ok({ success: true, epoch: vaultEpoch });
      }

      case 'LOCK_VAULT':
        lockVault();
        return ok({ success: true });

      case 'GET_ENTRIES_FOR_URL': {
        if (!isUnlocked) return fail('Vault is locked', 'VAULT_LOCKED');
        if (!message.payload?.url) return fail('No URL provided');

        resetAutoLockTimer();
        const timestamp = Date.now();
        const passwords = db.getPasswordsForUrl(message.payload.url);
        const totpEntries = db.getTotpEntriesForUrl(message.payload.url);
        return ok({
          passwords,
          totpEntries,
          codes: totpEntries.map((entry) => buildOtpCodeResult(entry, timestamp, true)),
          epoch: vaultEpoch,
          serverTime: timestamp,
        });
      }

      case 'GET_TOTP': {
        if (!isUnlocked) return fail('Vault is locked', 'VAULT_LOCKED');

        const now = Date.now();
        const entries = db.getTotpEntries();
        return ok({
          entries,
          codes: entries.map((entry) => buildOtpCodeResult(entry, now, true)),
          epoch: vaultEpoch,
          serverTime: now,
        });
      }

      case 'GET_PASSWORDS':
        if (!isUnlocked) return fail('Vault is locked', 'VAULT_LOCKED');
        return ok({ passwords: db.getPasswords() });

      case 'GENERATE_TOTP': {
        if (!isUnlocked) return fail('Vault is locked', 'VAULT_LOCKED');

        // Accept either a stored entry id or a raw secret.
        if (message.payload?.id) {
          const entry = db.getTotpEntries().find((e) => e.id === message.payload.id);
          if (!entry) return fail('Entry not found');
          const result = buildOtpCodeResult(entry, Date.now(), true);
          if (result.error) return fail(result.error);
          return ok(result);
        }

        if (!message.payload?.secret) return fail('No secret provided');
        return ok({ code: generateTotpCode(message.payload.secret, message.payload.options) });
      }

      case 'GENERATE_TOTP_BATCH': {
        if (!isUnlocked) return fail('Vault is locked', 'VAULT_LOCKED');

        const ids: string[] | undefined = message.payload?.ids;
        const wanted = ids && ids.length ? new Set(ids) : null;
        const timestamp = Date.now();
        const codes = db
          .getTotpEntries()
          .filter((e) => !wanted || wanted.has(e.id))
          .map((entry) => buildOtpCodeResult(entry, timestamp, true));
        return ok({ codes, epoch: vaultEpoch, serverTime: timestamp });
      }

      case 'INCREMENT_HOTP': {
        if (!isUnlocked) return fail('Vault is locked', 'VAULT_LOCKED');

        const entry = db.getTotpEntries().find((e) => e.id === message.payload?.id);
        if (!entry) return fail('Entry not found');
        if (entry.type !== 'HOTP') return fail('Entry is not an HOTP entry');

        const counter = Math.max(0, Math.trunc(entry.counter ?? 0)) + 1;
        db.updateTotpEntry(entry.id, { counter });
        resetAutoLockTimer();
        bumpVaultEpoch();
        return ok(buildOtpCodeResult({ ...entry, counter }, Date.now(), true));
      }

      case 'VERIFY_TOTP': {
        if (!isUnlocked) return fail('Vault is locked', 'VAULT_LOCKED');
        if (!message.payload?.token || !message.payload?.secret) return fail('Token and secret required');
        return ok({
          valid: verifyTotpCode(message.payload.token, message.payload.secret, message.payload.options),
        });
      }

      case 'SAVE_PASSWORD': {
        if (!isUnlocked) return fail('Vault is locked', 'VAULT_LOCKED');
        if (!message.payload?.password) return fail('No password provided');

        const entry = db.addPassword({
          title: message.payload.title || message.payload.url || 'Saved from browser',
          username: message.payload.username || '',
          password: message.payload.password,
          url: message.payload.url,
          notes: message.payload.notes,
          category: message.payload.category,
        });
        resetAutoLockTimer();
        bumpVaultEpoch();
        return ok({ success: true, entry, epoch: vaultEpoch });
      }

      case 'SAVE_TOTP': {
        if (!isUnlocked) return fail('Vault is locked', 'VAULT_LOCKED');

        // The extension may hand us a scanned QR URI or explicit fields.
        const candidates = message.payload?.uri
          ? parseOtpInput(message.payload.uri)
          : [message.payload || {}];

        const saved: TwoFactorEntry[] = [];
        const errors: string[] = [];

        for (const candidate of candidates) {
          if (!candidate?.secret) {
            errors.push('Missing secret');
            continue;
          }
          const check = validateTotpSecret(candidate.secret, candidate.encoding);
          if (!check.valid) {
            errors.push(check.error || 'Invalid secret');
            continue;
          }
          saved.push(
            db.addTotpEntry(
              normalizeTotpEntry({
                title: candidate.title || candidate.issuer || candidate.account || 'Scanned',
                issuer: candidate.issuer,
                account: candidate.account,
                secret: candidate.secret,
                type: candidate.type === 'HOTP' ? 'HOTP' : 'TOTP',
                algorithm: candidate.algorithm,
                digits: candidate.digits,
                period: candidate.period,
                counter: candidate.counter,
                encoding: candidate.encoding,
                steam: candidate.steam,
              }) as Omit<TwoFactorEntry, 'id' | 'createdAt' | 'updatedAt'>
            )
          );
        }

        if (!saved.length) return fail(errors[0] || 'Nothing to save');
        resetAutoLockTimer();
        bumpVaultEpoch();
        return ok({ success: true, entries: saved, errors, epoch: vaultEpoch });
      }

      case 'GET_BIOMETRIC_STATUS': {
        const biometricConfig = db.getBiometricConfig();
        return ok({
          enabled: biometricConfig?.enabled || false,
          credentialId: biometricConfig?.credentialId,
          hasConfig: !!biometricConfig,
        });
      }

      case 'BIOMETRIC_UNLOCK': {
        if (!message.payload?.credentialId) return fail('No credential ID provided');

        const bioConfig = db.getBiometricConfig();
        if (!bioConfig?.enabled || bioConfig.credentialId !== message.payload.credentialId) {
          return fail('Biometric not configured or invalid credential');
        }

        const storedKey = db.getBiometricKey();
        if (!storedKey) return fail('No biometric key stored');

        db.setEncryptionKey(storedKey);
        sessionToken = db.createSessionToken();
        isUnlocked = true;
        resetAutoLockTimer();
        updateTrayMenu();
        bumpVaultEpoch();
        notifyBridgeStatus();
        return ok({ success: true, epoch: vaultEpoch });
      }

      case 'BIOMETRIC_REGISTER': {
        if (!message.payload?.credentialId) return fail('No credential ID provided');
        try {
          if (!db.isSafeStorageAvailable()) {
            return fail('Biometric requires OS secure storage which is not available on this system');
          }
          db.saveBiometricConfig({
            enabled: true,
            credentialId: message.payload.credentialId,
            authenticatorData: message.payload.authenticatorData,
            createdAt: Date.now(),
          });
          const keyBound = bindBiometricKey();
          return ok({ success: true, keyBound });
        } catch (err: any) {
          return fail(err?.message || 'Biometric registration failed');
        }
      }

      case 'SHOW_WINDOW':
        if (mainWindow) {
          if (mainWindow.isMinimized()) mainWindow.restore();
          mainWindow.show();
          mainWindow.focus();
        }
        return ok({ success: true });

      default:
        return fail(`Unknown message type: ${message.type}`);
    }
  } catch (err: any) {
    console.error('Bridge message failed:', message.type, err);
    return fail(err?.message || 'Internal error');
  }
}

// ============================================
// Auto-Lock Timer
// ============================================

function resetAutoLockTimer(): void {
  if (autoLockTimer) clearTimeout(autoLockTimer);

  const settings = db.getSettings();
  if (isUnlocked && settings.autoLockMinutes > 0) {
    autoLockTimer = setTimeout(() => {
      lockVault();
      mainWindow?.webContents.send('vault:auto-locked');
    }, settings.autoLockMinutes * 60 * 1000);
  }
}

function resetAutoBackupTimer(): void {
  if (autoBackupTimer) clearInterval(autoBackupTimer);
  autoBackupTimer = null;

  try {
    const settingsPath = path.join(app.getPath('userData'), 'backup-settings.json');
    if (!fs.existsSync(settingsPath)) return;
    const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf-8'));
    if (!settings.enabled || !settings.intervalMinutes) return;

    autoBackupTimer = setInterval(() => {
      if (!isUnlocked) return;
      try {
        const backupDir = settings.backupPath || path.join(app.getPath('userData'), 'backups');
        if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });
        const timestamp = Date.now();
        const filename = `vaultguard-backup-${timestamp}.json`;
        const filePath = path.join(backupDir, filename);
        const data = db.exportVaultData();
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
        lastBackupTime = timestamp;
        mainWindow?.webContents.send('backup:created', { filename });
        // Clean old backups
        if (settings.maxBackups > 0) {
          const files = fs.readdirSync(backupDir).filter((f: string) => f.startsWith('vaultguard-backup-')).sort();
          while (files.length > settings.maxBackups) {
            const oldFile = files.shift()!;
            fs.unlinkSync(path.join(backupDir, oldFile));
          }
        }
      } catch (err) {
        console.error('Auto-backup failed:', err);
      }
    }, settings.intervalMinutes * 60 * 1000);
  } catch {
    // Ignore errors reading backup settings
  }
}

/**
 * Store the current encryption key for future biometric unlocks.
 * Safe to call any time; a no-op while the vault is locked or
 * Windows Hello is not configured.
 */
function bindBiometricKey(): boolean {
  try {
    const bio = db.getBiometricConfig();
    if (!bio?.enabled || !bio.credentialId) return false;
    const key = db.getEncryptionKey();
    if (!key) return false;
    db.saveBiometricKey(key);
    return true;
  } catch (err) {
    console.error('Failed to store biometric key:', err);
    return false;
  }
}

function lockVault(): void {
  isUnlocked = false;
  sessionToken = null;
  db.clearEncryptionKey();
  db.invalidateAllSessions();

  if (autoLockTimer) {
    clearTimeout(autoLockTimer);
    autoLockTimer = null;
  }

  // The extension caches entries in chrome.storage.session for instant
  // codes. Bump the epoch so its next poll sees the lock and wipes them;
  // it also drops its cache when any request answers VAULT_LOCKED.
  vaultEpoch++;

  mainWindow?.webContents.send('vault:locked');
  updateTrayMenu();
  notifyBridgeStatus();
}

/**
 * Incremented on every unlock/lock and every write. The extension sends
 * the epoch it last saw; a mismatch tells it to refetch instead of
 * trusting its cache.
 */
let vaultEpoch = 1;

/** Call after any change that invalidates the extension's cached entries. */
function bumpVaultEpoch(): void {
  vaultEpoch++;
  mainWindow?.webContents.send('vault:changed', { epoch: vaultEpoch });
}

/** Rebuild the tray menu so its Lock/Unlock item matches reality. */
function updateTrayMenu(): void {
  if (!tray) return;

  try {
    tray.setContextMenu(
      Menu.buildFromTemplate([
        { label: isUnlocked ? 'VaultGuard — unlocked' : 'VaultGuard — locked', enabled: false },
        { type: 'separator' },
        { label: 'Open VaultGuard', click: () => showMainWindow() },
        isUnlocked
          ? { label: 'Lock Vault', click: () => lockVault() }
          : { label: 'Unlock Vault', click: () => showMainWindow() },
        { type: 'separator' },
        {
          label: 'Quit',
          click: () => {
            isQuitting = true;
            isUnlocked = false;
            app.quit();
          },
        },
      ])
    );
    tray.setToolTip(isUnlocked ? 'VaultGuard (unlocked)' : 'VaultGuard (locked)');
  } catch (err) {
    console.error('Failed to update tray menu:', err);
  }
}

function showMainWindow(): void {
  if (!mainWindow) {
    void createWindow();
    return;
  }
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
}

// ============================================
// App Lifecycle
// ============================================

/** True once the user really means to exit (vs. closing to the tray). */
let isQuitting = false;

// Only set up the full app if NOT in native messaging mode
if (!isNativeMessagingMode) {
  app.whenReady().then(() => {
    db = new VaultDatabase();
    loadPairedTokens();
    setupIPC();
    void createWindow();
    createTray();
    resetAutoBackupTimer();

    // Loopback bridge: the transport the native host proxies into, and the
    // fallback the extension uses when the host manifest is not registered.
    startHttpFallbackServer();

    // Register the native messaging host manifest. This used to be win32
    // only, so Chrome on macOS/Linux could never find the host at all.
    registerNativeMessagingHost();

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        void createWindow();
      } else {
        showMainWindow();
      }
    });
  });
}

app.on('window-all-closed', () => {
  // Windows/Linux: stay resident in the tray so the extension bridge and
  // the unlocked session survive closing the window. macOS does this by
  // convention already.
});

app.on('before-quit', () => {
  isQuitting = true;
  if (autoLockTimer) clearTimeout(autoLockTimer);
  if (autoBackupTimer) clearInterval(autoBackupTimer);
  stopHttpFallbackServer();
  removeBridgeDescriptor();
  try {
    db?.clearEncryptionKey();
  } catch {
    /* db may not exist yet */
  }
});

// ============================================
// Loopback Bridge (HTTP fallback transport)
// ============================================
//
// Native messaging is the primary transport. This loopback server is the
// fallback for when the host manifest is not registered (fresh install,
// portable use, a browser we do not register). It is also what the native
// host proxies into, so both transports converge on handleBridgeMessage.

// Narrowed from 100 ports to 10: the old code probed 19800-19899 one at a
// time, and the extension mirrored that scan, so discovery could take the
// better part of a minute.
const HTTP_FALLBACK_PORT_RANGE = { min: 19800, max: 19809 };
let httpFallbackServer: http.Server | null = null;
let httpFallbackPort: number = 0;
let httpFallbackToken: string = '';

/** Tokens handed out to extensions that completed pairing. */
const pairedTokens = new Map<string, { extensionId: string; pairedAt: number }>();
/** In-flight pairing request awaiting the user's approval in the app. */
let pendingPairing: { code: string; extensionId: string; expiresAt: number } | null = null;

function startHttpFallbackServer(): void {
  httpFallbackToken = crypto.randomBytes(32).toString('hex');
  loadPairedTokens();

  httpFallbackServer = http.createServer((req, res) => {
    // Only the app's own renderer and browser extensions may talk to us.
    const origin = req.headers.origin || '';
    const allowed =
      origin.startsWith('chrome-extension://') ||
      origin.startsWith('moz-extension://') ||
      origin.startsWith('http://localhost');
    res.setHeader('Access-Control-Allow-Origin', allowed ? origin : 'null');
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Vault-Token, X-Extension-Id');
    res.setHeader('Vary', 'Origin');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = (req.url || '').split('?')[0];

    // Discovery probe. Deliberately reveals nothing but "an app is here".
    if (req.method === 'GET' && url === '/health') {
      sendJson(res, 200, {
        status: 'ok',
        app: 'VaultGuard',
        version: app.getVersion(),
        protocol: 1,
        // Whether the vault is open is needed for the extension badge and
        // is not a secret — the popup shows it either way.
        unlocked: isUnlocked,
        hasAuthConfig: safeHasAuthConfig(),
      });
      return;
    }

    // --- Pairing ---------------------------------------------------------
    // The extension cannot read the token file, so it asks to pair and the
    // user approves the request inside the desktop app. (The previous build
    // served the session token from an unauthenticated GET /token, which
    // handed vault access to any process that could reach loopback.)
    if (req.method === 'POST' && url === '/pair/request') {
      readBody(req, res, (body) => {
        const extensionId = String(body?.extensionId || '').slice(0, 64);
        if (!extensionId) return sendJson(res, 400, { error: 'extensionId is required' });

        const code = crypto.randomInt(0, 1_000_000).toString().padStart(6, '0');
        pendingPairing = { code, extensionId, expiresAt: Date.now() + 120_000 };

        showPairingPrompt(code, extensionId, String(body?.browser || 'Browser'), pendingPairing.expiresAt);
        sendJson(res, 200, { status: 'pending', expiresIn: 120 });
      });
      return;
    }

    if (req.method === 'POST' && url === '/pair/confirm') {
      readBody(req, res, (body) => {
        const code = String(body?.code || '').replace(/\D/g, '');
        const extensionId = String(body?.extensionId || '').slice(0, 64);

        if (!pendingPairing || Date.now() > pendingPairing.expiresAt) {
          pendingPairing = null;
          return sendJson(res, 410, { error: 'Pairing request expired — try again' });
        }
        if (pendingPairing.extensionId !== extensionId) {
          return sendJson(res, 403, { error: 'Pairing request is for a different extension' });
        }
        if (
          code.length !== 6 ||
          !crypto.timingSafeEqual(Buffer.from(code), Buffer.from(pendingPairing.code))
        ) {
          return sendJson(res, 403, { error: 'Incorrect pairing code' });
        }

        const token = crypto.randomBytes(32).toString('hex');
        pairedTokens.set(token, { extensionId, pairedAt: Date.now() });
        pendingPairing = null;
        persistPairedTokens();
        connectedExtensions.add(extensionId);
        lastExtensionSeenAt = Date.now();
        notifyBridgeStatus();

        sendJson(res, 200, { token, app: 'VaultGuard', version: app.getVersion() });
      });
      return;
    }

    // --- Authenticated endpoints ----------------------------------------

    const auth = authenticateRequest(req);
    if (!auth.ok) {
      sendJson(res, 401, { type: 'ERROR', error: 'Unauthorized', payload: { code: 'UNPAIRED' } });
      return;
    }

    if (req.method === 'GET' && url === '/auth') {
      sendJson(res, 200, { isUnlocked, hasAuthConfig: safeHasAuthConfig() });
      return;
    }

    if (req.method === 'POST' && url === '/message') {
      readBody(req, res, (body) => {
        if (!body || typeof body.type !== 'string') {
          return sendJson(res, 400, { type: 'ERROR', error: 'Malformed message' });
        }
        sendJson(res, 200, handleBridgeMessage(body as NativeMessage, auth.extensionId));
      });
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not Found' }));
  });

  httpFallbackServer.on('error', (err: any) => {
    console.error('Loopback bridge error:', err.message);
  });

  tryListenOnPort(HTTP_FALLBACK_PORT_RANGE.min);
}

function sendJson(res: http.ServerResponse, status: number, payload: any): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload));
}

/** Read a JSON body with a hard size cap, then hand it to `done`. */
function readBody(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  done: (body: any) => void
): void {
  const chunks: Buffer[] = [];
  let size = 0;
  let aborted = false;

  req.on('data', (chunk: Buffer) => {
    size += chunk.length;
    if (size > MAX_MSG_SIZE_FROM_EXT) {
      aborted = true;
      sendJson(res, 413, { type: 'ERROR', error: 'Request too large' });
      req.destroy();
      return;
    }
    chunks.push(chunk);
  });

  req.on('end', () => {
    if (aborted) return;
    try {
      done(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {});
    } catch (err: any) {
      sendJson(res, 400, { type: 'ERROR', error: 'Invalid JSON body' });
    }
  });

  req.on('error', () => {
    if (!aborted) sendJson(res, 400, { type: 'ERROR', error: 'Request failed' });
  });
}

function authenticateRequest(req: http.IncomingMessage): { ok: boolean; extensionId?: string } {
  const header = req.headers['x-vault-token'];
  const token = Array.isArray(header) ? header[0] : header;
  if (!token) return { ok: false };

  // The native host proxy uses the session token from bridge.json.
  if (httpFallbackToken && timingSafeCompare(token, httpFallbackToken)) {
    const idHeader = req.headers['x-extension-id'];
    return { ok: true, extensionId: (Array.isArray(idHeader) ? idHeader[0] : idHeader) || 'native-host' };
  }

  for (const [candidate, meta] of pairedTokens) {
    if (timingSafeCompare(token, candidate)) return { ok: true, extensionId: meta.extensionId };
  }
  return { ok: false };
}

function timingSafeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function safeHasAuthConfig(): boolean {
  try {
    return db.hasAuthConfig();
  } catch {
    return false;
  }
}

function pairedTokensPath(): string {
  return path.join(app.getPath('userData'), 'paired-extensions.json');
}

function loadPairedTokens(): void {
  try {
    const raw = JSON.parse(fs.readFileSync(pairedTokensPath(), 'utf-8'));
    if (Array.isArray(raw)) {
      for (const item of raw) {
        if (typeof item?.token === 'string' && typeof item?.extensionId === 'string') {
          pairedTokens.set(item.token, {
            extensionId: item.extensionId,
            pairedAt: item.pairedAt || Date.now(),
          });
        }
      }
    }
  } catch {
    // No pairings yet.
  }
}

function persistPairedTokens(): void {
  try {
    const serialized = Array.from(pairedTokens.entries()).map(([token, meta]) => ({
      token,
      extensionId: meta.extensionId,
      pairedAt: meta.pairedAt,
    }));
    fs.writeFileSync(pairedTokensPath(), JSON.stringify(serialized), { mode: 0o600 });
  } catch (err: any) {
    console.error('Failed to persist extension pairings:', err.message);
  }
}

/** Ask the user to approve a pairing request, in-app or via a dialog. */
function showPairingPrompt(code: string, extensionId: string, browser: string, expiresAt: number): void {
  if (mainWindow) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
    mainWindow.webContents.send('bridge:pairing-request', { code, extensionId, browser, expiresAt });
    return;
  }

  // No window (started minimised to tray): fall back to a native dialog.
  dialog.showMessageBox({
    type: 'info',
    title: 'Connect browser extension',
    message: `Pairing code: ${code}`,
    detail: `Enter this code in the VaultGuard extension (${browser}) to let it connect.\n\nExtension ID: ${extensionId}`,
    buttons: ['OK'],
  });
}

function tryListenOnPort(port: number): void {
  if (!httpFallbackServer) return;
  if (port > HTTP_FALLBACK_PORT_RANGE.max) {
    console.error('Loopback bridge: no free port in range');
    notifyBridgeStatus();
    return;
  }

  const onError = (err: any) => {
    if (err.code === 'EADDRINUSE' || err.code === 'EACCES') {
      tryListenOnPort(port + 1);
    } else {
      console.error('Loopback bridge error:', err.message);
    }
  };

  httpFallbackServer.once('error', onError);

  httpFallbackServer.listen(port, '127.0.0.1', () => {
    httpFallbackServer?.removeListener('error', onError);
    httpFallbackPort = port;
    console.log(`Loopback bridge listening on http://127.0.0.1:${port}`);

    // Publish coordinates for the native host proxy (0600).
    writeBridgeDescriptor(port, httpFallbackToken);
    notifyBridgeStatus();
  });
}

function stopHttpFallbackServer(): void {
  removeBridgeDescriptor();

  if (httpFallbackServer) {
    httpFallbackServer.close();
    httpFallbackServer = null;
  }
  httpFallbackPort = 0;
}

/** Snapshot for the Settings screen's connection panel. */
function getBridgeStatus(): BridgeStatus {
  const manifestPath = path.join(app.getPath('userData'), 'native-messaging-host.json');
  return {
    httpPort: httpFallbackPort || null,
    httpRunning: !!httpFallbackServer && httpFallbackPort > 0,
    nativeHostInstalled: fs.existsSync(manifestPath) && hostRegisteredBrowsers.length > 0,
    nativeHostManifestPath: fs.existsSync(manifestPath) ? manifestPath : null,
    registeredBrowsers: [...hostRegisteredBrowsers],
    registrationErrors: [...hostRegistrationErrors],
    connectedExtensions: connectedExtensions.size,
    lastExtensionSeenAt,
  };
}

let bridgeStatusNotifyTimer: NodeJS.Timeout | null = null;

/** Coalesce status pushes so a burst of requests is one renderer update. */
function notifyBridgeStatus(): void {
  if (bridgeStatusNotifyTimer) return;
  bridgeStatusNotifyTimer = setTimeout(() => {
    bridgeStatusNotifyTimer = null;
    try {
      mainWindow?.webContents.send('bridge:status-changed', getBridgeStatus());
    } catch {
      // Window closed mid-flight.
    }
  }, 250);
}

// ============================================
// Native Messaging Host Registration (Windows)
// ============================================
//
// The extension expects a native host manifest pointing to a .bat file
// (the standard native messaging host pattern). We package the native
// host files (bat, js, json template) with the app and copy them to
// %APPDATA%\VaultGuard\native-host\ on first run, then register a
// manifest pointing to the bat file with the discovered extension IDs.

function ensureNativeHostFilesInstalled(): string {
  // Target directory where the native host files live for registration
  const targetDir = path.join(app.getPath('appData'), 'VaultGuard', 'native-host');
  fs.mkdirSync(targetDir, { recursive: true });

  // Source directory: in production, extraResources puts them at process.resourcesPath/native-host
  // In development, they're at ../../assets/native-host from dist/main/
  const isDev = process.env.NODE_ENV === 'development';
  const sourceDir = isDev
    ? path.join(__dirname, '../../assets/native-host')
    : path.join(process.resourcesPath, 'native-host');

  const files = [
    'vaultguard-native-host.bat',
    'vaultguard-native-host.js',
    'com.vaultguard.native.json', // template
  ];

  for (const file of files) {
    const src = path.join(sourceDir, file);
    const dest = path.join(targetDir, file);
    try {
      if (fs.existsSync(src)) {
        fs.copyFileSync(src, dest);
      }
    } catch {
      // If copy fails (e.g., source not found in some packaging scenarios),
      // we'll still try registration — the manifest path will just be invalid.
    }
  }

  return targetDir;
}

function registerNativeMessagingHost(): void {
  hostRegistrationErrors = [];
  hostRegisteredBrowsers = [];

  // Ensure native host files are installed to AppData
  const nativeHostDir = ensureNativeHostFilesInstalled();
  const batPath = path.join(nativeHostDir, 'vaultguard-native-host.bat');

  // Discover installed VaultGuard extension IDs from Chrome/Edge/Brave
  const extensionIds = discoverExtensionIds();

  const manifest = {
    name: NATIVE_HOST_NAME,
    description: 'VaultGuard Native Messaging Host',
    path: batPath,
    type: 'stdio',
    allowed_origins: extensionIds.map((id) => `chrome-extension://${id}/`),
  };

  const manifestPath = path.join(app.getPath('userData'), 'native-messaging-host.json');

  if (!extensionIds.length) {
    hostRegistrationErrors.push(
      'No VaultGuard extension found yet. Load the extension, then click "Reconnect extension" in Settings.'
    );
  }

  try {
    fs.mkdirSync(path.dirname(manifestPath), { recursive: true });
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  } catch (err: any) {
    hostRegistrationErrors.push(`Could not write host manifest: ${err.message}`);
    notifyBridgeStatus();
    return;
  }

  // Register in Windows Registry for all browsers
  if (process.platform === 'win32') {
    registerInRegistry(manifestPath);
  } else {
    registerInUserDirs(manifestPath, manifest);
  }

  console.log(
    `Native messaging host registered for ${extensionIds.length} extension(s): ${extensionIds.join(', ') || 'none'}`
  );
  notifyBridgeStatus();
}

function discoverExtensionIds(): string[] {
  const ids: string[] = [];

  // Method 1: Check stored extension ID from user settings (highest priority)
  try {
    const settingsPath = path.join(app.getPath('userData'), 'extension-id.txt');
    if (fs.existsSync(settingsPath)) {
      const storedId = fs.readFileSync(settingsPath, 'utf-8').trim();
      if (/^[a-z]{32}$/.test(storedId) && !ids.includes(storedId)) {
        ids.push(storedId);
        console.log(`Using stored extension ID: ${storedId}`);
      }
    }
  } catch {
    // Ignore
  }

  // Method 2: Scan Chrome Preferences file for unpacked extensions (auto-detect)
  // Copy to temp first to avoid lock issues when browser is running
  const userDataDir = path.join(app.getPath('home'), 'AppData', 'Local');
  const browsers = [
    { name: 'Chrome', base: path.join(userDataDir, 'Google', 'Chrome', 'User Data'), profile: 'Default' },
    { name: 'Edge', base: path.join(userDataDir, 'Microsoft', 'Edge', 'User Data'), profile: 'Default' },
    { name: 'Brave', base: path.join(userDataDir, 'BraveSoftware', 'Brave-Browser', 'User Data'), profile: 'Default' },
  ];

  for (const browser of browsers) {
    const prefsPath = path.join(browser.base, browser.profile, 'Preferences');
    if (!fs.existsSync(prefsPath)) continue;

    try {
      // Copy to temp to avoid lock issues
      const tempPrefs = path.join(app.getPath('temp'), `vaultguard-prefs-${browser.name}-${Date.now()}.json`);
      fs.copyFileSync(prefsPath, tempPrefs);
      const prefsRaw = fs.readFileSync(tempPrefs, 'utf-8');
      fs.unlinkSync(tempPrefs);
      
      const prefs = JSON.parse(prefsRaw);
      const settings = prefs?.extensions?.settings || {};

      for (const [extId, extData] of Object.entries(settings) as any[]) {
        if (!/^[a-z]{32}$/.test(extId)) continue;
        if (ids.includes(extId)) continue;

        const manifest = extData?.manifest;

        // Check if this is VaultGuard by name, description, or path
        const name = (manifest?.name || '').toLowerCase();
        const desc = (manifest?.description || '').toLowerCase();
        const extPath = (extData?.path || '').toLowerCase();

        if (
          name === 'vaultguard' ||
          name === 'vault guard' ||
          desc.includes('vaultguard') ||
          extPath.includes('vaultguard')
        ) {
          ids.push(extId);
          console.log(`Found VaultGuard extension in ${browser.name} Preferences: ${extId}`);
        }
      }
    } catch (err: unknown) {
      console.warn(`Failed to read ${browser.name} Preferences:`, (err as Error).message);
    }
  }

  // Method 3: Scan installed extensions directories (for Chrome Web Store installs)
  const chromeExtDir = path.join(userDataDir, 'Google', 'Chrome', 'User Data', 'Default', 'Extensions');
  const edgeExtDir = path.join(userDataDir, 'Microsoft', 'Edge', 'User Data', 'Default', 'Extensions');
  const braveExtDir = path.join(userDataDir, 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'Extensions');

  const browserDirs = [
    { dir: chromeExtDir, browser: 'Chrome' },
    { dir: edgeExtDir, browser: 'Edge' },
    { dir: braveExtDir, browser: 'Brave' },
  ];

  for (const { dir, browser } of browserDirs) {
    if (!fs.existsSync(dir)) continue;

    try {
      const entries = fs.readdirSync(dir);
      for (const extId of entries) {
        if (!/^[a-z]{32}$/.test(extId)) continue;
        if (ids.includes(extId)) continue;

        const extPath = path.join(dir, extId);
        const versions = fs.readdirSync(extPath).filter((v: string) => fs.statSync(path.join(extPath, v)).isDirectory());

        for (const version of versions) {
          const manifestFile = path.join(extPath, version, 'manifest.json');
          if (!fs.existsSync(manifestFile)) continue;

          try {
            const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf-8'));
            if (
              manifest.name === 'VaultGuard' ||
              manifest.name === 'vaultguard' ||
              (manifest.description && manifest.description.toLowerCase().includes('vaultguard'))
            ) {
              ids.push(extId);
              console.log(`Found VaultGuard extension in ${browser}: ${extId}`);
            }
          } catch {
            // Skip if manifest is invalid
          }
        }
      }
    } catch (err: unknown) {
      console.warn(`Failed to scan ${browser} extensions directory:`, (err as Error).message);
    }
  }

  return ids;
}

/**
 * Browsers that read native-messaging host manifests from HKCU.
 *
 * These keys are written with `String.raw` on purpose. The previous code
 * used a plain template literal — `` `reg add "HKCU\Software\Google\...` ``
 * — so `\S`, `\G`, `\C` and `\N` were parsed as escape sequences and the
 * key collapsed to "HKCUSoftwareGoogleChromeNativeMessagingHosts...".
 * Every registration silently failed, which is why `connectNative()` in
 * the extension could never find the host.
 */
const WINDOWS_HOST_REGISTRY_KEYS: { browser: string; key: string }[] = [
  { browser: 'Chrome', key: String.raw`HKCU\Software\Google\Chrome\NativeMessagingHosts` },
  { browser: 'Chrome Beta', key: String.raw`HKCU\Software\Google\Chrome Beta\NativeMessagingHosts` },
  { browser: 'Chromium', key: String.raw`HKCU\Software\Chromium\NativeMessagingHosts` },
  { browser: 'Edge', key: String.raw`HKCU\Software\Microsoft\Edge\NativeMessagingHosts` },
  // Brave lives under BraveSoftware\Brave-Browser, not Brave\Brave.
  { browser: 'Brave', key: String.raw`HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts` },
  { browser: 'Vivaldi', key: String.raw`HKCU\Software\Vivaldi\NativeMessagingHosts` },
  { browser: 'Opera', key: String.raw`HKCU\Software\Opera Software\NativeMessagingHosts` },
];

function registerInRegistry(manifestPath: string): void {
  const { execFileSync } = require('child_process');
  const absolutePath = path.resolve(manifestPath);
  let registered = 0;

  for (const { browser, key } of WINDOWS_HOST_REGISTRY_KEYS) {
    try {
      // execFile (not a shell string) so paths with spaces need no quoting.
      execFileSync(
        'reg',
        ['add', `${key}\\${NATIVE_HOST_NAME}`, '/ve', '/t', 'REG_SZ', '/d', absolutePath, '/f'],
        { stdio: 'ignore', windowsHide: true }
      );
      hostRegisteredBrowsers.push(browser);
      registered++;
    } catch (err: any) {
      // A browser that is not installed still has no key; that is normal
      // and must not be reported as a failure.
      if (!isBrowserAbsent(key)) {
        hostRegistrationErrors.push(`${browser}: ${err.message?.split('\n')[0] || 'registry write failed'}`);
      }
    }
  }

  if (!registered) {
    hostRegistrationErrors.push('Could not register the native host with any browser.');
  } else {
    console.log(`Native host registered for: ${hostRegisteredBrowsers.join(', ')}`);
  }
}

/** True when the browser's own registry root does not exist. */
function isBrowserAbsent(hostKey: string): boolean {
  try {
    const { execFileSync } = require('child_process');
    // Strip the trailing \NativeMessagingHosts to test the browser root.
    const browserRoot = hostKey.replace(/\\NativeMessagingHosts$/i, '');
    execFileSync('reg', ['query', browserRoot], { stdio: 'ignore', windowsHide: true });
    return false;
  } catch {
    return true;
  }
}

/**
 * macOS/Linux equivalent: browsers read per-user manifest directories
 * rather than a registry.
 */
function registerInUserDirs(manifestPath: string, manifest: object): void {
  const home = app.getPath('home');
  const targets =
    process.platform === 'darwin'
      ? [
          { browser: 'Chrome', dir: `${home}/Library/Application Support/Google/Chrome/NativeMessagingHosts` },
          { browser: 'Edge', dir: `${home}/Library/Application Support/Microsoft Edge/NativeMessagingHosts` },
          { browser: 'Brave', dir: `${home}/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts` },
          { browser: 'Chromium', dir: `${home}/Library/Application Support/Chromium/NativeMessagingHosts` },
        ]
      : [
          { browser: 'Chrome', dir: `${home}/.config/google-chrome/NativeMessagingHosts` },
          { browser: 'Chromium', dir: `${home}/.config/chromium/NativeMessagingHosts` },
          { browser: 'Brave', dir: `${home}/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts` },
          { browser: 'Edge', dir: `${home}/.config/microsoft-edge/NativeMessagingHosts` },
        ];

  const contents = JSON.stringify(manifest, null, 2);

  for (const { browser, dir } of targets) {
    // Only install for browsers the user actually has.
    if (!fs.existsSync(path.dirname(dir))) continue;
    try {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, `${NATIVE_HOST_NAME}.json`), contents);
      hostRegisteredBrowsers.push(browser);
    } catch (err: any) {
      hostRegistrationErrors.push(`${browser}: ${err.message}`);
    }
  }

  if (!hostRegisteredBrowsers.length) {
    hostRegistrationErrors.push('No supported browser directory found for the native host.');
  }
  void manifestPath;
}

// Export for testing
export { db, isUnlocked, lockVault };
