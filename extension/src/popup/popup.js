/**
 * VaultGuard popup.
 *
 * Loaded as an ES module so it can share the audited OTP engine in
 * `src/lib/otp.js` instead of re-implementing base32 and the otpauth URI
 * format — the old popup parsed setup keys by hand and got issuer/account
 * backwards on labels like "GitHub:me@example.com".
 *
 * Codes are rendered live, each on its own period. The previous build hardcoded
 * a 30-second countdown for every entry, so 60-second and Steam entries showed
 * a timer that had nothing to do with the code beside it.
 */

import { formatCode, parseOtpInput, validateSecret } from '../lib/otp.js';

// --- State -------------------------------------------------------------

let currentTab = null;
let status = { connected: false, unlocked: false, needsPairing: false };
let passwords = [];
let totpEntries = [];
const codes = new Map(); // entry id -> { code, nextCode, expiresAt, period, digits, error }
let biometric = { enabled: false, credentialId: null };
let ticker = null;
let refreshInFlight = false;
let pairingDeadline = 0;
let pairingTimer = null;
let pendingEntries = null; // parsed from the Add dialog, awaiting Save

const screens = {
  loading: document.getElementById('loading'),
  disconnected: document.getElementById('disconnected'),
  pairing: document.getElementById('pairing'),
  locked: document.getElementById('locked'),
  unlocked: document.getElementById('unlocked'),
};

const el = (id) => document.getElementById(id);

// --- Messaging ---------------------------------------------------------

/**
 * The service worker always answers, but it may answer with `{ error }`.
 * A rejection here means the worker itself could not be reached.
 */
async function send(message) {
  try {
    const response = await chrome.runtime.sendMessage(message);
    return response ?? {};
  } catch (err) {
    return { error: err?.message || 'The extension background is not responding' };
  }
}

// --- Screens ----------------------------------------------------------

function showScreen(name) {
  for (const [key, node] of Object.entries(screens)) {
    node.classList.toggle('active', key === name);
  }
  if (name !== 'unlocked') stopTicker();
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text == null ? '' : String(text);
  return div.innerHTML;
}

/** `''[0]` is undefined, which used to throw on entries with a blank title. */
function avatarLetter(...candidates) {
  for (const value of candidates) {
    const trimmed = String(value || '').trim();
    if (trimmed) return trimmed[0].toUpperCase();
  }
  return '?';
}

function toast(message) {
  const node = document.createElement('div');
  node.className = 'copied-toast';
  node.textContent = message;
  document.body.appendChild(node);
  setTimeout(() => node.remove(), 1500);
}

function showError(node, message) {
  if (!node) return;
  node.textContent = message;
  node.classList.remove('hidden');
  setTimeout(() => node.classList.add('hidden'), 6000);
}

async function copy(text, label = 'Copied') {
  try {
    await navigator.clipboard.writeText(text);
    toast(label);
  } catch {
    // Clipboard permission can be refused; a selectable fallback still works.
    const area = document.createElement('textarea');
    area.value = text;
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    document.execCommand('copy');
    area.remove();
    toast(label);
  }
}

// --- Boot -------------------------------------------------------------

async function init() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTab = tab || null;
  } catch {
    currentTab = null;
  }

  renderPageInfo();
  await refreshStatus();
}

function renderPageInfo() {
  if (!currentTab) return;

  el('page-title').textContent = currentTab.title || 'Current page';

  let hostname = '';
  try {
    hostname = new URL(currentTab.url).hostname;
  } catch {
    hostname = '';
  }
  el('page-url').textContent = hostname || 'This page';

  // Chrome already has the favicon. The old popup asked
  // google.com/s2/favicons for it, which told Google every site the user
  // opened the popup on.
  const icon = el('page-favicon');
  icon.textContent = '';
  if (currentTab.favIconUrl && /^https?:|^data:/.test(currentTab.favIconUrl)) {
    const img = document.createElement('img');
    img.src = currentTab.favIconUrl;
    img.alt = '';
    img.addEventListener('error', () => {
      img.remove();
      icon.textContent = avatarLetter(hostname);
    });
    icon.appendChild(img);
  } else {
    icon.textContent = avatarLetter(hostname);
  }
}

async function refreshStatus() {
  const result = await send({ type: 'GET_AUTH_STATUS' });
  status = {
    connected: !!result.connected,
    unlocked: !!result.unlocked,
    needsPairing: !!result.needsPairing,
    transport: result.transport,
    version: result.version,
    error: result.error,
  };

  if (status.needsPairing) {
    showScreen('pairing');
    return;
  }

  if (!status.connected) {
    el('disconnected-reason').textContent =
      status.error || 'Start VaultGuard on this computer, then try again.';
    await renderOfflineEntries();
    showScreen('disconnected');
    return;
  }

  if (!status.unlocked) {
    showScreen('locked');
    el('master-password').focus();
    await loadBiometricStatus();
    return;
  }

  el('transport-line').textContent =
    status.transport === 'native' ? 'Connected' : 'Connected · local bridge';
  showScreen('unlocked');
  await loadEntries();
}

/** Extension-owned entries stay usable with the desktop app closed. */
async function renderOfflineEntries() {
  const { entries } = await send({ type: 'GET_LOCAL_TOTP_ENTRIES' });
  const list = Array.isArray(entries) ? entries : [];
  const section = el('offline-section');

  if (!list.length) {
    section.classList.add('hidden');
    return;
  }

  section.classList.remove('hidden');
  el('offline-count').textContent = String(list.length);
  totpEntries = list.map((entry) => ({ ...entry, origin: 'local' }));
  codes.clear();
  renderTotpList(el('offline-list'));
  await refreshCodes(totpEntries);
  startTicker();
}

// --- Unlock -----------------------------------------------------------

async function loadBiometricStatus() {
  const result = await send({ type: 'GET_BIOMETRIC_STATUS' });
  biometric = { enabled: !!result.enabled, credentialId: result.credentialId || null };

  const isConfigured = biometric.enabled && biometric.credentialId;

  // This runs on the locked screen only: offer unlock when configured,
  // otherwise offer first-time setup.
  el('biometric-section').classList.remove('hidden');
  el('biometric-btn').classList.toggle('hidden', !isConfigured);
  el('biometric-setup-btn').classList.toggle('hidden', isConfigured);
}

el('unlock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const input = el('master-password');
  const button = el('unlock-btn');
  if (!input.value) return;

  button.disabled = true;
  button.textContent = 'Unlocking…';

  const result = await send({ type: 'UNLOCK_VAULT', password: input.value });
  input.value = '';
  button.disabled = false;
  button.textContent = 'Unlock';

  if (result.success) {
    status.unlocked = true;
    showScreen('unlocked');
    await loadEntries();
  } else {
    showError(el('error-message'), result.error || 'That password did not work');
    input.focus();
  }
});

el('toggle-password').addEventListener('click', () => {
  const input = el('master-password');
  input.type = input.type === 'password' ? 'text' : 'password';
  el('toggle-password').setAttribute(
    'aria-label',
    input.type === 'password' ? 'Show password' : 'Hide password'
  );
  input.focus();
});

el('biometric-btn').addEventListener('click', async () => {
    // First verify with WebAuthn in the extension popup (secure context)
    try {
      const status = await send({ type: 'GET_BIOMETRIC_STATUS' });
      if (!status.enabled || !status.credentialId) {
        showError(el('error-message'), 'Biometric authentication is not configured');
        return;
      }

      // WebAuthn verification in the secure extension context
      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);

      const credential = await navigator.credentials.get({
        publicKey: {
          challenge,
          rpId: 'localhost',
          allowCredentials: [{
            id: Uint8Array.from(atob(status.credentialId), c => c.charCodeAt(0)),
            type: 'public-key',
            transports: ['internal'],
          }],
          userVerification: 'required',
          timeout: 60000,
        },
      });

      if (!credential) {
        showError(el('error-message'), 'Windows Hello verification was cancelled');
        return;
      }
    } catch (err) {
      if (err.name === 'NotAllowedError') {
        showError(el('error-message'), 'Windows Hello verification was cancelled');
        return;
      }
      showError(el('error-message'), 'Windows Hello verification failed: ' + err.message);
      return;
    }

    // If WebAuthn succeeded, now unlock the vault via the desktop app
    const result = await send({
      type: 'BIOMETRIC_UNLOCK',
      credentialId: biometric.credentialId,
    });
    if (result.success) {
      status.unlocked = true;
      showScreen('unlocked');
      await loadEntries();
    } else if (typeof result.error === 'string' && result.error.includes('No biometric key')) {
      // Setup finished while the vault was locked, so the key was never
      // stored. Offer the one-time password step to complete it.
      showError(el('error-message'), 'Windows Hello needs one password entry to finish setup');
      el('biometric-finish-form').classList.remove('hidden');
      el('biometric-finish-password').focus();
    } else {
      showError(el('error-message'), result.error || 'Windows Hello could not verify you');
    }
  });

el('biometric-setup-btn').addEventListener('click', async () => {
  const button = el('biometric-setup-btn');
  button.disabled = true;
  button.textContent = 'Setting up…';

  try {
    // Create WebAuthn credential in the extension popup (secure context)
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);

    const credential = await navigator.credentials.create({
      publicKey: {
        challenge,
        rp: { name: 'VaultGuard', id: 'localhost' },
        user: {
          id: new Uint8Array(16),
          name: 'VaultGuard User',
          displayName: 'VaultGuard',
        },
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' },
          { alg: -257, type: 'public-key' },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
        },
        timeout: 60000,
        attestation: 'none',
      },
    });

    if (!credential) {
      showError(el('error-message'), 'Windows Hello setup was cancelled');
      button.disabled = false;
      button.textContent = 'Setup Windows Hello';
      return;
    }

    const credentialId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
    const response = credential.response;
    const authenticatorData = btoa(String.fromCharCode(...new Uint8Array(response.getAuthenticatorData())));

    // Register with desktop app
    const result = await send({
      type: 'REGISTER_BIOMETRIC',
      credentialId,
      authenticatorData,
    });

    if (result.success && result.keyBound === false) {
      // The vault was locked during setup, so the encryption key could not
      // be captured. Ask for the master password once; the resulting unlock
      // binds the key on the desktop side.
      toast('Almost done — one password entry needed');
      await loadBiometricStatus();
      el('biometric-finish-form').classList.remove('hidden');
      el('biometric-finish-password').focus();
      return;
    }

    if (result.success) {
      toast('Windows Hello enabled!');
      await loadBiometricStatus();
    } else {
      showError(el('error-message'), result.error || 'Failed to enable Windows Hello');
    }
  } catch (err) {
    if (err.name === 'NotAllowedError') {
      showError(el('error-message'), 'Windows Hello setup was cancelled');
    } else {
      showError(el('error-message'), 'Windows Hello setup failed: ' + err.message);
    }
  } finally {
    button.disabled = false;
    button.textContent = 'Setup Windows Hello';
  }
});

// Final step of Hello setup when the vault was locked during registration:
// this unlock is what stores the encryption key for future biometric unlocks.
el('biometric-finish-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const input = el('biometric-finish-password');
  const button = el('biometric-finish-btn');
  if (!input.value) return;

  button.disabled = true;
  button.textContent = 'Checking…';

  const result = await send({ type: 'UNLOCK_VAULT', password: input.value });
  button.disabled = false;
  button.textContent = 'Finish setup';

  if (result.success) {
    input.value = '';
    el('biometric-finish-form').classList.add('hidden');
    status.unlocked = true;
    showScreen('unlocked');
    await loadEntries();
    toast('Windows Hello is ready for next time');
  } else {
    showError(el('biometric-finish-error'), result.error || 'That password did not work');
    input.focus();
  }
});

el('lock-btn').addEventListener('click', async () => {
  await send({ type: 'LOCK_VAULT' });
  stopTicker();
  status.unlocked = false;
  showScreen('locked');
  el('master-password').focus();
  await loadBiometricStatus();
});

el('retry-btn').addEventListener('click', async () => {
  const button = el('retry-btn');
  button.disabled = true;
  button.textContent = 'Looking for the app…';
  await send({ type: 'RECONNECT' });
  button.disabled = false;
  button.textContent = 'Try again';
  await refreshStatus();
});

el('open-vault-btn').addEventListener('click', async () => {
  const result = await send({ type: 'OPEN_VAULT_APP' });
  if (result.success) window.close();
  else toast(result.error || 'Could not reach the desktop app');
});

// --- Pairing ----------------------------------------------------------

el('pair-start-btn').addEventListener('click', async () => {
  const button = el('pair-start-btn');
  button.disabled = true;
  button.textContent = 'Asking the desktop app…';

  const result = await send({ type: 'START_PAIRING' });
  button.disabled = false;
  button.textContent = 'Show me the code';

  if (!result.success) {
    showError(el('pair-error'), result.error || 'Could not reach the desktop app');
    el('pair-error').classList.remove('hidden');
    return;
  }

  el('pairing-step-start').classList.add('hidden');
  el('pairing-step-code').classList.remove('hidden');
  el('pair-code').focus();
  startPairingCountdown(result.expiresIn || 120);
});

function startPairingCountdown(seconds) {
  pairingDeadline = Date.now() + seconds * 1000;
  clearInterval(pairingTimer);
  const render = () => {
    const left = Math.max(0, Math.ceil((pairingDeadline - Date.now()) / 1000));
    el('pair-countdown').textContent = left ? `Expires in ${left}s` : 'That code expired.';
    if (!left) {
      clearInterval(pairingTimer);
      el('pair-confirm-btn').disabled = true;
    }
  };
  render();
  pairingTimer = setInterval(render, 1000);
}

// Grouped as "123 456" while typing, to match how the desktop shows it.
el('pair-code').addEventListener('input', (event) => {
  const digits = event.target.value.replace(/\D/g, '').slice(0, 6);
  event.target.value = digits.length > 3 ? `${digits.slice(0, 3)} ${digits.slice(3)}` : digits;
});

el('pair-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = el('pair-confirm-btn');
  const code = el('pair-code').value.replace(/\D/g, '');
  if (code.length !== 6) {
    showError(el('pair-error'), 'Enter all six digits');
    return;
  }

  button.disabled = true;
  button.textContent = 'Connecting…';
  const result = await send({ type: 'CONFIRM_PAIRING', code });
  button.disabled = false;
  button.textContent = 'Connect';

  if (!result.success) {
    showError(el('pair-error'), result.error || 'That code did not match');
    el('pair-code').select();
    return;
  }

  clearInterval(pairingTimer);
  toast('Connected');
  await refreshStatus();
});

el('pair-cancel-btn').addEventListener('click', () => {
  clearInterval(pairingTimer);
  el('pairing-step-code').classList.add('hidden');
  el('pairing-step-start').classList.remove('hidden');
  el('pair-confirm-btn').disabled = false;
  el('pair-code').value = '';
});

// --- Entries ----------------------------------------------------------

function setPageStatus(kind, text) {
  const dot = el('page-status').querySelector('.status-dot');
  dot.className = `status-dot${kind === 'scanning' ? ' scanning' : kind === 'none' ? ' no-match' : ''}`;
  el('page-status').querySelector('.status-text').textContent = text;
}

async function loadEntries() {
  if (!currentTab?.url) {
    setPageStatus('none', 'No page to match against');
    return;
  }

  setPageStatus('scanning', 'Looking for matches…');
  const result = await send({ type: 'GET_ENTRIES_FOR_URL', url: currentTab.url });

  if (result.locked) {
    status.unlocked = false;
    showScreen('locked');
    await loadBiometricStatus();
    return;
  }
  if (result.needsPairing) {
    showScreen('pairing');
    return;
  }

  passwords = Array.isArray(result.passwords) ? result.passwords : [];
  totpEntries = Array.isArray(result.totpEntries) ? result.totpEntries : [];

  codes.clear();
  for (const code of result.codes || []) {
    if (code?.id) codes.set(code.id, code);
  }

  renderPasswords();
  renderTotpList(el('totp-list'));

  const total = passwords.length + totpEntries.length;
  if (result.error && !total) setPageStatus('none', result.error);
  else if (total) setPageStatus('ok', `${total} match${total === 1 ? '' : 'es'} for this site`);
  else setPageStatus('none', 'Nothing saved for this site');

  // Fill in any code the app did not send (extension-owned entries).
  const missing = totpEntries.filter((e) => !codes.has(e.id) && !isHotp(e));
  if (missing.length) await refreshCodes(missing);

  startTicker();
}

function isHotp(entry) {
  return String(entry?.type || 'TOTP').toUpperCase() === 'HOTP';
}

// --- Passwords --------------------------------------------------------

function renderPasswords() {
  el('password-count').textContent = String(passwords.length);
  const list = el('password-list');
  list.textContent = '';

  if (!passwords.length) {
    list.innerHTML = '<div class="empty-state"><p>No saved login for this site</p></div>';
    return;
  }

  for (const entry of passwords) {
    const item = document.createElement('div');
    item.className = 'credential-item';
    item.innerHTML = `
      <div class="credential-info">
        <div class="credential-icon">${escapeHtml(avatarLetter(entry.title, entry.username))}</div>
        <div class="credential-text">
          <div class="credential-name">${escapeHtml(entry.title || 'Untitled')}</div>
          <div class="credential-username">${escapeHtml(entry.username || 'No username')}</div>
        </div>
      </div>
      <div class="credential-actions">
        <button class="action-btn" data-act="user" title="Copy username">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
          </svg>
        </button>
        <button class="action-btn" data-act="pass" title="Copy password">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
          </svg>
        </button>
        <button class="action-btn" data-act="fill" title="Fill this page">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="9 11 12 14 22 4"/>
            <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
          </svg>
        </button>
      </div>`;

    item.querySelector('[data-act="user"]').addEventListener('click', () =>
      copy(entry.username || '', 'Username copied')
    );
    item.querySelector('[data-act="pass"]').addEventListener('click', () =>
      copy(entry.password || '', 'Password copied')
    );
    item.querySelector('[data-act="fill"]').addEventListener('click', async () => {
      await send({
        type: 'AUTO_FILL',
        data: { username: entry.username, password: entry.password },
      });
      toast('Filled');
    });

    list.appendChild(item);
  }
}

// --- 2FA codes --------------------------------------------------------

function renderTotpList(list) {
  el('totp-count').textContent = String(totpEntries.length);
  list.textContent = '';

  if (!totpEntries.length) {
    list.innerHTML = '<div class="empty-state"><p>No 2FA code for this site</p></div>';
    return;
  }

  for (const entry of totpEntries) {
    list.appendChild(renderTotpItem(entry));
  }
  paintCodes();
}

function renderTotpItem(entry) {
  const item = document.createElement('div');
  item.className = 'credential-item totp-item';
  item.dataset.id = entry.id;

  const hotp = isHotp(entry);
  const subtitle = entry.account || entry.issuer || (entry.origin === 'local' ? 'Saved in this browser' : 'Personal');

  item.innerHTML = `
    <div class="credential-info">
      <div class="credential-icon">${escapeHtml(avatarLetter(entry.issuer, entry.title, entry.account))}</div>
      <div class="credential-text">
        <div class="credential-name">${escapeHtml(entry.issuer || entry.title || 'Untitled')}</div>
        <div class="credential-username">${escapeHtml(subtitle)}</div>
        <div class="totp-code" data-role="code">••• •••</div>
      </div>
    </div>
    <div class="credential-actions">
      ${hotp
        ? `<button class="action-btn" data-act="advance" title="Get the next code">
             <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
               <polyline points="23 4 23 10 17 10"/>
               <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
             </svg>
           </button>`
        : `<div class="ring" data-role="ring"><span data-role="ring-text"></span></div>`}
      <button class="action-btn" data-act="copy" title="Copy code">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
        </svg>
      </button>
      <button class="action-btn" data-act="fill" title="Fill this page">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="9 11 12 14 22 4"/>
          <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
        </svg>
      </button>
    </div>`;

  item.querySelector('[data-act="copy"]').addEventListener('click', async () => {
    const code = await codeFor(entry);
    if (code) await copy(code, 'Code copied');
  });

  item.querySelector('[data-act="fill"]').addEventListener('click', async () => {
    const code = await codeFor(entry);
    if (!code) return;
    await send({ type: 'AUTO_FILL_TOTP', code });
    toast('Code filled');
  });

  // A counter-based code is only valid once, so it is never generated on load
  // — that would burn a code every time the popup opened.
  item.querySelector('[data-act="advance"]')?.addEventListener('click', async () => {
    const result = await send({ type: 'GENERATE_TOTP', entry });
    if (result.error) {
      toast(result.error);
      return;
    }
    codes.set(entry.id, result);
    entry.counter = result.counter;
    paintCodes();
  });

  return item;
}

async function codeFor(entry) {
  const known = codes.get(entry.id);
  if (known?.code) return known.code;

  const result = await send({ type: 'GENERATE_TOTP', entry });
  if (result.error) {
    toast(result.error);
    return null;
  }
  codes.set(entry.id, result);
  paintCodes();
  return result.code;
}

/** Ask the worker for a fresh batch. Never overlaps with itself. */
async function refreshCodes(entries) {
  const wanted = entries.filter((e) => !isHotp(e));
  if (!wanted.length || refreshInFlight) return;

  refreshInFlight = true;
  const result = await send({ type: 'GENERATE_CODES', entries: wanted });
  refreshInFlight = false;

  for (const code of result.codes || []) {
    if (code?.id) codes.set(code.id, code);
  }
  paintCodes();
}

/** Write current values into the DOM. No layout is rebuilt, so nothing flickers. */
function paintCodes() {
  const now = Date.now();

  for (const item of document.querySelectorAll('.totp-item')) {
    const entry = totpEntries.find((e) => e.id === item.dataset.id);
    if (!entry) continue;

    const code = codes.get(entry.id);
    const codeNode = item.querySelector('[data-role="code"]');

    if (code?.error) {
      codeNode.textContent = 'Unavailable';
      codeNode.classList.add('totp-code-error');
      continue;
    }

    codeNode.classList.remove('totp-code-error');
    codeNode.textContent = code?.code ? formatCode(code.code) : isHotp(entry) ? 'Tap ↻ for a code' : '••• •••';

    const ring = item.querySelector('[data-role="ring"]');
    if (!ring || !code?.expiresAt) continue;

    const period = (code.period || entry.period || 30) * 1000;
    const remainingMs = Math.max(0, code.expiresAt - now);
    const fraction = Math.max(0, Math.min(1, remainingMs / period));

    ring.style.setProperty('--pct', fraction.toFixed(3));
    ring.querySelector('[data-role="ring-text"]').textContent = String(Math.ceil(remainingMs / 1000));
    ring.classList.toggle('warning', remainingMs <= 10000 && remainingMs > 5000);
    ring.classList.toggle('danger', remainingMs <= 5000);
  }
}

/**
 * One timer for the whole list. Each entry expires on its own period, so the
 * tick just repaints and asks for a new batch when anything has run out.
 */
function startTicker() {
  stopTicker();
  ticker = setInterval(() => {
    paintCodes();
    const now = Date.now();
    const stale = totpEntries.filter((entry) => {
      if (isHotp(entry)) return false;
      const code = codes.get(entry.id);
      return !code || !code.expiresAt || code.expiresAt <= now;
    });
    if (stale.length) refreshCodes(stale);
  }, 250);
}

function stopTicker() {
  if (ticker) clearInterval(ticker);
  ticker = null;
}

window.addEventListener('unload', stopTicker);

// --- Add a 2FA code ---------------------------------------------------

const modal = el('qr-scanner-modal');
const otpauthInput = el('otpauth-input');
const issuerInput = el('issuer-input');
const accountInput = el('account-input');
const saveBtn = el('qr-save-btn');
const preview = el('qr-preview');
const video = el('qr-video');
const noCamera = el('qr-no-camera');

let stream = null;
let scanTimer = null;
let detector = null;
let scanCanvas = null;

el('add-2fa-btn').addEventListener('click', () => {
  pendingEntries = null;
  otpauthInput.value = '';
  issuerInput.value = '';
  accountInput.value = '';
  preview.classList.add('hidden');
  saveBtn.disabled = true;
  modal.classList.remove('hidden');
  startCamera();
});

function closeModal() {
  modal.classList.add('hidden');
  stopCamera();
}

el('qr-close-btn').addEventListener('click', closeModal);
el('qr-cancel-btn').addEventListener('click', closeModal);

/**
 * Parse whatever was pasted using the shared engine, so migration payloads,
 * multi-line exports, hex secrets and Steam entries all work the same way
 * here as they do in the desktop app.
 */
function parsePasted() {
  const raw = otpauthInput.value.trim();
  pendingEntries = null;
  preview.classList.add('hidden');
  saveBtn.disabled = true;
  if (!raw) return;

  let entries = parseOtpInput(raw);

  // A bare secret is also valid input; take the names from the two fields.
  if (!entries.length && !/^otpauth/i.test(raw)) {
    const check = validateSecret(raw);
    if (!check.valid) {
      preview.textContent = check.error || 'That does not look like a valid setup key';
      preview.className = 'qr-preview qr-preview-error';
      return;
    }
    entries = [
      {
        type: 'TOTP',
        secret: raw.replace(/\s+/g, '').toUpperCase(),
        issuer: issuerInput.value.trim(),
        account: accountInput.value.trim(),
        title: issuerInput.value.trim() || accountInput.value.trim() || '2FA code',
      },
    ];
  }

  if (!entries.length) {
    preview.textContent = 'Could not read that setup key';
    preview.className = 'qr-preview qr-preview-error';
    return;
  }

  const bad = entries.find((e) => !validateSecret(e.secret, e.encoding).valid);
  if (bad) {
    preview.textContent = validateSecret(bad.secret, bad.encoding).error || 'That secret is not valid';
    preview.className = 'qr-preview qr-preview-error';
    return;
  }

  pendingEntries = entries;
  if (entries.length === 1) {
    const [entry] = entries;
    issuerInput.value = entry.issuer || issuerInput.value;
    accountInput.value = entry.account || accountInput.value;
    preview.textContent = `${entry.issuer || entry.title || '2FA code'}${entry.account ? ` · ${entry.account}` : ''} · ${entry.type} · ${entry.digits} digits`;
  } else {
    preview.textContent = `${entries.length} accounts ready to import`;
  }
  preview.className = 'qr-preview';
  saveBtn.disabled = false;
}

otpauthInput.addEventListener('input', parsePasted);
issuerInput.addEventListener('input', () => {
  if (pendingEntries?.length === 1 && !/^otpauth/i.test(otpauthInput.value.trim())) parsePasted();
});
accountInput.addEventListener('input', () => {
  if (pendingEntries?.length === 1 && !/^otpauth/i.test(otpauthInput.value.trim())) parsePasted();
});

saveBtn.addEventListener('click', async () => {
  if (!pendingEntries?.length) return;

  saveBtn.disabled = true;
  saveBtn.textContent = 'Saving…';

  // One name for one entry: honour whatever the user typed over the QR label.
  if (pendingEntries.length === 1) {
    const typedIssuer = issuerInput.value.trim();
    const typedAccount = accountInput.value.trim();
    if (typedIssuer) pendingEntries[0].issuer = typedIssuer;
    if (typedAccount) pendingEntries[0].account = typedAccount;
    pendingEntries[0].title = typedIssuer || pendingEntries[0].title || typedAccount || '2FA code';
    if (currentTab?.url) pendingEntries[0].url = currentTab.url;
  }

  const result = await send({
    type: 'SAVE_TOTP_FROM_QR',
    uri: pendingEntries.map((e) => e.uri).filter(Boolean).join('\n'),
    entries: pendingEntries,
  });

  saveBtn.disabled = false;
  saveBtn.textContent = 'Save';

  if (!result.success) {
    showError(el('qr-error-message'), result.error || 'Could not save that code');
    return;
  }

  toast(result.target === 'desktop' ? 'Saved to your vault' : 'Saved in this browser');
  closeModal();
  await loadEntries();
});

el('paste-clipboard-btn').addEventListener('click', async () => {
  try {
    const text = await navigator.clipboard.readText();
    if (!text.trim()) {
      showError(el('qr-error-message'), 'The clipboard is empty');
      return;
    }
    otpauthInput.value = text.trim();
    parsePasted();
  } catch {
    showError(el('qr-error-message'), 'Chrome would not let the extension read the clipboard');
  }
});

// Screen-scrape the page instead of the webcam — this is how most people
// actually see a QR code, since it is on the screen and not on paper.
el('scan-page-btn').addEventListener('click', async () => {
  const result = await send({ type: 'START_QR_CAPTURE', tabId: currentTab?.id });
  if (result.success) window.close();
  else showError(el('qr-error-message'), result.error || 'This page cannot be scanned');
});

// --- Camera scanning --------------------------------------------------

async function startCamera() {
  if ('BarcodeDetector' in window && !detector) {
    try {
      detector = new BarcodeDetector({ formats: ['qr_code'] });
    } catch {
      detector = null;
    }
  }

  try {
    stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment', width: 320, height: 320 },
    });
    video.srcObject = stream;
    noCamera.classList.add('hidden');
    video.style.display = '';
    el('qr-overlay').style.display = '';
    if (detector) scanTimer = setInterval(scanFrame, 400);
  } catch {
    // No camera, or the user said no. Pasting and page-scanning still work.
    noCamera.classList.remove('hidden');
    video.style.display = 'none';
    el('qr-overlay').style.display = 'none';
  }
}

function stopCamera() {
  if (stream) {
    stream.getTracks().forEach((track) => track.stop());
    stream = null;
  }
  if (scanTimer) clearInterval(scanTimer);
  scanTimer = null;
  video.srcObject = null;
}

async function scanFrame() {
  if (!detector || video.readyState !== video.HAVE_ENOUGH_DATA) return;

  scanCanvas ??= document.createElement('canvas');
  scanCanvas.width = video.videoWidth;
  scanCanvas.height = video.videoHeight;
  scanCanvas.getContext('2d').drawImage(video, 0, 0);

  try {
    const found = await detector.detect(scanCanvas);
    for (const barcode of found) {
      const value = barcode.rawValue || '';
      if (/^otpauth(-migration)?:\/\//i.test(value)) {
        otpauthInput.value = value;
        parsePasted();
        stopCamera();
        toast('QR code read');
        return;
      }
    }
  } catch {
    // A dropped frame is not worth reporting.
  }
}

// --- Go ---------------------------------------------------------------

init();
