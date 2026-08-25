import React, { useState, useEffect, useRef } from 'react';
import { AppSettings, BridgeStatus } from '@vaultguard/shared';

interface SettingsProps {
  onLock: () => void;
}

export default function Settings({ onLock }: SettingsProps) {
  const [settings, setSettings] = useState<AppSettings>({
    autoLockMinutes: 5,
    clipboardClearSeconds: 30,
    autoFillOnPageLoad: true,
    showNotifications: true,
    theme: 'dark',
    language: 'en',
    minimizeToTray: true,
    startWithWindows: false,
    biometricEnabled: false,
  });
  const [showChangePassword, setShowChangePassword] = useState(false);
  const [notification, setNotification] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);
  const [biometricAvailable, setBiometricAvailable] = useState(false);
  const [biometricLoading, setBiometricLoading] = useState(false);
  const [showCSVImport, setShowCSVImport] = useState(false);

  useEffect(() => {
    loadSettings();
    checkBiometricAvailability();
    loadBiometricState();
  }, []);

  const loadBiometricState = async () => {
    try {
      const status = await window.vaultAPI.getBiometricStatus();
      setSettings(prev => ({ ...prev, biometricEnabled: status.enabled }));
    } catch {
      // Ignore errors
    }
  };

  const checkBiometricAvailability = async () => {
    try {
      // Check if WebAuthn is available in this context
      // Electron renders from file:// which is NOT a secure context for WebAuthn
      // In that case, fall back to IPC-based biometric check
      const isSecureContext = typeof window !== 'undefined' && window.isSecureContext;
      
      if (isSecureContext && typeof PublicKeyCredential !== 'undefined') {
        // WebAuthn is available (extension popup, localhost dev server, etc.)
        try {
          const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
          setBiometricAvailable(available);
          return;
        } catch {
          // Fall through to IPC check
        }
      }
      
      // Not a secure context or WebAuthn unavailable - use IPC fallback
      // This works in Electron where the main process can access OS secure storage
      const status = await window.vaultAPI.getBiometricStatus();
      // Show the section if biometric is configured or if we can check via IPC
      setBiometricAvailable(true);
    } catch {
      // Last resort: show biometric option with a note that it may not work
      setBiometricAvailable(true);
    }
  };

  const handleEnableBiometric = async () => {
    setBiometricLoading(true);
    try {
      const isSecureContext = typeof window !== 'undefined' && window.isSecureContext;

      if (!isSecureContext) {
        // Electron file:// origin - WebAuthn is not available
        // Guide user to use browser extension for biometric setup
        showNotification('info', 'Windows Hello setup requires a secure context. Please use the browser extension popup to enable biometric, or run the desktop app from the dev server (npm run dev:desktop).');
        setBiometricLoading(false);
        return;
      }

      // Create WebAuthn credential (only works in secure context)
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
      }) as PublicKeyCredential;

      if (credential) {
        const credentialId = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
        const response = credential.response as AuthenticatorAttestationResponse;
        const authenticatorData = btoa(String.fromCharCode(...new Uint8Array(response.getAuthenticatorData())));

        const result = await window.vaultAPI.registerBiometric({ credentialId, authenticatorData });
        if (result.success) {
          await updateSetting('biometricEnabled', true);
          showNotification('success', 'Windows Hello enabled successfully');
        } else {
          showNotification('error', result.error || 'Failed to enable biometric');
        }
      }
    } catch (err: any) {
      if (err.name === 'NotAllowedError') {
        showNotification('error', 'Biometric setup was cancelled by user');
      } else if (err.message?.includes('HTTPS') || err.message?.includes('secure context')) {
        showNotification('error', 'Windows Hello requires a secure context. Please run from localhost or use the browser extension.');
      } else {
        showNotification('error', 'Failed to enable biometric: ' + err.message);
      }
    } finally {
      setBiometricLoading(false);
    }
  };

  const handleDisableBiometric = async () => {
    const result = await window.vaultAPI.disableBiometric();
    if (result.success) {
      await updateSetting('biometricEnabled', false);
      showNotification('success', 'Windows Hello disabled');
    } else {
      showNotification('error', result.error || 'Failed to disable biometric');
    }
  };

  const handleExportCSV = async () => {
    const result = await window.vaultAPI.exportCSV();
    if (result.success) {
      showNotification('success', `Exported ${result.count} passwords to CSV`);
    } else if (!result.canceled) {
      showNotification('error', result.error || 'CSV export failed');
    }
  };

  const handleImportCSV = async () => {
    const result = await window.vaultAPI.importCSV();
    if (result.success) {
      const message = result.count === 0 
        ? 'All entries already exist in the vault'
        : `Imported ${result.count} passwords` + (result.duplicatesSkipped ? ` (${result.duplicatesSkipped} duplicates skipped)` : '');
      showNotification('success', message);
      setShowCSVImport(false);
    } else if (!result.canceled) {
      showNotification('error', result.errors?.join(', ') || result.error || 'CSV import failed');
    }
  };

  const loadSettings = async () => {
    const result = await window.vaultAPI.getSettings();
    setSettings(result);
  };

  const updateSetting = async <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => {
    const updated = { ...settings, [key]: value };
    setSettings(updated);
    await window.vaultAPI.updateSettings({ [key]: value });
  };

  const handleExport = async () => {
    const result = await window.vaultAPI.exportVault();
    if (result.success) {
      showNotification('success', `Vault exported to ${result.path}`);
    } else if (!result.canceled) {
      showNotification('error', result.error || 'Export failed');
    }
  };

  const handleImport = async () => {
    const result = await window.vaultAPI.importVault();
    if (result.success) {
      showNotification('success', 'Vault imported successfully');
    } else if (!result.canceled) {
      showNotification('error', result.error || 'Import failed');
    }
  };

  const showNotification = (type: 'success' | 'error' | 'info', message: string) => {
    setNotification({ type, message });
    setTimeout(() => setNotification(null), 3000);
  };

  return (
    <div className="space-y-6 animate-fade-in max-w-2xl">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-gray-400 text-sm mt-1">Configure VaultGuard preferences</p>
      </div>

      {/* Security Settings */}
      <div className="glass-card p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-vault-400">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
          Security
        </h2>

        <div className="space-y-4">
          <SettingRow
            title="Auto-lock timeout"
            description="Automatically lock the vault after inactivity"
            control={
              <select
                value={settings.autoLockMinutes}
                onChange={(e) => updateSetting('autoLockMinutes', parseInt(e.target.value))}
                className="input-field w-32"
              >
                <option value="1">1 minute</option>
                <option value="5">5 minutes</option>
                <option value="15">15 minutes</option>
                <option value="30">30 minutes</option>
                <option value="60">1 hour</option>
                <option value="0">Never</option>
              </select>
            }
          />

          <SettingRow
            title="Clipboard auto-clear"
            description="Automatically clear copied passwords after"
            control={
              <select
                value={settings.clipboardClearSeconds}
                onChange={(e) => updateSetting('clipboardClearSeconds', parseInt(e.target.value))}
                className="input-field w-32"
              >
                <option value="10">10 seconds</option>
                <option value="30">30 seconds</option>
                <option value="60">1 minute</option>
                <option value="120">2 minutes</option>
              </select>
            }
          />

          <SettingRow
            title="Change Master Password"
            description="Update your master password"
            control={
              <button onClick={() => setShowChangePassword(true)} className="btn-secondary text-sm">
                Change Password
              </button>
            }
          />

          {/* Biometric Authentication */}
          {biometricAvailable && (
            <SettingRow
              title="Windows Hello"
              description="Use fingerprint or face to unlock"
              control={
                biometricLoading ? (
                  <div className="spinner w-5 h-5" />
                ) : settings.biometricEnabled ? (
                  <button onClick={handleDisableBiometric} className="btn-danger text-sm">
                    Disable
                  </button>
                ) : (
                  <button onClick={handleEnableBiometric} className="btn-secondary text-sm">
                    Enable
                  </button>
                )
              }
            />
          )}
        </div>
      </div>

      {/* Auto-fill Settings */}
      <div className="glass-card p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-vault-400">
            <circle cx="12" cy="12" r="10" />
            <circle cx="12" cy="12" r="4" />
            <line x1="21.17" y1="8" x2="12" y2="8" />
            <line x1="3.95" y1="6.06" x2="8.54" y2="14" />
            <line x1="10.88" y1="21.94" x2="15.46" y2="14" />
          </svg>
          Browser Extension
        </h2>

        <div className="space-y-4">
          <SettingRow
            title="Auto-fill on page load"
            description="Automatically detect and offer to fill login forms"
            control={
              <ToggleSwitch
                checked={settings.autoFillOnPageLoad}
                onChange={(v) => updateSetting('autoFillOnPageLoad', v)}
              />
            }
          />

          <ExtensionPanel onNotify={showNotification} />
        </div>
      </div>

      {/* General Settings */}
      <div className="glass-card p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-vault-400">
            <circle cx="12" cy="12" r="3" />
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
          </svg>
          General
        </h2>

        <div className="space-y-4">
          <SettingRow
            title="Show notifications"
            description="Display notifications for vault actions"
            control={
              <ToggleSwitch
                checked={settings.showNotifications}
                onChange={(v) => updateSetting('showNotifications', v)}
              />
            }
          />

          <SettingRow
            title="Minimize to tray"
            description="Keep VaultGuard running in system tray when minimized"
            control={
              <ToggleSwitch
                checked={settings.minimizeToTray}
                onChange={(v) => updateSetting('minimizeToTray', v)}
              />
            }
          />

          <SettingRow
            title="Theme"
            description="Choose your preferred color scheme"
            control={
              <select
                value={settings.theme}
                onChange={(e) => updateSetting('theme', e.target.value as any)}
                className="input-field w-32"
              >
                <option value="dark">Dark</option>
                <option value="light">Light</option>
                <option value="system">System</option>
              </select>
            }
          />
        </div>
      </div>

      {/* Data Management */}
      <div className="glass-card p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-vault-400">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
            <polyline points="17 8 12 3 7 8" />
            <line x1="12" y1="3" x2="12" y2="15" />
          </svg>
          Data Management
        </h2>

        <div className="space-y-3">
          <button onClick={handleExport} className="w-full flex items-center gap-3 p-4 bg-dark-bg/50 rounded-xl hover:bg-dark-hover/50 transition-colors text-left">
            <div className="w-10 h-10 rounded-xl bg-green-500/20 flex items-center justify-center text-green-400">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                <polyline points="7 10 12 15 17 10" />
                <line x1="12" y1="15" x2="12" y2="3" />
              </svg>
            </div>
            <div>
              <p className="font-medium text-sm">Export Vault</p>
              <p className="text-xs text-gray-400">Download an encrypted backup of your vault</p>
            </div>
          </button>

          <button onClick={handleImport} className="w-full flex items-center gap-3 p-4 bg-dark-bg/50 rounded-xl hover:bg-dark-hover/50 transition-colors text-left">
            <div className="w-10 h-10 rounded-xl bg-blue-500/20 flex items-center justify-center text-blue-400">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                <polyline points="17 8 12 3 7 8" />
                <line x1="12" y1="3" x2="12" y2="15" />
              </svg>
            </div>
            <div>
              <p className="font-medium text-sm">Import Vault</p>
              <p className="text-xs text-gray-400">Restore from a previously exported backup</p>
            </div>
          </button>

          {/* CSV Import/Export */}
          <div className="border-t border-dark-border mt-4 pt-4">
            <p className="text-xs text-gray-500 mb-3 uppercase tracking-wide">CSV Import/Export</p>
            <div className="space-y-2">
              <button onClick={handleExportCSV} className="w-full flex items-center gap-3 p-3 bg-dark-bg/30 rounded-lg hover:bg-dark-hover/50 transition-colors text-left">
                <div className="w-8 h-8 rounded-lg bg-green-500/10 flex items-center justify-center text-green-400">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                    <polyline points="14 2 14 8 20 8" />
                    <line x1="16" y1="13" x2="8" y2="13" />
                    <line x1="16" y1="17" x2="8" y2="17" />
                    <polyline points="10 9 9 9 8 9" />
                  </svg>
                </div>
                <div>
                  <p className="text-sm font-medium">Export as CSV</p>
                  <p className="text-xs text-gray-400">Compatible with other password managers</p>
                </div>
              </button>

              <button onClick={handleImportCSV} className="w-full flex items-center gap-3 p-3 bg-dark-bg/30 rounded-lg hover:bg-dark-hover/50 transition-colors text-left">
                <div className="w-8 h-8 rounded-lg bg-orange-500/10 flex items-center justify-center text-orange-400">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                    <polyline points="14 2 14 8 20 8" />
                    <line x1="12" y1="18" x2="12" y2="12" />
                    <polyline points="9 15 12 18 15 15" />
                  </svg>
                </div>
                <div>
                  <p className="text-sm font-medium">Import from CSV</p>
                  <p className="text-xs text-gray-400">Import from Chrome, Firefox, 1Password, etc.</p>
                </div>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Danger Zone */}
      <div className="glass-card p-6 border border-red-500/20">
        <h2 className="text-lg font-semibold mb-4 text-red-400 flex items-center gap-2">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
            <line x1="12" y1="9" x2="12" y2="13" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
          Danger Zone
        </h2>

        <button
          onClick={onLock}
          className="btn-danger w-full"
        >
          Lock Vault Now
        </button>
      </div>

      {/* Change Password Modal */}
      {showChangePassword && (
        <ChangePasswordModal
          onClose={() => setShowChangePassword(false)}
          onSuccess={() => {
            setShowChangePassword(false);
            showNotification('success', 'Master password changed successfully');
          }}
        />
      )}

      {/* Notification */}
      {notification && (
        <div className="fixed top-4 right-4 z-50 toast">
          <div className={`${notification.type === 'success' ? 'bg-green-500/20 border-green-500/30' : 'bg-red-500/20 border-red-500/30'} border rounded-xl px-4 py-3 flex items-center gap-3 shadow-lg backdrop-blur-sm`}>
            <span className={notification.type === 'success' ? 'text-green-400' : 'text-red-400'}>
              {notification.type === 'success' ? '✓' : '✕'}
            </span>
            <span className="text-sm">{notification.message}</span>
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * Honest, live view of the extension link. This panel used to render a green
 * "Connected" dot unconditionally, which made a broken bridge indistinguishable
 * from a working one. There are two independent transports and either one is
 * enough, so both are reported separately.
 */
function ExtensionPanel({ onNotify }: { onNotify: (type: 'success' | 'error', message: string) => void }) {
  const [status, setStatus] = useState<BridgeStatus | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    const load = () =>
      window.vaultAPI
        .getBridgeStatus()
        .then((s) => {
          if (alive) setStatus(s);
        })
        .catch(() => {});

    load();
    // The main process pushes on every change; the poll only keeps the
    // "last seen" clock honest while the page stays open.
    const timer = window.setInterval(load, 10_000);
    const unsub = window.vaultAPI?.onBridgeStatusChanged?.((s) => setStatus(s));

    return () => {
      alive = false;
      window.clearInterval(timer);
      unsub?.();
    };
  }, []);

  const reregister = async () => {
    setBusy(true);
    try {
      const next = await window.vaultAPI.registerNativeHost();
      setStatus(next);
      if (next.registrationErrors.length) {
        onNotify('error', `Registered for ${next.registeredBrowsers.length || 'no'} browser(s), with errors`);
      } else if (next.registeredBrowsers.length) {
        onNotify('success', `Native host registered for ${next.registeredBrowsers.join(', ')}`);
      } else {
        onNotify('error', 'No supported browser found to register with');
      }
    } catch (err: any) {
      onNotify('error', err?.message || 'Could not register the native host');
    } finally {
      setBusy(false);
    }
  };

  const extIdInputRef = useRef<HTMLInputElement>(null);
  const [setExtIdBusy, setSetExtIdBusy] = useState(false);

  const handleSetExtensionId = async () => {
    const extId = extIdInputRef.current?.value.trim();
    if (!extId || !/^[a-z]{32}$/.test(extId)) {
      onNotify('error', 'Invalid extension ID (must be 32 lowercase letters)');
      return;
    }
    setSetExtIdBusy(true);
    try {
      const result = await window.vaultAPI.setExtensionId(extId);
      if (result.success) {
        onNotify('success', 'Extension ID set successfully. Re-registering native host...');
        extIdInputRef.current!.value = '';
        // Refresh status after a moment
        setTimeout(() => {
          window.vaultAPI.getBridgeStatus().then(setStatus);
        }, 1000);
      } else {
        onNotify('error', result.error || 'Failed to set extension ID');
      }
    } catch (err: any) {
      onNotify('error', err?.message || 'Failed to set extension ID');
    } finally {
      setSetExtIdBusy(false);
    }
  };

  if (!status) {
    return (
      <div className="bg-dark-bg/50 rounded-xl p-4 border border-dark-border">
        <p className="text-xs text-gray-400">Checking the extension link…</p>
      </div>
    );
  }

  const live = status.connectedExtensions > 0;
  const reachable = status.nativeHostInstalled || status.httpRunning;

  const headline = live
    ? `${status.connectedExtensions} extension${status.connectedExtensions === 1 ? '' : 's'} connected`
    : reachable
    ? 'Waiting for the extension'
    : 'No way in yet';

  const dot = live ? 'bg-green-500' : reachable ? 'bg-amber-500' : 'bg-red-500';
  const text = live ? 'text-green-400' : reachable ? 'text-amber-400' : 'text-red-400';

  return (
    <div className="bg-dark-bg/50 rounded-xl border border-dark-border divide-y divide-dark-border">
      <div className="p-4 flex items-start justify-between gap-4">
        <div>
          <p className="font-medium text-sm">Extension Status</p>
          <p className="text-xs text-gray-400 mt-1">
            {live
              ? 'The browser extension is talking to this vault.'
              : reachable
              ? 'This app is listening. Install or reload the VaultGuard extension in your browser.'
              : 'Neither transport is available, so the extension cannot reach the vault.'}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0 pt-0.5">
          <div className={`w-2 h-2 rounded-full ${dot} ${live ? 'animate-pulse' : ''}`} />
          <span className={`text-sm ${text}`}>{headline}</span>
        </div>
      </div>

      <div className="p-4 space-y-2.5">
        <TransportRow
          ok={status.nativeHostInstalled}
          name="Native messaging"
          detail={
            status.registeredBrowsers.length
              ? `Registered for ${status.registeredBrowsers.join(', ')}`
              : 'Not registered with any browser'
          }
        />
        <TransportRow
          ok={status.httpRunning}
          name="Local bridge"
          detail={
            status.httpRunning
              ? `Listening on 127.0.0.1:${status.httpPort} (needs pairing)`
              : 'Not listening'
          }
        />

        {status.lastExtensionSeenAt != null && (
          <p className="text-xs text-gray-500 pt-1">
            Extension last seen {relativeTime(status.lastExtensionSeenAt)}.
          </p>
        )}

        {status.nativeHostManifestPath && (
          <p className="text-[11px] text-gray-600 font-mono break-all pt-1">
            {status.nativeHostManifestPath}
          </p>
        )}
      </div>

      {status.registrationErrors.length > 0 && (
        <div className="p-4">
          <p className="text-xs font-medium text-red-300 mb-1.5">Registration problems</p>
          <ul className="space-y-1">
            {status.registrationErrors.map((err, i) => (
              <li key={i} className="text-xs text-red-400/80 leading-relaxed">
                • {err}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="p-4 flex items-center gap-2">
        <button
          onClick={reregister}
          disabled={busy}
          className="text-xs px-3 py-1.5 rounded-lg bg-vault-500/15 text-vault-300 border border-vault-500/25 hover:bg-vault-500/25 transition-colors disabled:opacity-50"
        >
          {busy ? 'Registering…' : 'Re-register native host'}
        </button>
        <span className="text-[11px] text-gray-500">
          Run this after installing a browser or reinstalling the extension, then reload the extension.
        </span>
      </div>

      {/* Manual Extension ID Entry */}
      <div className="p-4 border-t border-dark-border">
        <p className="text-xs font-medium text-gray-300 mb-2">Manual Extension ID (if auto-detection fails)</p>
        <div className="flex gap-2">
          <input
            ref={extIdInputRef}
            type="text"
            placeholder="32-character extension ID"
            className="flex-1 input-field text-xs font-mono"
            maxLength={32}
          />
          <button
            onClick={handleSetExtensionId}
            disabled={setExtIdBusy}
            className="text-xs px-3 py-1.5 rounded-lg bg-vault-500/15 text-vault-300 border border-vault-500/25 hover:bg-vault-500/25 transition-colors disabled:opacity-50 shrink-0"
          >
            {setExtIdBusy ? 'Setting…' : 'Set Extension ID'}
          </button>
        </div>
        <p className="text-[11px] text-gray-500 mt-1">
          Find the ID in chrome://extensions (enable Developer mode) or edge://extensions
        </p>
      </div>
    </div>
  );
}

function TransportRow({ ok, name, detail }: { ok: boolean; name: string; detail: string }) {
  return (
    <div className="flex items-start gap-2.5">
      <span className={`mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 ${ok ? 'bg-green-500' : 'bg-gray-600'}`} />
      <div className="min-w-0">
        <p className="text-xs font-medium">{name}</p>
        <p className={`text-xs mt-0.5 ${ok ? 'text-gray-400' : 'text-gray-500'}`}>{detail}</p>
      </div>
    </div>
  );
}

function relativeTime(timestamp: number): string {
  const seconds = Math.max(0, Math.round((Date.now() - timestamp) / 1000));
  if (seconds < 10) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'} ago`;
  return new Date(timestamp).toLocaleString();
}

function SettingRow({ title, description, control }: {
  title: string;
  description: string;
  control: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between py-2">
      <div>
        <p className="text-sm font-medium">{title}</p>
        <p className="text-xs text-gray-400 mt-0.5">{description}</p>
      </div>
      {control}
    </div>
  );
}

function ToggleSwitch({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      onClick={() => onChange(!checked)}
      className={`relative w-11 h-6 rounded-full transition-colors ${checked ? 'bg-vault-500' : 'bg-dark-border'}`}
    >
      <div
        className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${checked ? 'left-6' : 'left-1'}`}
      />
    </button>
  );
}

function ChangePasswordModal({ onClose, onSuccess }: {
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (newPassword !== confirmPassword) {
      setError('New passwords do not match');
      return;
    }

    if (newPassword.length < 8) {
      setError('New password must be at least 8 characters');
      return;
    }

    setIsLoading(true);
    try {
      const result = await window.vaultAPI.changePassword(currentPassword, newPassword);
      if (result.success) {
        onSuccess();
      } else {
        setError(result.error || 'Failed to change password');
      }
    } catch (err: any) {
      setError(err.message || 'An error occurred');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center modal-backdrop" onClick={onClose}>
      <div className="glass-card w-full max-w-md p-6 animate-slide-in" onClick={(e) => e.stopPropagation()}>
        <h2 className="text-xl font-bold mb-6">Change Master Password</h2>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm text-gray-300 mb-1">Current Password</label>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="input-field"
              required
            />
          </div>

          <div>
            <label className="block text-sm text-gray-300 mb-1">New Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="input-field"
              required
            />
          </div>

          <div>
            <label className="block text-sm text-gray-300 mb-1">Confirm New Password</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="input-field"
              required
            />
          </div>

          {error && (
            <div className="bg-red-500/10 border border-red-500/20 rounded-lg px-4 py-3 text-red-400 text-sm">
              {error}
            </div>
          )}

          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={onClose} className="btn-secondary">Cancel</button>
            <button type="submit" disabled={isLoading} className="btn-primary">
              {isLoading ? 'Changing...' : 'Change Password'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
