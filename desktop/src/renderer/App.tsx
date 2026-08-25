import React, { useState, useEffect, useCallback } from 'react';
import LoginScreen from './components/LoginScreen';
import Dashboard from './components/Dashboard';
import PasswordVault from './components/PasswordVault';
import TwoFactorVault from './components/TwoFactorVault';
import Settings from './components/Settings';
import PasswordGenerator from './components/PasswordGenerator';
import BackupManager from './components/BackupManager';
import Sidebar from './components/Sidebar';
import TitleBar from './components/TitleBar';

type View = 'dashboard' | 'passwords' | '2fa' | 'generator' | 'backups' | 'settings';

interface PairingRequest {
  code: string;
  extensionId: string;
  browser: string;
  expiresAt: number;
}

export default function App() {
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [hasAuthConfig, setHasAuthConfig] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [currentView, setCurrentView] = useState<View>('dashboard');
  const [notification, setNotification] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);
  const [pairing, setPairing] = useState<PairingRequest | null>(null);

  useEffect(() => {
    checkAuthStatus();

    // Listen for auto-lock events
    const unsubLock = window.vaultAPI?.onVaultLocked?.(() => {
      setIsUnlocked(false);
      checkAuthStatus();
      showNotification('info', 'Vault has been locked');
    });
    const unsubAutoLock = window.vaultAPI?.onVaultAutoLocked?.(() => {
      setIsUnlocked(false);
      checkAuthStatus();
      showNotification('info', 'Vault auto-locked due to inactivity');
    });
    // The browser extension can unlock the vault too; without this the desktop
    // window would sit on the login screen while the extension had full access.
    const unsubRemote = window.vaultAPI?.onVaultUnlockedRemotely?.(() => {
      setIsUnlocked(true);
      showNotification('info', 'Vault unlocked from the browser extension');
    });
    // Pairing has to be answerable from anywhere, including the lock screen —
    // the bridge accepts pairing requests while the vault is still locked.
    const unsubPairing = window.vaultAPI?.onPairingRequest?.((req) => setPairing(req));

    return () => {
      unsubLock?.();
      unsubAutoLock?.();
      unsubRemote?.();
      unsubPairing?.();
    };
  }, []);

  const checkAuthStatus = async () => {
    try {
      if (!window.vaultAPI) {
        console.error('vaultAPI not available - preload may not have loaded');
        setHasAuthConfig(false);
        setIsUnlocked(false);
        return;
      }
      const status = await window.vaultAPI.getAuthStatus();
      setHasAuthConfig(status.hasAuthConfig);
      setIsUnlocked(status.isUnlocked);
    } catch (err) {
      console.error('Failed to check auth status:', err);
      // On error, assume vault exists (don't force setup mode)
      setHasAuthConfig(true);
      setIsUnlocked(false);
    } finally {
      setIsLoading(false);
    }
  };

  const handleUnlock = useCallback((success: boolean) => {
    if (success) {
      setIsUnlocked(true);
      showNotification('success', 'Vault unlocked successfully');
    }
  }, []);

  const handleLock = useCallback(async () => {
    await window.vaultAPI.lock();
    setIsUnlocked(false);
    setCurrentView('dashboard');
    showNotification('info', 'Vault locked');
  }, []);

  const showNotification = useCallback((type: 'success' | 'error' | 'info', message: string) => {
    setNotification({ type, message });
    setTimeout(() => setNotification(null), 3000);
  }, []);

  // Ctrl/Cmd+L locks, matching the shortcut every other password manager uses.
  useEffect(() => {
    if (!isUnlocked) return;
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'l') {
        e.preventDefault();
        handleLock();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isUnlocked, handleLock]);

  const handlePairing = useCallback(async (approved: boolean) => {
    setPairing(null);
    try {
      await window.vaultAPI.respondToPairing(approved);
    } catch {
      // The request may already have expired in the main process.
    }
    if (!approved) showNotification('info', 'Extension pairing denied');
  }, [showNotification]);

  if (isLoading) {
    return (
      <div className="h-screen w-screen flex items-center justify-center bg-dark-bg">
        <div className="flex flex-col items-center gap-4">
          <div className="spinner" />
          <p className="text-gray-400 text-sm">Loading VaultGuard...</p>
        </div>
      </div>
    );
  }

  const pairingPrompt = pairing && (
    <PairingModal
      request={pairing}
      onApprove={() => handlePairing(true)}
      onDeny={() => handlePairing(false)}
    />
  );

  // Show login/unlock screen
  if (!isUnlocked) {
    return (
      <>
        <LoginScreen
          hasAuthConfig={hasAuthConfig}
          onUnlock={handleUnlock}
        />
        {pairingPrompt}
        {notification && <Notification {...notification} />}
      </>
    );
  }

  // Main app layout
  return (
    <div className="h-screen w-screen flex flex-col bg-dark-bg">
      <TitleBar onLock={handleLock} />

      <div className="flex flex-1 overflow-hidden">
        <Sidebar
          currentView={currentView}
          onViewChange={setCurrentView}
          onLock={handleLock}
        />

        <main className="flex-1 overflow-auto p-6">
          {currentView === 'dashboard' && <Dashboard />}
          {currentView === 'passwords' && <PasswordVault />}
          {currentView === '2fa' && <TwoFactorVault />}
          {currentView === 'generator' && <PasswordGenerator />}
          {currentView === 'backups' && <BackupManager />}
          {currentView === 'settings' && <Settings onLock={handleLock} />}
        </main>
      </div>

      {pairingPrompt}
      {notification && <Notification {...notification} />}
    </div>
  );
}

/**
 * Shown when a browser extension asks to use the loopback bridge. The code is
 * generated here and typed into the extension, so a page or another local
 * process cannot pair itself without the user seeing this window.
 */
function PairingModal({ request, onApprove, onDeny }: {
  request: PairingRequest;
  onApprove: () => void;
  onDeny: () => void;
}) {
  const [secondsLeft, setSecondsLeft] = useState(() =>
    Math.max(0, Math.ceil((request.expiresAt - Date.now()) / 1000))
  );

  useEffect(() => {
    const tick = window.setInterval(() => {
      const left = Math.max(0, Math.ceil((request.expiresAt - Date.now()) / 1000));
      setSecondsLeft(left);
      if (left === 0) onDeny();
    }, 1000);
    return () => window.clearInterval(tick);
  }, [request.expiresAt, onDeny]);

  return (
    <div className="fixed inset-0 z-[60] modal-backdrop flex items-center justify-center p-6">
      <div className="glass-card w-full max-w-md p-6 vault-unlock" role="dialog" aria-modal="true">
        <h2 className="text-lg font-semibold">Connect browser extension?</h2>
        <p className="text-sm text-gray-400 mt-1.5">
          The VaultGuard extension in <span className="text-gray-200">{request.browser}</span> wants
          access to this vault. Type this code into the extension to allow it.
        </p>

        <div className="my-5 py-4 rounded-xl bg-dark-bg/70 border border-vault-500/25 text-center">
          <span className="totp-code text-4xl font-semibold text-vault-300">
            {request.code.slice(0, 3)} {request.code.slice(3)}
          </span>
          <p className="text-xs text-gray-500 mt-2">
            Expires in {secondsLeft}s
          </p>
        </div>

        <p className="text-[11px] text-gray-500 font-mono break-all">
          Extension ID: {request.extensionId}
        </p>
        <p className="text-xs text-amber-400/80 mt-3">
          If you did not just click "Connect" in the extension, deny this.
        </p>

        <div className="flex gap-3 mt-5">
          <button onClick={onDeny} className="btn-danger flex-1">
            Deny
          </button>
          <button onClick={onApprove} className="btn-primary flex-1">
            I entered the code
          </button>
        </div>
      </div>
    </div>
  );
}

function Notification({ type, message }: { type: string; message: string }) {
  const bgColor = {
    success: 'bg-green-500/20 border-green-500/30',
    error: 'bg-red-500/20 border-red-500/30',
    info: 'bg-vault-500/20 border-vault-500/30',
  }[type] || 'bg-vault-500/20 border-vault-500/30';

  const iconColor = {
    success: 'text-green-400',
    error: 'text-red-400',
    info: 'text-vault-400',
  }[type] || 'text-vault-400';

  return (
    <div className="fixed top-4 right-4 z-50 toast">
      <div className={`${bgColor} border rounded-xl px-4 py-3 flex items-center gap-3 shadow-lg backdrop-blur-sm`}>
        <span className={iconColor}>
          {type === 'success' && '✓'}
          {type === 'error' && '✕'}
          {type === 'info' && 'ℹ'}
        </span>
        <span className="text-sm">{message}</span>
      </div>
    </div>
  );
}
